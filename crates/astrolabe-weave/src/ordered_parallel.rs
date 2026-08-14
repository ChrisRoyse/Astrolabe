//! Bounded deterministic scheduling for independent source-owned rows.
//!
//! Workers own strided source ordinals (`worker`, `worker + width`, ...), while
//! the coordinator reads one capacity-one channel per worker in global source
//! order and acknowledges every accepted row before that worker advances. A
//! worker can therefore retain at most one completed row, and no early
//! contiguous range can serialize every later worker behind an undrained
//! channel. Computation order is concurrent; acceptance order is always
//! `0..source_count`.

use std::any::Any;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

/// Physical scheduler accounting for one independent-row pass.
///
/// Timing values are observations, never persisted-value inputs. `worker_compute_ns`
/// measures wall time spent inside the declared worker callback (excluding channel
/// blocking); production effective-worker claims still use independently sampled
/// process CPU divided by scheduler wall time.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ParallelScheduleTelemetry {
    pub stage: String,
    pub source_count: usize,
    pub requested_workers: usize,
    pub effective_workers: usize,
    pub started_workers: usize,
    pub completed_sources: usize,
    pub worker_compute_ns: u64,
    pub coordinator_wait_ns: u64,
    pub elapsed_ns: u64,
}

#[derive(Debug)]
pub(crate) enum OrderedParallelFailureKind<E> {
    InvalidWorkerCount,
    Capacity {
        component: &'static str,
        requested_items: usize,
        message: String,
    },
    Telemetry {
        field: &'static str,
        message: String,
    },
    Spawn {
        worker_index: usize,
        message: String,
    },
    Compute {
        source: usize,
        error: Box<E>,
    },
    Accept {
        source: usize,
        error: Box<E>,
    },
    Disconnected {
        worker_index: usize,
        expected_source: usize,
        message: String,
    },
    OrderDrift {
        worker_index: usize,
        expected_source: usize,
        observed_source: usize,
    },
    WorkerPanicked {
        worker_index: usize,
        message: String,
    },
}

#[derive(Debug)]
pub(crate) struct OrderedParallelFailure<E> {
    pub kind: OrderedParallelFailureKind<E>,
    pub telemetry: ParallelScheduleTelemetry,
}

struct WorkerRow<T, E> {
    source: usize,
    compute_ns: Result<u64, String>,
    result: Result<T, E>,
}

fn duration_ns(duration: Duration, field: &'static str) -> Result<u64, String> {
    u64::try_from(duration.as_nanos()).map_err(|error| {
        format!(
            "ASTRO_WEAVE_SCHEDULER_TELEMETRY_OVERFLOW: {field} duration {}ns is not representable as u64: {error}",
            duration.as_nanos()
        )
    })
}

fn add_telemetry_ns(total: &mut u64, increment: u64, field: &'static str) -> Result<(), String> {
    *total = total.checked_add(increment).ok_or_else(|| {
        format!(
            "ASTRO_WEAVE_SCHEDULER_TELEMETRY_OVERFLOW: {field} total {total}ns plus {increment}ns exceeded u64"
        )
    })?;
    Ok(())
}

fn finish<E>(
    mut telemetry: ParallelScheduleTelemetry,
    started: Instant,
    terminal: Option<OrderedParallelFailureKind<E>>,
) -> Result<ParallelScheduleTelemetry, Box<OrderedParallelFailure<E>>> {
    match duration_ns(started.elapsed(), "elapsed_ns") {
        Ok(elapsed_ns) => telemetry.elapsed_ns = elapsed_ns,
        Err(message) => {
            return Err(Box::new(OrderedParallelFailure {
                kind: OrderedParallelFailureKind::Telemetry {
                    field: "elapsed_ns",
                    message,
                },
                telemetry,
            }));
        }
    }
    match terminal {
        Some(kind) => Err(Box::new(OrderedParallelFailure { kind, telemetry })),
        None => Ok(telemetry),
    }
}

fn panic_message(payload: Box<dyn Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

/// Computes independent source rows concurrently and accepts them in exact source
/// order with O(workers × one-row) retained results.
pub(crate) fn run_ordered_parallel<State, Row, Failure, Init, Work, Accept>(
    stage: impl Into<String>,
    source_count: usize,
    requested_workers: usize,
    init: Init,
    work: Work,
    mut accept: Accept,
) -> Result<ParallelScheduleTelemetry, Box<OrderedParallelFailure<Failure>>>
where
    State: Send,
    Row: Send,
    Failure: Send,
    Init: Fn(usize) -> Result<State, Failure> + Sync,
    Work: Fn(&mut State, usize) -> Result<Row, Failure> + Sync,
    Accept: FnMut(usize, Row) -> Result<(), Failure>,
{
    let started = Instant::now();
    let mut telemetry = ParallelScheduleTelemetry {
        stage: stage.into(),
        source_count,
        requested_workers,
        ..ParallelScheduleTelemetry::default()
    };
    if requested_workers == 0 {
        return finish(
            telemetry,
            started,
            Some(OrderedParallelFailureKind::InvalidWorkerCount),
        );
    }
    if source_count == 0 {
        return finish(telemetry, started, None);
    }

    let effective_workers = requested_workers.min(source_count);
    telemetry.effective_workers = effective_workers;
    if effective_workers == 1 {
        telemetry.started_workers = 1;
        let mut state = match init(0) {
            Ok(state) => state,
            Err(error) => {
                return finish(
                    telemetry,
                    started,
                    Some(OrderedParallelFailureKind::Compute {
                        source: 0,
                        error: Box::new(error),
                    }),
                );
            }
        };
        for source in 0..source_count {
            let compute_started = Instant::now();
            let row = work(&mut state, source);
            let compute_ns = match duration_ns(compute_started.elapsed(), "worker_compute_ns") {
                Ok(value) => value,
                Err(message) => {
                    return finish(
                        telemetry,
                        started,
                        Some(OrderedParallelFailureKind::Telemetry {
                            field: "worker_compute_ns",
                            message,
                        }),
                    );
                }
            };
            if let Err(message) = add_telemetry_ns(
                &mut telemetry.worker_compute_ns,
                compute_ns,
                "worker_compute_ns",
            ) {
                return finish(
                    telemetry,
                    started,
                    Some(OrderedParallelFailureKind::Telemetry {
                        field: "worker_compute_ns",
                        message,
                    }),
                );
            }
            let row = match row {
                Ok(row) => row,
                Err(error) => {
                    return finish(
                        telemetry,
                        started,
                        Some(OrderedParallelFailureKind::Compute {
                            source,
                            error: Box::new(error),
                        }),
                    );
                }
            };
            if let Err(error) = accept(source, row) {
                return finish(
                    telemetry,
                    started,
                    Some(OrderedParallelFailureKind::Accept {
                        source,
                        error: Box::new(error),
                    }),
                );
            }
            telemetry.completed_sources = source + 1;
        }
        return finish(telemetry, started, None);
    }

    thread::scope(|scope| {
        let mut handles = Vec::new();
        if let Err(error) = handles.try_reserve_exact(effective_workers) {
            return finish(
                telemetry,
                started,
                Some(OrderedParallelFailureKind::Capacity {
                    component: "worker handle table",
                    requested_items: effective_workers,
                    message: error.to_string(),
                }),
            );
        }
        let mut receivers = Vec::<mpsc::Receiver<WorkerRow<Row, Failure>>>::new();
        if let Err(error) = receivers.try_reserve_exact(effective_workers) {
            return finish(
                telemetry,
                started,
                Some(OrderedParallelFailureKind::Capacity {
                    component: "worker receiver table",
                    requested_items: effective_workers,
                    message: error.to_string(),
                }),
            );
        }
        let mut acknowledgements = Vec::<mpsc::SyncSender<()>>::new();
        if let Err(error) = acknowledgements.try_reserve_exact(effective_workers) {
            return finish(
                telemetry,
                started,
                Some(OrderedParallelFailureKind::Capacity {
                    component: "worker acknowledgement table",
                    requested_items: effective_workers,
                    message: error.to_string(),
                }),
            );
        }

        let mut spawn_failure = None;
        for worker_index in 0..effective_workers {
            let (sender, receiver) = mpsc::sync_channel(1);
            let (acknowledge, acknowledged) = mpsc::sync_channel(0);
            let init = &init;
            let work = &work;
            let thread_name = format!("astro-ordered-{worker_index}");
            match thread::Builder::new()
                .name(thread_name)
                .spawn_scoped(scope, move || {
                    let mut state = match init(worker_index) {
                        Ok(state) => state,
                        Err(error) => {
                            let _ = sender.send(WorkerRow {
                                source: worker_index,
                                compute_ns: Ok(0),
                                result: Err(error),
                            });
                            return;
                        }
                    };
                    let mut source = worker_index;
                    while source < source_count {
                        let compute_started = Instant::now();
                        let result = work(&mut state, source);
                        let failed = result.is_err();
                        let row = WorkerRow {
                            source,
                            compute_ns: duration_ns(compute_started.elapsed(), "worker_compute_ns"),
                            result,
                        };
                        if sender.send(row).is_err() || failed {
                            return;
                        }
                        if acknowledged.recv().is_err() {
                            return;
                        }
                        if source_count - source <= effective_workers {
                            break;
                        }
                        source += effective_workers;
                    }
                }) {
                Ok(handle) => {
                    receivers.push(receiver);
                    acknowledgements.push(acknowledge);
                    handles.push((worker_index, handle));
                    telemetry.started_workers = handles.len();
                }
                Err(error) => {
                    spawn_failure = Some(OrderedParallelFailureKind::Spawn {
                        worker_index,
                        message: error.to_string(),
                    });
                    break;
                }
            }
        }

        if let Some(kind) = spawn_failure {
            drop(receivers);
            drop(acknowledgements);
            for (_, handle) in handles {
                let _ = handle.join();
            }
            return finish(telemetry, started, Some(kind));
        }

        let mut terminal = None;
        for expected_source in 0..source_count {
            let worker_index = expected_source % effective_workers;
            let wait_started = Instant::now();
            let received = receivers[worker_index].recv();
            let wait_ns = match duration_ns(wait_started.elapsed(), "coordinator_wait_ns") {
                Ok(value) => value,
                Err(message) => {
                    terminal = Some(OrderedParallelFailureKind::Telemetry {
                        field: "coordinator_wait_ns",
                        message,
                    });
                    break;
                }
            };
            if let Err(message) = add_telemetry_ns(
                &mut telemetry.coordinator_wait_ns,
                wait_ns,
                "coordinator_wait_ns",
            ) {
                terminal = Some(OrderedParallelFailureKind::Telemetry {
                    field: "coordinator_wait_ns",
                    message,
                });
                break;
            }
            let row = match received {
                Ok(row) => row,
                Err(error) => {
                    terminal = Some(OrderedParallelFailureKind::Disconnected {
                        worker_index,
                        expected_source,
                        message: error.to_string(),
                    });
                    break;
                }
            };
            let compute_ns = match row.compute_ns {
                Ok(value) => value,
                Err(message) => {
                    terminal = Some(OrderedParallelFailureKind::Telemetry {
                        field: "worker_compute_ns",
                        message,
                    });
                    break;
                }
            };
            if let Err(message) = add_telemetry_ns(
                &mut telemetry.worker_compute_ns,
                compute_ns,
                "worker_compute_ns",
            ) {
                terminal = Some(OrderedParallelFailureKind::Telemetry {
                    field: "worker_compute_ns",
                    message,
                });
                break;
            }
            if row.source != expected_source {
                terminal = Some(OrderedParallelFailureKind::OrderDrift {
                    worker_index,
                    expected_source,
                    observed_source: row.source,
                });
                break;
            }
            let value = match row.result {
                Ok(value) => value,
                Err(error) => {
                    terminal = Some(OrderedParallelFailureKind::Compute {
                        source: expected_source,
                        error: Box::new(error),
                    });
                    break;
                }
            };
            if let Err(error) = accept(expected_source, value) {
                terminal = Some(OrderedParallelFailureKind::Accept {
                    source: expected_source,
                    error: Box::new(error),
                });
                break;
            }
            telemetry.completed_sources = expected_source + 1;
            let wait_started = Instant::now();
            if let Err(error) = acknowledgements[worker_index].send(()) {
                let acknowledgement_ns =
                    match duration_ns(wait_started.elapsed(), "coordinator_wait_ns") {
                        Ok(value) => value,
                        Err(message) => {
                            terminal = Some(OrderedParallelFailureKind::Telemetry {
                                field: "coordinator_wait_ns",
                                message,
                            });
                            break;
                        }
                    };
                if let Err(message) = add_telemetry_ns(
                    &mut telemetry.coordinator_wait_ns,
                    acknowledgement_ns,
                    "coordinator_wait_ns",
                ) {
                    terminal = Some(OrderedParallelFailureKind::Telemetry {
                        field: "coordinator_wait_ns",
                        message,
                    });
                    break;
                }
                terminal = Some(OrderedParallelFailureKind::Disconnected {
                    worker_index,
                    expected_source,
                    message: format!("worker acknowledgement disconnected: {error}"),
                });
                break;
            }
            let acknowledgement_ns =
                match duration_ns(wait_started.elapsed(), "coordinator_wait_ns") {
                    Ok(value) => value,
                    Err(message) => {
                        terminal = Some(OrderedParallelFailureKind::Telemetry {
                            field: "coordinator_wait_ns",
                            message,
                        });
                        break;
                    }
                };
            if let Err(message) = add_telemetry_ns(
                &mut telemetry.coordinator_wait_ns,
                acknowledgement_ns,
                "coordinator_wait_ns",
            ) {
                terminal = Some(OrderedParallelFailureKind::Telemetry {
                    field: "coordinator_wait_ns",
                    message,
                });
                break;
            }
        }
        drop(receivers);
        drop(acknowledgements);

        let mut first_panic = None;
        for (worker_index, handle) in handles {
            if let Err(payload) = handle.join()
                && first_panic.is_none()
            {
                first_panic = Some((worker_index, panic_message(payload)));
            }
        }
        if let Some((worker_index, message)) = first_panic
            && matches!(
                terminal,
                None | Some(OrderedParallelFailureKind::Disconnected { .. })
            )
        {
            terminal = Some(OrderedParallelFailureKind::WorkerPanicked {
                worker_index,
                message,
            });
        }

        finish(telemetry, started, terminal)
    })
}
