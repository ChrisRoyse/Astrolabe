use super::{AppendAck, Wal};
use calyx_core::{CalyxError, Clock, Result};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

type BatchReply = Sender<Result<BatchResponse>>;

enum BatchOp {
    Append(Vec<u8>),
    Flush,
    TipSeq,
}

enum BatchResponse {
    Ack(AppendAck),
    Flush,
    TipSeq(u64),
}

struct BatchRequest {
    op: BatchOp,
    respond: BatchReply,
}

/// Fsync-backed group commit wrapper around `Wal`.
#[derive(Debug)]
pub struct GroupCommitBatcher {
    sender: Sender<BatchRequest>,
    _thread: JoinHandle<()>,
}

impl GroupCommitBatcher {
    pub fn new(wal: Wal, group_commit_window: Duration, clock: Arc<dyn Clock>) -> Result<Self> {
        validate_window(group_commit_window)?;
        let (sender, receiver) = mpsc::channel();
        let wal = Arc::new(Mutex::new(wal));
        let thread = thread::spawn(move || run_batcher(wal, receiver, group_commit_window, clock));
        Ok(Self {
            sender,
            _thread: thread,
        })
    }

    pub fn submit(&self, payload: Vec<u8>) -> Result<AppendAck> {
        let (respond, receive) = mpsc::channel();
        self.sender
            .send(BatchRequest {
                op: BatchOp::Append(payload),
                respond,
            })
            .map_err(|_| CalyxError::disk_pressure("group commit batcher is closed"))?;
        match receive
            .recv()
            .map_err(|_| CalyxError::disk_pressure("group commit response channel closed"))?
        {
            Ok(BatchResponse::Ack(ack)) => Ok(ack),
            Ok(_) => Err(CalyxError::disk_pressure("missing WAL ack")),
            Err(error) => Err(error),
        }
    }

    pub fn flush_sync(&self) -> Result<()> {
        let (respond, receive) = mpsc::channel();
        self.sender
            .send(BatchRequest {
                op: BatchOp::Flush,
                respond,
            })
            .map_err(|_| CalyxError::disk_pressure("group commit batcher is closed"))?;
        match receive
            .recv()
            .map_err(|_| CalyxError::disk_pressure("group commit flush channel closed"))?
        {
            Ok(BatchResponse::Flush) => Ok(()),
            Ok(_) => Err(CalyxError::disk_pressure("missing WAL flush ack")),
            Err(error) => Err(error),
        }
    }

    pub fn tip_seq(&self) -> Result<u64> {
        let (respond, receive) = mpsc::channel();
        self.sender
            .send(BatchRequest {
                op: BatchOp::TipSeq,
                respond,
            })
            .map_err(|_| CalyxError::disk_pressure("group commit batcher is closed"))?;
        match receive
            .recv()
            .map_err(|_| CalyxError::disk_pressure("group commit tip channel closed"))?
        {
            Ok(BatchResponse::TipSeq(seq)) => Ok(seq),
            Ok(_) => Err(CalyxError::disk_pressure("missing WAL tip ack")),
            Err(error) => Err(error),
        }
    }
}

pub(super) fn validate_window(window: Duration) -> Result<()> {
    if window > super::DEFAULT_GROUP_COMMIT_WINDOW {
        return Err(CalyxError::disk_pressure(
            "group_commit_window exceeds 2 ms limit",
        ));
    }
    Ok(())
}

fn run_batcher(
    wal: Arc<Mutex<Wal>>,
    receiver: Receiver<BatchRequest>,
    group_commit_window: Duration,
    _clock: Arc<dyn Clock>,
) {
    while let Ok(first) = receiver.recv() {
        if !matches!(first.op, BatchOp::Append(_)) {
            flush_requests(&wal, vec![first]);
            continue;
        }
        let mut requests = vec![first];
        let deadline = std::time::Instant::now() + group_commit_window;
        loop {
            let now = std::time::Instant::now();
            if now >= deadline {
                break;
            }
            match receiver.recv_timeout(deadline.saturating_duration_since(now)) {
                Ok(request) => requests.push(request),
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        flush_requests(&wal, requests);
    }
}

fn flush_requests(wal: &Mutex<Wal>, requests: Vec<BatchRequest>) {
    let payloads: Vec<_> = requests
        .iter()
        .filter_map(|request| match &request.op {
            BatchOp::Append(payload) => Some(payload.as_slice()),
            BatchOp::Flush | BatchOp::TipSeq => None,
        })
        .collect();
    let result = if payloads.is_empty() {
        Ok(Vec::new())
    } else {
        wal.lock()
            .expect("group commit WAL lock poisoned")
            .append_batch(&payloads)
    };
    match result {
        Ok(acks) => {
            let mut acks = acks.into_iter();
            let mut tip_seq = None;
            for request in requests {
                let response = match request.op {
                    BatchOp::Append(_) => acks
                        .next()
                        .map(BatchResponse::Ack)
                        .ok_or_else(|| CalyxError::disk_pressure("missing WAL ack")),
                    BatchOp::Flush => Ok(BatchResponse::Flush),
                    BatchOp::TipSeq => {
                        let seq = match tip_seq {
                            Some(seq) => Ok(seq),
                            None => wal
                                .lock()
                                .expect("group commit WAL lock poisoned")
                                .durable_tip_seq()
                                .inspect(|seq| tip_seq = Some(*seq)),
                        };
                        seq.map(BatchResponse::TipSeq)
                    }
                };
                let _ = request.respond.send(response);
            }
        }
        Err(error) => {
            for request in requests {
                let _ = request.respond.send(Err(error.clone()));
            }
        }
    }
}
