#!/usr/bin/env python3
"""Self-tests for the #281 min-of-N hook-budget measurement in
scripts/check-hook-contracts.py.

Drives the gate module's latency-trial machinery with stubbed runners (no
binary needed): a contention profile must pass with the retry visible, a
regression profile must fail listing every sample, and a correctness
violation on a retry trial must fail immediately. Also pins the
``budget_trials`` contract-knob validation (fail-closed on absent, non-int,
bool, and out-of-range values).
"""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-hook-contracts.py"
CONTRACT = ROOT / "ci" / "hook-contracts.json"


def load_checker():
    spec = importlib.util.spec_from_file_location("check_hook_contracts", CHECKER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {CHECKER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expect_fail(fn, *fragments):
    """Assert fn raises the gate's SystemExit(1); return nothing on match."""
    try:
        fn()
    except SystemExit as error:
        assert error.code == 1, f"expected exit 1, got {error.code}"
        return
    raise AssertionError(f"expected gate failure containing {fragments}, but it passed")


class FailCapture:
    """Swap the module's fail() for one that records the message before exiting."""

    def __init__(self, module):
        self.module = module
        self.messages = []

    def __enter__(self):
        self._original = self.module.fail

        def capturing_fail(message):
            self.messages.append(message)
            raise SystemExit(1)

        self.module.fail = capturing_fail
        return self

    def __exit__(self, *exc):
        self.module.fail = self._original
        return False


def scripted_trials(profile):
    """A run_trial stub yielding (result, elapsed_ms) pairs from a script."""
    remaining = list(profile)

    def run_trial():
        assert remaining, "trial requested beyond scripted profile"
        return remaining.pop(0)

    return run_trial, remaining


def main() -> int:
    checker = load_checker()
    budget_ms = 300
    budget_trials = 5

    def ok_trial(result):
        return None

    # (a) Contention profile: first sample over budget, second under. Must
    # pass, with BOTH samples recorded (retry visible, never silent).
    run_trial, remaining = scripted_trials([("r1", 350.0), ("r2", 120.0)])
    result, samples = checker.run_latency_trials(
        run_trial,
        ok_trial,
        budget_ms=budget_ms,
        budget_trials=budget_trials,
        label="contention-profile",
    )
    assert result == "r2", f"expected the passing trial's result, got {result!r}"
    assert samples == [350.0, 120.0], f"retries must be recorded: {samples}"
    assert not remaining, "estimator stopped before consuming the passing trial"

    # Fast path: a healthy first trial takes exactly one sample.
    run_trial, remaining = scripted_trials([("r1", 80.0), ("never", 0.0)])
    result, samples = checker.run_latency_trials(
        run_trial,
        ok_trial,
        budget_ms=budget_ms,
        budget_trials=budget_trials,
        label="fast-path",
    )
    assert result == "r1" and samples == [80.0], (result, samples)
    assert len(remaining) == 1, "fast path must not run extra trials"

    # (b) Regression profile: every trial over budget. Must fail and list
    # every sample.
    run_trial, _ = scripted_trials([("r", 400.0 + i) for i in range(budget_trials)])
    with FailCapture(checker) as capture:
        expect_fail(
            lambda: checker.run_latency_trials(
                run_trial,
                ok_trial,
                budget_ms=budget_ms,
                budget_trials=budget_trials,
                label="regression-profile",
            )
        )
    (message,) = capture.messages
    assert "all 5 trials" in message, message
    for sample in ["400.0", "401.0", "402.0", "403.0", "404.0"]:
        assert sample in message, f"sample {sample} missing from failure: {message}"

    # (c) Correctness violation on a RETRY trial: fail immediately with the
    # correctness message, not a budget message.
    def strict_trial(result):
        if result == "bad-rc":
            checker.fail("stub-correctness rc=7")

    run_trial, remaining = scripted_trials(
        [("slow-but-clean", 350.0), ("bad-rc", 90.0), ("never", 0.0)]
    )
    with FailCapture(checker) as capture:
        expect_fail(
            lambda: checker.run_latency_trials(
                run_trial,
                strict_trial,
                budget_ms=budget_ms,
                budget_trials=budget_trials,
                label="correctness-on-retry",
            )
        )
    (message,) = capture.messages
    assert "stub-correctness rc=7" in message, message
    assert len(remaining) == 1, "correctness violation must stop the trial loop"

    # Held-open-stdin ceiling test: a ceiling miss retries; a later in-ceiling
    # silent exit passes with all samples recorded.
    timeout_script = [
        (False, 950.0, None, "", ""),
        (True, 400.0, 0, "", ""),
    ]

    def stub_timeout_trial(binary, env, ceiling_ms):
        return timeout_script.pop(0)

    original_timeout_trial = checker.run_timeout_trial
    checker.run_timeout_trial = stub_timeout_trial
    try:
        report = checker.assert_timeout_is_silent(
            Path("stub-binary"), {}, 900, budget_trials
        )
        assert report == {"ms": 400.0, "samples_ms": [950.0, 400.0], "trials": 2}, report

        # All-N ceiling misses must fail listing every sample.
        timeout_script[:] = [(False, 950.0 + i, None, "", "") for i in range(budget_trials)]
        with FailCapture(checker) as capture:
            expect_fail(
                lambda: checker.assert_timeout_is_silent(
                    Path("stub-binary"), {}, 900, budget_trials
                )
            )
        (message,) = capture.messages
        assert "any of 5 trials" in message, message

        # A non-silent in-ceiling exit is a correctness violation: immediate fail.
        timeout_script[:] = [
            (False, 950.0, None, "", ""),
            (True, 200.0, 0, "leaked stdout", ""),
        ]
        with FailCapture(checker) as capture:
            expect_fail(
                lambda: checker.assert_timeout_is_silent(
                    Path("stub-binary"), {}, 900, budget_trials
                )
            )
        (message,) = capture.messages
        assert "was not silent" in message, message
    finally:
        checker.run_timeout_trial = original_timeout_trial

    # Contract-knob validation: the shipped contract must validate and carry
    # budget_trials; corrupted knobs must fail closed.
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    validated_budget, validated_trials, validated_ceiling = checker.validate_contract(
        contract
    )
    assert validated_budget == 300 and validated_ceiling >= 300
    assert 1 <= validated_trials <= 10, validated_trials

    for corruption in [None, "5", 5.0, True, 0, -1, 11]:
        bad = copy.deepcopy(contract)
        if corruption is None:
            del bad["budget_trials"]
        else:
            bad["budget_trials"] = corruption
        with FailCapture(checker) as capture:
            expect_fail(lambda b=bad: checker.validate_contract(b))
        (message,) = capture.messages
        assert "budget_trials" in message, (corruption, message)

    print(
        "test-check-hook-contracts OK: "
        "min-of-N estimator, retry visibility, regression bite, "
        "per-trial correctness, ceiling retries, knob validation"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
