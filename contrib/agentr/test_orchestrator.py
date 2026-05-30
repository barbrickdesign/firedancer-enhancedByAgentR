#!/usr/bin/env python3

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from orchestrator import AgentROrchestrator, ExecResult, HealPolicy, WorkloadSpec


class FakeRunner:
    def __init__(self, table):
        self.table = {k: list(v) for k, v in table.items()}
        self.calls = []

    def __call__(self, command: str, timeout_sec: int):
        self.calls.append(command)
        if command not in self.table or not self.table[command]:
            return ExecResult(command, 0, "", "", 0.01, False)
        return self.table[command].pop(0)


class OrchestratorTests(unittest.TestCase):
    def test_retry_heals_failure(self):
        runner = FakeRunner(
            {
                "job": [
                    ExecResult("job", 1, "", "temporary failure", 0.01, False),
                    ExecResult("job", 0, "", "", 0.01, False),
                ]
            }
        )
        orch = AgentROrchestrator(runner=runner, sleep_fn=lambda _: None)
        report = orch.run([WorkloadSpec(name="w1", command="job")])
        self.assertEqual(report.healed, 1)
        self.assertEqual(report.unresolved, 0)

    def test_restart_path_for_unhealthy_runtime(self):
        runner = FakeRunner(
            {
                "job": [
                    ExecResult("job", 1, "", "unhealthy", 0.01, False),
                    ExecResult("job", 0, "", "", 0.01, False),
                ],
                "restart": [ExecResult("restart", 0, "", "", 0.01, False)],
            }
        )
        orch = AgentROrchestrator(runner=runner, sleep_fn=lambda _: None)
        report = orch.run([WorkloadSpec(name="w1", command="job", restart_command="restart")])
        self.assertIn("restart", runner.calls)
        self.assertEqual(report.healed, 1)

    def test_cleanup_path_runs(self):
        runner = FakeRunner(
            {
                "job": [
                    ExecResult("job", 1, "", "retry me", 0.01, False),
                    ExecResult("job", 0, "", "", 0.01, False),
                ],
                "cleanup": [ExecResult("cleanup", 0, "", "", 0.01, False)],
            }
        )
        orch = AgentROrchestrator(runner=runner, sleep_fn=lambda _: None)
        orch.run([WorkloadSpec(name="w1", command="job", cleanup_command="cleanup")])
        self.assertIn("cleanup", runner.calls)

    def test_quarantine_skips_known_bad(self):
        orch = AgentROrchestrator(known_bad={"bad"}, sleep_fn=lambda _: None)
        report = orch.run([WorkloadSpec(name="bad", command="job")])
        self.assertEqual(report.skipped_quarantine, 1)
        self.assertEqual(report.workloads[0].status, "skipped")

    def test_non_retryable_remains_unresolved(self):
        runner = FakeRunner({"job": [ExecResult("job", 2, "", "fatal", 0.01, False)]})
        orch = AgentROrchestrator(runner=runner, sleep_fn=lambda _: None)
        report = orch.run([WorkloadSpec(name="w1", command="job")])
        self.assertEqual(report.unresolved, 1)

    def test_circuit_breaker_opens(self):
        runner = FakeRunner(
            {
                "a": [ExecResult("a", 2, "", "fatal", 0.01, False)],
                "b": [ExecResult("b", 2, "", "fatal", 0.01, False)],
            }
        )
        orch = AgentROrchestrator(
            policy=HealPolicy(circuit_breaker_threshold=1),
            runner=runner,
            sleep_fn=lambda _: None,
        )
        report = orch.run([WorkloadSpec(name="a", command="a"), WorkloadSpec(name="b", command="b")])
        self.assertEqual(report.workloads[1].status, "skipped")

    def test_denylist_blocks_destructive_command(self):
        orch = AgentROrchestrator(sleep_fn=lambda _: None)
        report = orch.run([WorkloadSpec(name="bad", command="rm -rf /")])
        self.assertEqual(report.workloads[0].category, "denylist")

    def test_wallet_redaction_in_audit(self):
        wallet = "5hSWosj58ki4A6hSfQrvteQU5QvyCWmhHn4AuqgaQzqr"
        runner = FakeRunner({"job": [ExecResult("job", 1, "", wallet, 0.01, False)]})
        orch = AgentROrchestrator(redaction_values=[wallet], runner=runner, sleep_fn=lambda _: None)
        orch.run([WorkloadSpec(name="w1", command="job", max_attempts=1)])
        self.assertNotIn(wallet, orch.audit[0].message)


if __name__ == "__main__":
    unittest.main()
