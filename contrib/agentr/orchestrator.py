#!/usr/bin/env python3
"""AgentR orchestrator with self-healing execution methods."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable


@dataclass
class ExecResult:
    command: str
    returncode: int
    stdout: str
    stderr: str
    duration_sec: float
    timed_out: bool = False


@dataclass
class WorkloadSpec:
    name: str
    command: str
    retryable_exit_codes: tuple[int, ...] = (1,)
    max_attempts: int = 3
    timeout_sec: int = 600
    stall_timeout_sec: int = 600
    cleanup_command: str | None = None
    restart_command: str | None = None
    tags: tuple[str, ...] = ()


@dataclass
class HealPolicy:
    max_heals_per_run: int = 20
    cooldown_sec: float = 1.0
    circuit_breaker_threshold: int = 5
    denylist_patterns: tuple[str, ...] = (
        r"\brm\s+-rf\s+/",
        r"\bmkfs\b",
        r"\bdd\s+if=",
        r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;\s*:",
    )


@dataclass
class HealEvent:
    workload: str
    attempt: int
    event: str
    category: str
    action: str
    message: str
    timestamp: float


@dataclass
class WorkloadReport:
    name: str
    status: str
    category: str
    attempts: int
    healed: bool
    quarantined: bool
    final_returncode: int | None
    events: list[HealEvent] = field(default_factory=list)


@dataclass
class RunReport:
    healed: int
    unresolved: int
    skipped_quarantine: int
    total: int
    workloads: list[WorkloadReport]
    audit: list[HealEvent]


class AgentROrchestrator:
    def __init__(
        self,
        *,
        policy: HealPolicy | None = None,
        known_bad: Iterable[str] = (),
        redaction_values: Iterable[str] = (),
        runner: Callable[[str, int], ExecResult] | None = None,
        sleep_fn: Callable[[float], None] | None = None,
    ) -> None:
        self.policy = policy or HealPolicy()
        self.known_bad = set(known_bad)
        self.audit: list[HealEvent] = []
        self._heal_count = 0
        self._consecutive_failures = 0
        self._circuit_open = False
        self._runner = runner or self._default_runner
        self._sleep = sleep_fn or time.sleep
        self._redaction_values = [v for v in redaction_values if v]

    @staticmethod
    def _default_runner(command: str, timeout_sec: int) -> ExecResult:
        start = time.time()
        try:
            proc = subprocess.run(
                command,
                shell=True,
                text=True,
                capture_output=True,
                timeout=timeout_sec,
                check=False,
            )
            return ExecResult(
                command=command,
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_sec=time.time() - start,
                timed_out=False,
            )
        except subprocess.TimeoutExpired as exc:
            return ExecResult(
                command=command,
                returncode=124,
                stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
                stderr=(exc.stderr or "") if isinstance(exc.stderr, str) else "",
                duration_sec=time.time() - start,
                timed_out=True,
            )

    def _redact(self, text: str) -> str:
        sanitized = text
        for value in self._redaction_values:
            sanitized = sanitized.replace(value, "[REDACTED]")
        sanitized = re.sub(r"\b[1-9A-HJ-NP-Za-km-z]{32,64}\b", "[REDACTED_B58]", sanitized)
        return sanitized

    def _is_denied(self, command: str) -> bool:
        for pattern in self.policy.denylist_patterns:
            if re.search(pattern, command):
                return True
        return False

    def _classify_failure(self, spec: WorkloadSpec, result: ExecResult) -> tuple[str, bool]:
        combined = (result.stdout + "\n" + result.stderr).lower()
        if result.timed_out or result.duration_sec >= spec.stall_timeout_sec:
            return "stalled_job", True
        if "unhealthy" in combined or "healthcheck failed" in combined:
            return "unhealthy_runtime", True
        if result.returncode in spec.retryable_exit_codes:
            return "retryable_failure", True
        return "non_retryable_failure", False

    def _event(self, workload: str, attempt: int, event: str, category: str, action: str, message: str) -> HealEvent:
        entry = HealEvent(
            workload=workload,
            attempt=attempt,
            event=event,
            category=category,
            action=action,
            message=self._redact(message),
            timestamp=time.time(),
        )
        self.audit.append(entry)
        return entry

    def _run_cmd(self, cmd: str, timeout_sec: int) -> ExecResult:
        return self._runner(cmd, timeout_sec)

    def _perform_heal_action(self, spec: WorkloadSpec, attempt: int, category: str) -> tuple[str, str | None]:
        if self._heal_count >= self.policy.max_heals_per_run:
            self._circuit_open = True
            return "circuit_open", None

        action = "retry"
        cmd = None
        if category in {"stalled_job", "unhealthy_runtime"} and spec.restart_command:
            action = "restart"
            cmd = spec.restart_command
        elif spec.cleanup_command:
            action = "cleanup"
            cmd = spec.cleanup_command

        self._heal_count += 1
        self._event(spec.name, attempt, "heal_action", category, action, f"performing {action}")
        return action, cmd

    def run(self, workloads: list[WorkloadSpec]) -> RunReport:
        reports: list[WorkloadReport] = []
        skipped_quarantine = 0

        for spec in workloads:
            if spec.name in self.known_bad or self._circuit_open:
                skipped_quarantine += 1
                event = self._event(spec.name, 0, "quarantine", "quarantine", "skip", "known bad or circuit open")
                reports.append(
                    WorkloadReport(
                        name=spec.name,
                        status="skipped",
                        category="quarantine",
                        attempts=0,
                        healed=False,
                        quarantined=True,
                        final_returncode=None,
                        events=[event],
                    )
                )
                continue

            if self._is_denied(spec.command):
                event = self._event(spec.name, 0, "blocked", "denylist", "block", "command blocked by denylist")
                reports.append(
                    WorkloadReport(
                        name=spec.name,
                        status="failed",
                        category="denylist",
                        attempts=0,
                        healed=False,
                        quarantined=False,
                        final_returncode=126,
                        events=[event],
                    )
                )
                self._consecutive_failures += 1
                if self._consecutive_failures >= self.policy.circuit_breaker_threshold:
                    self._circuit_open = True
                continue

            events: list[HealEvent] = []
            status = "failed"
            category = "non_retryable_failure"
            final_returncode: int | None = None
            healed = False
            attempts_run = 0

            for attempt in range(1, spec.max_attempts + 1):
                attempts_run = attempt
                result = self._run_cmd(spec.command, spec.timeout_sec)
                final_returncode = result.returncode
                if result.returncode == 0:
                    status = "passed"
                    category = "ok"
                    self._consecutive_failures = 0
                    if attempt > 1:
                        healed = True
                        events.append(self._event(spec.name, attempt, "healed", "healed", "pass", "workload healed after retry"))
                    break

                category, retryable = self._classify_failure(spec, result)
                events.append(
                    self._event(
                        spec.name,
                        attempt,
                        "failure",
                        category,
                        "classify",
                        f"attempt failed rc={result.returncode} stderr={result.stderr.strip()}",
                    )
                )
                self._consecutive_failures += 1
                if self._consecutive_failures >= self.policy.circuit_breaker_threshold:
                    self._circuit_open = True
                    events.append(self._event(spec.name, attempt, "circuit", "circuit_breaker", "open", "circuit breaker opened"))

                if not retryable or attempt >= spec.max_attempts:
                    break

                action, action_cmd = self._perform_heal_action(spec, attempt, category)
                if action == "circuit_open":
                    events.append(self._event(spec.name, attempt, "circuit", "circuit_breaker", "open", "max heal count reached"))
                    break
                if action_cmd:
                    _ = self._run_cmd(action_cmd, min(spec.timeout_sec, 120))

                backoff = self.policy.cooldown_sec * (2 ** (attempt - 1))
                self._sleep(backoff)

            reports.append(
                WorkloadReport(
                    name=spec.name,
                    status=status,
                    category=category,
                    attempts=attempts_run,
                    healed=healed,
                    quarantined=False,
                    final_returncode=final_returncode,
                    events=events,
                )
            )

        healed_count = len([w for w in reports if w.healed])
        unresolved = len([w for w in reports if w.status == "failed"])

        return RunReport(
            healed=healed_count,
            unresolved=unresolved,
            skipped_quarantine=skipped_quarantine,
            total=len(reports),
            workloads=reports,
            audit=self.audit,
        )


def _load_workloads(path: str) -> tuple[list[WorkloadSpec], set[str]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    known_bad = set(data.get("known_bad", []))
    workloads = []
    for entry in data.get("workloads", []):
        workloads.append(
            WorkloadSpec(
                name=entry["name"],
                command=entry["command"],
                retryable_exit_codes=tuple(entry.get("retryable_exit_codes", [1, 124])),
                max_attempts=int(entry.get("max_attempts", 3)),
                timeout_sec=int(entry.get("timeout_sec", 600)),
                stall_timeout_sec=int(entry.get("stall_timeout_sec", entry.get("timeout_sec", 600))),
                cleanup_command=entry.get("cleanup_command"),
                restart_command=entry.get("restart_command"),
                tags=tuple(entry.get("tags", [])),
            )
        )
    return workloads, known_bad


def _json_ready(report: RunReport) -> dict:
    return {
        "healed": report.healed,
        "unresolved": report.unresolved,
        "skipped_quarantine": report.skipped_quarantine,
        "total": report.total,
        "workloads": [
            {
                **{k: v for k, v in asdict(w).items() if k != "events"},
                "events": [asdict(e) for e in w.events],
            }
            for w in report.workloads
        ],
        "audit": [asdict(e) for e in report.audit],
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="AgentR self-healing orchestrator")
    parser.add_argument("--plan", required=True, help="Path to JSON workload plan")
    parser.add_argument("--max-heals", type=int, default=20)
    parser.add_argument("--cooldown", type=float, default=1.0)
    parser.add_argument("--breaker-threshold", type=int, default=5)
    parser.add_argument("--report", default="-", help="Output report path or '-' for stdout")
    args = parser.parse_args(argv)

    workloads, known_bad = _load_workloads(args.plan)
    wallet = os.environ.get("AGENTR_VAULT_WALLET", "")

    orch = AgentROrchestrator(
        policy=HealPolicy(
            max_heals_per_run=args.max_heals,
            cooldown_sec=args.cooldown,
            circuit_breaker_threshold=args.breaker_threshold,
        ),
        known_bad=known_bad,
        redaction_values=[wallet],
    )
    report = orch.run(workloads)
    payload = json.dumps(_json_ready(report), indent=2)

    if args.report == "-":
        print(payload)
    else:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(payload)

    return 1 if report.unresolved else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
