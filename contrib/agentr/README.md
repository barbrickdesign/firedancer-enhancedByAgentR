# AgentR Orchestrator (Self-Healing)

`contrib/agentr/orchestrator.py` provides a self-healing orchestration layer for autonomous build/test enhancement runs.

## Features
- Detects failed builds/tests, stalled jobs (timeout), and unhealthy runtime signals.
- Classifies failures into retryable and non-retryable categories.
- Performs bounded remediation: retry, cleanup, restart, and quarantine skip.
- Enforces guardrails: max-heal cap, cooldown backoff, circuit breaker, destructive command denylist.
- Emits structured audit/report output with healed/unresolved metrics.
- Redacts secrets, including vault wallet values from logs/events.

## Usage
```bash
AGENTR_VAULT_WALLET='<wallet>' \
python3 contrib/agentr/orchestrator.py \
  --plan contrib/agentr/example_plan.json \
  --report -
```

## Plan schema
- `known_bad`: workload names to quarantine.
- `workloads[]`:
  - `name`, `command`
  - `retryable_exit_codes`
  - `max_attempts`
  - `timeout_sec`, `stall_timeout_sec`
  - `cleanup_command`, `restart_command`
