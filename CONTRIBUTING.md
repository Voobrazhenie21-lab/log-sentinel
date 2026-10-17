# Contributing to Log Sentinel

Thank you for your interest in contributing! Log Sentinel is a zero-dependency,
standard-library-only project, and we aim to keep it that way.

## Ground Rules

- **Zero runtime dependencies.** Do not add third-party packages to
  `[project.dependencies]`. New detections must be implemented with the Python
  standard library only.
- **Air-gapped friendly.** The engine must work fully offline against bundled or
  user-supplied log files.
- **Detection parity.** New correlation rules should reference MITRE ATT&CK
  technique IDs and, where applicable, the equivalent Wazuh rule ID.

## Development Setup

```bash
git clone https://github.com/Voobrazhenie21-lab/log-sentinel.git
cd log-sentinel

# Using uv (recommended)
uv sync --extra dev
uv run pytest -v

# Or plain pip
pip install -e ".[dev]"
pytest -v
```

## Adding a New Detection Rule

1. Implement the rule in `log_sentinel/engine.py` (next rule ID: `LS-RULE-011`).
2. Add sample telemetry to `samples/` and cover the rule with tests in
   `tests/test_log_sentinel.py`.
3. Document the rule in the README detection matrix (Rule ID, Title, Source,
   MITRE ATT&CK, Wazuh parity, Severity).
4. Update `log_sentinel/__init__.py` version if behavior changes.

## Pull Request Checklist

- [ ] `pytest -v` passes locally.
- [ ] New/changed rules have test coverage and sample data.
- [ ] README detection matrix updated.
- [ ] No secrets, API keys, or real customer data in commits.
- [ ] Commit messages follow conventional style (`feat:`, `fix:`, `docs:`, `ci:`).

## Code Style

- Type hints on all public functions.
- Dataclasses for structured records (see `models.py`).
- Keep parsers defensive: never crash on malformed log lines — skip and continue.
