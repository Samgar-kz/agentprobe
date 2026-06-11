# Contributing to AgentProbe

Thanks for your interest. AgentProbe is an alpha research/defensive tool, so the
bar is "correct, honest, and reproducible" over "feature-complete."

## Ground rules

1. **No fabricated results.** Every number in docs/README must trace back to a
   real run with a CSV in `data/` (or `results/`). Illustrative output must be
   labeled as illustrative.
2. **Defensive framing only.** Contributions that turn this into a portable
   attack/bypass toolkit will be rejected. See [SECURITY.md](SECURITY.md).
3. **Tests required.** New behavior needs tests. Bug fixes should include a
   regression test where practical.

## Dev setup

```bash
git clone https://github.com/Samgar-kz/agentprobe.git
cd agentprobe
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,openai]"
```

## Before opening a PR

```bash
# Run the test suite
pytest tests/ -v

# Lint
ruff check agentprobe/ tests/

# (optional) format
black agentprobe/ tests/
```

CI runs pytest on Python 3.10 / 3.11 / 3.12 plus ruff. PRs must be green.

## Adding an attack transform

Attack transforms live in `agentprobe/attacks/transforms.py` and are registered
via `registry.py`. Each transform needs:
- a unique `name`
- a `category` (one of: `classic`, `pragmatic`, `register`, `discourse`, `codeswitch`)
- a `rationale` explaining the linguistic hypothesis being tested

## Adding a defense

Defenses live in `agentprobe/injection/defenses.py` (or `screening.py` for the
separate-LLM-pass family). Use the existing `Defense` dataclass. The `name` you
choose is what appears in CSV/JSON reports, so keep it stable and snake_case.

## Adding a target adapter

Adapters live in `agentprobe/adapters/`. Implement the `Target` protocol from
`agentprobe/target.py`. Current adapters: `dummy`, `http`, `http_async`.

## Commit style

Conventional-commit-ish prefixes are appreciated: `feat:`, `fix:`, `docs:`,
`test:`, `ci:`, `chore:`.
