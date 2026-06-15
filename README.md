# AgentProbe: Defense Evaluation Harness for LLM Agents

[![CI](https://github.com/Samgar-kz/agentprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/Samgar-kz/agentprobe/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)]()

## What This Is

A testing framework for measuring your LLM agent's **resistance to indirect prompt injection** and **comparing defense effectiveness**. Tests your own systems or those you have permission to test.

Three things it does:

1. **Measure** — leak rate per defense, with confidence intervals (`injection-scan` / `analyze`).
2. **Compare & gate** — did a change make your agent *better or worse*? `compare` / `trend` flag only statistically significant regressions and exit non-zero, so they drop straight into CI.
3. **Reproduce** — every headline number re-derives from a committed CSV with one command (`make reproduce`).

NOT an attack generator or bypass toolkit. NOT for probing other people's systems.

## Quickstart

Run a full injection scan against the bundled vulnerable agent in ~30 seconds — no API key, fully offline:

```bash
pip install agentprobe-injection
agentprobe scan --target dummy --oracle legacy
```

Example output (illustrative — `dummy` is an intentionally-vulnerable fixture; a hardened agent should score far lower):

```
╭──────── AgentProbe scan ────────╮
│ Target:   dummy                 │
│ Attacks:  45                    │
│ Hits:     16 (36%)              │
│ Duration: 2.1s                  │
╰─────────────────────────────────╯

Category          Hits / Total   Rate
classic           6 / 12         50%
pragmatic         4 / 11         36%
register          3 / 11         27%
...
```

Point it at your own agent over HTTP, or gate CI on the result:

```bash
agentprobe scan --target http --endpoint https://my-agent/chat --json-report results.json
```

**How results are judged.** The defense-effectiveness tables below come from **deterministic detectors** (substring + tool-call inspection, guarded so an injection the agent merely *reports* isn't counted as a leak) — they do **not** depend on an LLM's opinion. The separate `--oracle semantic` LLM-as-judge is independently validated against human labels at **87.5% agreement / Cohen's kappa 0.75** ([details](#oracle-validation)).

### Why this matters

Indirect prompt injection — instructions hidden in the *data* an agent reads (emails, documents, web pages, tool outputs) rather than typed by the user — slips past prompt-level defenses. AgentProbe measures how much your agent leaks under that pressure and which defenses actually reduce it. Full cross-model results are below.

## How To Use

### Test Your Own Agent

> **Note:** The PyPI package is named `agentprobe-injection` (the plain
> `agentprobe` name was already taken). The import package and CLI command are
> still `agentprobe`.

```bash
# Install from PyPI
pip install agentprobe-injection

# Or install the latest from GitHub
pip install git+https://github.com/Samgar-kz/agentprobe.git

# Or clone for development
git clone https://github.com/Samgar-kz/agentprobe.git
cd agentprobe && pip install -e .

export OPENAI_API_KEY="..."

agentprobe scan \
  --target dummy \
  --oracle semantic \
  --json-report results.json

# Check results
cat results.json | jq '.statistics'
```

### GitHub Action (CI/CD gate)

Gate your pipeline on injection resistance. The action wraps `agentprobe scan`,
maps its exit code to a pass/fail, writes a JSON report, and posts a summary to
the run. Zero config runs an offline self-test against the bundled agent; point it
at your endpoint to actually gate. Full template: [examples/ci/agentprobe.yml](examples/ci/agentprobe.yml).

```yaml
# .github/workflows/agentprobe.yml
jobs:
  injection-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Samgar-kz/agentprobe@v1.1
        with:
          target: http
          endpoint: https://my-agent.internal/chat
          auth-header: ${{ secrets.AGENT_TOKEN }}
          fail-threshold: "0.0"        # fail the build on any successful injection
```

Inputs are all optional with CI-friendly defaults (`target: dummy`,
`oracle: legacy` — offline, no key). Use `oracle: semantic` for the LLM-as-judge
(set `OPENAI_API_KEY` via `env:`, never as an input). `soft-fail: true` reports
without failing the build. Outputs: `outcome`, `hits`, `total`, `success-rate`,
`report-path`. The `dummy` target is a vulnerable fixture and never gates the build.

### Regression tracking

A single scan is a snapshot; what a team actually needs is *did my agent get
worse?* `agentprobe compare` diffs two report JSONs and flags only
**statistically significant** changes (pooled two-proportion test, p<0.05) — a
naive 7%→3% diff on a small sample is noise, and this won't cry wolf on it.

```bash
agentprobe injection-scan --out scan_001          # baseline — commit scan_001.json
# ...later, after a prompt / model / tool change...
agentprobe injection-scan --out scan_002
agentprobe compare scan_001.json scan_002.json    # exit 2 if anything regressed
```

```
Leak rate:  6.3% (101/1600) -> 3.5% (56/1600)   Δ -2.8pp   FAIL

Improved (significant):
  + markdown_image_exfil   12.5% -> 1.5%   Δ -11.0pp
Regressed (significant):
  - enumerate_tools         1.2% -> 7.5%   Δ +6.2pp  ⚠
Within noise: 1 probe(s)
```

Note the verdict: the overall leak rate *dropped*, yet the run **FAILs** because
one probe regressed — a net average can hide a per-probe regression. Exit codes
match the GitHub Action contract (`0` clean, `2` regression, `1` error), so
`agentprobe compare baseline.json "$NEW"` drops straight into a CI step to gate
merges on "no injection regression". Works on `scan`, `injection-scan`, and
`utility-scan` reports; choose the grouping with `--by`
(probe/defense/carrier/category), or `--soft-fail` to report without gating.

For more than two points, `agentprobe trend scan_001.json scan_002.json
scan_003.json …` tracks the rate across an ordered series, testing each step
against the previous one and flagging only statistically significant moves
(same exit-code contract). This is the regression-tracking loop — run, commit the
report, repeat, and `trend` shows whether your agent is drifting worse over time
without standing up a dashboard.

### Available Defenses to Test

The harness measures effectiveness of these defenses:

1. **`none`** — baseline (no defense applied)
2. **`delimited`** — wrap data in `<<<UNTRUSTED_DATA_BEGIN>>>...<<<UNTRUSTED_DATA_END>>>` markers
3. **`spotlight`** — datamarking: mark every data token so the model separates data from instructions
4. **`sandwich`** — repeat the do-not-obey rule after the data (recency effect)
5. **`instr_hierarchy`** — tag data with an explicit low privilege level; assert system instructions outrank tool/data content
6. **`llm_filter`** — separate LLM verification pass to detect/strip injection before execution

Test each against YOUR agent. See which work, which break utility.

### How It Works

1. **Injection probes:** 11 instructions spanning data exfiltration (incl. a zero-click markdown/HTML image beacon), unauthorized actions, system-prompt disclosure, content injection, and behavior hijacking (`agentprobe/injection/instructions.py`), embedded in realistic carriers across six channels — email, document, web page, knowledge base (RAG / retrieval poisoning), long-term memory (memory poisoning), and tool output (poisoned search/API results). The knowledge-base, memory, and tool-output channels route to dedicated agent scenarios (`search_knowledge_base` / `recall_memory` / `web_search` tools) so the probe arrives as *trusted retrieved context or a tool result*, not as an external message.
2. **Defense Applicator:** Wraps the data with each defense mechanism
3. **Target Adapter:** Sends to your agent, captures response
4. **Oracle:** Each probe carries a deterministic detector (substring / tool-call inspection, guarded against counting a *reported* instruction as a leak). The separate `agentprobe scan` path uses a gpt-4o-mini LLM-as-judge.
5. **Utility Harness:** Runs benign legitimate tasks to ensure defenses don't break normal functionality
6. **Report:** Table showing defense effectiveness, utility cost, and per-defense overhead (tokens / latency)

### Defense vs Utility Trade-off

A defense is only practical if it preserves utility on legitimate tasks. The
**gpt-4o-mini — utility** table above (auto-generated from
`data/utility_gpt4omini.csv`) shows task success rate per defense; 100% means the
defense introduced no false positives in that run.

In the committed run, the five string-based defenses held 100% success across the
benign task suite. The benign suite is defined in
`agentprobe/injection/benign_tasks.py`; it currently includes a *legitimate
forward* task (the one case where correct behavior requires a tool call a defense
could wrongly block) that postdates the committed CSV — re-run `utility-scan` to
score it. The `llm_filter` defense is not in the committed utility CSV; add it
with `--llm-filter`.

Run your own:

```bash
agentprobe utility-scan --repeats 3 --temp 0.7 --out utility_results
# include the screening defense (extra cost):
agentprobe utility-scan --repeats 3 --llm-filter --out utility_results
```

## Command-Line Usage

### Reproduce the defense results (no repo clone needed)

The harness behind the tables above ships in the package, so a plain
`pip install agentprobe-injection` can reproduce the headline numbers:

```bash
export OPENAI_API_KEY="..."

# Injection leak rate per defense, with 95% CI and per-defense overhead:
agentprobe injection-scan --repeats 5 --temp 0.7 --out results

# Add the separate-screening defense (costs an extra model call):
agentprobe injection-scan --repeats 5 --llm-filter --out results

# Anthropic backend:
agentprobe injection-scan --backend anthropic --model claude-haiku-4-5 --repeats 5

# Utility (false-positive) cost per defense:
agentprobe utility-scan --repeats 3 --temp 0.7 --out utility_results
```

#### Cross-provider runs

Backends are routed through [litellm](https://github.com/BerkeleyAI/litellm), so the
same battery runs against any supported provider — making the defense table
cross-provider. Select with `--backend` (and optionally `--model`); each backend
needs its own API key in the environment:

| `--backend` | Default model | Required env key |
|---|---|---|
| `openai` | `gpt-4o-mini` | `OPENAI_API_KEY` |
| `anthropic` | `claude-haiku-4-5` | `ANTHROPIC_API_KEY` |
| `gemini` | `gemini-2.5-flash` | `GEMINI_API_KEY` |
| `groq` | `llama-3.3-70b-versatile` | `GROQ_API_KEY` |
| `deepseek` | `deepseek-chat` | `DEEPSEEK_API_KEY` |
| `mistral` | `mistral-small-latest` | `MISTRAL_API_KEY` |

```bash
agentprobe injection-scan --backend gemini --repeats 5 --out data/gemini
agentprobe injection-scan --backend groq --model llama-3.3-70b-versatile --repeats 5 --out data/groq
# A bare --model gets the backend's provider prefix; pass a full litellm route
# (e.g. --model gemini/gemini-1.5-pro) to override the provider entirely.
```

Both write `<out>.csv` and `<out>.json`. Regenerate the README tables from the
CSVs (and let CI verify they never drift) with:

```bash
python scripts/gen_results_tables.py --check    # CI guard
python scripts/gen_results_tables.py --write    # update README from data/

# Validate the LLM judge against human labels (agreement + Cohen's kappa):
python scripts/validate_oracle.py
```

### Basic scan
```bash
# Test dummy agent
agentprobe scan --target dummy

# Test HTTP agent
agentprobe scan --target http \
  --endpoint http://localhost:8000/chat \
  --input-field message \
  --output-field reply
```

### Control oracle
```bash
# Use semantic oracle (default, requires OPENAI_API_KEY)
agentprobe scan --target dummy --oracle semantic

# Use legacy oracle (offline, pattern matching)
agentprobe scan --target dummy --oracle legacy

# Set confidence threshold
agentprobe scan --target dummy --oracle semantic --min-confidence 0.85
```

### Reports
```bash
# JSON report with statistics
agentprobe scan --target dummy --json-report results.json

# Verbose logging
agentprobe scan --target dummy --verbose 2
```

## Roadmap

**Primary role:** a **defense evaluator** for AI-security engineers — measure how
your agent leaks under indirect injection and which defenses help. CI gating (the
GitHub Action, `compare` / `trend`) is the *delivery channel* to a team; the
benchmark numbers and findings are *outputs*, not the product. When these roles
conflict, defense evaluation wins.

**Current limitations**
- Findings are per-model snapshots; channel risk is model-specific — the memory
  effect even reverses between gpt-4o-mini and deepseek (Finding #3). Treat
  absolute numbers as model-relative.
- The committed cross-channel scores are `repeats=2` on two models — not yet a
  high-N, many-model run.
- The semantic/hybrid oracle is validated on a small seed set (N=24); the
  deterministic detectors are the trustworthy default.

**Planned work**
- **Longitudinal benchmarking** — `trend` already tracks the rate across an
  ordered series of reports with significance testing; next is a documented
  workflow (commit a dated scan per run → `agentprobe trend scan_*.json`) so model
  drift over months is visible, plus a thin `benchmark` wrapper.
- Score the full 21-carrier battery at higher N across more models.
- Grow the oracle-validation set toward ~50 labeled cases.

**Future attack surfaces**
- Vector-store poisoning beyond single-chunk retrieval (multi-hop / ranking manipulation).
- Memory-poisoning evolution (cross-session persistence, tool write-back memory).
- Multi-tool traces where one tool's output poisons a later tool call.

## Key Findings from Our Research

Our testing on gpt-4o-mini and claude-haiku-4-5 reveals three data-backed findings,
plus one observation that is *not* yet backed by a frontier-model run:

1. **Indirect injection through data IS a real vulnerability**
   - Information hidden in tool outputs (emails, documents, web pages) bypasses prompt-level defenses
   - Separation at prompt level is not enough
   - Backed by 10-probe runs on `data/gpt4omini.csv`, `data/haiku45.csv`, `data/gemini.csv`, `data/deepseek.csv` (N=700/defense each)

2. **Defense effectiveness is model-specific, but rankings are stable**
   - Datamarking (`spotlight`) is the strongest string-level defense on every model tested
   - Privilege tagging (`instr_hierarchy`) is consistently the weakest — at or near baseline
   - Absolute leak rates differ widely by model (haiku ≪ gemini < deepseek < gpt-4o-mini); treat them as relative rankings

3. **Channel risk is model-specific — even the memory effect reverses across models**
   - On **gpt-4o-mini**, an injection recalled from the agent's own long-term **memory** leaks far more than the same injection in an inbox email (31.4% vs 18.5%, two-proportion p<0.001) — memory is the *most* dangerous channel
   - On **deepseek-chat** the same test **reverses**: memory is the *safest* channel (0.5% vs 5.5% email, p=0.001). So "memory poisoning is worst" is a gpt-4o-mini artifact, not a general property
   - **RAG / retrieved knowledge base** and **poisoned tool output** are ≈ email on both models — no "it's internal / it's a tool result, so trust it" effect
   - **What is stable cross-model is the *defense* ranking, not the *channel* ranking** (see Finding #2): `instr_hierarchy` weakest, datamarking/sandwich strongest on both models
   - Within-channel framing matters on gpt-4o-mini: a memory "standing user instruction" is the worst carrier (40.9%), a retrieved FAQ never leaks (0%), a structured tool "note" field (17.3%) leaks ~2× a search snippet (9.1%)
   - Datasets: `full_channel_scan.csv` (gpt-4o-mini), `deepseek_channel_scan.csv` (deepseek), both repeats=2, N=220–660/channel

4. **(Not yet validated on frontier models) Surface-level linguistic transforms add little**
   - Pragmatic implicature, register shifts, and code-switching are included as
     *measurement probes* in `agentprobe/attacks/transforms.py`
   - So far they have only been exercised against the in-process simulator
     (`DummyVulnerableAgent`), **not** against a real model with a committed CSV.
     Until such a run exists, this is a hypothesis, not a result — see
     [CONTRIBUTING.md](CONTRIBUTING.md)'s "no fabricated results" rule.

## Results: Defense Effectiveness

The tables below are **generated directly from the CSVs in `data/`** by
`scripts/gen_results_tables.py`, with Wilson 95% confidence intervals. They are
not hand-typed — `scripts/gen_results_tables.py --check` runs in CI and fails the
build if a README number drifts from the data. Defense names match the `defense`
column in the CSV outputs and JSON reports.

<!-- AUTOGEN:results BEGIN (generated by scripts/gen_results_tables.py — do not edit by hand) -->

**gpt-4o-mini**

| Defense | Leak Rate | 95% CI | N |
|---|---|---|---|
| `none` | 21.1% | 18.3–24.3% | 700 |
| `delimited` | 11.9% | 9.7–14.5% | 700 |
| `spotlight` | 2.0% | 1.2–3.3% | 700 |
| `sandwich` | 15.4% | 12.9–18.3% | 700 |
| `instr_hierarchy` | 17.0% | 14.4–20.0% | 700 |

**gpt-4o**

| Defense | Leak Rate | 95% CI | N |
|---|---|---|---|
| `none` | 10.7% | 5.7–19.1% | 84 |
| `delimited` | 0.0% | 0.0–4.4% | 84 |
| `spotlight` | 1.2% | 0.2–6.4% | 84 |
| `sandwich` | 2.4% | 0.7–8.3% | 84 |
| `instr_hierarchy` | 4.8% | 1.9–11.6% | 84 |
| `llm_filter` | 0.0% | 0.0–4.4% | 84 |

**claude-haiku-4-5**

| Defense | Leak Rate | 95% CI | N |
|---|---|---|---|
| `none` | 0.6% | 0.2–1.5% | 700 |
| `delimited` | 0.3% | 0.1–1.0% | 700 |
| `spotlight` | 0.7% | 0.3–1.7% | 700 |
| `sandwich` | 0.0% | 0.0–0.5% | 700 |
| `instr_hierarchy` | 0.6% | 0.2–1.5% | 700 |

**gemini-2.5-flash**

| Defense | Leak Rate | 95% CI | N |
|---|---|---|---|
| `none` | 5.6% | 4.1–7.6% | 694 |
| `delimited` | 2.6% | 1.6–4.0% | 698 |
| `spotlight` | 1.4% | 0.8–2.6% | 700 |
| `sandwich` | 3.7% | 2.6–5.4% | 699 |
| `instr_hierarchy` | 3.9% | 2.7–5.6% | 700 |

**deepseek-chat**

| Defense | Leak Rate | 95% CI | N |
|---|---|---|---|
| `none` | 9.4% | 7.5–11.8% | 700 |
| `delimited` | 4.3% | 3.0–6.1% | 700 |
| `spotlight` | 5.1% | 3.7–7.0% | 700 |
| `sandwich` | 2.0% | 1.2–3.3% | 700 |
| `instr_hierarchy` | 8.3% | 6.5–10.6% | 700 |

**gpt-4o-mini — utility (benign-task success)**

| Defense | Success Rate | 95% CI | N |
|---|---|---|---|
| `none` | 100.0% | 86.2–100.0% | 24 |
| `delimited` | 100.0% | 86.2–100.0% | 24 |
| `spotlight` | 100.0% | 86.2–100.0% | 24 |
| `sandwich` | 100.0% | 86.2–100.0% | 24 |
| `instr_hierarchy` | 100.0% | 86.2–100.0% | 24 |

<!-- AUTOGEN:results END -->

> **Note on the `gpt-4o` table:** those numbers are from the older 2-instruction
> battery (N=84) and are **not** directly comparable to the other tables, which use
> the current 10-probe battery (N=700). Re-run `agentprobe injection-scan --backend
> openai --model gpt-4o` to refresh it on the same probes.

The other four tables are from one run of the same 10-probe battery (5 string
defenses × 14 carriers × 10 probes × 5 repeats = 700 per defense per model). The
battery has since grown — both **11 probes** (a zero-click markdown/HTML
image-beacon, `markdown_image_exfil`) and **21 carriers** across three new
channels: `knowledge_base` (RAG / retrieval poisoning), `memory` (memory
poisoning), and `tool_output` (poisoned web-search / API results). They deliver
the same probes through content that carries *implied trust* — a retrieved chunk,
a recalled memory note, a tool result — unlike an inbox email. The four AUTOGEN
tables above predate these channels; the full 21-carrier battery is scored
separately in `full_channel_scan.csv` (gpt-4o-mini) and `deepseek_channel_scan.csv`
(deepseek), both repeats=2, and analyzed in Key Findings #3 / the Evidence section.
Headline: the memory effect is **model-specific** — the worst channel on
gpt-4o-mini, reversed to the safest on deepseek; only the *defense* ranking is
stable across models.

**Model robustness ranking (baseline `none`):** claude-haiku-4-5 (0.6%) ≫
gemini-2.5-flash (5.6%) > deepseek-chat (9.4%) > gpt-4o-mini (21.1%). Absolute
leak rates are model-specific — read them as relative defense rankings, not
universal constants. Note that the broader 10-probe battery surfaced a handful of
leaks on claude-haiku-4-5 (0.6% baseline) that the old 2-probe battery missed
entirely (0%) — a concrete payoff of widening the probe set.

### Key Finding: datamarking wins, privilege-tagging ≈ baseline

Across every model tested, **`spotlight` (datamarking) is the strongest
prompt-level defense**: it cuts the leak rate to 2.0% on gpt-4o-mini, 1.4% on
gemini, and 0.7% on haiku (on deepseek, `sandwich` edges it out, 2.0% vs 5.1%).
By contrast, **`instr_hierarchy` (privilege tagging) is consistently the weakest**,
landing at or near baseline (17.0% vs 21.1% on gpt-4o-mini; 8.3% vs 9.4% on
deepseek).

This suggests: **prompt-level instructions and delimiters are incomplete;
token-level datamarking is the most reliable string-only defense, and asserting a
privilege hierarchy in the prompt buys little.** (The separate-screening defense
`llm_filter` was not included in this run — add `--llm-filter` to evaluate it; it
costs an extra model call per data item, reported as overhead.)

## Evidence — reproduce every number

Every headline claim above traces to a committed dataset and a single command, so
a skeptic can re-derive the numbers rather than take them on trust. The findings
from the injection battery are judged by **deterministic detectors**, so they
reproduce **offline** (no API key, exact numbers); only the oracle-agreement
figure needs a key.

| Claim | Dataset | Command | Output |
|---|---|---|---|
| **#2** datamarking wins (`spotlight` 2.0%), `instr_hierarchy` ≈ baseline (21.1%) | `data/gpt4omini.csv` (N=700/defense) | `agentprobe analyze data/gpt4omini.csv` | leak rate by defense + 95% CI |
| **#3** memory effect is model-specific: worst on gpt-4o-mini (31.4% vs 18.5%, p<0.001), reversed to safest on deepseek (0.5% vs 5.5%, p=0.001) | `full_channel_scan.csv`, `deepseek_channel_scan.csv` | `agentprobe analyze full_channel_scan.csv` (and `… deepseek_channel_scan.csv`) | leak rate by channel + two-proportion p vs email |
| **Oracle** 87.5% agreement, Cohen's kappa 0.75 | `data/oracle_labeled.jsonl` (N=24 human-labeled) | `OPENAI_API_KEY=… agentprobe validate-oracle` | agreement, kappa, confusion matrix |

Or run them all at once:

```bash
make reproduce         # findings #2 and #3 — offline, no API key
make validate-oracle   # oracle agreement/kappa — needs OPENAI_API_KEY
```

`agentprobe analyze` recomputes leak rate by defense and by channel (with Wilson
95% CIs and a two-proportion test of each channel against the inbox-email
baseline) directly from any committed injection-scan CSV — no model call, since
the battery is judged deterministically.

## Responsible Use

- **Only test systems you own or have written permission to test**
- Destination: understanding YOUR defenses, not generating portable bypasses
- Disclose findings responsibly (if testing third-party systems with permission)
- The framework measures vulnerability, it's not a jailbreak toolkit

## Architecture

```
agentprobe/
├── oracle_base.py              # Unified Oracle ABC: Deterministic / Semantic / Hybrid + Verdict
├── oracle_semantic.py          # LLM-as-judge engine using gpt-4o-mini (scan path)
├── oracle_legacy.py            # Fallback: substring matching
├── oracle.py                   # Legacy judge() dispatcher (attacks/scan path)
├── oracle_validation.py        # Oracle-vs-human agreement (validate-oracle command)
├── analyze.py                  # Offline leak-rate analysis from a committed CSV
├── compare.py                  # Regression diff between two reports (significance-gated)
├── adapters/
│   ├── dummy.py               # Built-in intentionally-vulnerable agent simulator
│   ├── http.py                # Test any HTTP-accessible agent (sync)
│   └── http_async.py          # Async HTTP adapter for concurrent scans
├── injection/
│   ├── carriers.py            # Carriers: email, document, webpage, knowledge_base (RAG), memory
│   ├── instructions.py        # Injection probes (11) + per-probe leak detectors
│   ├── defenses.py            # Defense mechanisms to evaluate
│   ├── screening.py           # Screening defense (separate LLM pass)
│   ├── benign_tasks.py        # Utility harness tasks
│   ├── oracle.py              # Deterministic injection oracle (probe-aware)
│   ├── tool_agent.py          # Real LLM agent under test (email / knowledge-base / memory scenarios)
│   └── harness.py             # Injection + utility harness engine (CI of the results)
├── engine.py                  # Synchronous scan
├── engine_async.py            # Async scan
├── metrics.py                 # Statistical analysis (Wilson CI, effect sizes)
├── report.py                  # Report generation
├── logging_config.py          # Structured logging, cost tracking
└── cli.py                     # Command-line interface

scripts/
├── gen_results_tables.py       # Generate/verify README tables from data/*.csv
└── validate_oracle.py          # Measure LLM-judge agreement vs human labels
```

## Measurement Infrastructure

- **Probes:** 11 injection instructions × 21 carriers across 6 channels (email, document, webpage, knowledge_base, memory, tool_output), each with a deterministic detector (committed result tables were run on the first 10 probes × 14 carriers — see Results)
- **Oracle (injection-scan):** `--oracle deterministic` (default, free, exact), `--oracle hybrid` (detector precision + LLM recall), or `--oracle semantic` (LLM only) — unified `Oracle` interface in `agentprobe/oracle_base.py`
- **Oracle (scan path):** gpt-4o-mini with Structured Outputs (semantic judgment) — see oracle validation below
- **Statistics:** Wilson 95% CIs on every rate; McNemar's test for pairwise defense comparison (`mcnemar_test.py`)
- **Overhead:** per-defense tokens and latency reported alongside effectiveness
- **Utility Harness:** task success rate per defense on benign tasks (see *Defense vs Utility Trade-off* above)
- **Benchmarking:** Latency / throughput available via `--async --concurrency N` on HTTP targets

All numbers above are generated from the committed CSVs in `/data/` by
`scripts/gen_results_tables.py`; `--check` runs in CI so they can't drift.

### Oracle validation

The defense tables are judged by **deterministic detectors** (substring / tool-call
inspection), so they don't depend on an LLM's opinion. The separate `agentprobe
scan` command instead uses a gpt-4o-mini **LLM-as-judge**, and that judge is what
the numbers below validate — measured against a hand-labeled set
(`data/oracle_labeled.jsonl`) with `scripts/validate_oracle.py`:

| Metric | Value |
|---|---|
| Agreement (accuracy) | 87.5% |
| Cohen's kappa | 0.75 (substantial) |
| Labeled cases (N) | 24 |
| False negatives (missed leaks) | 2 — a forward stated in text; one persona hijack |
| False positives | 1 — a response that *warns about* a link, judged as emitting it |

This is a small seed set, so the estimate is wide; the two false negatives are the
costly error for a security tool. Reproduce / extend it with
`python scripts/validate_oracle.py` (set `OPENAI_API_KEY`), and grow
`data/oracle_labeled.jsonl` toward ~50 cases for a tighter number.

## Testing Your Own Code

```bash
# Run all tests
pytest tests/ -v

# Test a specific component
pytest tests/test_oracle_semantic.py -v

# Run with coverage
pytest tests/ --cov=agentprobe

# Benchmark async performance
agentprobe scan --target dummy --async --concurrency 15
```

## What's NOT Included

- Evasion techniques or obfuscation tooling (intentionally)
- Zero-day exploits or novel vulnerabilities
- Portable bypass payloads designed to be transferable across different systems

**Note on linguistic transforms:** The harness *does* include pragmatic, register, discourse and code-switching (ru-en) categories — but as **measurement probes**, not as attack tooling. So far they have only been run against the in-process simulator, not a real model with a committed CSV, so we make no frontier-model claim about them yet (see Key Findings #4).

This is a **defensive measurement tool**, not an offensive toolkit.

## Citation

If you use this in research, cite as:

```bibtex
@misc{agentprobe2026,
  title={AgentProbe: Evaluating LLM Agent Defenses Against Indirect Injection},
  author={Samgar},
  year={2026},
  url={https://github.com/Samgar-kz/agentprobe}
}
```

## License

MIT
