# AgentProbe: Defense Evaluation Harness for LLM Agents

[![CI](https://github.com/Samgar-kz/agentprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/Samgar-kz/agentprobe/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)]()

## What This Is

A testing framework for measuring your LLM agent's **resistance to indirect prompt injection** and **comparing defense effectiveness**. Tests your own systems or those you have permission to test.

NOT an attack generator or bypass toolkit. NOT for probing other people's systems.

## Key Findings from Our Research

Our testing on gpt-4o-mini and claude-haiku-4-5 reveals three things:

1. **Surface-level linguistic transforms don't work on modern models**
   - Pragmatic implicature, register shifts, code-switching: ~0% success rate
   - Modern LLMs aren't fooled by just changing speech act or tone

2. **Indirect injection through data IS a real vulnerability**
   - Information hidden in tool outputs (emails, documents, web pages) bypasses prompt-level defenses
   - Separation at prompt level is not enough

3. **Asymmetry: Models leak data more readily than execute unauthorized actions**
   - Defending against information leakage != defending against tool abuse
   - Different threat models need different defenses

## Results: Defense Effectiveness

**gpt-4o-mini**

Defense names below match the `defense` column in the CSV outputs (`data/`) and JSON reports.

| Defense (code name) | Leak Rate | N |
|---------------------|-----------|---|
| `none` (baseline) | 29.8% | 84 |
| `delimited` (delimiter wrap) | 25.0% | 84 |
| `instr_hierarchy` (privilege-level instruction) | 31.0% | 84 |
| `sandwich` (recency reinforcement) | 15.5% | 84 |
| `spotlight` (datamarking) | 6.0% | 84 |
| `llm_filter` (separate screening pass) | 0% | 84 |

For reference, the same battery on **gpt-4o** leaks much less (baseline 10.7%, `delimited`/`llm_filter` 0%), and **claude-haiku-4-5** holds 0% across every defense — so absolute numbers are model-specific; treat them as relative defense rankings, not universal constants.

**claude-haiku-4-5** holds baseline at 0% leak rate across all test conditions; defense differentiation is not measurable on this model.

### Key Finding: Screening (and datamarking) beat prompt-level defenses

The separate verification pass (`llm_filter`) achieved 0 successful leaks in 84 test runs on gpt-4o-mini. The next best is `spotlight` (datamarking) at 6.0%. By contrast, prompt-level instruction (`instr_hierarchy`, 31.0%) was *no better than baseline* (29.8%).

This suggests: **prompt-level instructions and delimiters are incomplete; either token-level datamarking or a separate, independent judgment pass is required to reliably catch injection.**

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

1. **Injection Generator:** Creates test payloads (carriers: email, document, web page) with hidden canary instructions
2. **Defense Applicator:** Wraps the data with each defense mechanism
3. **Target Adapter:** Sends to your agent, captures response
4. **Semantic Oracle:** Uses gpt-4o-mini to judge: did agent leak data or follow the hidden instruction?
5. **Utility Harness:** Runs benign legitimate tasks to ensure defenses don't break normal functionality
6. **Report:** Table showing defense effectiveness + utility cost

### Defense vs Utility Trade-off

**Result:** All 5 defenses preserve utility on legitimate tasks (120/120 runs, 0% false-positive rate).

Tested on 8 benign tasks (extract dates, risks, budget, sentiment, action items, meeting notes, legitimately forward to internal address) with 3 repeats each:

| Defense | False-Positive Rate | Status |
|---------|-------------------|--------|
| `none` | 0% | baseline |
| `delimited` | 0% | safe to use |
| `spotlight` | 0% | safe to use |
| `sandwich` | 0% | safe to use |
| `instr_hierarchy` | 0% | safe to use |
| `llm_filter` | 0% | safe to use |

Conclusion: **Defenses do not break legitimate agent functionality** (in current test suite). Task success rate remains 100% across all defenses, making the injection effectiveness/defense trade-off directly comparable (both measured under same utility constraints).

Run your own: `python run_utility_harness.py --repeats=3 --temp=0.7 --out=utility_results.csv`

## Responsible Use

- **Only test systems you own or have written permission to test**
- Destination: understanding YOUR defenses, not generating portable bypasses
- Disclose findings responsibly (if testing third-party systems with permission)
- The framework measures vulnerability, it's not a jailbreak toolkit

## Architecture

```
agentprobe/
├── oracle_semantic.py          # LLM-as-judge using gpt-4o-mini
├── oracle_legacy.py            # Fallback: substring matching
├── oracle.py                   # Oracle interface
├── adapters/
│   ├── dummy.py               # Built-in intentionally-vulnerable agent simulator
│   ├── http.py                # Test any HTTP-accessible agent (sync)
│   └── http_async.py          # Async HTTP adapter for concurrent scans
├── injection/
│   ├── carriers.py            # Email, document, web page wrappers
│   ├── defenses.py            # Defense mechanisms to evaluate
│   ├── benign_tasks.py        # Utility harness tasks
│   └── screening.py           # Screening defense (separate LLM pass)
├── engine.py                  # Synchronous scan
├── engine_async.py            # Async scan
├── metrics.py                 # Statistical analysis (Wilson CI, effect sizes)
├── report.py                  # Report generation
├── logging_config.py          # Structured logging, cost tracking
└── cli.py                     # Command-line interface
```

## Command-Line Usage

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

## Measurement Infrastructure

- **Oracle:** gpt-4o-mini with Structured Outputs (semantic judgment)
- **Test Harness:** Carriers simulate real data flows (email, document, web page)
- **Utility Harness:** Measures task success rate per defense on benign tasks (see *Defense vs Utility Trade-off* above)
- **Benchmarking:** Latency / throughput available via `--async --concurrency N` on HTTP targets

All numbers above are from actual test runs (CSV in /data/).

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

**Note on linguistic transforms:** The harness *does* include pragmatic, register, discourse and code-switching (ru-en) categories — but as **measurement probes**, not as attack tooling. Our data shows surface-level linguistic transforms have ~0% success on modern frontier models, which is itself a useful finding for defenders deciding where to invest.

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
