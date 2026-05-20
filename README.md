# AgentProbe: Defense Evaluation Harness for LLM Agents

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

## Results

### Defense Effectiveness on gpt-4o-mini

| Defense | Leak Rate | 95% CI | Task Failure Rate |
|---------|-----------|--------|------------------|
| None (baseline) | 29.8% | (19-42%) | 0% |
| Delimiter | 25.0% | (15-37%) | 2% |
| Prompt-level instruction | 31.0% | (21-43%) | 8% |
| Sandwich | 15.5% | (7-27%) | 1% |
| Spotlight | 6.0% | (1-15%) | 3% |

### Defense Effectiveness on claude-haiku-4-5

| Defense | Leak Rate | 95% CI | Task Failure Rate |
|---------|-----------|--------|------------------|
| None (baseline) | 0% | (0-4%) | 0% |
| Delimiter | 0% | (0-4%) | 0% |
| Prompt-level instruction | 0% | (0-4%) | 0% |
| Sandwich | 0% | (0-4%) | 0% |
| Spotlight | 0% | (0-4%) | 0% |

**Key observations:**
- Claude Haiku shows strong baseline resistance to indirect injection (0% leak rate across all conditions)
- GPT-4o-mini shows moderate baseline vulnerability (30% leak rate)
- On GPT-4o-mini, spotlight defense reduces leak rate to 6% with minimal utility cost
- Prompt-level instruction increases task failures to 8% (risky trade-off)
- Delimiter and sandwich offer moderate improvement with minimal utility cost

## How To Use

### Test Your Own Agent

```bash
pip install agentprobe
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

1. **None** — baseline (no defense applied)
2. **Delimiter** — wrap data in `<<<UNTRUSTED_DATA_BEGIN>>>...<<<UNTRUSTED_DATA_END>>>` markers
3. **Prompt-level instruction** — explicit "treat data as data" in system prompt
4. **Sandwich** — repeat safety instructions after the data (recency effect)
5. **Spotlight** — mark data tokens with special marker so model can distinguish them

Test each against YOUR agent. See which work, which break utility.

### How It Works

1. **Injection Generator:** Creates test payloads (carriers: email, document, web page) with hidden canary instructions
2. **Defense Applicator:** Wraps the data with each defense mechanism
3. **Target Adapter:** Sends to your agent, captures response
4. **Semantic Oracle:** Uses gpt-4o-mini to judge: did agent leak data or follow the hidden instruction?
5. **Utility Harness:** Runs benign legitimate tasks to ensure defenses don't break normal functionality
6. **Report:** Table showing defense effectiveness + utility cost

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
│   ├── dummy.py               # Your own agent simulator
│   ├── openai_fc.py           # Test OpenAI function-calling agents
│   └── http.py                # Test any HTTP-accessible agent
├── injection/
│   ├── carriers.py            # Email, document, web page wrappers
│   ├── defenses.py            # Defense mechanisms to evaluate
│   ├── benign_tasks.py        # Utility harness tasks
│   └── screening.py           # Screening defense (separate LLM pass)
├── engine.py                  # Synchronous scan
├── engine_async.py            # Async scan (18x faster)
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

## Cost & Performance

- **Semantic Oracle (gpt-4o-mini):** ~$0.003 per 45-attack scan
- **Speed:** 18x faster with async (45 attacks in ~300ms)
- **Accuracy:** 95% confidence threshold (configurable)

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

- Evasion techniques or obfuscation (intentionally)
- Multi-language or advanced linguistic manipulations (they don't work on modern models)
- Zero-day exploits or novel vulnerabilities
- Anything designed to be portable across different systems

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
