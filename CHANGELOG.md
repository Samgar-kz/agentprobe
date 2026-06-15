# Changelog

All notable changes to AgentProbe are documented here. Versions are the git tags
used by the GitHub Action (`uses: Samgar-kz/agentprobe@v1.2`); the floating `v1`
tag tracks the latest `v1.x`. The PyPI package (`agentprobe-injection`) is
versioned separately.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [v1.2] — 2026-06-15

### Added
- **Async injection harness** (`injection-scan --async [--concurrency N]`): probes
  run concurrently under an `asyncio.Semaphore` (default 8) on `litellm.acompletion`,
  a ~5–10× wall-clock speedup (measured: 1155 runs in ~5 min vs ~45 min sync).
  Sync remains the default; `ToolAgent.asend` mirrors `send`. Aggregates are
  identical to the sync path.
- **`CallableTarget`**: wrap any `fn(prompt: str) -> str` (or `dict` / `AgentResponse`)
  as a scan target — the 80/20 adapter for LangChain / LlamaIndex / CrewAI / custom
  loops, in-process, no HTTP server. CLI: `scan --target callable:module:function`.

## [v1.1] — 2026-06-15

### Added
- **`compare`** — diff two reports and flag only statistically significant
  regressions (pooled two-proportion test, p<0.05); exit code 2 gates CI.
- **`trend`** — track the rate across an ordered series of reports (longitudinal
  regression tracking) with the same significance test.
- **Reproducibility layer** — `analyze <csv>` (offline leak rate by defense/channel
  with Wilson CIs + two-proportion vs email), `validate-oracle` (agreement / Cohen's
  kappa vs human labels), a `Makefile` (`make reproduce` / `validate-oracle`), and a
  README **Evidence** section mapping every headline number to a dataset + command.
- **Unified Oracle interface** (`oracle_base.py`): `Oracle` ABC + `Verdict`, with
  `DeterministicOracle`, `SemanticOracle` (adapter), and `HybridOracle` (detector
  precision + LLM recall). Selectable via `injection-scan --oracle`.
- **New injection channels** — `knowledge_base` (RAG / retrieval poisoning),
  `memory` (memory poisoning), and `tool_output` (poisoned search/API results),
  each routed to a dedicated agent scenario. Battery grew to 21 carriers × 11 probes.

### Changed
- README restructured practical-first (Quickstart → How To Use → Command-Line Usage
  → Roadmap → research findings); added a **Roadmap** that states the primary role
  (defense evaluator; CI is the delivery channel).

### Research
- Scored the full 21-carrier battery on gpt-4o-mini (`full_channel_scan.csv`) and
  cross-checked on deepseek-chat (`deepseek_channel_scan.csv`). **Finding: the memory
  channel's risk is model-specific and reverses** — the most dangerous channel on
  gpt-4o-mini (31.4% vs 18.5% email) but the safest on deepseek (0.5% vs 5.5%). Only
  the *defense* ranking is stable cross-model.

## [v1] — 2026-06-13

### Added
- Indirect-injection battery across email / document / webpage carriers with
  deterministic per-probe detectors; multi-provider harness via `litellm` (OpenAI,
  Anthropic, Gemini, Groq, DeepSeek, Mistral).
- Separate `injection-scan` (leak rate per defense, Wilson CIs) and `utility-scan`
  (false-positive cost) harnesses; defenses: none / delimited / spotlight / sandwich
  / instr_hierarchy / llm_filter.
- Zero-click markdown/HTML image-beacon exfiltration probe (`markdown_image_exfil`).
- Semantic LLM-as-judge oracle with cost metrics + oracle validation vs human labels.
- **GitHub Action** for CI/CD injection gating (exit-code contract: 0 clean / 2
  finding / 1 error); README tables auto-generated from `data/*.csv` with a CI
  drift guard.
- Project meta: `SECURITY.md`, `CONTRIBUTING.md`, `TROUBLESHOOTING.md`; published as
  `agentprobe-injection` on PyPI.

[v1.2]: https://github.com/Samgar-kz/agentprobe/releases/tag/v1.2
[v1.1]: https://github.com/Samgar-kz/agentprobe/releases/tag/v1.1
[v1]: https://github.com/Samgar-kz/agentprobe/releases/tag/v1
