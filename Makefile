.PHONY: help test lint tables reproduce validate-oracle

# Override with: make PYTHON=python reproduce
PYTHON ?= python3

help:
	@echo "AgentProbe make targets:"
	@echo "  make test            - run the test suite"
	@echo "  make lint            - ruff lint (agentprobe/ tests/)"
	@echo "  make tables          - verify README tables match data/ (CI guard)"
	@echo "  make reproduce       - recompute the deterministic findings offline (no API key)"
	@echo "  make validate-oracle - reproduce oracle agreement/kappa (needs OPENAI_API_KEY)"

test:
	$(PYTHON) -m pytest tests/ -q

lint:
	$(PYTHON) -m ruff check agentprobe/ tests/

tables:
	$(PYTHON) scripts/gen_results_tables.py --check

# Findings #2 (defense ranking) and #3 (channels incl. RAG/memory). Offline and
# deterministic — a pure function of the committed CSVs, no API key required.
reproduce:
	@echo "== Finding #2 — defense effectiveness (gpt-4o-mini, N=700/defense) =="
	$(PYTHON) -m agentprobe.cli analyze data/gpt4omini.csv
	@echo "== Finding #3 — channels incl. RAG/memory (gpt-4o-mini, repeats=2) =="
	$(PYTHON) -m agentprobe.cli analyze rag_memory_scan.csv

# Oracle agreement / Cohen's kappa vs human labels. Needs OPENAI_API_KEY
# (one model call per labeled case — cents on the seed set).
validate-oracle:
	$(PYTHON) -m agentprobe.cli validate-oracle
