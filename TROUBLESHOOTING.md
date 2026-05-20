# Troubleshooting Guide

## Network Issues

### "Connection timeout" during harness

**Problem:** Script hangs or prints "fallback: Connection timeout"

**Root causes:**
1. Internet connection lost
2. OpenAI API unavailable (check status.openai.com)
3. Firewall blocking api.openai.com
4. ISP DNS issues

**Solutions:**
```bash
# 1. Verify connectivity
ping api.openai.com

# 2. Verify API key works
curl -s https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY" | head -5

# 3. Check environment
echo $OPENAI_API_KEY  # Should show sk-...
env | grep OPENAI

# 4. Set longer timeout (if needed)
export LITELLM_HTTP_TIMEOUT=60
python run_injection_stats.py --repeats=3
```

**What happens:**
- Tenacity retries 3 times with 2-10s exponential backoff
- If all fail: falls back to substring oracle (legacy)
- Script completes (reduced accuracy)

---

### "ModuleNotFoundError: No module named 'scipy'"

**Problem:**
```
from scipy.stats import binomtest
ModuleNotFoundError: No module named 'scipy'
```

**Solution:**
```bash
# Install dependencies
pip install -e .

# Or manually:
pip install scipy matplotlib numpy
```

---

### "ValueError: OPENAI_API_KEY environment variable is required"

**Problem:** Script can't find API key

**Solution:**
```bash
# Set API key
export OPENAI_API_KEY=sk-your-actual-key-here

# Verify it's set
echo $OPENAI_API_KEY  # Should print your key (not empty)

# Then run
python run_injection_stats.py
```

---

### "Connection refused" or "Failed to resolve host"

**Problem:** Firewall or network blocking OpenAI API

**Solutions:**
```bash
# 1. Check firewall
sudo ufw status  # Linux
# macOS: System Preferences → Security & Privacy → Firewall

# 2. Test proxy (if behind corporate proxy)
curl -x http://proxy.company.com:8080 https://api.openai.com

# 3. Use different network (mobile hotspot, different WiFi)
```

---

## Dependency Issues

### "No module named 'litellm'"

```bash
pip install -e .  # Installs all dependencies
```

### "No module named 'tenacity'"

```bash
pip install tenacity>=8.2
```

---

## Data Issues

### "File not found: data/gpt4omini.csv"

**Problem:** Script can't find data folder

**Solution:**
```bash
# Verify files exist
ls -la data/*.csv

# If missing, re-run harness
python run_injection_stats.py --backend openai --repeats=3 --out data/gpt4omini.csv
```

---

### CSV has fewer rows than expected

**Possible causes:**
1. Network failed during harness (partial data)
2. Set wrong `--repeats` value
3. Previous run was incomplete

**Solution:**
```bash
# Check what was logged
wc -l data/*.csv

# Re-run if needed (appends to existing)
python run_injection_stats.py --backend openai --repeats=5 --out data/gpt4omini.csv
```

---

## Analysis Issues

### "McNemar test shows no significant differences"

**Possible causes:**
1. Sample size too small (n < 30 per defense)
2. All defenses equally effective
3. All defenses equally ineffective

**Solution:**
```bash
# Run more iterations
python run_injection_stats.py --repeats=10 --out results/large_run.csv
python mcnemar_test.py --injection results/large_run.csv
```

---

### "Pareto plot shows all points clustered at (0,0)"

**Problem:** All defenses have 0% leak and 0% false-positive

**Meaning:** Defenses are working perfectly on this model  
**This is good!** Means:
- No vulnerabilities found in test suite
- Utility preserved (no false positives)
- Model is naturally resistant

**Check:**
```bash
# Verify data
head data/utility_gpt4omini.csv
head data/gpt4omini.csv

# If all success/0 outcomes: normal
# Model is just very robust
```

---

## Performance Issues

### Script runs very slowly

**Possible causes:**
1. Network latency (LLM API slow)
2. Machine underpowered
3. Semaphore too low (async bottleneck)

**Solutions:**
```bash
# 1. Check network latency
time curl https://api.openai.com

# 2. Increase semaphore (async concurrency)
# Edit engine_async.py: semaphore_limit=50 (was 15)

# 3. Reduce repeats for testing
python run_injection_stats.py --repeats=2  # Quick test
```

---

## Offline / No API Key

### I want to analyze existing data without API calls

**Solution:** Use analysis tools (no network needed)
```bash
# McNemar test (local)
python mcnemar_test.py --injection data/gpt4omini.csv

# Pareto plot (local)
python plot_pareto.py \
  --injection data/gpt4omini.csv \
  --utility data/utility_gpt4omini.csv \
  --out results/pareto_offline.png
```

**These work without:**
- Internet connection
- API keys
- Any network resource

---

## Getting Help

### Check the README
```bash
cat README.md | grep -A 5 "Quick Start"
```

### Check RESILIENCE.md
```bash
cat RESILIENCE.md
```

### Enable verbose logging
```bash
python run_injection_stats.py --verbose 2>&1 | tee debug.log
tail -f debug.log
```

### Contact
- File an issue: https://github.com/Samgar-kz/agentprobe/issues
- Check existing issues: https://github.com/Samgar-kz/agentprobe/issues

---

## Common Workflows

### Scenario: I have no internet, can I still work?

**Yes!** Analysis works offline:
```bash
# 1. Run harness on machine WITH internet
python run_injection_stats.py --repeats=5 --out results/harness.csv

# 2. Copy CSV to offline machine
scp results/harness.csv offline-machine:/tmp/

# 3. On offline machine, analyze
cd /tmp
python mcnemar_test.py --injection harness.csv  # No API needed
python plot_pareto.py --injection harness.csv --utility harness.csv --out plot.png
```

---

### Scenario: Network died mid-run, what now?

**Results are safe!** CSV is written per row:
```bash
# Check what was saved
wc -l data/gpt4omini.csv  # Should have some rows

# Continue from where we left off
# (Note: current version starts fresh, but doesn't lose previous data)
```

If you want to merge partial runs:
```bash
# Don't use --out again, it overwrites
# Instead, manually merge:
cat partial1.csv partial2.csv | sort -u > merged.csv
```

---

## Still Stuck?

1. **Run a sanity check:**
   ```bash
   pip install -e .
   python -c "import agentprobe; print('OK')"
   ```

2. **Check versions:**
   ```bash
   python --version  # Need 3.10+
   pip list | grep -E "scipy|matplotlib|anthropic|litellm"
   ```

3. **Review RESILIENCE.md for network tolerance details**

4. **Open GitHub issue with error log:**
   ```bash
   python run_injection_stats.py --verbose 2>&1 > error.log
   cat error.log
   ```
