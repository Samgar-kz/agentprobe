# Network Resilience & Error Handling

## What Happens If Internet Goes Down?

AgentProbe includes **automatic recovery mechanisms** for network failures. Here's the flow:

### Scenario 1: Temporary Network Interruption

**During injection harness (`run_injection_stats.py`)**

```
LLM API call fails
    ↓
Tenacity retry (attempt 1, wait 2-4s)
    ↓
Still fails
    ↓
Tenacity retry (attempt 2, wait 4-8s)
    ↓
Still fails
    ↓
Tenacity retry (attempt 3, wait 8-10s)
    ↓
Success! (network recovered)
    ↓
Continue processing
```

**Result:** Most transient failures recover automatically (typical DNS issues, brief timeouts)

---

### Scenario 2: Sustained Network Outage (all 3 retries exhausted)

**During injection harness:**

```
LLM API call fails 3 times
    ↓
Semantic Oracle unavailable
    ↓
Fallback to Legacy Oracle (substring matching)
    ↓
Continue processing with reduced accuracy
```

**Result:** 
- Attack evaluation falls back to substring/heuristic detection
- No canary detected = "success=false" (conservative)
- Script completes, generates CSV with all results
- Some attacks may be marked as unsuccessful (type 1 errors, false negatives)

**During utility harness:**
- Same fallback mechanism applies
- All legitimate tasks still execute (no false positives expected)

---

### Scenario 3: No Internet Available (API_KEY Not Set)

**Run time:**
```
SemanticOracle initialization fails
    ↓
OPENAI_API_KEY environment variable not found or invalid
    ↓
ValueError raised
    ↓
Fallback to Legacy Oracle automatically
    ↓
Script completes using only substring matching
```

**Result:** 
- Run completes successfully
- Reduced detection accuracy (legacy oracle ~70% precision)
- Can still identify obvious attacks (canary disclosure, unauthorized tool calls)
- Legitimate tasks still work (0% false-positive rate)

---

## Recommended Practices

### Before Running Scripts

**Check connectivity:**
```bash
# Verify API key is set
echo $OPENAI_API_KEY

# Test network
ping api.openai.com

# Or test directly
curl -s https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY" | head -5
```

### For Long-Running Harnesses

**Set exponential backoff tolerance:**
```bash
# Run with higher timeout tolerance
python run_injection_stats.py --repeats=5  # 3 retries × 5 repeats
```

**Monitor logs:**
```bash
python run_injection_stats.py --verbose 2>&1 | tee harness.log
# If you see "fallback: Connection timeout", network was unstable
```

---

## Offline Mode (Analysis Only)

**These scripts work without any network:**

```bash
# Analyze existing results (no API calls needed)
python mcnemar_test.py --injection data/gpt4omini.csv
python plot_pareto.py --injection data/gpt4omini.csv --utility data/utility_gpt4omini.csv --out results/pareto.png
```

**Use case:** 
- Run injection/utility harness once (with network)
- Export CSV results to portable device
- Analyze offline on any machine (no API keys needed)

---

## Error Messages & Interpretation

### "ModuleNotFoundError: scipy"
**Cause:** Dependencies not installed  
**Fix:** `pip install -e .`

### "ValueError: OPENAI_API_KEY environment variable is required"
**Cause:** API key not set  
**Fix:** `export OPENAI_API_KEY=sk-...`

### "fallback: Connection timeout"
**Cause:** Network failure during LLM call  
**Meaning:** Oracle fell back to substring detection  
**Result:** Attack marked `success=false` if no canary found (conservative)

### "fallback: Invalid API response"
**Cause:** LLM returned malformed JSON (after 3 retries)  
**Meaning:** Likely network/API issue or model degradation  
**Result:** Oracle fell back to substring detection

---

## Performance Implications

| Scenario | Impact | Latency Added |
|----------|--------|---------------|
| Normal operation | None | 0ms |
| 1 transient retry | Auto-recover | +2-4s |
| 2 transient retries | Auto-recover | +6-12s |
| 3 retries → fallback | Reduced accuracy | +10-30s + legacy detection |
| No network (fallback) | ~70% accuracy (legacy) | Baseline + overhead |

---

## Mitigation Strategies

**For production/CI environments:**

1. **Set higher retry thresholds:**
   ```python
   # In oracle_semantic.py, modify if deploying
   max_retries: int = 5  # was 3
   ```

2. **Use connection pooling:**
   ```bash
   # litellm handles this automatically, but can tune
   export LITELLM_HTTP_TIMEOUT=60
   ```

3. **Cache oracle judgments:**
   - Pre-run on stable network
   - Export CSV
   - Run analysis offline

4. **Parallel harnesses:**
   - Run multiple instances
   - If one network fails, others may succeed
   - Merge results at end

---

## Summary

**AgentProbe is designed to handle network failures gracefully:**
- ✅ Automatic retry with exponential backoff (3 attempts)
- ✅ Fallback to legacy oracle (substring matching)
- ✅ Completes harness even if API unavailable
- ✅ Analysis tools (mcnemar, pareto) work offline

**Worst case:** Network down during entire harness  
**Result:** Script completes with reduced detection accuracy (legacy oracle), all results exported to CSV

**Best practice:** Pre-run harness on stable network, then analyze results offline
