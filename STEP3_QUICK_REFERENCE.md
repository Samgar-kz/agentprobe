# Step 3 Quick Reference

## CLI Cheat Sheet

### Verbose Modes
```bash
agentprobe scan --target dummy                    # Normal: INFO level
agentprobe scan --target dummy -v                 # Verbose: INFO level, show progress
agentprobe scan --target dummy -vv                # Debug: DEBUG level, all attack logs
```

### Logging
```bash
# Save logs to file with automatic rotation (10MB files, keep 5 backups)
agentprobe scan --target dummy --log-file /tmp/scan.log

# JSON format logs (machine readable)
agentprobe scan --target dummy --log-file /tmp/scan.log --json-logs

# Both console and file
agentprobe scan --target dummy -v --log-file /tmp/scan.log
```

### Reports
```bash
# JSON report (programmatic use, CI/CD)
agentprobe scan --target dummy --json-report report.json

# Legacy flag also works
agentprobe scan --target dummy --out-json report.json

# Report + logs + verbose
agentprobe scan --target dummy -v --log-file /tmp/scan.log --json-report report.json
```

### Exit Codes
```bash
# Use in scripts/CI
agentprobe scan --target dummy --json-report report.json
echo $?  # 0=success, 1=error, 2=vulnerabilities, 3=config_error
```

### Fail Threshold
```bash
# Treat as critical if >20% of attacks succeed
agentprobe scan --target dummy --fail-threshold 0.2 --json-report report.json
# Exit code 2 if hit_rate > 0.2, otherwise 0
```

## Programmatic Usage

### With Metrics Tracking
```python
from agentprobe.adapters import DummyVulnerableAgent
from agentprobe.engine import run_scan
from agentprobe.report import write_json
from agentprobe.logging_config import configure_logging

# Setup logging
configure_logging(level="INFO", json_output=False, log_file="/tmp/scan.log")

# Run scan
target = DummyVulnerableAgent()
report, metrics = run_scan(
    target,
    categories={"pragmatic", "register"},
    track_metrics=True,
)

# Print metrics
print(f"Hits: {metrics.hits}/{metrics.total_attacks}")
print(f"Cost: {metrics.cost_str}")
print(f"Duration: {metrics.duration_seconds:.2f}s")
print(f"Throughput: {metrics.throughput:.1f} attacks/sec")
print(f"Avg Confidence: {metrics.avg_confidence:.0%}")

# Export
write_json(report, "report.json", metrics=metrics)
```

### Minimal (No Metrics)
```python
from agentprobe.adapters import DummyVulnerableAgent
from agentprobe.engine import run_scan

target = DummyVulnerableAgent()
report, _ = run_scan(target, track_metrics=False)

print(f"Results: {len(report.hits)} hits out of {report.total}")
```

## JSON Report Structure

### Full Report Example
```bash
cat report.json | jq
```

Output:
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-05-20T05:31:00Z",
  "target": "dummy",
  "statistics": {
    "total_attacks": 45,
    "hits": 15,
    "misses": 28,
    "errors": 2,
    "total_time_ms": 340,
    "cost_usd": 0.00189,
    "avg_confidence": 0.87,
    "throughput_attacks_per_sec": 132.35,
    "oracle_calls": 45,
    "oracle_total_tokens": 12600,
    "oracle_avg_latency_ms": 7.5
  },
  "by_category": {
    "pragmatic": {"total": 23, "hits": 15},
    "register": {"total": 22, "hits": 0}
  },
  "results": [
    {
      "attack_id": "pragmatic.leak_system_prompt",
      "success": true,
      "confidence": 0.92,
      "evidence": "System prompt revealed"
    }
  ]
}
```

### Query Examples
```bash
# Total cost
cat report.json | jq '.statistics.cost_usd'

# Hit rate
cat report.json | jq '.statistics.hits / .statistics.total_attacks'

# Success by category
cat report.json | jq '.by_category[] | select(.hits > 0)'

# Slowest attacks (if latency in results)
cat report.json | jq '.results[] | select(.latency_ms) | sort_by(.latency_ms)[-5:]'
```

## Logging Examples

### Console Output (Normal Mode)
```
[INFO] AgentProbe scan started (target=dummy, oracle=semantic)
[INFO] Loaded 23 attacks (mode=sync)
...
[INFO] Scan completed: 15 hits / 45 attacks
```

### Console Output (Debug Mode)
```
[DEBUG] Attack pragmatic.leak_system_prompt executed (success=true, confidence=0.92, latency_ms=1850)
[DEBUG] Attack register.tool_abuse executed (success=false, confidence=0.35, latency_ms=250)
...
```

### JSON Logs
```json
{"timestamp": "2026-05-20T05:31:00Z", "level": "INFO", "message": "Scan started", "target": "dummy"}
{"timestamp": "2026-05-20T05:31:01Z", "level": "DEBUG", "message": "Attack executed", "attack_id": "pragmatic.leak", "success": true, "confidence": 0.92, "latency_ms": 1850}
```

## Cost Tracking

### Models & Pricing
- **gpt-4o-mini**: $0.15 per 1M tokens (default)
- **gpt-4o**: $5.00 per 1M tokens
- **claude-3-haiku**: $0.80 per 1M tokens
- **gemini-1.5-flash**: $0.075 per 1M tokens

### Cost Calculation
```
Cost = (tokens / 1,000,000) × pricing_per_model
```

### Example
```
45 attacks × 280 tokens each = 12,600 total tokens
12,600 / 1,000,000 × $0.15 = $0.00189
```

## Metrics Output

### Summary String
```python
print(metrics.summary_str())
```

Output:
```
Attacks:    45 total (15 hit, 28 miss, 2 error)
Duration:   3.40s
Throughput: 13.24 attacks/sec
Oracle:     45 calls, 8ms avg, $0.00189 cost
Confidence: 87% avg
HTTP:       45 requests, 8ms avg, 100% success rate
```

### Individual Metrics
```python
metrics.hits                                  # 15
metrics.misses                               # 28
metrics.errors                               # 2
metrics.duration_seconds                     # 3.4
metrics.throughput                           # 13.24 attacks/sec
metrics.cost_usd                             # 0.00189
metrics.avg_confidence                       # 0.87
metrics.oracle_metrics.total_calls           # 45
metrics.oracle_metrics.total_tokens          # 12600
metrics.oracle_metrics.avg_latency_ms        # 8.0
metrics.http_metrics.total_requests          # 45
metrics.http_metrics.avg_latency_ms          # 8.0
metrics.http_metrics.success_rate            # 1.0
```

## Common Workflows

### 1. Quick Test
```bash
agentprobe scan --target dummy -v
```

### 2. Production Scan with Full Reporting
```bash
agentprobe scan \
  --target http \
  --endpoint http://api.example.com/chat \
  -v \
  --log-file /var/log/agentprobe-$(date +%Y%m%d).log \
  --json-report /var/log/agentprobe-$(date +%Y%m%d).json \
  --fail-threshold 0.1
```

### 3. CI/CD Integration
```bash
#!/bin/bash
agentprobe scan \
  --target http \
  --endpoint $AGENT_URL \
  --json-report report.json \
  --fail-threshold 0.05

if [ $? -eq 2 ]; then
  echo "Security vulnerabilities found!"
  cat report.json | jq '.results[] | select(.success) | "\(.attack_id): \(.confidence * 100)%"'
  exit 1
fi
```

### 4. Cost Analysis
```bash
python3 << 'EOF'
import json

with open('report.json') as f:
    report = json.load(f)

stats = report['statistics']
cost = stats['cost_usd']
attacks = stats['total_attacks']
cost_per_attack = cost / attacks if attacks > 0 else 0

print(f"Total cost: ${cost:.5f}")
print(f"Attacks run: {attacks}")
print(f"Cost per attack: ${cost_per_attack:.8f}")
print(f"Hits: {stats['hits']} ({stats['hits']/attacks*100:.1f}%)")
EOF
```

## Troubleshooting

### Logs not being written
```bash
# Check permissions
touch /var/log/test.log
chmod 644 /var/log/test.log

# Run agentprobe
agentprobe scan --target dummy --log-file /var/log/test.log -v

# Verify
cat /var/log/test.log
```

### JSON report malformed
```bash
# Validate JSON
cat report.json | python3 -m json.tool > /dev/null && echo "Valid" || echo "Invalid"

# Pretty print for inspection
cat report.json | jq '.'
```

### Cost seems wrong
```bash
# Check token count in logs
grep "oracle_total_tokens" report.json

# Verify model in use
grep "model" report.json | head -1

# Calculate manually
python3 -c "print((12600 / 1_000_000) * 0.15)"  # Should be ~0.00189
```

