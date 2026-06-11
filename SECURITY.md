# Security Policy

## Scope and intent

AgentProbe is a **defensive measurement tool**. It is designed to help you test
LLM agents you own or have explicit written permission to test. It is not an
attack toolkit and ships no portable bypass payloads.

## Reporting a vulnerability in AgentProbe itself

If you find a security issue in AgentProbe's own code (e.g. a way the harness
could be abused to attack third-party systems, an injection in the report
renderer, an unsafe deserialization, or a secret-leak in logging), please
report it privately rather than opening a public issue.

- **Preferred:** Open a [GitHub Security Advisory](https://github.com/Samgar-kz/agentprobe/security/advisories/new) (private).
- **Alternative:** Open a minimal public issue that says "security report, please contact me" **without** exploit details, and we will arrange a private channel.

Please include:
- A description of the issue and its impact
- Steps to reproduce (proof-of-concept, minimal)
- Affected version (`agentprobe --version`) and environment

## Disclosure expectations

- We aim to acknowledge reports within **7 days**.
- We aim to ship a fix or mitigation within **30 days** for confirmed issues.
- We will credit reporters in the release notes unless you ask otherwise.

## Responsible use reminder

When using AgentProbe against any system:

- Only test systems you **own** or have **written permission** to test.
- Do not use findings to attack third-party systems.
- Disclose findings responsibly to the system owner.

## Supported versions

AgentProbe is in **alpha** (`0.2.x`). Only the latest released version receives
security fixes. Pin a specific commit/tag if you need stability.
