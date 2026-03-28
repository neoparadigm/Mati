# 🛡️ Mati

### Self-evolving threat intelligence for OpenClaw agents.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue?style=flat&labelColor=555)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat&labelColor=555)](LICENSE)
[![No GPU Required](https://img.shields.io/badge/⚡_No_GPU_Required-yellow?style=flat&labelColor=555)](#)
[![Skill Evolution](https://img.shields.io/badge/🧬_Skill_Evolution-orange?style=flat&labelColor=555)](#how-it-works)

---

**Mati** is an OpenAI-compatible proxy that sits between your [OpenClaw](https://openclaw.ai) agent and the upstream LLM. It intercepts every request, injects threat intelligence skills, logs priority predictions, and scores them against objective ground truth. When Mati is wrong, it analyses *why* and synthesises corrective skills automatically.

Unlike general-purpose agent evolution frameworks, Mati's reward signal comes from reality — not from another LLM's opinion.

A CVE either gets added to [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) or it doesn't. A public exploit either appears or it doesn't. That objective, verifiable signal produces faster convergence and more reliable skills than subjective scoring.

```
User ↔ OpenClaw ↔ Mati Proxy (:30100) ↔ LLM
                      │
                      ├─ injects threat intel skills
                      ├─ logs priority predictions
                      ├─ scores against ground truth
                      ├─ analyses failure patterns
                      └─ synthesises corrective skills
```

---

## Quick Start
## Try it
```bash
git clone https://github.com/neoparadigm/Mati.git && cd Mati
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
python3 -m mati.cli feeds
```

Tests OSINT feed connectivity. No API keys needed. You should see ✅ for CISA KEV, CVEDB, EPSS, Shodan InternetDB, and ThreatFox.

Then point your OpenClaw agent at `http://127.0.0.1:30100/v1`. Mati intercepts requests transparently — your agent doesn't know it exists.

```bash
mati status         # check health + loaded skills
mati feeds          # test OSINT feed connectivity
mati score          # calculate accuracy scorecard
mati evolve         # run evolution cycle
```

---

## How It Works

Mati operates as a **dual-loop** system, specialised for the threat intelligence domain where outcomes are objectively verifiable.

### Loop 1: Skill Injection (immediate)

On every request, Mati retrieves the most relevant threat intelligence skills from its skill library and injects them into the system prompt. The agent benefits from accumulated expertise without any retraining.

Skills are short, auditable rules like:

```json
{
  "name": "epss-above-07-escalate",
  "rule": "When EPSS > 0.7, escalate to at least P2 regardless of exploit availability."
}
```

Mati ships with 10 base skills covering CISA KEV, EPSS escalation, high-risk vendor patterns, supply chain attacks, email authentication, and more. Evolved skills are added automatically by the evolution engine.

### Loop 2: Evolution (weekly)

```
Day 1    Mati scans feeds, assigns priorities, logs predictions
           ↓
Day 2-30  Ground truth arrives (KEV additions, exploit publications)
           ↓
Day 30    Scorer calculates accuracy (precision, recall, lead time)
           ↓
Week 4    Analyser identifies failure patterns (3+ same root cause)
           ↓
Week 5    Synthesiser generates corrective skills from patterns
           ↓
Week 7    Validator measures — did the new skill improve accuracy?
           ↓
           YES → skill becomes permanent
           NO  → skill is retired with reasoning logged
```

### Why objective ground truth matters

| Approach | Reward signal | Reliability |
|----------|--------------|-------------|
| Generic | LLM judge scores response quality | Subjective, varies by judge model |
| Human feedback | Analyst confirms/corrects | High quality but doesn't scale |
| **Mati** | CISA KEV additions, exploit publications, EPSS changes | **Objective, verifiable, automated** |

Mati doesn't need a human or an LLM to know when it was wrong. Reality tells it.

---

## Architecture

```
mati/
├── config.py        # MatiConfig — all settings in one place
├── proxy.py         # OpenAI-compatible proxy with skill injection
├── feeds.py         # OSINT fetchers (11+ free sources)
├── skills.py        # Skill retrieval, injection, and storage
├── scorer.py        # Prediction scoring against ground truth
├── analyser.py      # Failure pattern identification
├── synthesiser.py   # Corrective skill generation
├── models.py        # Data models (Prediction, Scorecard, etc.)
└── cli.py           # CLI: setup, start, status, score, evolve
```

### OSINT Data Sources (all free)

| Source | What it provides | Auth |
|--------|-----------------|------|
| CISA KEV (GitHub mirror) | Actively exploited CVEs | None |
| CVEDB (Shodan) | CVE + EPSS + KEV in one call | None |
| EPSS (FIRST.org) | Exploitation probability scores | None |
| NIST NVD | Full CVE database | Free API key |
| GitHub Advisory | Security advisories across ecosystems | Free token |
| GitHub PoC search | Public exploit code | Free token |
| Shodan InternetDB | Open ports, vulns per IP | None |
| crt.sh | Certificate transparency logs | None |
| Google DNS API | DMARC, SPF, MTA-STS checks | None |
| AlienVault OTX | Threat pulses and IOCs | Free API key |
| Abuse.ch ThreatFox | Malware IOCs | None |

### Accuracy Metrics

Mati tracks five metrics that together measure threat intelligence quality:

- **Precision** — of all P1 calls, what % were actually exploited?
- **Recall** — of all CVEs added to KEV, what % did Mati flag as P1 first?
- **Lead time** — how many days before KEV addition did Mati flag it?
- **Priority accuracy** — what % of all priority assignments were correct?
- **Miss rate** — what % of exploited CVEs were classified P3/P4?

Run `mati score` to see your current scorecard.

---

## Failure Root Causes

The analyser classifies every prediction failure into a root cause:

| Root Cause | What Went Wrong |
|-----------|----------------|
| `EPSS_UNDERWEIGHT` | High EPSS score was available but not weighted heavily enough |
| `VENDOR_BLIND_SPOT` | CVE affected a vendor not in the watchlist |
| `EXPLOIT_LAG` | Public exploit appeared between daily scans |
| `CORRELATION_MISS` | Multiple risk signals existed but weren't combined |
| `HISTORICAL_PATTERN` | Vendor with exploitation history wasn't weighted |
| `CONTEXT_MISS` | CVE description keywords indicated easy exploitation |
| `FALSE_ALARM_OVERREACTION` | P1 assigned based on CVSS alone without complexity check |

When 3+ failures share the same root cause, the synthesiser generates a corrective skill. The skill is injected into future requests immediately — no retraining needed.

---

## Configuration

All settings via `MatiConfig` in `config.py` or `~/.mati/config.json`:

| Field | Default | Description |
|-------|---------|-------------|
| `llm_api_base` | `https://openrouter.ai/api/v1` | Upstream LLM endpoint |
| `llm_model` | `openrouter/auto` | Model for agent requests |
| `proxy_port` | `30100` | Local proxy port |
| `skills_enabled` | `True` | Inject skills into prompts |
| `auto_evolve` | `True` | Auto-summarise skills after sessions |
| `evolution_enabled` | `True` | Enable the evolution engine |
| `evolution_min_failures` | `3` | Min failures before skill synthesis |

Environment variables: `MATI_LLM_API_KEY`, `NVD_API_KEY`, `GITHUB_TOKEN`, `SHODAN_API_KEY`, `OTX_API_KEY`

---

## Comparison

| Capability | Recorded Future | SecureClaw | MetaClaw | **Mati** |
|-----------|----------------|-----------|---------|------|
| Threat intelligence feeds | Proprietary | No | No | 11+ free OSINT |
| Learns from failures | No | No | Yes (subjective) | **Yes (objective)** |
| Skill evolution | No | No | Yes (general) | **Yes (security-specific)** |
| Accuracy benchmarks | No | No | Yes | **Yes (5 metrics)** |
| Runs on commodity hardware | No | Yes | Yes | **Yes** |
| OpenAI-compatible proxy | No | No | Yes | **Yes** |
| Cost | $100k+/year | Free | Free | **Free** |

---

## Acknowledgements

Mati builds on:

- [OpenClaw](https://openclaw.ai) — the agent framework
- [CISA KEV](https://github.com/cisagov/kev-data) — ground truth for exploitation
- [FIRST.org EPSS](https://www.first.org/epss/) — exploitation probability scoring

---

## Citation

```bibtex
@misc{mati2026,
  author       = {Subhajyoti Chakraborty},
  title        = {Mati: Self-Evolving Threat Intelligence through Objective Ground Truth},
  year         = {2026}
}
```

## License

[MIT](LICENSE)
