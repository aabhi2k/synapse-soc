# SYNAPSE-SOC
### Event-Driven Security Alert Correlation, Risk Prioritization & Human-in-the-Loop SOC Triage

> **Enterprise-oriented SOC prototype for turning high-volume security telemetry into correlated incidents, prioritized analyst queues, MITRE ATT&CK context, grounded handover briefs, and controlled response workflows.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![NetworkX](https://img.shields.io/badge/Correlation-NetworkX-2C3E50.svg)](https://networkx.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/Threat%20Model-MITRE%20ATT%26CK-red.svg)](https://attack.mitre.org/)
[![Tests](https://img.shields.io/badge/tests-29%20passing-brightgreen.svg)](#verification-status)
[![Status](https://img.shields.io/badge/status-validated%20prototype-orange.svg)](#security-and-production-readiness)

---

## 1. Executive Summary

SYNAPSE-SOC addresses a common SOC problem: **thousands of heterogeneous alerts, very few analyst hours, and insufficient context for deciding what deserves immediate attention**.

The platform implements an event-driven pipeline that:

1. Ingests host, file, deception, and replay telemetry.
2. Normalizes events into a common `Alert` model.
3. Applies stateful behavioral detection rules.
4. Correlates related alerts into security incidents.
5. Enriches incidents with MITRE ATT&CK techniques/tactics.
6. Scores incidents using asset criticality, severity, kill-chain progression, and noise discounts.
7. Presents a ranked analyst queue through terminal and FastAPI interfaces.
8. Generates grounded shift-handover summaries.
9. Supports human-approved containment workflows.
10. Exposes measurable SOC workload/compression metrics.

The design is intentionally **analyst-first**: automation narrows and explains the queue; a human remains the authority for consequential response actions.

---

## 2. SOC Problem

A traditional alert-centric workflow looks like:

```text
Telemetry
   ↓
Security tools
   ↓
Thousands of independent alerts
   ↓
Manual investigation
   ↓
Repeated context gathering
   ↓
Analyst fatigue / delayed escalation
```

SYNAPSE-SOC changes the unit of work from **individual alerts** to **correlated incidents**:

```text
┌───────────────────────────────────────────────────────────────┐
│                     TELEMETRY SOURCES                         │
│ Windows Events │ FIM │ SSH Honeypot │ Cowrie │ Replay │ Data │
└──────────────────────────────┬────────────────────────────────┘
                               ↓
                    ┌──────────────────────┐
                    │ Unified Event Queue  │
                    │ asyncio + thread     │
                    │ safe ingestion       │
                    └──────────┬───────────┘
                               ↓
                    ┌──────────────────────┐
                    │ Detection Rules      │
                    │ Stateful windows     │
                    │ Behavioral signals   │
                    └──────────┬───────────┘
                               ↓
                    ┌──────────────────────┐
                    │ Alert Correlation    │
                    │ Entity/time/graph    │
                    │ incident formation   │
                    └──────────┬───────────┘
                               ↓
              ┌────────────────────────────────┐
              │ Context + MITRE ATT&CK Mapping │
              └────────────────┬───────────────┘
                               ↓
                    ┌──────────────────────┐
                    │ Risk / CADR Scoring  │
                    │ Asset + severity +   │
                    │ progression + noise  │
                    └──────────┬───────────┘
                               ↓
          ┌────────────────────┴────────────────────┐
          ↓                                         ↓
 ┌──────────────────┐                       ┌─────────────────┐
 │ Analyst Console  │                       │ Escalation /   │
 │ FastAPI + Rich   │                       │ HITL workflow  │
 └────────┬─────────┘                       └────────┬────────┘
          └────────────────────┬────────────────────┘
                               ↓
                       Investigation / Response
```

---

## 3. Core Capabilities

| Capability | Implementation | SOC value |
|---|---|---|
| Common alert schema | Pydantic `Alert` model | Normalizes heterogeneous telemetry |
| Stateful detection | Sliding-window rule engine | Detects behavior rather than isolated events |
| Alert correlation | Time/entity/graph correlation | Converts alert floods into incidents |
| Asset criticality | Tier 0–3 model | Prioritizes crown-jewel assets |
| Risk scoring | Severity + asset + ATT&CK progression + discounts | Produces an analyst-oriented queue |
| MITRE ATT&CK | Cached STIX Enterprise ATT&CK data | Gives detections a common threat language |
| FIM | Watchdog-based protected-directory monitoring | Detects ransomware-like file velocity |
| Deception | SSH honeypot + Cowrie adapter | Turns unauthorized probing into high-confidence signals |
| Streaming | `asyncio.Queue` + thread-safe bridge | Supports live source ingestion |
| Web console | FastAPI | Investigation, triage, notes, handover |
| Terminal console | Rich | Lightweight SOC/NOC-style live view |
| AI-assisted handover | Gemini / Ollama / deterministic fallback | Produces analyst-readable incident summaries |
| Notifications | Telegram / Discord | Mobile escalation path |
| HITL response | Approval-aware bot action interface | Prevents the bot itself from deciding containment |
| Replay/demo | Recorded attack telemetry + simulation | Repeatable demonstrations and regression testing |

---

## 4. Detection Coverage

The current streaming rule engine contains five primary behavioral rules:

| Detection | MITRE | Trigger concept | Severity |
|---|---|---|---|
| Credential brute force | T1110.001 | Repeated failed authentication in a short window | HIGH |
| Post-brute successful authentication | T1078 | Successful authentication after repeated failures | CRITICAL |
| Suspicious process after login | T1059.001 | Suspicious process/script activity shortly after logon | HIGH |
| Mass file change / encryption | T1486 | Rapid protected-file modification/encryption activity | HIGH/CRITICAL |
| Honeypot interaction | T1046 | Unauthorized service discovery/probing against deception infrastructure | HIGH |

The engine is not a full IDS/EDR replacement. It is a **correlation and triage layer** designed to sit above telemetry-producing controls.

---

## 5. Risk Model

The risk engine is deliberately not based only on alert count.

Conceptually:

```text
Risk =
    Asset Criticality
  + Peak Alert Severity
  + MITRE Kill-Chain Progression
  + Multi-Entity / Volume Signal
  - Known Noise / Authorized Activity Discounts
```

### Asset tiers

| Tier | Meaning | Example |
|---|---|---|
| T0 | Crown Jewel | Domain controller / identity infrastructure |
| T1 | Mission Critical | Production database / production application |
| T2 | Internal Business | Employee workstation / corporate service |
| T3 | Dev / Lab / Deception | Development node / honeypot |

This is important operationally: **a medium-severity event on a Tier-0 identity asset can deserve more attention than a high-volume event on a Tier-3 lab asset.**

---

## 6. Verification Status

The repository was statically inspected and executed from the supplied archive.

### Verified

| Check | Result | MTTT (min) | Notes |
|---|---:|---:|---|
| Python compilation | PASS | — | All Python sources compile |
| Automated tests | **29/29 PASS** | — | `pytest -q` completed successfully |
| Batch pipeline | **PASS** | — | 3,000 alerts → 7 incidents |
| Batch processing runtime | **~9.9 s** | — | Observed in audit environment |
| Alert compression | **3000 → 7** | — | 99.77% reduction in analyst queue objects |
| Campaign alert capture in supplied synthetic dataset | **88/88** | — | Manual recomputation from ground-truth labels |
| High-risk campaign coverage | **88/88** | — | All supplied campaign alerts belonged to risk ≥75 incidents |
| CICIDS evaluation script | **FAIL** | — | Shipped script imports non-existent `Correlator` class |
| Web containment authorization | **GAP** | **TBD** | API endpoint lacks an authentication/authorization/approval enforcement layer |
| True production MTTT | **TBD** | **TBD** | No real analyst start/end timestamps are captured |

### Important interpretation

**3000 → 7 is incident compression, not a 99.77% false-positive reduction.**

Likewise, the repository's current MTTT calculator contains **assumption-based analyst-time scenarios**. Those estimates should not be represented as measured production MTTT until analyst workflow timestamps are instrumented.

A defensible production MTTT definition should be:

```text
MTTT = median / mean(
    analyst_first_action_timestamp
    -
    alert_or_incident_available_timestamp
)
```

For SOC reporting, also capture **P50, P90 and P95**, split by severity/tier.

---

## 7. Benchmark Interpretation

The supplied 3,000-alert dataset contains:

- 2,912 benign-labelled events across multiple benign/noise categories.
- 88 campaign-labelled events.
- 3 major campaign groupings:
  - `CAMPAIGN_APT_DOMAIN_COMPROMISE`
  - `CAMPAIGN_WEB_API_EXPLOIT`
  - `CAMPAIGN_INSIDER_EXFIL`

The verified batch run formed seven incidents. Three high-risk incidents contained all 88 campaign-labelled alerts.

However, one high-risk incident also contained **182 `BENIGN_AV_FALSE_POSITIVE` alerts**. This is valuable from a SOC-engineering perspective: the system successfully surfaces the campaign, but its prioritization layer still requires tuning to prevent a noisy benign stream from contaminating a high-priority incident.

**Do not claim perfect precision or zero false positives from this dataset.**

---

## 8. MTTT / SOC KPI Framework

The project should evolve from synthetic workload estimates toward operational telemetry.

| KPI | Definition | Current state | Target instrumentation |
|---|---|---|---|
| **MTTT** | Time from incident availability to first analyst action | **TBD** | Record `incident_available_at`, `analyst_first_action_at` |
| MTTA | Time to acknowledge | TBD | Record acknowledgement event |
| MTTI | Time to investigate | TBD | Record investigation start/end |
| MTTC | Time to contain | TBD | Record approved containment dispatch/completion |
| MTTR | Time to recover/respond | TBD | Record recovery/closure |
| Compression | Raw alerts / incidents | **428.6×** | Already measurable |
| High-risk recall | True attack alerts in risk ≥75 incidents / all true attacks | **100% on supplied synthetic campaign labels** | Recompute on independent labelled test data |
| High-risk precision | True attack alerts / all alerts in risk ≥75 incidents | **32.6% on supplied labels** | Tune correlation/discount logic |
| Analyst queue size | Number of incidents requiring human review | **7** on supplied 3k dataset | Track over time |
| Escalation rate | Escalated incidents / total incidents | TBD | Record notification decisions |
| Containment success | Successful approved actions / approved actions | TBD | Integrate with real EDR/firewall/IdP APIs |

---

## 9. AI-Assisted Handover Design

SYNAPSE-SOC supports three summarization paths:

1. **Deterministic fallback**
2. **Google Gemini**
3. **Local Ollama model**

The intended security property is **grounding**:

- incident metadata is supplied to the summarizer;
- alert IDs are included as citations;
- the analyst can edit the generated brief;
- the system should not be treated as an autonomous incident commander.

This architecture aligns with recent research showing that LLMs can assist SOC triage while prioritization remains difficult and susceptible to noise.

**Recommended production control:** treat generated text as analyst assistance, not evidence. Evidence remains the underlying alert, log, event, packet, process, or endpoint artifact.

---

## 10. Data Sources

### Live / near-live sources

- Windows Security Event Log
- Windows process creation telemetry
- File Integrity Monitoring via Watchdog
- SSH deception/honeypot telemetry
- Cowrie log adapter
- Recorded attack replay

### Research / evaluation data

- Supplied synthetic enterprise alert dataset
- CICIDS2017 adapter/evaluation path
- MITRE ATT&CK Enterprise STIX cache

---

## 11. Installation

### Recommended environment

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate
```

Install the dependencies used by the project:

```bash
pip install fastapi uvicorn networkx pydantic rich httpx watchdog pyyaml
```

Optional Windows/event integrations:

```bash
pip install pywin32
```

Optional evaluation packages:

```bash
pip install scikit-learn matplotlib seaborn
```

### Environment variables

```bash
GEMINI_API_KEY="..."
TELEGRAM_BOT_TOKEN="..."
TELEGRAM_CHAT_ID="..."
DISCORD_WEBHOOK_URL="..."
ABUSEIPDB_API_KEY="..."
```

Do not commit real credentials.

---

## 12. Running the Project

### Run the automated tests

```bash
pytest -q
```

Expected baseline from this audit:

```text
29 passed
```

### Run the batch SOC pipeline

```bash
python main.py --batch
```

This reads:

```text
data/alerts_3000.json
```

and writes:

```text
data/incidents_triaged.json
```

### Run the streaming detector

```bash
python main.py --live
```

### Run the attack demonstration

```bash
python main.py --demo
```

### Replay recorded telemetry

```bash
python main.py --replay --dataset data/captured_attacks.json
```

### Start the FastAPI console

```bash
python main.py --web
```

Then open:

```text
http://localhost:8000
```

**Do not expose this service directly to an untrusted network in its current form.**

---

## 13. Repository Layout

```text
Protoype/
├── config/
│   └── triage_assumptions.yaml
├── data/
│   ├── adapters/
│   ├── mitre/
│   ├── alerts_3000.json
│   ├── captured_attacks.json
│   └── incidents_triaged.json
├── engine/
│   ├── correlator.py
│   ├── detection_rules.py
│   ├── ip_enrichment.py
│   ├── metrics.py
│   ├── mitre_mapper.py
│   ├── models.py
│   ├── risk_scorer.py
│   ├── streaming_correlator.py
│   └── summarizer.py
├── notifications/
├── sources/
├── tests/
├── web/
├── demo_attack_simulation.py
├── replay_mode.py
├── main.py
└── README.md
```

---

## 14. Production Readiness Assessment

### Current maturity

**Validated prototype / pre-production engineering stage**

### Strong areas

- Clear event-driven architecture.
- Good separation between sources, detection, correlation, scoring and presentation.
- Stateful detection windows.
- Asset-aware prioritization.
- MITRE ATT&CK context.
- Multiple ingestion paths.
- Replay and simulation support.
- Automated test suite.
- Human-in-the-loop concept for response.
- Deterministic fallback when external LLM services are unavailable.

### Production blockers

#### 1. Authentication and authorization

The FastAPI application currently exposes triage and containment endpoints without an enterprise identity/RBAC layer.

Required:

```text
SSO / OIDC
      ↓
RBAC
      ↓
SOC role
      ↓
Permission-scoped actions
      ↓
Immutable audit record
```

Recommended roles:

- L1 Analyst — triage / notes
- L2 Analyst — escalation / enrichment
- Incident Responder — containment
- SOC Lead — override / suppression
- Auditor — read-only

#### 2. Containment enforcement

The web API should not be able to mark an incident contained simply because an HTTP request was received.

Use:

```text
Request
  ↓
Authenticated analyst
  ↓
Authorization check
  ↓
Explicit confirmation
  ↓
Approval record
  ↓
Real EDR / firewall / IdP API
  ↓
Verified execution result
  ↓
Immutable audit event
```

#### 3. Persistent storage

The current web state is primarily JSON/in-memory.

Production should use a transactional database such as PostgreSQL and an event/audit store.

#### 4. MTTT instrumentation

Add explicit events:

```text
INCIDENT_CREATED
INCIDENT_ACKNOWLEDGED
INVESTIGATION_STARTED
ESCALATED
CONTAINMENT_REQUESTED
CONTAINMENT_APPROVED
CONTAINMENT_EXECUTED
INCIDENT_CLOSED
```

#### 5. Evaluation pipeline

The supplied `scripts/evaluate_cicids.py` currently imports `Correlator`, while the implementation exposes `AlertCorrelator`. This must be corrected before publishing CICIDS benchmark results.

The evaluation should also separate:

- detection recall,
- precision,
- F1,
- false-positive rate,
- alert-to-incident compression,
- time-to-first-true-positive,
- ranking quality,
- analyst workload.

#### 6. Test realism

The current unit tests are useful but should be supplemented with:

- adversarial test cases;
- malformed telemetry;
- timestamp skew;
- duplicate events;
- event replay;
- queue saturation;
- API authorization tests;
- containment approval tests;
- model prompt-injection tests;
- LLM output validation tests;
- regression datasets with immutable expected metrics.

---

## 15. Research Basis

SYNAPSE-SOC's architecture maps well to established SOC/IDS research.

### Alert correlation

**Alert correlation surveys** describe grouping related IDS alerts using similarity, statistical, knowledge-based and hybrid techniques to reduce analyst overload.

- Al-Mamory et al., *Alert correlation in collaborative intelligent intrusion detection systems—A survey*, Applied Soft Computing, 2011.
- DOI: https://doi.org/10.1016/j.asoc.2010.12.004

- Yu Beng et al., *A Survey of Intrusion Alert Correlation and Its Design Considerations*, IETE Technical Review, 2014.
- DOI: https://doi.org/10.1080/02564602.2014.906864

### MITRE ATT&CK-driven analytics

The project uses ATT&CK tactics/techniques to add threat-informed context to alerts and to score attack progression.

- Strom et al., *Finding Cyber Threats with ATT&CK-Based Analytics*, MITRE, 2017.
- https://www.mitre.org/news-insights/publication/finding-cyber-threats-attck-based-analytics

- MITRE ATT&CK knowledge base:
- https://attack.mitre.org/

### CICIDS2017

The repository includes a CICIDS2017 adapter. CICIDS2017 is a widely used labelled intrusion-detection dataset containing normal traffic and multiple attack families across a five-day capture.

- Sharafaldin, Lashkari & Ghorbani, *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*, ICISSP, 2018.
- Dataset: https://www.unb.ca/cic/datasets/ids-2017.html

### AI-assisted SOC triage

Recent work reinforces the need to keep human analysts in the loop: LLMs can support alert interpretation and classification, but prioritization quality and false-positive control remain challenging.

- Rieger et al., *Possibilities and limitations of using large language models (LLMs) for alert classification and prioritisation in security operations centers (SOCs)*, Expert Systems with Applications, 2026.
- DOI: https://doi.org/10.1016/j.eswa.2026.133194

---

## 16. Recommended Research-to-Engineering Roadmap

| Priority | Improvement | Why it matters |
|---|---|---|
| P0 | Add OIDC/SSO + RBAC | Prevent unauthorized SOC actions |
| P0 | Enforce approval server-side | Make HITL a real security control |
| P0 | Fix CICIDS evaluator | Make benchmark reproducible |
| P0 | Instrument MTTT/MTTA/MTTC | Replace assumptions with operational evidence |
| P1 | PostgreSQL + immutable audit log | Reliable enterprise state |
| P1 | Real EDR/firewall/IdP adapters | Move from simulated to verified response |
| P1 | Deduplication + idempotency keys | Prevent repeated response actions |
| P1 | Rate limiting / API gateway | Protect the SOC control plane |
| P1 | Structured observability | Prometheus/OpenTelemetry + centralized logs |
| P2 | Detection-as-code | Versioned rules, test fixtures and CI |
| P2 | ATT&CK coverage matrix | Identify telemetry/detection gaps |
| P2 | Analyst feedback loop | Learn suppression/prioritization from verdicts |
| P3 | ML/LLM ranking experiments | Compare rules, ML and LLM-assisted triage |
| P3 | Multi-tenant architecture | Support managed SOC / MSSP use cases |

---

## 17. Security Design Principles

1. **Human authorization for consequential actions.**
2. **Least privilege for integrations.**
3. **Evidence before explanation.**
4. **Deterministic controls around probabilistic AI.**
5. **Immutable auditability of analyst and automation actions.**
6. **No security KPI should be inferred from an unvalidated assumption.**
7. **Detection quality and workload reduction must be measured separately.**

---

## 18. Limitations

This repository should currently be presented as an **enterprise-grade architecture prototype**, not as a production SIEM/SOAR replacement.

In particular:

- The supplied dataset is synthetic and/or replay-oriented.
- The current MTTT figures are assumption-driven rather than measured analyst telemetry.
- The CICIDS evaluation script requires correction before use.
- The FastAPI control plane needs authentication, authorization and server-side approval enforcement.
- Containment actions are simulated rather than guaranteed integrations with EDR/firewall/identity infrastructure.
- JSON persistence is not equivalent to a transactional enterprise event store.
- No formal independent red-team validation is included.
- No statistical confidence intervals are currently reported.

These limitations do not invalidate the architecture; they define the next engineering and validation stage.

---

## 19. Final SOC Analyst Verdict

### **Architecture: Strong**
The separation of ingestion, detection, correlation, risk scoring and analyst presentation is coherent and appropriate for a SOC triage platform.

### **Detection concept: Strong prototype**
The behavioral rules cover several meaningful attack chains and demonstrate stateful reasoning rather than isolated signature matching.

### **Correlation: Strong**
The system successfully turns 3,000 supplied alerts into 7 incident objects in the verified batch run.

### **Evaluation: Needs hardening**
The test suite passes, but the CICIDS benchmark path is currently broken and the MTTT calculator mixes measured pipeline statistics with assumed analyst-time estimates.

### **Security controls: Needs hardening**
The web control plane is the biggest production risk because containment endpoints are not protected by authentication/RBAC and do not independently enforce human approval.

### **Enterprise readiness: Pre-production**
With identity/RBAC, transactional persistence, immutable audit logging, corrected evaluation, real MTTT instrumentation and verified response integrations, SYNAPSE-SOC can move from a strong demonstration/prototype toward a defensible enterprise SOC platform.

---

## 20. License

This project currently declares an MIT-style licensing intent in its project documentation. Before public distribution, ensure that all bundled datasets, ATT&CK data, third-party assets and generated artifacts have compatible redistribution terms.

---

> **Bottom line:** SYNAPSE-SOC has the right architecture for an analyst-centric alert-triage platform. The most important next step is not adding more AI—it is making the **security control plane, evaluation methodology, and SOC timing metrics production-grade**.
