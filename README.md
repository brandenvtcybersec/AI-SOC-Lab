# AI SOC LAB



A hands-on blue team lab integrating Splunk Enterprise + Sysmon + Python-based detection automation to simulate real-world SOC workflows.



This project demonstrates:



* Custom detection logic in Splunk (SPL)
* REST-based log collection via Python
* MITRE ATT\&CK technique mapping
* Host-aware, time-window correlation
* Risk scoring and severity classification
* Auto-generated SOC-style incident reports with escalation narrative



#### **Architecture Overview**



\[ Windows Host ]

      |

      |  (Sysmon Events)

      v

\[ Splunk Enterprise ]

      |

      |  (REST API - oneshot search)

      v

\[ Python Collector ]

      |

      v

cases\_\*.json

      |

      v

\[ Triage Engine ]

      |

      v

Markdown + JSON Incident Reports



#### **Key Features**



1\. **Detection Engineering**



* Custom SPL detections including:
* Encoded PowerShell execution
* Suspicious scripting outbound network traffic
* Brute force followed by successful authentication
* Service creation events (persistence)
* LOLBins misuse
* Office spawning PowerShell



Each detection includes MITRE ATT\&CK mapping.



2\. **MITRE ATT\&CK Mapping**



Examples:



* T1059.001 — PowerShell
* T1027 — Obfuscated/Compressed Files
* T1071 — Application Layer Protocol
* T1105 — Ingress Tool Transfer
* T1110 — Brute Force
* T1543.003 — Windows Service



3\. **Correlation Engine**



The triage engine performs:



* Host-level grouping
* Time-window correlation (default: 10 minutes)
* Detection chaining (Execution → Network, etc.)
* Risk scoring based on weighted detections
* Escalation only when correlated signals occur



Example chain:



Encoded PowerShell + Outbound TCP 443 from PowerShell = CRITICAL correlated execution-to-network chain



4\. **SOC-Style Incident Report**



Auto-generated report includes:



* Executive SOC escalation note
* Timeline
* Technical evidence
* MITRE mappings
* Severity and score
* Confidence statement
* Recommended next actions



Example output snippet:



SOC Escalation Note

Severity: CRITICAL

Confidence: Medium



Observed chain: Execution → Network

Host: DESKTOP-L1M6HAK

Encoded PowerShell followed by outbound TCP/443 activity.



#### **Repository Structure**



agents/

├── collector/

│   ├── src/collector.py

│   ├── requirements.txt

│   └── cases/

├── triage/

│   ├── src/triage\_report.py

│   └── output/

docs/

└── examples/



#### **How to Run**



**1. Create virtual environment**



python -m venv .venv .venv\\Scripts\\activate



**2. Install dependencies**



pip install -r agents/collector/requirements.txt



**3. Configure environment**



Create .env in agents/collector/:



SPLUNK\_HOST=localhost

SPLUNK\_PORT=8089

SPLUNK\_USERNAME=admin

SPLUNK\_PASSWORD=your\_password



**4. Run Collector**



python agents/collector/src/collector.py



Generates:

agents/collector/cases/cases\_<timestamp>.json



**5. Run Triage Engine**



python agents/triage/src/triage\_report.py



Generates:

agents/triage/output/report\_<timestamp>.md

agents/triage/output/triage\_<timestamp>.json



#### **Version Milestones**



Tag	               Description

v1-collector	  Splunk REST collector with cases output

v2-triage-mitre	  Triage engine with MITRE ATT\&CK mapping

v3-correlation	  Host/time correlation + scoring + SOC escalation narrative



#### **Skills Demonstrated**



* SIEM engineering
* Detection development (SPL)
* Log analysis
* Threat correlation logic
* MITRE ATT\&CK alignment
* Python automation
* Incident reporting workflow
* Blue team analytical reasoning



#### **Purpose**



This lab is designed to simulate a real SOC environment and demonstrate practical understanding of:



* Detection → Triage → Correlation → Escalation



It is intentionally built from scratch rather than using prebuilt detection frameworks.



#### **Disclaimer**



This project is for educational and defensive security purposes only.

