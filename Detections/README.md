# Detections

Detection rules and queries for identifying attacks in the lab environment.

## Contents

- Sigma rules
- Windows Event Log queries
- Splunk/ELK queries
- YARA rules

## Format

Each detection should include:
- **Attack:** What technique this detects
- **Data Source:** Logs/events required
- **Logic:** How the detection works
- **False Positives:** Known benign triggers
- **MITRE ATT&CK:** Technique ID

## Naming Convention

`technique-name_detection.yml` or `.md`
