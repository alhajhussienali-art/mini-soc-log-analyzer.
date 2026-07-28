# Mini SOC Log Analyzer

A lightweight Python security tool for analyzing authentication logs and detecting suspicious login activity, including potential brute-force attacks.

## Features

- Parses common SSH-style authentication logs.
- Detects failed login attempts.
- Aggregates activity by source IP.
- Flags IP addresses that exceed a configurable failed-login threshold.
- Produces a concise SOC-style security report.
- Includes sample logs and unit tests.
- Uses only the Python standard library.

## Detection Logic

The default rule flags a source IP when it reaches **5 or more failed authentication attempts** in the analyzed log.

This is a simple threshold-based detection intended for learning and portfolio demonstration. In production, thresholds should be tuned to the environment and combined with additional signals.

## MITRE ATT&CK

The detection is relevant to:

- **T1110 – Brute Force**
- **T1110.001 – Password Guessing**

## Project Structure

```text
mini-soc-log-analyzer/
├── src/
│   └── log_analyzer.py
├── sample_logs/
│   └── auth.log
├── tests/
│   └── test_log_analyzer.py
├── .gitignore
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.10+
- No third-party packages required

## Usage

From the project root:

```bash
python src/log_analyzer.py sample_logs/auth.log
```

Custom threshold:

```bash
python src/log_analyzer.py sample_logs/auth.log --threshold 3
```

Example output:

```text
=== Mini SOC Log Analyzer ===

Log file: sample_logs/auth.log
Total events: 18
Failed logins: 12
Successful logins: 3
Unique source IPs: 5

Suspicious IPs:
- 192.168.1.45: 7 failed attempts [HIGH]
- 10.10.10.23: 5 failed attempts [HIGH]

Potential detection:
T1110 - Brute Force
```

## Run Tests

```bash
python -m unittest discover -s tests -v
```

## Security Notes

This project is intentionally defensive. It analyzes logs that you provide and does not perform network scanning, credential attacks, exploitation, or automated blocking.

## Future Improvements

- JSON/CSV report export
- Time-window based detection
- GeoIP enrichment
- Windows Event Log support
- SIEM integration
- Severity scoring
- Allowlist support
