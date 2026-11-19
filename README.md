# AWS CloudTrail Security Investigation

## Overview

A hands-on AWS Cloud Security project that uses AWS CloudTrail and Python to investigate AWS management events, identify potentially sensitive activity, and generate structured security reports.

## Project Objectives

- Configure AWS CloudTrail for management event monitoring.
- Store audit logs securely in Amazon S3.
- Analyze CloudTrail events using Python.
- Detect selected security-sensitive activities.
- Generate JSON investigation reports.
- Practice defensive cloud security and incident investigation.

## Project Structure

```text
aws-cloudtrail-security-investigation/
├── README.md
├── scripts/
│   ├── lookup-events.ps1
│   └── investigate.py
├── reports/
│   ├── sample-events.json
│   └── sample-report-redacted.json
└── screenshots/
```

## Technologies

- AWS CloudTrail
- Amazon S3
- AWS CLI
- Python 3
- PowerShell
- JSON
- Git and GitHub

## Detection Capabilities

The Python investigation script includes basic detection rules for:

| Event | Severity |
| --- | --- |
| Failed ConsoleLogin | HIGH |
| CreateAccessKey | HIGH |
| CreateLoginProfile | HIGH |
| AttachUserPolicy | HIGH |
| AttachRolePolicy | HIGH |
| DeleteTrail | CRITICAL |
| StopLogging | CRITICAL |
| PutEventSelectors | HIGH |

## Investigation Reports

The script generates a JSON report containing:

- Total events analyzed
- Total security findings
- Identity type distribution
- AWS service distribution
- Top five most frequent events
- Findings grouped by severity
- Investigation conclusion

## Run the Project

Run the investigation script:

```powershell
python .\scripts\investigate.py .\reports\sample-events.json
```

Run Python syntax validation:

```powershell
python -m py_compile .\scripts\investigate.py
```

## Security Considerations

- Keep AWS credentials outside the repository.
- Never publish raw CloudTrail logs.
- Remove account IDs, IP addresses, ARNs, and other sensitive identifiers from public reports.
- Keep Amazon S3 Block Public Access enabled.
- Use IAM users or roles with appropriate permissions rather than routine root access.

## Limitations

This is an educational security investigation tool, not a production SIEM.

Its detection rules cover only selected event types. A report with zero findings does not prove that an AWS environment is secure.

## Disclaimer

This project is intended for educational and defensive cybersecurity purposes only.
