
import json
import sys
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone

# Evenements consideres comme sensibles
SENSITIVE_EVENTS = {
    "CreateAccessKey": "HIGH",
    "CreateLoginProfile": "HIGH",
    "CreatePolicy": "MEDIUM",
    "AttachUserPolicy": "HIGH",
    "AttachRolePolicy": "HIGH",
    "CreateUser": "MEDIUM",
    "DeleteTrail": "CRITICAL",
    "StopLogging": "CRITICAL",
    "PutEventSelectors": "HIGH",
}


def investigate(events):
    findings = []

    for event in events:
        event_name = event.get("EventName", "Unknown")
        username = event.get("Username") or "Unknown"
        event_id = event.get("EventId", "Unknown")

        try:
            details = json.loads(
                event.get("CloudTrailEvent", "{}")
            )
        except (json.JSONDecodeError, TypeError):
            details = {}

        identity = details.get("userIdentity") or {}
        identity_type = identity.get("type", "Unknown")
        invoked_by = identity.get("invokedBy")
        source_ip = details.get("sourceIPAddress", "Unknown")

        # Exclure les services AWS de ces regles utilisateur
        if identity_type == "AWSService":
            continue

        # Detection des echecs de connexion Console
        if event_name == "ConsoleLogin":
            response = details.get("responseElements") or {}

            if response.get("ConsoleLogin") == "Failure":
                findings.append({
                    "severity": "HIGH",
                    "event": event_name,
                    "username": username,
                    "event_id": event_id,
                    "identity_type": identity_type,
                    "invoked_by": invoked_by,
                    "source_ip": source_ip,
                    "reason": "Failed console login"
                })

        # Detection des operations AWS sensibles
        if event_name in SENSITIVE_EVENTS:
            findings.append({
                "severity": SENSITIVE_EVENTS[event_name],
                "event": event_name,
                "username": username,
                "event_id": event_id,
                "identity_type": identity_type,
                "invoked_by": invoked_by,
                "source_ip": source_ip,
                "reason": "Sensitive AWS activity"
            })

    return findings


def main():
    if len(sys.argv) != 2:
        print("Usage: python investigate.py events.json")
        sys.exit(1)

    input_file = Path(sys.argv[1])

    if not input_file.is_file():
        print(f"Input file not found: {input_file}")
        sys.exit(1)

    with input_file.open("r", encoding="utf-8-sig") as file:
        data = json.load(file)

    events = data.get("Events", [])
    findings = investigate(events)

    # Statistiques par service AWS
    service_names = []

    for event in events:
        try:
            details = json.loads(
                event.get("CloudTrailEvent", "{}")
            )
        except (json.JSONDecodeError, TypeError):
            details = {}

        service_names.append(
            details.get("eventSource", "Unknown")
        )

    service_summary = dict(Counter(service_names))

    # Top 5 des evenements les plus frequents
    event_names = [
        event.get("EventName", "Unknown")
        for event in events
    ]

    top_events = Counter(event_names).most_common(5)

    # Calcul de la repartition des identites
    identity_types = []

    for event in events:
        try:
            details = json.loads(
                event.get("CloudTrailEvent", "{}")
            )
        except (json.JSONDecodeError, TypeError):
            details = {}

        identity = details.get("userIdentity") or {}
        identity_types.append(
            identity.get("type", "Unknown")
        )

    # Construction du rapport
    
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "total_events": len(events),
        "total_findings": len(findings),

        "identity_summary": dict(Counter(identity_types)),

        "service_summary": service_summary,

        "top_5_events": [
            {
                "event": name,
                "count": count
            }
            for name, count in top_events
        ],

        "severity_summary": dict(
            Counter(item["severity"] for item in findings)
        ),

        "findings": findings,

        "conclusion": (
            "Security findings detected. Review required."
            if findings
            else "No findings detected by the configured detection rules."
        )
    }


    # Enregistrement du rapport
    output_file = Path("reports") / "investigation-report.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"Events analyzed: {len(events)}")
    print(f"Findings: {len(findings)}")
    print(f"Report saved: {output_file}")


if __name__ == "__main__":
    main()
