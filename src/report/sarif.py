import json
import os
from datetime import datetime

def severity_to_sarif(severity: str) -> str:
    severity = severity.upper()
    if severity in ("CRITICAL", "HIGH"):
        return "error"
    elif severity == "MEDIUM":
        return "warning"
    return "note"

def to_sarif(findings: list, target_path: str, report_dir: str) -> str:
    """Convert findings list to SARIF 2.1.0 format and save it."""
    results = []
    for f in findings:
        rule_id = f.get("id", "sinful-unknown")
        severity = f.get("severity", "WARNING")
        
        results.append({
            "ruleId": rule_id,
            "level": severity_to_sarif(severity),
            "message": {"text": f.get("message", "Vulnerability detected")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("path", ""), "uriBaseId": "%SRCROOT%"},
                    "region": {
                        "startLine": f.get("start_line", 1),
                        "endLine": f.get("end_line", 1),
                    }
                }
            }],
            "properties": {
                "cwe": f.get("cwe", []),
                "severity": severity,
                "confidence": f.get("confidence", 0),
            }
        })
        
    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Sinful", "version": "1.0.0"}}, "results": results}]
    }

    os.makedirs(report_dir, exist_ok=True)
    time_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(report_dir, f"sinful_report_{time_stamp}.sarif")
    
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2)
        
    return report_path
