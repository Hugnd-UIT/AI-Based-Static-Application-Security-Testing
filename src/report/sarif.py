import json
import os
from datetime import datetime

# Hàm tạo report dạng SARIF
def report_sarif(findings: list, target: str, out: str) -> str:
    results = []
    for f in findings:
        rule = f.get("id", "sinful-unknown")
        severity = f.get("severity", "WARNING").upper()
        
        level = "error" if severity in ("CRITICAL", "HIGH") else "warning" if severity == "MEDIUM" else "note"
        
        results.append({
            "ruleId": rule,
            "level": level,
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
                "cwe": f.get("cwe_ids") or f.get("cwe", []),
                "severity": severity,
                "confidence": f.get("confidence", 0),
            }
        })
        
    data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Sinful", "version": "1.0.0"}}, "results": results}]
    }

    os.makedirs(out, exist_ok=True)
    time = datetime.now().strftime("%Y%m%d_%H%M%S")
    report = os.path.join(out, f"sinful_report_{time}.sarif")
    
    with open(report, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        
    return report
