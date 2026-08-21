import os
from datetime import datetime

# Hàm tạo report dạng HTML
def report_html(findings: list, target: str, out: str) -> str:
    # Giao diện HTML
    html = [
        "<html>",
        "<head>",
        "<title>Sinful Report</title>",
        "<style>",
        "body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f9; color: #333; }",
        "h1 { color: #2c3e50; }",
        ".finding { background: #fff; padding: 15px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }",
        ".critical, .high { border-left: 5px solid #e74c3c; }",
        ".medium { border-left: 5px solid #f39c12; }",
        ".low, .info { border-left: 5px solid #3498db; }",
        "h3 { margin-top: 0; }",
        "pre { background: #272822; color: #f8f8f2; padding: 10px; border-radius: 3px; overflow-x: auto; }",
        "</style>",
        "</head>",
        "<body>",
        "<h1>Sinful Report</h1>",
        f"<p><strong>Target:</strong> {target}</p>",
        f"<p><strong>Total Findings:</strong> {len(findings)}</p>"
    ]
    
    if not findings:
        html.append("<p>No vulnerabilities found.</p>")
    else:
        for f in findings:
            sev = f.get('severity', 'INFO').lower()
            html.append(f"<div class='finding {sev}'>")
            
            rule = f.get('id') or f.get('check_id') or f.get('rule_id', 'Unknown')
            msg = f.get('message') or f.get('title') or f.get('description', 'N/A')
            file = f.get('path') or f.get('file', 'N/A')
            line = f.get('start_line') or f.get('start') or f.get('line', 'N/A')
            if isinstance(line, dict): line = line.get('line', 'N/A')
            
            html.append(f"<h3>{rule} ({f.get('severity', 'INFO')})</h3>")
            html.append(f"<p><strong>File:</strong> {file} (Line: {line})</p>")
            html.append(f"<p><strong>Message:</strong> {msg}</p>")
            
            if f.get('cwe'):
                html.append(f"<p><strong>CWE:</strong> {', '.join(f.get('cwe'))}</p>")
                
            code = f.get("code")
            if code:
                html.append("<p><strong>Code:</strong></p>")
                html.append(f"<pre><code>{code}</code></pre>")
                
            dflow = f.get("data_flow")
            if dflow and isinstance(dflow, list):
                html.append("<p><strong>Data Flow:</strong></p>")
                html.append("<ul>")
                for step in dflow:
                    html.append(f"<li>{step}</li>")
                html.append("</ul>")
                
            html.append("</div>")
            
    html.append("</body></html>")
    
    os.makedirs(out, exist_ok=True)
    time = datetime.now().strftime("%Y%m%d_%H%M%S")
    report = os.path.join(out, f"sinful_report_{time}.html")
    
    with open(report, "w", encoding="utf-8") as f:
        f.write("\n".join(html))
        
    return report
