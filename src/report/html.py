import os
from datetime import datetime

def to_html(findings: list, target_path: str, report_dir: str) -> str:
    """Generate an HTML report for the findings and save it."""
    
    html_content = [
        "<html>",
        "<head>",
        "<title>Sinful SAST Report</title>",
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
        "<h1>Sinful SAST Report</h1>",
        f"<p><strong>Target:</strong> {target_path}</p>",
        f"<p><strong>Total Findings:</strong> {len(findings)}</p>"
    ]
    
    if not findings:
        html_content.append("<p>No vulnerabilities found.</p>")
    else:
        for f in findings:
            sev = f.get('severity', 'INFO').lower()
            html_content.append(f"<div class='finding {sev}'>")
            
            rule_id = f.get('id') or f.get('check_id') or f.get('rule_id', 'Unknown')
            msg = f.get('message') or f.get('title') or f.get('description', 'N/A')
            file_path = f.get('path') or f.get('file', 'N/A')
            line_num = f.get('start_line') or f.get('start') or f.get('line', 'N/A')
            if isinstance(line_num, dict): line_num = line_num.get('line', 'N/A')
            
            html_content.append(f"<h3>{rule_id} ({f.get('severity', 'INFO')})</h3>")
            html_content.append(f"<p><strong>File:</strong> {file_path} (Line: {line_num})</p>")
            html_content.append(f"<p><strong>Message:</strong> {msg}</p>")
            
            if f.get('cwe'):
                html_content.append(f"<p><strong>CWE:</strong> {', '.join(f.get('cwe'))}</p>")
                
            code = f.get("code")
            if code:
                html_content.append("<p><strong>Code Snippet:</strong></p>")
                html_content.append(f"<pre><code>{code}</code></pre>")
                
            dflow = f.get("data_flow")
            if dflow and isinstance(dflow, list):
                html_content.append("<p><strong>Data Flow:</strong></p>")
                html_content.append("<ul>")
                for step in dflow:
                    html_content.append(f"<li>{step}</li>")
                html_content.append("</ul>")
                
            html_content.append("</div>")
            
    html_content.append("</body></html>")
    
    os.makedirs(report_dir, exist_ok=True)
    time_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(report_dir, f"sinful_report_{time_stamp}.html")
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(html_content))
        
    return report_path
