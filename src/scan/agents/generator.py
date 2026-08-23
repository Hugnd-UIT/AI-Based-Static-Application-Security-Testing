import os
import yaml

def generate(data, templates="src/scan/rules", output="."):
    if not data:
        return None
        
    rules = []
    languages = list(set([item['language'] for item in data]))
    
    for language in languages:
        path = os.path.join(templates, f"{language}.yml")
        if not os.path.exists(path):
            continue
            
        with open(path, 'r', encoding='utf-8') as document:
            try:
                base = yaml.safe_load(document)
            except Exception:
                continue
                
        if not base or 'rules' not in base:
            continue
            
        rule = base['rules'][0]
        rule['id'] = f"dynamic-ai-{rule['id']}"
        
        search_rule = {
            "id": f"dynamic-ai-search-{language}",
            "mode": "search",
            "message": "Potential vulnerability: dangerous function call or defect detected.",
            "severity": "WARNING",
            "languages": rule.get("languages", [language]),
            "pattern-either": []
        }
        
        for item in data:
            if item['language'] == language:
                name = item['function']
                if item['type'] == 'source':
                    # Pattern bắt hàm trả về dữ liệu 
                    rule['pattern-sources'].append({"pattern": f"{name}(...)"})
                    
                    if language in ["javascript", "typescript"]:
                        rule['pattern-sources'].append({
                            "pattern-inside": f"function {name}(..., $REQ, ...) {{\n  ...\n}}",
                            "pattern": "$REQ"
                        })
                        rule['pattern-sources'].append({
                            "pattern-inside": f"{name} = (..., $REQ, ...) => {{\n  ...\n}}",
                            "pattern": "$REQ"
                        })
                    elif language == "python":
                        rule['pattern-sources'].append({
                            "pattern-inside": f"def {name}(..., $REQ, ...):\n  ...",
                            "pattern": "$REQ"
                        })
                    elif language == "php":
                        rule['pattern-sources'].append({
                            "pattern-inside": f"function {name}(..., $REQ, ...) {{\n  ...\n}}",
                            "pattern": "$REQ"
                        })
                    elif language == "ruby":
                        rule['pattern-sources'].append({
                            "pattern-inside": f"def {name}(..., $REQ, ...)\n  ...",
                            "pattern": "$REQ"
                        })
                    elif language == "go":
                        rule['pattern-sources'].append({
                            "pattern-inside": f"func {name}(..., $REQ $T, ...) $R {{\n  ...\n}}",
                            "pattern": "$REQ"
                        })
                        rule['pattern-sources'].append({
                            "pattern-inside": f"func ($RCV) {name}(..., $REQ $T, ...) $R {{\n  ...\n}}",
                            "pattern": "$REQ"
                        })
                    elif language in ["c", "cpp"]:
                        rule['pattern-sources'].append({
                            "pattern-inside": f"$RET {name}(..., $TYPE $REQ, ...) {{\n  ...\n}}",
                            "pattern": "$REQ"
                        })
                        rule['pattern-sources'].append({
                            "pattern-inside": f"$RET $CLASS::{name}(..., $TYPE $REQ, ...) {{\n  ...\n}}",
                            "pattern": "$REQ"
                        })
                    elif language in ["java", "csharp"]:
                        rule['pattern-sources'].append({
                            "pattern-inside": f"$RET {name}(..., $TYPE $REQ, ...) {{\n  ...\n}}",
                            "pattern": "$REQ"
                        })
                    elif language == "rust":
                        rule['pattern-sources'].append({
                            "pattern-inside": f"fn {name}(..., $REQ: $TYPE, ...) {{\n  ...\n}}",
                            "pattern": "$REQ"
                        })
                    elif language == "scala":
                        rule['pattern-sources'].append({
                            "pattern-inside": f"def {name}(..., $REQ: $TYPE, ...) = {{\n  ...\n}}",
                            "pattern": "$REQ"
                        })
                elif item['type'] == 'sink':
                    # Pattern bắt hàm thực thi nguy hiểm (taint sink)
                    rule['pattern-sinks'].append({"pattern": f"{name}(...)"})
                elif item['type'] == 'vuln':
                    # Pattern bắt hàm chứa lỗ hổng trực tiếp
                    search_rule['pattern-either'].append({"pattern": f"{name}(...)"})
                    
        rules.append(rule)
        if search_rule['pattern-either']:
            rules.append(search_rule)
        
    if not rules:
        return None
        
    final = {"rules": rules}
    destination = os.path.join(output, "custom-rules.yml")
    
    with open(destination, 'w', encoding='utf-8') as file:
        yaml.dump(final, file, default_flow_style=False, sort_keys=False)
        
    return destination