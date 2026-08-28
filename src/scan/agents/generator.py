import os
import yaml

def generate(data, templates=None, output=None):
    if not data:
        return None

    templates = str(templates or os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules"))
    output = str(output or os.getcwd())

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
                        for mod in ["public", "protected", "private", ""]:
                            prefix = f"{mod} " if mod else ""
                            rule['pattern-sources'].append({
                                "pattern-inside": f"{prefix}function {name}(...) {{\n  ...\n}}",
                                "pattern": "$REQ"
                            })
                            rule['pattern-sources'].append({
                                "pattern-inside": f"{prefix}static function {name}(...) {{\n  ...\n}}",
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
                        for mod in ["public", "protected", "private", "internal"]:
                            rule['pattern-sources'].append({
                                "pattern-inside": f"{mod} $RET {name}(...) {{\n  ...\n}}",
                                "pattern": "$REQ"
                            })
                            rule['pattern-sources'].append({
                                "pattern-inside": f"{mod} static $RET {name}(...) {{\n  ...\n}}",
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
                    # Bắt luôn khi không chứng minh được luồng taint trong cùng file
                    search_rule['pattern-either'].append({"pattern": f"{name}(...)"})

        rules.append(rule)
        if search_rule['pattern-either']:
            rules.append(search_rule)
        
    if not rules:
        return None
        
    final = {"rules": rules}
    os.makedirs(output, exist_ok=True)
    destination = os.path.join(output, "custom-rules.yml")
    
    with open(destination, 'w', encoding='utf-8') as file:
        yaml.dump(final, file, default_flow_style=False, sort_keys=False)
        
    return destination