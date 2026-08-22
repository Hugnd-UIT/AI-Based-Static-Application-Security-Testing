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
        
        for item in data:
            if item['language'] == language:
                name = item['function']
                if item['type'] == 'source':
                    # Pattern bắt hàm trả về dữ liệu 
                    rule['pattern-sources'].append({"pattern": f"{name}(...)"})
                    
                    # Pattern bắt hàm nhận request HTTP 
                    rule['pattern-sources'].append({
                        "pattern-inside": f"function {name}(..., $REQ, ...) {{\n  ...\n}}",
                        "pattern": "$REQ"
                    })
                    rule['pattern-sources'].append({
                        "pattern-inside": f"{name} = (..., $REQ, ...) => {{\n  ...\n}}",
                        "pattern": "$REQ"
                    })
                elif item['type'] == 'sink':
                    # Pattern bắt hàm thực thi nguy hiểm
                    rule['pattern-sinks'].append({"pattern": f"{name}(...)"})
                    
        rules.append(rule)
        
    if not rules:
        return None
        
    final = {"rules": rules}
    destination = os.path.join(output, "custom-rules.yml")
    
    with open(destination, 'w', encoding='utf-8') as file:
        yaml.dump(final, file, default_flow_style=False, sort_keys=False)
        
    return destination