import json
from src.llm import fetch_llm

def classify(targets, cwe, model=None):
    if not targets:
        return []

    results = []
    size = 20
    
    for i in range(0, len(targets), size):
        batch = targets[i:i + size]
        
        functions = ""
        for f in batch:
            functions += f"- {f['signature']}\n"
            if f.get('context'):
                functions += f"  Comment: {f['context']}\n"
            if f.get('body'):
                functions += f"  Body snippet:\n{f['body']}\n"
                
        prompt = f"""\
            # Role
            You are an elite Static Analysis Classifier for Sinful.

            # Objective
            Analyze a list of internal function signatures (and body snippets) and classify them as 'source', 'sink', 'vuln', or ignore them if safe, specifically focusing on the {cwe} vulnerability.

            # Context
            You will be provided with a list of functions extracted from the codebase.

            # Procedure
            1. Analyze each function signature, its comments, and its body snippet.
            2. Classify as 'source' if it is an entry point for untrusted data (e.g., HTTP handlers, file readers).
            3. Classify as 'sink' if it is a dangerous execution point (e.g., executing raw SQL, shell commands) that is vulnerable ONLY IF untrusted data flows into it.
            4. Classify as 'vuln' if the function is INHERENTLY VULNERABLE regardless of data flow (e.g., it contains a hardcoded cryptographic key, performs a double free, or has an obvious use-after-free).
            5. If a function is safe, DO NOT include it in the output.
            6. Format the classification into a strict JSON array.

            # Output Contract
            ## Expected JSON
            ```json
            [
            {{
                "function": "functionName",
                "type": "source",
                "cwe": "{cwe}"
            }},
            {{
                "function": "executeSqlQuery",
                "type": "sink",
                "cwe": "{cwe}"
            }},
            {{
                "function": "encryptData",
                "type": "vuln",
                "cwe": "{cwe}"
            }}
            ]
            ```

            # Constraints
            - Output EXACTLY ONE valid JSON block matching the schema.
            - Do NOT output any conversational text or markdown outside of the JSON array.
            - Focus STRICTLY on {cwe} and obvious high-severity flaws.

            ## Functions to Analyze
            {functions}
        """
                
        try:
            response = fetch_llm(prompt, model=model, jfmt=True)
            if response:
                if isinstance(response, str):
                    if "```json" in response:
                        response = response.split("```json")[1].split("```")[0].strip()
                    elif "```" in response:
                        response = response.split("```")[1].strip()
                    parsed = json.loads(response)
                else:
                    parsed = response
                    
                if isinstance(parsed, list):
                    mapping = {f['function']: f for f in batch}
                    for item in parsed:
                        name = item.get('function')
                        if name in mapping:
                            item['file'] = mapping[name]['file']
                            item['language'] = mapping[name]['language']
                            item['start_line'] = mapping[name].get('start_line', 1)
                            item['end_line'] = mapping[name].get('end_line', 1)
                            results.append(item)
        except Exception as e:
            print(f"Classification error: {e}")
            
    return results