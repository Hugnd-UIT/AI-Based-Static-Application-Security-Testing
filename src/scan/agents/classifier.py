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
            if f['context']:
                functions += f"  Comment: {f['context']}\n"
                
        prompt = f"""\
            # Role
            You are an elite Static Analysis Classifier for Sinful.

            # Objective
            Analyze a list of internal function signatures and classify them as 'source' (entry points for untrusted data), 'sink' (dangerous execution points), or ignore them if safe, specifically focusing on the {cwe} vulnerability.

            # Context
            You will be provided with a list of function signatures extracted from the codebase.

            # Procedure
            1. Analyze each function signature and its associated comments.
            2. Determine if the function acts as a 'source' (e.g., HTTP request handlers, file readers, database readers) where an attacker can inject malicious input.
            3. Determine if the function acts as a 'sink' (e.g., executing raw SQL, executing shell commands, deserialization) that could lead to {cwe} if the input is untrusted.
            4. If a function is neither a source nor a sink, DO NOT include it in the output.
            5. Format the classification into a strict JSON array.

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
            }}
            ]
            ```

            # Constraints
            - Output EXACTLY ONE valid JSON block matching the schema.
            - Do NOT output any conversational text or markdown outside of the JSON array.
            - Focus STRICTLY on {cwe}.

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
                            results.append(item)
        except Exception as e:
            print(f"Classification error: {e}")
            
    return results