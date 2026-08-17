def apply_patch(file_content: str, old_code: str, new_code: str) -> str:
    if old_code in file_content:
        return file_content.replace(old_code, new_code, 1)
        
    old_lines = [l.strip() for l in old_code.strip().split('\n')]
    file_lines = file_content.split('\n')
    
    if old_lines:
        for i in range(len(file_lines) - len(old_lines) + 1):
            match = True
            for j, old_l in enumerate(old_lines):
                if file_lines[i+j].strip() != old_l:
                    match = False
                    break
            if match:
                before = '\n'.join(file_lines[:i])
                after = '\n'.join(file_lines[i+len(old_lines):])
                
                # Try to preserve indentation of the first line if new_code is missing it
                orig_indent = file_lines[i][:len(file_lines[i]) - len(file_lines[i].lstrip())]
                new_lines = new_code.strip('\n').split('\n')
                
                # If AI didn't indent the first line, add it
                if new_lines and len(new_lines[0]) - len(new_lines[0].lstrip()) == 0:
                    new_lines = [orig_indent + l for l in new_lines]
                    new_code_indented = '\n'.join(new_lines)
                else:
                    new_code_indented = new_code.strip('\n')
                    
                return before + ('\n' if before else '') + new_code_indented + ('\n' if after else '') + after

    raise ValueError("Could not find exact match for 'old_code' in the file.")

def patch(file_path: str, old_code: str, new_code: str) -> bool:
    try:
        with open(file_path, "r", encoding="utf-8") as file_obj:
            file_content = file_obj.read()

        new_content = apply_patch(file_content, old_code, new_code)

        with open(file_path, "w", encoding="utf-8") as file_obj:
            file_obj.write(new_content)

        return True

    except ValueError:
        return False
    except Exception as patch_err:
        print(f"[!] Patch error on {file_path}: {patch_err}")
        return False
