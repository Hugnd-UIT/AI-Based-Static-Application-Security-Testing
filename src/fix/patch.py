def replace_code(file_content: str, old_code: str, new_code: str) -> str:

    if old_code in file_content:

        return file_content.replace(old_code, new_code, 1)
        
    old_lines = [line.strip() for line in old_code.strip().split('\n')]
    file_lines = file_content.split('\n')
    
    if old_lines:

        for line_idx in range(len(file_lines) - len(old_lines) + 1):
            is_match = True

            for list_idx, old_line in enumerate(old_lines):

                if file_lines[line_idx+list_idx].strip() != old_line:
                    is_match = False
                    break

            if is_match:
                before_code = '\n'.join(file_lines[:line_idx])
                after_code = '\n'.join(file_lines[line_idx+len(old_lines):])
                
                orig_indent = file_lines[line_idx][:len(file_lines[line_idx]) - len(file_lines[line_idx].lstrip())]
                new_lines = new_code.strip('\n').split('\n')
                
                if new_lines and len(new_lines[0]) - len(new_lines[0].lstrip()) == 0:
                    new_lines = [orig_indent + line for line in new_lines]
                    new_code = '\n'.join(new_lines)

                else:
                    new_code = new_code.strip('\n')
                    
                return before_code + ('\n' if before_code else '') + new_code + ('\n' if after_code else '') + after_code

    raise ValueError("Could not find exact match for 'old_code' in the file.")

def apply_patch(file_path: str, old_code: str, new_code: str) -> bool:
    try:
        with open(file_path, "r", encoding="utf-8") as file_obj:
            file_content = file_obj.read()

        new_content = replace_code(file_content, old_code, new_code)

        with open(file_path, "w", encoding="utf-8") as file_obj:
            file_obj.write(new_content)

        return True

    except ValueError:

        return False

    except Exception as patch_err:
        print(f"[!] Patch error on {file_path}: {patch_err}")

        return False

