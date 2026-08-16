def apply_patch(file_content: str, old_code: str, new_code: str) -> str:
    if old_code in file_content:
        return file_content.replace(old_code, new_code, 1)
    raise ValueError("Could not find exact match for 'old_code' in the file.")

def patch(file_path: str, old_code: str, new_code: str) -> bool:
    try:
        with open(file_path, "r", encoding="utf-8") as file_obj:
            file_content = file_obj.read()

        new_content = apply_patch(file_content, old_code, new_code)

        with open(file_path, "w", encoding="utf-8") as file_obj:
            file_obj.write(new_content)

        return True

    except Exception as patch_err:
        print(f"[!] Patch failed on {file_path}: {patch_err}")
        return False
