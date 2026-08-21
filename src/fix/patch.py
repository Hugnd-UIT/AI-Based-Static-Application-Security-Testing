# Hàm tìm kiếm và thay thế code
def replace_code(content: str, old: str, new: str) -> str:

    # Nếu code cũ trùng code mới thì thay thế ngay lập tức
    if old in content:
        return content.replace(old, new, 1)
        
    olds = [line.strip() for line in old.strip().split('\n')]
    lines = content.split('\n')
    
    # Nếu code cũ không trùng code mới thì tìm kiếm và thay thế từng dòng
    if olds:

        for idx in range(len(lines) - len(olds) + 1):
            match = True

            for j, line in enumerate(olds):

                if lines[idx+j].strip() != line:
                    match = False
                    break

            if match:
                before = '\n'.join(lines[:idx])
                after = '\n'.join(lines[idx+len(olds):])
                
                indent = lines[idx][:len(lines[idx]) - len(lines[idx].lstrip())]
                news = new.strip('\n').split('\n')
                
                if news and len(news[0]) - len(news[0].lstrip()) == 0:
                    news = [indent + l for l in news]
                    new = '\n'.join(news)

                else:
                    new = new.strip('\n')
                    
                return before + ('\n' if before else '') + new + ('\n' if after else '') + after

    raise ValueError("Could not find exact match for 'old' in the file")

# Hàm áp dụng bản vá lỗi
def apply_patch(path: str, old: str, new: str) -> bool:
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        updated = replace_code(content, old, new)

        with open(path, "w", encoding="utf-8") as f:
            f.write(updated)

        return True

    except ValueError:

        return False

    except Exception as err:
        print(f"[!] Patch error on {path}: {err}")

        return False
