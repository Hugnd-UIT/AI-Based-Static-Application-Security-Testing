import sys
import os
import json
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))

from dotenv import load_dotenv
load_dotenv(root / ".env")

from main import run_scan
from src.report.json import report_json

here = Path(__file__).resolve().parent

# Hàm lấy danh sách project cần quét
def pick(args):
    names = [a for a in args if not a.startswith("-")]
    out = []

    for d in sorted(here.iterdir()):
        if not d.is_dir() or not (d / "vulnerabilities.json").exists():
            continue

        if names and d.name not in names:
            continue

        out.append(d)

    return out

# Hàm quét một project và ghi report vào thư mục của nó
def run_one(proj, nosca=False):
    rdir = proj / "reports"

    # Xóa report cũ để verify chỉ đọc kết quả lần này
    if rdir.exists():
        for old in rdir.glob("sinful_report_*"):
            old.unlink()

    # Project nào có mốc CVE thì mới chạy SCA, cờ -nosca để đo riêng SAST cho nhanh
    truth = json.load(open(proj / "vulnerabilities.json", encoding="utf-8"))
    need_sca = any("cve" in v for v in truth.get("expected", []))
    os.environ["SINFUL_SKIP_SCA"] = "0" if need_sca and not nosca else "1"

    t0 = time.time()
    res = run_scan(str(proj))
    dur = time.time() - t0

    if res.get("status") != "success":
        print(f"[!] {proj.name} failed: {res.get('message')}", flush=True)
        return None

    path = report_json(res, str(rdir))
    finds = res.get("data", {}).get("findings", [])
    lost = res.get("data", {}).get("unverified", 0)

    # Ghi kèm số điểm mất phán quyết để log không bị hiểu là quét sạch
    tail = f" ({lost} unverified)" if lost else ""
    print(f"[+] {proj.name}: {len(finds)} findings in {dur:.0f}s{tail} -> {Path(path).name}", flush=True)

    return path

def main():
    projs = pick(sys.argv[1:])
    nosca = "-nosca" in sys.argv[1:]

    if not projs:
        print("No benchmark project matched.")
        return

    print(f"Running {len(projs)} benchmark(s): {', '.join(p.name for p in projs)}\n", flush=True)

    for proj in projs:
        try:
            run_one(proj, nosca)

        except KeyboardInterrupt:
            print("\nInterrupted.")
            return

        except Exception as err:
            print(f"[!] {proj.name} crashed: {err}", flush=True)

if __name__ == "__main__":
    main()
