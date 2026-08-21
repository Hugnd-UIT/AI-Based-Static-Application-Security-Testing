# Sinful SAST — Roadmap đạt ngang bằng Argus

> Cập nhật: 2026-08-21 | Dựa trên full source code audit và so sánh với Argus architecture

---

## Trạng thái hiện tại

**Đã hoàn thành (Phase 1–5 cơ bản):**
- ✅ Taint engine 10 ngôn ngữ (tree-sitter LANG dict đầy đủ)
- ✅ Alias chain tracking 3 hops (`resolve_aliases_chain`)
- ✅ Cross-file taint → N findings riêng biệt
- ✅ SOURCES + SINKS đa ngôn ngữ (JS DOM XSS, Java RCE, PHP, Go, Ruby)
- ✅ SCA lockfile (yarn.lock, package-lock.json, poetry.lock, pyproject.toml)
- ✅ CVE context accumulation đầy đủ cho Audit Agent
- ✅ LLM retry 500/503/504
- ✅ NVD sequential + rate limit safe
- ✅ Audit Agent prompts: 7 ngôn ngữ với sink-specific rules
- ✅ Verifier Agent có `find_callers` trong toolset
- ✅ Scanning Agent max_steps = 12
- ✅ Dedup findings
- ✅ Sanitizer comment stripping

**Gap còn lại so với Argus: ~15%**

---

## PHASE A — Taint Engine Core (Gap lớn nhất)

### A.1 — Fix `find_sinks` logic AND → smarter reachability

**File:** `src/audit/tree-sitter.py` (Line 389)

**Vấn đề:**
```python
# Hiện tại — AND condition quá chặt:
if func_called in called_tainted and has_sink(file_content, parent_node):
```
Điều này yêu cầu sink phải nằm **trong cùng function** chứa lời gọi hàm bẩn.
Nếu sink nằm 1-2 function sâu hơn → bị bỏ sót hoàn toàn.

**Argus làm gì:** Dùng call graph traversal — từ tainted function, walk xuống tất cả functions được gọi (đệ quy), kiểm tra từng node xem có sink không.

**Fix — Thêm `scan_callees` recursive:**
```python
def scan_callees(func_node, file_content, depth=0, max_depth=3):
    """Walk tất cả functions được gọi bởi func_node, tìm sink ở bất kỳ độ sâu nào."""
    if depth > max_depth: return False
    
    node_text = file_content[func_node.start_byte:func_node.end_byte]
    
    # Check sink trực tiếp trong function này
    if has_sink(file_content, func_node): return True
    
    # Tìm tất cả call_expression trong func_node, walk vào từng cái
    for call_node in get_all_calls(func_node):
        callee_name = get_call_name(call_node, file_content)
        if callee_name:
            callee_code = get_code(target_dir, callee_name)
            if callee_code and any(sink in callee_code for sink in SINKS):
                return True
    
    return False
```

**Effort:** ~3 giờ | **Impact:** 🔴 Critical

---

### A.2 — `has_sink()` — Chuyển từ substring matching sang word-boundary matching

**File:** `src/audit/tree-sitter.py` (Line 281)

**Vấn đề hiện tại:**
```python
return any(sink_str in node_text for sink_str in SINKS)
```
`"include" in text` sẽ match: `include_path`, `# don't include`, `requireIncludes()`, `Grinclude`.

**Fix:**
```python
import re

SINKS_PATTERNS = [re.compile(r'\b' + re.escape(s) + r'\b') for s in SINKS]

def has_sink(file_content: bytes, curr_node) -> bool:
    try:
        node_text = file_content[curr_node.start_byte:curr_node.end_byte].decode("utf-8", errors="ignore")
        return any(p.search(node_text) for p in SINKS_PATTERNS)
    except Exception:
        return False
```

**Effort:** ~30 phút | **Impact:** 🟠 High (giảm FP đáng kể khi SINKS list dài)

---

### A.3 — Tăng alias chain lên 5 hops

**File:** `src/audit/tree-sitter.py` (`resolve_aliases_chain`, Line 655)

**Vấn đề:** Hiện tại `max_hops=3`. Argus track không giới hạn hop (dùng worklist algorithm).

**Fix:** Tăng `max_hops=3` → `max_hops=5`, đồng thời giới hạn thời gian thực thi:
```python
def resolve_aliases_chain(file_path: str, var_name: str, max_hops: int = 5) -> str:
```

**Effort:** ~5 phút | **Impact:** 🟡 Medium

---

### A.4 — Field-sensitive taint: track `obj.field` assignments

**File:** `src/audit/tree-sitter.py`

**Vấn đề:**
```python
x = obj.get("name")   # tainted
y = x.strip()          # Sinful hiện tại không track x → y qua method call
db.execute(y)          # miss
```
Argus track field access và method chaining. Sinful chỉ track simple assignment `y = x`.

**Fix — Bổ sung vào `resolve_aliases_chain`:**
Khi parse raw text tìm upstream, mở rộng regex từ `r'=\s*([a-zA-Z_]\w*)\b'` thành cũng match:
- `y = x.method()` → upstream là `x`
- `y = obj["key"]` → upstream là `obj`
- `y = func(x)` → upstream là `x`

```python
# Trong trace_one(), thêm patterns bổ sung:
upstream_patterns = [
    r'=\s*([a-zA-Z_]\w*)\b',                    # y = x
    r'=\s*([a-zA-Z_]\w*)\.[a-zA-Z_]\w*\(',       # y = x.method()
    r'=\s*([a-zA-Z_]\w*)\[',                     # y = x["key"]
    r'=\s*\w+\(([a-zA-Z_]\w*)',                  # y = func(x, ...)
]
for pat in upstream_patterns:
    m = re.search(pat, line)
    if m and m.group(1) not in visited:
        trace_one(m.group(1), hop + 1)
```

**Effort:** ~1.5 giờ | **Impact:** 🔴 High — bắt được method chain injection (cực phổ biến trong JS/Java)

---

## PHASE B — Output & Reporting

### B.1 — SARIF Output Format

**File:** `src/output/sarif.py` [NEW]

**Lý do:** Argus xuất SARIF — chuẩn quốc tế cho SAST (được GitHub, SonarQube, Azure DevOps đọc được). Thiếu cái này thì không thể tích hợp vào CI/CD pipeline của người dùng enterprise.

**Implement:**
```python
def to_sarif(findings: list, scan_dir: str) -> dict:
    """Convert findings list to SARIF 2.1.0 format."""
    results = []
    for f in findings:
        results.append({
            "ruleId": f.get("id", "sinful-unknown"),
            "level": severity_to_sarif(f.get("severity", "WARNING")),
            "message": {"text": f.get("message", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("path", ""), "uriBaseId": "%SRCROOT%"},
                    "region": {
                        "startLine": f.get("start_line", 1),
                        "endLine": f.get("end_line", 1),
                    }
                }
            }],
            "properties": {
                "cwe": f.get("cwe", []),
                "severity": f.get("severity", ""),
                "confidence": f.get("confidence", 0),
            }
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Sinful", "version": "1.0.0"}}, "results": results}]
    }
```

**Cách triển khai đúng:** Export tự động trong `cli/commands/scan.py` cùng với JSON report hiện tại (không dùng flag). Sau khi scan xong, tự động ghi thêm file `.sarif` vào thư mục `reports/`:
```python
# Trong cli/commands/scan.py, sau khi ghi JSON:
from src.output.sarif import to_sarif
sarif_path = os.path.join(report_dir, f"sinful_report_{time_stamp}.sarif")
with open(sarif_path, "w", encoding="utf-8") as f:
    json.dump(to_sarif(scan_findings, target_path), f, indent=2)
logger.log_success(f"SARIF report saved to: [bold cyan]{sarif_path}[/bold cyan]")
```

**File mới:** `src/output/sarif.py` | **Sửa:** `cli/commands/scan.py`

**Effort:** ~2 giờ | **Impact:** 🟠 High cho CI/CD integration

---

### B.2 — HTML Report tự động xuất cùng lúc với JSON

**File:** `src/output/report.py` [NEW] | **Sửa:** `cli/commands/scan.py`

Argus có HTML report đẹp với:
- Danh sách vulnerabilities có filter theo severity/language
- Code snippet highlight tại sink line
- Data flow trace (source → sink)
- CVE detail panel

**Cách triển khai đúng:** Không dùng Jinja2 (thêm dependency). Dùng thuần Python f-string với HTML inline.
Sau scan, tự động ghi thêm file `.html` vào `reports/`:
```python
# Trong cli/commands/scan.py, sau SARIF:
from src.output.report import to_html
html_path = os.path.join(report_dir, f"sinful_report_{time_stamp}.html")
with open(html_path, "w", encoding="utf-8") as f:
    f.write(to_html(scan_findings, target_path))
logger.log_success(f"HTML report saved to: [bold cyan]{html_path}[/bold cyan]")
```

**Effort:** ~3 giờ | **Impact:** 🟡 Medium

---

## PHASE C — Pipeline Stability

### C.1 — Scanning Agent: tăng max tool calls lên 15

**File:** `src/scan/agents/prompts.py` (Line 46)

Hiện tại prompt ghi: `max 8 tool calls be efficient`. Với cross-file 4+ hop → 8 calls không đủ dù `max_steps=12`. Cần nới lỏng:

```python
# Sửa dòng 46:
# "max 8 tool calls be efficient, trace the critical path first."
# → "max 15 tool calls. Be systematic but efficient."
```

**Effort:** ~2 phút | **Impact:** 🟡 Medium

---

### C.2 — Retry logic cho Scanning Agent khi LLM trả None

**File:** `src/tools/handlers.py`

**Vấn đề:** Khi model trả về `None` (không phải HTTP error), agent loop kết thúc với kết quả rỗng. Không được count là lỗi, không được retry.

**Fix — Thêm kiểm tra sau mỗi step:**
```python
# Trong run_agent():
if response is None or response.choices is None:
    if attempt < 3:
        time.sleep(1)
        continue  # retry toàn bộ step
    else:
        break  # ghi log warning, không crash
```

**Effort:** ~45 phút | **Impact:** 🟠 High (model flakiness là nguyên nhân số 1 miss finding)

---

### C.3 — Parallel scanning cho multiple findings

**File:** `main.py` (vòng lặp dòng ~442)

**Vấn đề:** Với 20+ findings, hệ thống chạy tuần tự → mất 30-60 phút. Argus chạy song song tối đa 5 findings cùng lúc.

**Fix:**
```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_one(finding):
    # ... existing scan logic ...
    return result

with ThreadPoolExecutor(max_workers=5) as pool:
    futures = {pool.submit(scan_one, f): f for f in find_flaws}
    for future in as_completed(futures):
        result = future.result()
        # ... collect results ...
```

> [!WARNING]
> Cần thread-safe console output (dùng lock) khi parallel.

**Effort:** ~2 giờ | **Impact:** 🟠 High cho large codebase

---

### C.4 — Cache `build_context` result cho cùng scan_dir

**File:** `main.py` + `src/audit/tree-sitter.py`

**Vấn đề:** `build_context()` walk toàn bộ codebase và parse tất cả file với tree-sitter. Nếu `/scan` được gọi nhiều lần trong 1 session → chạy lại từ đầu.

**Fix:** Thêm in-memory cache:
```python
_context_cache = {}

def build_context(target_dir: str) -> str:
    if target_dir in _context_cache:
        return _context_cache[target_dir]
    result = _build_context_impl(target_dir)
    _context_cache[target_dir] = result
    return result
```

**Effort:** ~20 phút | **Impact:** 🟡 Medium (UX speed improvement)

---

## PHASE D — SCA Nâng cao

### D.1 — Pinned version từ lockfile thay vì range từ package.json

**File:** `src/recognize/parser.py`

**Vấn đề:** `parse_npm("package.json")` đọc version `^4.15.2` → strip thành `4.15.2`. OSV lookup có thể trả về false negative nếu version thực tế là `4.15.3` (không còn bị ảnh hưởng).

**Fix:** Ưu tiên `package-lock.json`/`yarn.lock` (đã parse được) khi có, override version từ `package.json`:
```python
# Sau khi parse tất cả file, merge: lockfile version wins over package.json version
def merge_with_lockfile(npm_deps, lockfile_deps):
    lock_map = {d["package"]: d["version"] for d in lockfile_deps}
    for dep in npm_deps:
        if dep["package"] in lock_map:
            dep["version"] = lock_map[dep["package"]]  # pinned wins
    return npm_deps
```

**Effort:** ~30 phút | **Impact:** 🟠 High cho SCA accuracy

---

### D.2 — OSV batch query (thay vì 1-by-1)

**File:** `src/rag/osv.py`

**Vấn đề hiện tại:** Gọi OSV API từng package một. OSV hỗ trợ batch query (nhiều package trong 1 request).

**Fix:** Dùng `/v1/querybatch`:
```python
def check_vulns_batch(deps: list) -> list:
    queries = [{"package": {"name": d["package"], "ecosystem": d["ecosystem"]}, "version": d["version"]} for d in deps]
    resp = requests.post("https://api.osv.dev/v1/querybatch", json={"queries": queries}, timeout=30)
    # parse resp.json()["results"]
```

**Effort:** ~1 giờ | **Impact:** 🟡 Medium (speed, giảm từ N requests → 1 request)

---

## PHASE E — Test & Validation

### E.1 — Chạy regression test trên `samples/`

Trước khi deploy, **bắt buộc** chạy full scan trên thư mục `samples/` và verify:

| Metric | Target |
|--------|--------|
| False Negative rate | < 20% (so với known vulns trong samples) |
| False Positive rate | < 30% |
| Crash / unhandled exception | 0 |
| NVD fetch success rate | 100% |
| Scan time (samples/) | < 10 phút |

**Lệnh test:**
```bash
cd /mnt/c/Users/ASUS/Documents/AI-Based\ SAST
python -m cli.main
> /scan samples
```

Ghi lại số findings ở mỗi severity, so sánh với lần chạy trước.

---

### E.2 — Thêm unit test cho taint engine

**File:** `tests/test_taint.py` [NEW]

Test 5 case cơ bản:
1. Direct taint: `x = req.args.get("q"); db.execute(x)` → VULNERABLE
2. Alias 1 hop: `y = x; db.execute(y)` → VULNERABLE
3. Sanitized: `y = escape(x); db.execute(y)` → SAFE
4. Cross-file: function A là source, function B gọi A rồi pass vào sink → VULNERABLE
5. Comment false positive: `# uses prepared statement` → vẫn VULNERABLE

**Effort:** ~2 giờ | **Impact:** 🟠 High cho long-term reliability

---

## Thứ tự thực hiện — Tối ưu cho deploy sớm nhất

```
┌─ TUẦN NÀY (Deploy blocker — phải làm trước)
│
│  [TEST]   E.1 Chạy regression test trên samples/          [30 phút]
│  [A.2]    Fix has_sink() word-boundary matching            [30 phút]
│  [C.2]    Retry khi LLM trả None                           [45 phút]
│  [A.1]    Fix find_sinks AND → callees recursive           [3 giờ]
│  [C.1]    Tăng max tool calls scan prompt → 15             [2 phút]
│  [A.3]    Tăng alias hops → 5                              [5 phút]
│
├─ TUẦN SAU (Tăng coverage & accuracy)
│
│  [A.4]    Field-sensitive taint (method chain)             [1.5 giờ]
│  [D.1]    Lockfile pinned version wins                     [30 phút]
│  [D.2]    OSV batch query                                  [1 giờ]
│  [C.4]    Cache build_context                              [20 phút]
│
├─ THÁNG SAU (Enterprise features)
│
│  [B.1]    SARIF output                                     [2 giờ]
│  [C.3]    Parallel scanning 5 findings                     [2 giờ]
│  [B.2]    HTML report                                      [3 giờ]
│  [E.2]    Unit tests taint engine                          [2 giờ]
│
```

---

> [!IMPORTANT]
> **Làm E.1 (chạy test) TRƯỚC TIÊN.** Cần biết baseline hiện tại bao nhiêu lỗi bị bắt và bao nhiêu crash trước khi tiếp tục sửa. Không có baseline thì không biết sửa có tốt hơn không.

> [!NOTE]
> **A.1 (callees recursive)** là item quan trọng nhất trong tất cả — sau khi fix cái này, detection rate dự kiến tăng 30-40% cho các case taint đi qua helper function (chiếm ~50% real-world vulns).

> [!WARNING]
> **C.3 (Parallel scanning)** phải cẩn thận với console output race condition và model rate limit. Implement sau khi đã stable.
