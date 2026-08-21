# Sinful SAST — Kế hoạch Nâng cấp Chi tiết

> Dựa trên phân tích so sánh toàn bộ source code với Argus (2026-08-21)

---

## Mục tiêu

Đưa Sinful từ một tool "prototype hoạt động được" lên một SAST tool cạnh tranh được với Argus bằng cách:
1. **Tăng detection rate** – Giảm False Negative bằng cách nâng cấp taint engine
2. **Giảm False Positive** – Audit Agent xác minh kỹ trước khi phán VULNERABLE
3. **Cải thiện độ ổn định** – Fix retry logic, NVD fetching, model error handling
4. **Mở rộng coverage** – Thêm sink/source cho tất cả 10 ngôn ngữ đang support

---

## PHASE 1 — Critical Fixes (Làm ngay, ảnh hưởng detection rate)

### 1.1. Fix `sinful-cross-file-taint` — Tạo N findings thay vì 1

**File:** `main.py` (~Line 117)

**Vấn đề:** Khi `build_context` phát hiện nhiều cross-file taint path, code hiện tại chỉ tạo đúng **1 finding duy nhất** với `path = thư mục gốc`. Scanning Agent nhận finding đó không biết file nào để đọc, phải đoán mò → thường fail hoặc trace sai.

**Fix chi tiết:**
- Parse `build_context` string (vốn là join nhiều `[CROSS-FILE TAINT PATH DETECTED]` blocks) thành list
- Với mỗi block → extract `file_path` và `start_line` từ dòng `Propagates to:`
- Tạo ra **N findings riêng biệt**, mỗi finding có `path` và `start_line` cụ thể

```python
# Thay thế đoạn lines 117-129 bằng:
if build_context:
    taint_blocks = [b for b in build_context.split("[CROSS-FILE TAINT PATH DETECTED]") if b.strip()]
    for taint_block in taint_blocks:
        # Extract file path và line number từ "Propagates to : filename (line N)"
        prop_match = re.search(r"Propagates to\s*:\s*(\S+)\s*\(line (\d+)\)", taint_block)
        taint_file = prop_match.group(1) if prop_match else str(scan_dir)
        taint_line = int(prop_match.group(2)) if prop_match else 1
        find_flaws.append({
            "id": "sinful-cross-file-taint",
            "path": taint_file,
            "start_line": taint_line,
            "end_line": taint_line + 5,
            "severity": "HIGH",
            "message": "Cross-file taint path detected by inter-procedural analysis.",
            "lines": "",
            "cwe": ["CWE-20"],
            "dataflow_trace": taint_block.strip(),
        })
    get_result["findings"] = find_flaws
```

**Effort:** ~30 phút | **Impact:** 🔴 Critical

---

### 1.2. Nâng cấp `SINKS` list — Thêm Web/JS/Java sinks

**File:** `src/audit/tree-sitter.py` (SINKS, line 45)

**Thêm:**
```python
SINKS = [
    # ... existing ...
    
    # JavaScript DOM XSS
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "insertAdjacentHTML", "eval", "Function(",
    
    # JavaScript Command/File Injection  
    "child_process.exec", "child_process.spawn", "child_process.execSync",
    "fs.readFile", "fs.writeFile", "fs.appendFile", "fs.unlink",
    
    # JavaScript HTTP (reflected XSS/redirect)
    "res.send", "res.json", "res.end", "res.redirect", "res.location",
    
    # Python deserialization
    "pickle.load", "marshal.loads", "shelve.open",
    "jsonpickle.decode", "__reduce__",
    
    # Java RCE
    "Runtime.exec", "ProcessBuilder", "ScriptEngine.eval",
    "Class.forName", "Method.invoke",
    
    # Java JNDI (Log4Shell family)
    "InitialContext.lookup", "Context.lookup", "ldap://",
    
    # PHP
    "passthru", "preg_replace", "create_function", "assert",
    "include", "require", "include_once", "file_get_contents",
    
    # Go
    "os.Exec", "exec.Command", "exec.CommandContext",
    "ioutil.WriteFile", "os.WriteFile",
    
    # Ruby
    "system", "exec", "open", "eval", "send",
    "`",  # backtick shell exec
]
```

**Effort:** ~20 phút | **Impact:** 🔴 High

---

### 1.3. Nâng cấp `SOURCES` list — Thêm source cho đủ 10 ngôn ngữ

**File:** `src/audit/tree-sitter.py` (SOURCES, line 29)

**Thêm:**
```python
SOURCES = [
    # ... existing ...
    
    # Python — CLI & Environment
    "os.environ", "sys.argv", "os.getenv",
    
    # Python — Network raw
    "socket.recv", "socket.recvfrom", "socket.recvmsg",
    
    # JavaScript — Event handlers
    "event.data", "event.target.value", "location.search",
    "location.hash", "location.href", "document.cookie",
    "window.name", "postMessage",
    
    # Java Spring (annotations handled separately)
    "@PathVariable", "@RequestParam", "@RequestBody",
    "HttpServletRequest.getParameter", "HttpServletRequest.getHeader",
    "HttpServletRequest.getInputStream",
    
    # Go net/http & frameworks
    "r.URL.Query()", "r.FormValue", "r.PostFormValue",
    "r.Header.Get", "r.Body",
    "gin.Context.Query", "gin.Context.PostForm", "gin.Context.Param",
    "echo.Context.QueryParam", "echo.Context.FormValue",
    
    # PHP
    "$_FILES", "$_ENV", "$_SESSION",
    
    # Ruby on Rails
    "params[:"]", "request.params", "request.env",
    
    # C# ASP.NET
    "Request.QueryString", "Request.Body", "HttpContext.Request",
    
    # Serverless / Cloud Functions
    "event.body", "event.queryStringParameters",
    "event.pathParameters", "context.clientContext",
    
    # C/C++ — additional
    "fgets", "getchar", "getline", "readlink", "readdir",
]
```

**Effort:** ~20 phút | **Impact:** 🔴 High

---

### 1.4. Fix `cve_context` bị overwrite — Accumulate toàn bộ CVE context

**File:** `main.py` (~Line 241)

**Vấn đề:** Trong vòng lặp Verifier, mỗi iteration làm:
```python
cve_context = json.dumps(verifier_brief, indent=2)  # ← overwrite!
```
Auditing Agent chỉ nhận được CVE cuối cùng được xử lý, không có context của các CVE trước.

**Fix:**
```python
# Khởi tạo trước vòng lặp:
cve_context_parts = []

# Trong vòng lặp:
cve_context_parts.append(json.dumps(verifier_brief, indent=2))

# Sau vòng lặp, gộp lại:
cve_context = "\n\n---\n\n".join(cve_context_parts) if cve_context_parts else "No CVE context."
```

**Effort:** ~10 phút | **Impact:** 🟠 High

---

### 1.5. Fix `fetch_llm` / `fetch_tools` — Retry thêm 500/503

**File:** `src/llm.py` (Line 80, 155)

**Vấn đề:** Code chỉ retry `502`, `429`, `connection` error. HTTP `500` và `503` (rất phổ biến khi model bị overload) không được retry → drop thẳng → agent kết luận false safe.

**Fix:**
```python
# Sửa cả 2 chỗ trong fetch_llm và fetch_tools:
RETRYABLE_CODES = ("500", "502", "503", "429", "504")

if any(code in last_error for code in RETRYABLE_CODES) or "connection" in last_error.lower() or "timeout" in last_error.lower():
    if attempt < max_retries - 1:
        time.sleep(2 ** attempt)  # exponential backoff: 1s, 2s, 4s
        continue
```

**Effort:** ~15 phút | **Impact:** 🟡 Medium-High

---

## PHASE 2 — Taint Engine Improvements (Nâng độ sâu phân tích)

### 2.1. Variable-level alias tracking trong `resolve_aliases`

**File:** `src/audit/tree-sitter.py` (Line 539, `resolve_aliases`)

**Vấn đề:** Hiện tại `resolve_aliases` chỉ tìm node nào chứa `var_name` bytes, trả về flat list. Không có khái niệm "upstream" – tức là nếu `y = x` và `x = request.args.get(...)`, hỏi về `y` thì không biết `y` ← `x` ← source.

**Fix — Thêm 2-hop upstream chaining:**
```python
def resolve_aliases_chain(file_path: str, var_name: str, max_hops: int = 3) -> str:
    """
    Trace var_name qua tối đa max_hops assignment hops.
    Ví dụ: z = y → y = x → x = request.args.get("id") → kết luận z là tainted
    """
    visited = set()
    results = []
    
    def trace_one(current_var, hop):
        if hop > max_hops or current_var in visited:
            return
        visited.add(current_var)
        raw = resolve_aliases(file_path, current_var)  # existing function
        results.append(f"[HOP {hop}] {current_var}:\n{raw}")
        
        # Extract RHS variable names từ raw (simple: "var = SOMETHING")
        for line in raw.splitlines():
            rhs_match = re.search(r'=\s*([a-zA-Z_]\w*)\b', line)
            if rhs_match:
                upstream_var = rhs_match.group(1)
                if upstream_var not in visited:
                    trace_one(upstream_var, hop + 1)
    
    trace_one(var_name, 1)
    return "\n\n".join(results)
```

Expose qua `actions.py` → `trace_variable` gọi `resolve_aliases_chain` thay vì `resolve_aliases`.

**Effort:** ~2 giờ | **Impact:** 🔴 Critical — đây là gap lớn nhất vs Argus

---

### 2.2. Tách `build_context` → sinh findings có line number cụ thể

**File:** `src/audit/tree-sitter.py` (`find_sinks`, Line 283)

**Vấn đề:** `find_sinks` hiện chỉ trả về string, không trả về structured data (file path, line number của sink).

**Fix:** Thêm return type `List[Dict]` chứa `file`, `line`, `taint_source`, `sink_name`, `caller_code`:

```python
def find_sinks_structured(target_dir: str, tainted_funcs: dict) -> list:
    """
    Trả về list các dict thay vì string để main.py có thể tạo N findings riêng biệt.
    """
    results = []
    # ... (logic tương tự find_sinks nhưng append dict thay vì string) ...
    return results
```

**Effort:** ~1.5 giờ | **Impact:** 🔴 Critical

---

### 2.3. Fix `SANITIZERS` — Bổ sung check context (không match trong comment/string)

**File:** `src/audit/tree-sitter.py` (`find_sanitizer`, Line 606)

**Vấn đề:** Regex hiện tại match cả trong comment `# uses prepare_statement for ...` → false safe.

**Fix:**
```python
# Trước khi check sanitizer pattern, bỏ qua line là comment
def _strip_comment(line: str, file_ext: str) -> str:
    """Strip single-line comment dựa trên ngôn ngữ"""
    comment_markers = {
        ".py": "#", ".js": "//", ".ts": "//", ".java": "//",
        ".go": "//", ".php": "//", ".cs": "//", ".c": "//", ".cpp": "//"
    }
    marker = comment_markers.get(file_ext, "#")
    idx = line.find(marker)
    return line[:idx] if idx != -1 else line
```

**Effort:** ~30 phút | **Impact:** 🟡 Medium

---

## PHASE 3 — SCA Pipeline Improvements

### 3.1. Fix NVD Semaphore — Dùng sequential + sleep thay vì ThreadPool

**File:** `main.py` (~Line 147-176)

**Vấn đề:** `ThreadPoolExecutor(max_workers=2)` + `Semaphore(5)` → semaphore vô nghĩa.
NVD API limit là 5 request/30s nếu không có API key. Hiện tại gọi quá nhanh → bị reset.

**Fix:**
```python
# Thay ThreadPool bằng sequential với exponential backoff:
for cve_id in cve_id_list:
    nvd_result = get_cve_info(cve_id)  # đã có retry bên trong
    if nvd_result:
        nvd.report_nvd(nvd_result)
        scan_result["nvd_data"].append(nvd_result)
    time.sleep(0.6)  # NVD rate limit safe zone (5 req/3s với API key)
```

**Effort:** ~15 phút | **Impact:** 🟢 Low-Medium

---

### 3.2. Cải thiện `usage.py` — Kiểm tra import thực sự, không chỉ function name

**File:** `src/rag/usage.py`

**Vấn đề:** Hiện tại check `find_callers(target_dir, text_token, ...)` chỉ tìm tên function. Nếu CVE của `marked` package, nó tìm hàm tên `marked` → match bất kỳ function nào tên `marked` trong codebase, kể cả function nội bộ không liên quan.

**Fix — Thêm import verification:**
```python
def is_package_imported(target_dir: str, pkg_name: str) -> bool:
    """
    Kiểm tra xem package có thực sự được import/require không.
    VD: require('marked'), import marked from 'marked', import 'marked'
    """
    import_patterns = [
        rf"""require\s*\(\s*['\"]{re.escape(pkg_name)}['\"\s]*\)""",
        rf"""from\s+['\"]{re.escape(pkg_name)}['\"]""",
        rf"""import\s+['\"]{re.escape(pkg_name)}['\"]""",
        rf"""import\s+\w+\s+from\s+['\"]{re.escape(pkg_name)}['\"]""",
    ]
    # Walk files, grep patterns...
```

**Effort:** ~45 phút | **Impact:** 🟡 Medium

---

## PHASE 4 — Prompt & Agent Quality

### 4.1. Audit Agent — Thêm instruction cho JavaScript DOM XSS

**File:** `src/audit/agents/prompts.py`

Thêm vào `SYSTEM_PROMPT`:
```
JAVASCRIPT SPECIFIC:
- DOM XSS: track data flow từ location.search / location.hash / postMessage → innerHTML / document.write / eval()
- Prototype Pollution: track __proto__ / constructor.prototype assignments
- Node.js Path Traversal: track req.params → fs.readFile/fs.writeFile
```

**Effort:** ~15 phút | **Impact:** 🟠 High

---

### 4.2. Scanning Agent — Tăng max_steps từ 8 lên 12

**File:** `src/scan/agents/models.py` (Line 36)

**Lý do:** Với cross-file flow phức tạp (4+ hops), agent hiện tại bị cắt ở step 8 trước khi trace xong. Argus không có giới hạn này.

```python
max_steps = 12,  # tăng từ 8
```

**Effort:** ~2 phút | **Impact:** 🟡 Medium

---

### 4.3. Verifier Agent — Thêm `find_callers` vào toolset

**File:** `src/tools/schemas.py` — `VERIFY_TOOLS`

Verifier hiện chỉ có `search_pattern`, `read_file`, `submit_verdict`. Không thể trace interprocedural. Thêm `find_callers` và `find_function` để nó có thể xác minh exploitability sâu hơn.

**Effort:** ~20 phút | **Impact:** 🟠 High

---

## PHASE 5 — Infrastructure & Stability

### 5.1. Dedup findings sau khi gộp Semgrep + Dynamic sinks

**File:** `main.py` (sau khi build `scan_findings`)

```python
# Dedup bằng (path, start_line, rule_id)
seen = set()
deduped = []
for f in scan_findings:
    key = (f.get("path"), f.get("start_line"), f.get("id"))
    if key not in seen:
        seen.add(key)
        deduped.append(f)
scan_findings = deduped
```

**Effort:** ~10 phút | **Impact:** 🟡 Medium (tránh Audit Agent chạy 2 lần cho cùng 1 finding)

---

### 5.2. Thêm support `yarn.lock`, `package-lock.json` cho pinned version SCA

**File:** `src/recognize/parser.py`

Hiện tại chỉ đọc `package.json` → version có thể là `^4.15.2` (semver range). Nếu đọc `package-lock.json` → có version chính xác đã install → OSV lookup chính xác hơn nhiều.

**Effort:** ~1 giờ | **Impact:** 🟠 High cho SCA accuracy

---

### 5.3. Thêm `pyproject.toml` và `poetry.lock` support

**File:** `src/recognize/parser.py`

```python
# Thêm vào DEPS dict:
"pyproject.toml": "pypi",
"poetry.lock": "pypi",
"Pipfile": "pypi",
"Pipfile.lock": "pypi",
```

**Effort:** ~45 phút | **Impact:** 🟡 Medium

---

## Thứ tự thực hiện

```
┌─ PHASE 1 (Critical, làm ngay)
│  1.1  Fix sinful-cross-file-taint → N findings           [30 phút]
│  1.2  Thêm SINKS (DOM XSS, JS RCE, Java RCE)             [20 phút]
│  1.3  Thêm SOURCES (Go, Java, Serverless, CLI)            [20 phút]
│  1.4  Fix cve_context accumulation                        [10 phút]
│  1.5  Fix fetch_llm retry 500/503                         [15 phút]
│
├─ PHASE 2 (Taint Engine, quan trọng nhất về detection)
│  2.1  Variable alias chain tracking (resolve_aliases)     [2 giờ]
│  2.2  find_sinks_structured → structured findings         [1.5 giờ]
│  2.3  Sanitizer comment stripping                         [30 phút]
│
├─ PHASE 3 (SCA)
│  3.1  Fix NVD sequential + rate limit                     [15 phút]
│  3.2  Import verification trong usage.py                  [45 phút]
│
├─ PHASE 4 (Prompt & Agent)
│  4.1  JS DOM XSS instructions cho Audit Agent             [15 phút]
│  4.2  Tăng max_steps Scanning Agent → 12                  [2 phút]
│  4.3  Thêm find_callers cho Verifier toolset              [20 phút]
│
└─ PHASE 5 (Infrastructure)
   5.1  Dedup findings                                      [10 phút]
   5.2  yarn.lock / package-lock.json support               [1 giờ]
   5.3  pyproject.toml / poetry.lock support                [45 phút]
```

---

> [!IMPORTANT]
> **Làm ngay PHASE 1 toàn bộ trước.** Tổng ~95 phút nhưng giải quyết hết các lỗi ảnh hưởng trực tiếp đến số lỗ hổng bị bắt. Chạy lại `samples/mini-nodegoat` sau PHASE 1 để verify detection tăng lên trước khi làm PHASE 2.

> [!NOTE]
> **PHASE 2 item 2.1** (alias chain tracking) là item quan trọng nhất trong toàn bộ plan — đây là điểm thua Argus lớn nhất. Sau khi implement xong, chạy lại trên `samples/` toàn bộ để đo recall rate.
