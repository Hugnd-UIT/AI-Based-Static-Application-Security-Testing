# Sinful SAST — Weakness Analysis & Fix Plan

## Tóm tắt: Mạnh ở đâu, yếu ở đâu

Sau khi đọc toàn bộ code, dự án của sếp **đúng hướng và mạnh về kiến trúc**. Nhưng có **6 điểm yếu kỹ thuật thực tế** khiến kết quả chạy hay bị sai hoặc không ổn định. Dưới đây là phân tích thẳng thắn.

---

## BUG #1 (NGHIÊM TRỌNG): Verifier Agent nhận context quá tệ

### Vấn đề
Trong `main.py` dòng 208, sau khi RAG chạy xong:
```python
cve_context = json.dumps(rag_summary, indent=2)
```
Cái `cve_context` này là một đống JSON thô dày bao gồm cả `osv`, `nvd`, `firecrawl_poc`, `github_issues`... Sếp truyền hết đống này vào `verifier.start_verify(cve_context, ...)`. Con Verifier nhận được **hàng nghìn token vô nghĩa** → nó lạc đường → không biết mình cần tìm gì trong codebase → `Agent loop did not complete`.

### Fix
Trước khi gọi Verifier, tóm tắt lại context cho nó chỉ còn:
- Tên CVE
- Tên thư viện bị ảnh hưởng
- Các hàm nguy hiểm (từ `rag_summary["functions"]`)
- Attack vector (1 câu)

```python
# Trước khi gọi verifier:
verifier_brief = {
    "cve_id": rag_summary.get("cve_id"),
    "dependency": rag_summary.get("dependency"),
    "vulnerable_functions": rag_summary.get("functions", []),
    "attack_vector": rag_summary.get("attack_vector"),
}
poc_result = verifier.start_verify(json.dumps(verifier_brief, indent=2), ...)
```

**File sửa:** `main.py` (~5 dòng)

---

## BUG #2 (NGHIÊM TRỌNG): Surrogate Sink retry không log và không rõ ràng

### Vấn đề
Trong `main.py` dòng 341-344, khi Scan Agent đề xuất surrogate sink:
```python
elif trace_json and trace_json.get("surrogate_sink_proposed"):
    surrogate_func = trace_json.get("surrogate_function", "Unknown")
    finding_item["surrogate_sink_context"] = ...
    retry_count += 1
```
Không có **log nào** cho user biết là đang retry với surrogate nào. User thấy màn hình đứng im không biết đang làm gì.

### Fix
Thêm log dòng:
```python
logger.console.print(f"  ├─ [yellow]⚠ Flow broken → Surrogate: {surrogate_func} (retry {retry_count}/{max_retries})[/yellow]")
```

**File sửa:** `main.py` (1 dòng)

---

## BUG #3 (TRUNG BÌNH): Expanding Agent không có tool để verify

### Vấn đề
`SINK_EXPAND_TOOL_SET = [SUBMIT_VERDICT_SCHEMA]` — con Expander không có `search_pattern` hay `read_file`. Nó chỉ đoán mò từ CVE text rồi đề xuất pattern mà **không thể tự kiểm tra xem pattern đó có match gì trong codebase không**. Kết quả là nó hay đề xuất patterns quá generic (VD: `"execute"`) → gây noise lớn.

### Fix
Thêm `SEARCH_PATTERN_SCHEMA` vào toolset của nó:
```python
SINK_EXPAND_TOOL_SET = [SEARCH_PATTERN_SCHEMA, SUBMIT_VERDICT_SCHEMA]
```
Và sửa prompt để bảo nó **bắt buộc chạy `search_pattern` để verify** pattern có tồn tại trong codebase trước khi submit.

**File sửa:** `src/tools/schemas.py` (1 dòng), `src/rag/agents/prompts.py` (~5 dòng)

---

## BUG #4 (TRUNG BÌNH): RAG chỉ xử lý 1 CVE duy nhất

### Vấn đề
`rag_agents.start_rag()` trả về **1 dict** duy nhất, nghĩa là nó chỉ phân tích 1 CVE. Nhưng sếp có thể thu thập về **nhiều CVEs** qua OSV/NVD (từ nhiều dependency). Hiện tại, chỉ có đống JSON của tất cả CVEs được truyền vào, và RAG Agent chọn lấy 1 cái để phân tích → **bỏ sót tất cả các CVE còn lại**.

### Fix
Trong `main.py`, sau khi có `scan_result["nvd_data"]` (list), loop qua từng CVE một, gọi RAG + Verifier + Expander cho từng cái:
```python
for single_nvd in scan_result["nvd_data"]:
    rag_summary = rag_agents.start_rag(json.dumps(single_nvd), ...)
    # ... verifier, expander ...
```

**File sửa:** `main.py` (refactor vòng lặp RAG)

---

## BUG #5 (NHỎ): `fetch_llm` và `fetch_llm_tools` không share model fallback log

### Vấn đề
Trong `src/llm.py`, khi model chính bị lỗi và fallback sang model khác, **không có log nào** thông báo cho user. User thấy agent chạy lặng lẽ nhưng không biết nó đang dùng model gì.

### Fix
Thêm log khi fallback:
```python
if target_model != model_fallback[0]:
    from cli.views.logger import console
    console.print(f"  [dim]Fallback to {target_model}[/dim]")
```

**File sửa:** `src/llm.py` (~3 dòng)

---

## BUG #6 (NHỎ): Dynamic sinks từ Expander bị thiếu `severity` field

### Vấn đề
Trong `main.py` dòng 263-269, khi tạo `new_finding` từ sink mới:
```python
new_finding = {
    "id": f"dynamic-sink-{pat}",
    "message": ...,
    "path": file_path,
    "start_line": line_num,
    "end_line": line_num,
}
```
Thiếu field `"severity"` → khi đến dòng `summary_table` (`count_errors`, `count_warns`), nó raise `KeyError` hoặc không được đếm vào thống kê.

### Fix
Thêm `"severity": sink.get("severity", "WARNING")` vào `new_finding`.

**File sửa:** `main.py` (1 dòng)

---

## Thứ tự thực hiện

```
[Ưu tiên 1] BUG #1 — Fix Verifier context (5 dòng, impact cao nhất)
[Ưu tiên 2] BUG #6 — Fix severity field (1 dòng, fix crash)  
[Ưu tiên 3] BUG #2 — Thêm retry log (1 dòng, UX)
[Ưu tiên 4] BUG #3 — Thêm tool cho Expander (đọc thêm tool)
[Ưu tiên 5] BUG #5 — Thêm fallback log (3 dòng)
[Ưu tiên 6] BUG #4 — Loop qua nhiều CVE (refactor lớn nhất)
```

> [!IMPORTANT]
> BUG #1 và BUG #6 là quan trọng nhất. Fix 2 cái này trước, chạy lại test để xác nhận Verifier hoạt động đúng rồi mới làm tiếp.
