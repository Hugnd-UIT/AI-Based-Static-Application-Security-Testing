# Kế Hoạch SINFUL — Trạng Thái Thực Tế

## Trạng Thái Tổng Quan: ~95% Argus Parity

> [!IMPORTANT]
> Tất cả 4 GAP ban đầu đã được triển khai đầy đủ trong codebase. Tài liệu này cập nhật trạng thái thực tế và liệt kê các GAP còn lại để tiến lên 100%.

---

## ✅ Đã Hoàn Thành (So với Plan ban đầu)

| Thành phần | Trạng thái | Ghi chú |
|---|---|---|
| Pipeline 5 Agent | ✅ | Scan → RAG → Audit → Hack → Fix |
| ReAct Loop Audit Agent | ✅ | Multi-turn, tối đa 3 vòng lặp |
| RAG (OSV/NVD/Firecrawl/GitHub) | ✅ | Đầy đủ |
| Tree-sitter Cross-file Caller | ✅ | `build_context()`, `find_global_callers()` |
| Custom Taint Rules (10 ngôn ngữ) | ✅ | Semgrep rules |
| Hack Agent PoC | ✅ | `gen_poc()` |
| Fix Agent | ✅ | `gen_fix()` có patches |
| **GAP 1 — Inter-procedural Taint** | ✅ | `build_context()` + inject vào Audit Agent context |
| **GAP 2 — SCA Reachability** | ✅ | `src/rag/usage.py` — `check()` với Tree-sitter |
| **GAP 3 — Confidence Score / Severity** | ✅ | JSON verdict: `confidence`, `cvss_estimate`, `severity`, `vuln_class` |
| **GAP 4 — Multi-turn ReAct Loop** | ✅ | `while iterations < 3` + `NEED_MORE_CONTEXT` token |

---

## 🔴 GAP Còn Lại — Tiến Lên 100%

### GAP A — Forward Taint Propagation (Vẫn là gap so với Argus)

**Vấn đề:** `build_context()` hiện tại thực hiện **backward tracing** (ai gọi hàm bị lỗi). Chưa có **forward taint**: nếu `get_user_input()` ở `fileA.py` trả về tainted data, chưa tự động phát hiện khi `fileB.py` gọi hàm đó và đưa vào sink.

**Ví dụ chưa bắt được:**
```python
# fileA.py
def get_user_input():
    return request.args.get("id")  # Source ở đây

# fileB.py
from fileA import get_user_input
def process():
    uid = get_user_input()          # Taint lan sang fileB
    db.execute("SELECT * WHERE id=" + uid)  # Sink — chưa bắt được
```

**Giải pháp:**

#### [MODIFY] src/audit/tree-sitter.py
- Thêm `collect_tainted_functions(target_dir)` — scan project, tìm hàm có HTTP source trong body
- Thêm `find_cross_file_sinks(target_dir, tainted_funcs)` — tìm nơi gọi hàm tainted → vào sink
- Inject kết quả vào `build_context()` để Audit Agent nhận đầy đủ

**Độ phức tạp:** 🔴 Cao | **Ước tính:** ~3-4 giờ

---

### GAP B — Báo Cáo HTML/JSON Đầy Đủ

**Vấn đề:** Hiện tại kết quả chỉ hiển thị trên CLI (Rich console). Không có output file nào để share cho team, tích hợp CI/CD, hay hiển thị trên dashboard web.

**Giải pháp:**

#### [MODIFY] main.py
- Thêm flag `--output json` hoặc `--output html`
- Khi chạy xong, ghi `scan_result` ra file `.json` hoặc render HTML report

#### [NEW] src/reports/html.py
- Template HTML với bảng findings, CVSS scores, PoC code, patch diff

**Độ phức tạp:** 🟡 Trung bình | **Ước tính:** ~2-3 giờ

---

### GAP C — CI/CD Integration (GitHub Actions / GitLab)

**Vấn đề:** Chưa có cách tích hợp SINFUL vào pipeline CI/CD. Dev phải chạy tay, không thể scan tự động mỗi khi có commit/PR.

**Giải pháp:**

#### [NEW] .github/workflows/sinful-scan.yml
```yaml
name: Sinful SAST
on: [pull_request]
jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: pip install sinful-sast
      - run: sinful . --output json
      - uses: actions/upload-artifact@v3
        with:
          name: sinful-report
          path: sinful-report.json
```

**Độ phức tạp:** 🟢 Thấp | **Ước tính:** ~1 giờ

---

### GAP D — Scan Speed Optimization

**Vấn đề:** `time.sleep(15)` giữa mỗi Firecrawl call và `time.sleep(6)` giữa các CVE rất chậm. Với project có nhiều CVE, scan mất hàng chục phút.

**Giải pháp:**

#### [MODIFY] main.py
- Dùng `asyncio` + `aiohttp` để fetch song song (concurrent) thay vì tuần tự
- Hoặc đơn giản hơn: giảm rate limit sleep, tăng retry logic thay thế
- Cache NVD/OSV responses vào local SQLite để tránh gọi lại cùng CVE

**Độ phức tạp:** 🟡 Trung bình | **Ước tính:** ~2 giờ

---

### GAP E — Baseline / Diff Scan (So sánh với lần scan trước)

**Vấn đề:** Mỗi lần scan là scan full từ đầu. Dev không biết vulnerability nào là **mới xuất hiện** sau commit, cái nào đã có từ trước.

**Giải pháp:**

#### [NEW] src/baseline.py
- Lưu kết quả scan vào file `.sinful-baseline.json`
- Lần scan tiếp theo, so sánh findings mới vs baseline
- Chỉ report NEW findings + RESOLVED findings

**Độ phức tạp:** 🟢 Thấp | **Ước tính:** ~1.5 giờ

---

## Tóm Tắt Timeline & Độ Phức Tạp

| # | GAP | Độ phức tạp | Thời gian ước tính | Ưu tiên |
|---|---|---|---|---|
| A | Forward Taint Propagation | 🔴 Cao | ~3-4 giờ | P1 — Core quality |
| B | HTML/JSON Report Output | 🟡 Trung bình | ~2-3 giờ | P2 — Usability |
| C | CI/CD Integration | 🟢 Thấp | ~1 giờ | P2 — Adoption |
| D | Scan Speed Optimization | 🟡 Trung bình | ~2 giờ | P3 — UX |
| E | Baseline / Diff Scan | 🟢 Thấp | ~1.5 giờ | P3 — UX |

**Tổng còn lại:** ~10-11 giờ → Đưa SINFUL từ ~95% lên **100% Argus parity + vượt Argus**

## Thứ tự triển khai đề xuất:
```
GAP C (CI/CD)         → Dễ nhất, impact lớn ngay
GAP E (Baseline)      → Dễ, rất hữu ích cho Dev
GAP B (Report Output) → UX quan trọng cho demo/production
GAP D (Speed)         → Tăng trải nghiệm user
GAP A (Forward Taint) → Phức tạp nhất, làm cuối cùng
```

> [!NOTE]
> GAP C + E có thể làm song song trong 1 buổi vì hoàn toàn độc lập với nhau.
> GAP A là cải tiến lớn nhất về chất lượng detection nhưng cũng là phức tạp nhất.


## Trạng Thái Hiện Tại: ~85% Argus

| Thành phần | Trạng thái |
|---|---|
| Pipeline 5 Agent | ✅ Hoàn chỉnh |
| ReAct Loop Audit Agent | ✅ Hoàn chỉnh |
| RAG (OSV/NVD/Firecrawl/GitHub) | ✅ Hoàn chỉnh |
| Tree-sitter Cross-file Caller | ✅ Hoàn chỉnh |
| Custom Taint Rules (10 ngôn ngữ) | ✅ Hoàn chỉnh |
| Hack Agent PoC | ✅ Hoàn chỉnh |
| **Inter-procedural Taint Propagation** | ❌ Thiếu |
| **SCA Reachability Analysis** | ❌ Thiếu |
| **Confidence Score / Severity Ranking** | ❌ Thiếu |
| **Multi-turn ReAct Loop** | ⚠️ Hiện tại 3-step cố định, chưa iterative |

---

## GAP 1 — Inter-procedural Taint Propagation
**Vấn đề:** Tree-sitter hiện tại (`find_global_callers`) chỉ tìm **ai gọi hàm bị lỗi** (backward tracing). Nhưng chưa có khả năng **theo dõi dòng chảy dữ liệu qua tham số hàm sang file khác** (forward taint propagation).

**Ví dụ chưa bắt được:**
```
# fileA.py
def get_user_input():
    return request.args.get("id")  # Source ở đây

# fileB.py
from fileA import get_user_input
def process():
    uid = get_user_input()          # Taint lan sang fileB
    db.execute("SELECT * WHERE id=" + uid)  # Sink ở đây
```
Semgrep custom rules chỉ nhìn thấy trong 1 file. Tree-sitter hiện tại tìm được caller nhưng không trace taint qua parameter.

**Giải pháp:** Bổ sung hàm `build_cross_file_taint_graph()` vào `tree-sitter.py`:
1. Scan toàn bộ project, lập danh sách function definition + return values
2. Khi function trả về tainted data (từ HTTP sources), đánh dấu nó là tainted source
3. Các file import và gọi function đó → taint lan ra

### File cần sửa:
#### [MODIFY] [tree-sitter.py](file:///c:\Users\ASUS\Documents\AI-Based%20SAST\src\audit\tree-sitter.py)
- Thêm hàm `collect_tainted_functions(target_dir)` — scan toàn bộ project, tìm các hàm có HTTP source trong body
- Thêm hàm `find_cross_file_sinks(target_dir, tainted_funcs)` — tìm các chỗ gọi các hàm đó rồi chạy vào sink
- Kết quả trả về list các cross-file taint paths, inject vào context của Scan Agent

---

## GAP 2 — SCA Reachability Analysis
**Vấn đề:** Hiện tại khi phát hiện CVE của dependency (ví dụ: `requests==2.27.0` có CVE), hệ thống báo luôn mà không check xem **cái function bị lỗi của lib đó có thực sự được gọi trong code không**. → Tạo ra False Positive SCA.

**Ví dụ:**
```
# requirements.txt: pillow==9.0.0 (có CVE về Image.open())
# Nhưng code chỉ import pillow để resize, KHÔNG gọi Image.open()
# → Không nên báo CVE này
```

**Giải pháp:** Sau khi có danh sách CVE từ OSV, bổ sung bước reachability check:
1. Với mỗi CVE, xác định **tên hàm/method bị lỗi** (từ NVD description hoặc advisory)
2. Dùng Tree-sitter scan toàn bộ project tìm xem function đó có được gọi không
3. Nếu không tìm thấy → đánh dấu CVE là `reachable: false` → bỏ qua hoặc hạ độ ưu tiên

### File cần tạo/sửa:
#### [NEW] [src/rag/reachability.py](file:///c:\Users\ASUS\Documents\AI-Based%20SAST\src\rag\reachability.py)
```python
def check_reachability(target_dir, cve_list, ts_module):
    # Với mỗi CVE, extract tên function/method từ description
    # Dùng tree-sitter find_global_callers() để kiểm tra
    # Return cve_list đã có thêm field "reachable": True/False
```

#### [MODIFY] [main.py](file:///c:\Users\ASUS\Documents\AI-Based%20SAST\main.py)
- Sau `osv.check()`, gọi `reachability.check()` để filter CVE list
- Chỉ những CVE `reachable: true` mới được đưa vào RAG pipeline

---

## GAP 3 — Confidence Score & Severity Ranking
**Vấn đề:** Audit Agent hiện trả về nhị phân `[VULNERABLE]` / `[SAFE]`. Không có thông tin về **mức độ nghiêm trọng, độ tin cậy** để Dev biết ưu tiên sửa cái nào trước.

**Giải pháp:** Nâng cấp output của Audit Agent:

### File cần sửa:
#### [MODIFY] [src/audit/agents/prompts.py](file:///c:\Users\ASUS\Documents\AI-Based%20SAST\src\audit\agents\prompts.py)
Thay đổi Step 3 — thay vì output token nhị phân, yêu cầu AI output JSON:
```json
{
  "verdict": "VULNERABLE",
  "confidence": 9,
  "cvss_estimate": 8.5,
  "severity": "CRITICAL",
  "vuln_class": "IDOR",
  "reasoning_summary": "User-controlled ID flows directly to DB without ownership check"
}
```

#### [MODIFY] [main.py](file:///c:\Users\ASUS\Documents\AI-Based%20SAST\main.py)
- Parse JSON verdict từ Audit Agent
- Hiển thị confidence + severity trong CLI
- Sort findings theo `cvss_estimate` giảm dần

---

## GAP 4 — Multi-turn ReAct Loop (Iterative Reasoning)
**Vấn đề:** Audit Agent hiện tại chạy 3 bước cố định (Step 1→2→3). Argus mô tả một vòng lặp **iterative**: Nếu sau Step 2 chưa kết luận được, AI có thể yêu cầu thêm context (thêm file, thêm caller) rồi chạy lại.

**Giải pháp:** Implement vòng lặp ReAct thật sự trong `main.py`:

```
Lần 1: Audit Agent phân tích với context ban đầu
  → Nếu AI output "[NEED_MORE_CONTEXT: function_name]"
  → Tree-sitter fetch thêm code của function đó
  → Chạy lại Audit Agent với context bổ sung
  → Tối đa 3 vòng lặp
  → Lần cuối phải ra verdict
```

### File cần sửa:
#### [MODIFY] [src/audit/agents/prompts.py](file:///c:\Users\ASUS\Documents\AI-Based%20SAST\src\audit\agents\prompts.py)
- Thêm token `[NEED_MORE_CONTEXT: <function_name>]` vào instruction

#### [MODIFY] [main.py](file:///c:\Users\ASUS\Documents\AI-Based%20SAST\main.py)
- Wrap Audit Agent call trong vòng lặp `while iterations < 3`
- Parse `NEED_MORE_CONTEXT` token → gọi Tree-sitter fetch thêm
- Tiếp tục loop cho đến khi có `[VULNERABLE]` / `[SAFE]`

---

## Tóm Tắt Timeline & Độ Phức Tạp

| # | GAP | Độ phức tạp | Thời gian ước tính |
|---|---|---|---|
| 1 | Inter-procedural Taint Propagation | 🔴 Cao | ~3-4 giờ |
| 2 | SCA Reachability Analysis | 🟡 Trung bình | ~2 giờ |
| 3 | Confidence Score / Severity Ranking | 🟢 Thấp | ~1 giờ |
| 4 | Multi-turn ReAct Loop | 🟡 Trung bình | ~2 giờ |

**Tổng:** ~8-9 giờ → Đưa SINFUL từ ~85% lên **100% Argus parity**

## Thứ tự triển khai đề xuất:
```
GAP 3 (Confidence Score) → Dễ nhất, làm ấm máy
GAP 2 (SCA Reachability) → Độc lập, không phụ thuộc GAP khác
GAP 4 (Multi-turn ReAct) → Nâng chất lượng Audit Agent
GAP 1 (Inter-procedural) → Phức tạp nhất, làm cuối
```

> [!IMPORTANT]
> GAP 3 có thể triển khai ngay lập tức mà không cần thay đổi kiến trúc lớn.
> GAP 1 là cải tiến lớn nhất về chất lượng detection nhưng cũng phức tạp nhất.
