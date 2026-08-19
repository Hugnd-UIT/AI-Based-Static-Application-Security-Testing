# Upgrade Plan: Sinful SAST → Argus-Level

## Mục tiêu
Nâng điểm từ ~80% → 100% ngang Argus, giải quyết 3 điểm yếu core.

---

## Upgrade 1: Backward Recursion khi Data Flow bị gãy ⭐ (ưu tiên cao nhất)

### Vấn đề
Scan Agent trả về `data_flow: []` → ghi `⚠ Data flow untraceable` rồi bỏ qua.
Argus có bước "Recursion": leo ngược từ sink lên upstream caller, lấy caller cao nhất làm "surrogate sink" và trace lại.

### Cơ chế mới

```
SCAN AGENT → data_flow: []
    └─→ BACKWARD RECURSION:
            1. Lấy sink function từ finding (e.g., db.execute)
            2. Gọi find_callers(sink_func) để tìm ai gọi nó
            3. Lấy caller cao nhất (hoặc caller nào nhận input từ ngoài)
            4. Dùng caller đó làm "surrogate sink" mới
            5. Chạy lại SCAN AGENT với surrogate sink
            6. Nối backward path + forward path → full data_flow
```

### Files cần sửa
- **`main.py`**: Thêm logic sau khi SCAN AGENT trả về `data_flow: []`:
  - Gọi `ts_module.get_func_callers(sink_func, target_dir)` để build backward tree
  - Retry SCAN AGENT với surrogate sink (tối đa 2 lần)
- **`src/scan/agents/prompts.py`**: Thêm instruction "nếu không trace được từ source → sink trực tiếp, hãy thử gọi `find_callers` để tìm surrogate sinks"
- **`src/tools/schemas.py`**: Thêm `surrogate_sink` field vào `SUBMIT_VERDICT_SCHEMA` để agent report lại khi nó không trace được

---

## Upgrade 2: Dynamic Sink Expansion từ RAG ⭐⭐

### Vấn đề
RAG thu thập CVE của dependency → tóm tắt → chỉ truyền làm context cho Audit.
Argus còn dùng CVE context để **LLM đề xuất thêm sink patterns mới** → inject vào tập scan.

### Cơ chế mới

```
RAG AGENT hoàn thành
    └─→ SINK EXPANSION AGENT (mới):
            Input: CVE context + danh sách hàm trong codebase
            Output: danh sách sink patterns bổ sung (func names / regex)
            └─→ Inject vào Semgrep scan làm extra custom rules
                    HOẶC chạy thêm search_pattern() queries cho mỗi sink mới
```

### Files cần sửa/tạo
- **`src/rag/agents/sink_expander.py`** [NEW]: Agent nhỏ gọi LLM để extract "dangerous function names" từ CVE description
- **`main.py`**: Sau RAG, collect extra sinks → chạy `search_pattern()` trên codebase cho từng sink mới → append vào `scan_findings` nếu tìm thấy
- Không cần tạo Semgrep rule mới, dùng `search_pattern` tool của sếp là đủ

---

## Upgrade 3: Supply Chain PoC Pre-Verification ⭐

### Vấn đề
CVE của dependency được fetch về → truyền thẳng vào Audit làm context.
Argus verify exploitability của từng CVE dependency trước bằng PoC Agent.

### Cơ chế mới

```
OSV/NVD fetch CVE list
    └─→ [per CVE] POC VERIFICATION AGENT (mới nhỏ):
            Input: CVE description + code của dependency usage trong project
            Output: {exploitable: true/false, confidence: 80, reasoning: "..."}
            └─→ Filter: chỉ giữ CVE có exploitable=true hoặc confidence < 50
```

### Files cần sửa/tạo
- **`src/rag/agents/poc_verifier.py`** [NEW]: Gọi LLM với ReAct nhỏ, verify xem CVE này có thể exploit được trong context project hay không
- **`main.py`**: Sau khi fetch NVD, chạy poc_verifier → filter cve_list → giảm noise cho Audit Agent
- **`src/tools/schemas.py`**: Thêm `POC_VERIFY_TOOL_SET` dùng `read_file` + `search_pattern` + `submit_verdict`

---

## Giải đáp thắc mắc: Sinful SAST vs Argus Workflow

Sếp đang thắc mắc là thêm 2-3 agents nữa thì có bị "thừa" so với Argus không? Câu trả lời là **KHÔNG**. Thực chất, Argus cũng có ngần ấy Agent, chỉ là họ gọi tên khác đi. Dưới đây là luồng mapping 1-1 giữa Argus và bản nâng cấp của sếp:

### 1. Luồng xử lý Supply Chain (Dependencies)
- **Argus**: Dùng **RAG** tìm CVE $\rightarrow$ Chạy **PoC Agent** để verify xem CVE đó có exploit được không $\rightarrow$ Sinh ra các **Extra Sinks** (sink mới).
- **Sinful SAST (Plan)**: RAG Agent (đã có) $\rightarrow$ **PoC Verifier Agent (Upgrade 3)** $\rightarrow$ **Sink Expansion Agent (Upgrade 2)**.
$\Rightarrow$ *Kết luận: 2 con agent sếp thêm vào ở Upgrade 2 & 3 chính là để cover trọn vẹn sức mạnh phần Supply Chain của Argus!*

### 2. Luồng xử lý Data Flow (Re³)
- **Argus**: **Retrieval** (dùng CodeQL tìm data flow) $\rightarrow$ **Recursion** (nếu gãy flow, lùi lại tìm caller làm surrogate sink) $\rightarrow$ **Review** (Agent chuyên review từng hop xem có bị chặn bởi if/else hay sanitizer không).
- **Sinful SAST (Plan)**: **Scan Agent** (tương đương CodeQL Retrieval) $\rightarrow$ **Backward Recursion (Upgrade 1)** $\rightarrow$ **Audit Agent** (tương đương Review Agent).
$\Rightarrow$ *Kết luận: Sếp không đẻ thêm Agent ở đây, sếp chỉ thêm "Logic Recursion" vào giữa con Scan và con Audit để flow không bị gãy.*

### 3. Luồng xử lý sau khi phát hiện lỗi (Post-Detection)
- **Argus**: Không đề cập sâu đến việc tự động viết patch (Fix) hay gen exploit payload cho source code chính.
- **Sinful SAST**: Sếp có **Hack Agent** và **Fix Agent**.
$\Rightarrow$ *Kết luận: Đây là điểm sếp ĂN ĐỨT Argus! Argus chỉ tập trung tìm lỗi, sếp làm luôn cả đoạn exploit và fix.*

### 4. Tóm tắt luồng thực tế toàn bộ hệ thống của Argus (End-to-End Workflow)
Để sếp dễ hình dung, đây là sơ đồ chạy từ đầu đến cuối của Argus được nhắc trong bài báo:
```text
[BƯỚC 1: SINK SCANNING - Tìm lỗ hổng thư viện]
 1. Dependencies Parsing: Phân tích các file cấu hình (ví dụ: pom.xml) để lấy danh sách thư viện.
 2. RAG Retrieval: Tìm kiếm thông tin lỗ hổng (CVE, GitHub issues) liên quan đến thư viện đó.
 3. PoC Agent Verification: Gọi LLM (theo dạng ReAct) để đánh giá xem lỗ hổng CVE đó có thực sự khai thác được không. Xác minh xong sẽ lưu các Sinks của thư viện lại.

[BƯỚC 2: DATA FLOW ANALYSIS (Re³) - Dò tìm luồng dữ liệu độc hại]
 4. Retrieval (Forward Scan): Đưa các Sinks tìm được ở Bước 1 vào CodeQL để quét data flow từ Source -> Sink. Nếu thấy luồng đầy đủ, chuyển sang Review.
 5. Recursion (Chữa luồng gãy): Nếu CodeQL bị gãy luồng (không tìm được Source), Argus dò ngược từ Sink lên trên để tạo "Surrogate Sinks" (các hàm mồi). Sau đó chạy CodeQL quét lại từ Surrogate Sinks này.
 6. Review Agent: LLM Agent kiểm tra tỉ mỉ từng bước (hop-by-hop) của luồng dữ liệu xem có bị vướng if/else, try/catch hay hàm filter/sanitizer nào chặn lại không. Nếu vượt qua hết -> Báo cáo VULNERABLE.
```

---

## Thứ tự thực hiện

```
[Tuần 1] Upgrade 1: Backward Recursion
  - Fix lỗi "Data flow untraceable" ngay lập tức
  - Tác động cao nhất, code ít nhất

[Tuần 2] Upgrade 2: Dynamic Sink Expansion
  - Tạo src/rag/agents/sink_expander.py
  - Sửa main.py inject extra sinks

[Tuần 3] Upgrade 3: PoC Pre-Verification
  - Tạo src/rag/agents/poc_verifier.py
  - Filter CVE list trước khi audit
```

---

## Giải ngố cực mạnh: Con HACK chạy ở đâu? Và Argus có chính xác những con nào?

Sếp đang bị nhầm lẫn giữa **con HACK của sếp** và **con PoC của Argus**. Hai con này làm nhiệm vụ HOÀN TOÀN KHÁC NHAU và chạy ở hai thời điểm KHÁC NHAU. Để em giải thích rạch ròi:

### 1. Con Hack Agent của sếp chạy ở đâu?
**Nó vẫn chạy SAU Audit Agent như hiện tại.**
- **Tại sao?** Vì con Hack của sếp dùng để viết mã khai thác (exploit payload) cho cái lỗ hổng nằm trong **SOURCE CODE của sếp** (ví dụ file `app.py`). Nếu Audit chưa xác nhận đó là lỗ hổng thật (VULNERABLE), thì Hack chạy làm gì cho tốn tiền? 
$\rightarrow$ Thứ tự của sếp: `Scan (tìm đường) -> Audit (chốt lỗi) -> Hack (viết mã hack) -> Fix (sửa lỗi)`. **Không có gì thay đổi hết!**

### 2. Vậy con PoC Agent của Argus là gì? Tại sao nó chạy TRƯỚC?
Con PoC của Argus **KHÔNG HỀ** sinh mã hack cho source code của sếp. Nó dùng để test các lỗ hổng (CVE) của **THƯ VIỆN BÊN THỨ 3** (Dependencies).
Ví dụ: Code sếp dùng thư viện `log4j`.
- Con RAG lên mạng tải về CVE của `log4j`.
- Con PoC Agent của Argus sẽ nhảy vào: *"Ê để tao đọc CVE này xem trong project này có bị dính không, tao thử viết code hack cái thư viện này xem"*. 
- Nếu nó hack được $\rightarrow$ Trích xuất ra các **Sink** nguy hiểm của thư viện đó $\rightarrow$ Quăng cho CodeQL quét (tương đương con Scan của sếp).
$\rightarrow$ Do đó, con PoC Agent của Argus (chính là Upgrade 3 trong plan) bắt buộc phải chạy **TRƯỚC** khi vào vòng lặp Scan.

### 3. Tóm tắt 5 con Agent chính tả của Argus (Viết rõ không lửng lơ)
Trong bài báo mục 1 (Introduction), Argus có chính xác 5 con Agents:

1. **Dependency Scanning Agent**: Đọc file `pom.xml`, `package.json` xem sếp xài thư viện gì.
2. **Information Collecting Agent (RAG)**: Lên NVD, OSV, Github cào tất cả CVE của mấy cái thư viện đó về.
3. **PoC Generating Agent**: (Chính là con PoC Verifier em đề xuất ở Upgrade 3). Thử khai thác mấy cái CVE kia xem có chạy được không. Nếu chạy được thì trích xuất SINK.
4. **Data Flow Scanning Agent**: Dùng CodeQL quét từ Source đến Sink. (Có thêm kỹ thuật lùi Recursion - Upgrade 1). Tương đương con **Scan Agent** của sếp.
5. **Data Flow Reviewing Agent**: Kiểm tra từng bước luồng dữ liệu xem có bị if/else chặn không. Tương đương con **Audit Agent** của sếp.

**Sếp thấy chưa?** 
- Argus làm chó gì có con nào viết mã khai thác thẳng vào code của sếp (Hack Agent)!
- Argus cũng làm chó gì có con nào tự động vá lỗi cho code của sếp (Fix Agent)!
$\Rightarrow$ Nên em mới bảo sếp đẻ thêm 2 con Hack và Fix ở cuối là sếp **ĂN ĐỨT** Argus. Sếp chỉ bị khuyết đúng đoạn xử lý Thư viện (PoC CVE) và đoạn Chữa luồng gãy (Recursion) của nó thôi!

---

## Open Questions

> **Q1:** Upgrade 1 (Backward Recursion) — Tại sao retry scan agent tối đa 2 lần mà không phải "càng nhiều càng tốt"?
> **Giải thích:** Trong phân tích tĩnh (Static Analysis), nếu sếp lùi lại (backward) càng sâu, số lượng nhánh (paths) sẽ bùng nổ cấp số nhân (Path Explosion). Nếu retry vô hạn, LLM sẽ bị kẹt trong vòng lặp đọc file, tốn hàng chục nghìn token và rất nhiều thời gian mà chưa chắc tìm ra lỗi (vì flow gãy có thể đơn giản là do biến đó an toàn). Thực tế, 1-2 lần lùi (tương đương 1-2 function calls) là đủ để vượt qua các hàm wrapper/helper. Nếu quá 2 lần mà không thấy source, tỷ lệ cao đó là False Positive.

> **Q2:** Upgrade 2 (Sink Expansion) — Sếp muốn inject extra sinks bằng cách nào?
> - Option A: Chạy `search_pattern()` cho mỗi sink mới tìm được từ CVE (dễ làm, không cần rule file)
> - Option B: Tự động generate Semgrep YAML rule mới từ CVE context (mạnh hơn nhưng phức tạp hơn)

> **Q3:** Upgrade 3 (PoC Verifier) — Sếp có muốn làm không? Hay chỉ làm 1 và 2 trước?
