# Kế hoạch Tái cấu trúc Kiến trúc: Tích hợp Luồng Multi-Agent chuẩn Argus cho Sinful AI

Hiện tại, Sinful AI đang sử dụng **Kiến trúc Nguyên khối (Monolithic LLM Approach)**:
1. Semgrep tìm ra một đoạn code nghi ngờ có lỗi.
2. Các module RAG (OSV, NVD) tải thông tin CVE về.
3. Chỉ duy nhất một `Review Agent` (trong file `src/review/agents.py`) nhận toàn bộ đống dữ liệu khổng lồ này và phải tự suy luận đưa ra phán quyết cuối cùng.

Để đạt được kiến trúc "chuẩn bài" từ bài báo Argus, chúng ta cần chuyển đổi sang **Luồng Đa tác vụ Cộng tác (Collaborative Multi-Agent Pipeline)**, nơi các AI chuyên biệt sẽ hoàn thành từng nhiệm vụ nhỏ và chuyền dữ liệu cho nhau.

## Câu hỏi Mở cần sếp chốt
> [!IMPORTANT]
> Bài báo gốc phụ thuộc rất nhiều vào công cụ **CodeQL** để phân tích Luồng dữ liệu (Data Flow). Hiện tại Sinful AI đang xài **Semgrep** và AST (Tree-sitter). Sếp muốn tiếp tục dùng Semgrep làm công cụ quét chính (và dùng AI để mô phỏng lại việc dò luồng dữ liệu), hay sếp muốn tích hợp hẳn một công cụ nặng đô như CodeQL vào hệ thống?

> [!WARNING]
> Việc chia nhỏ bước Review thành nhiều lần gọi LLM (Agent 1 -> Agent 2 -> Agent 3) sẽ làm **tăng chi phí API và kéo dài thời gian quét**. Sếp có chấp nhận đánh đổi tốc độ/chi phí để đổi lấy độ chính xác cao hơn và giảm hẳn tỷ lệ nhận diện sai (False Positives) không?

## Các Thay đổi Đề xuất

Chúng ta sẽ đập đi xây lại luồng xử lý trong `src/review/agents.py` và `main.py` để điều phối một dây chuyền gồm 4 Agents chuyên biệt.

### 1. Agent RAG & Phụ thuộc (Người thu thập tình báo)
Hiện tại, `osv` và `nvd` đang nhồi nhét toàn bộ file JSON thô vào prompt cuối cùng.
- **Thay đổi**: Tạo một agent chuyên dụng đọc hiểu dữ liệu CVE/NVD/Firecrawl thô và chỉ xuất ra một bản tóm tắt ngắn gọn về *các hướng tấn công (attack vectors)* thực sự liên quan đến các thư viện mà dự án đang xài.

### 2. Agent Dò Luồng Dữ liệu (Người rà quét)
Hiện tại, Semgrep chỉ chỉ ra một dòng/hàm bị lỗi, và AI phải tự đoán ngữ cảnh.
- **Thay đổi**: Agent này sẽ nhận kết quả từ Semgrep và cây AST. Chỉ thị (prompt) duy nhất của nó là: "Hãy đóng vai một chuyên gia Dò luồng dữ liệu (Data Flow Tracer). Hãy xác định chính xác **Source** (nơi dữ liệu bẩn đi vào) và **Sink** (nơi thực thi nguy hiểm) trong ngữ cảnh này. Dò từng biến một xem dữ liệu chảy đi đâu."

### 3. Agent Kiểm duyệt Sanitization (Người kiểm duyệt)
Hiện tại, prompt nguyên khối phải tự mò mẫm tìm False Positives (lỗi báo nhầm).
- **Thay đổi**: Agent này nhận kết quả Luồng Dữ liệu (Data Flow Trace) từ Agent 2. Nhiệm vụ duy nhất của nó là phân tích "Hop-by-hop" (từng bước một): nó nhìn vào từng nút thắt trong luồng dữ liệu xem dữ liệu có đi qua hàm `validate()`, `sanitize()`, hoặc ép kiểu (type-casting) nào không. Nếu có, nó sẽ huỷ cảnh báo (giảm triệt để False Positives).

### 4. Agent Viết PoC (Hacker)
- **Thay đổi**: Nếu Agent 3 xác nhận lỗ hổng này có thể bị khai thác và chưa được vá (unsanitized), Agent 4 sẽ được gọi lên để viết một đoạn mã khai thác **Proof of Concept (PoC)** thực tế (ví dụ: một HTTP request hoặc payload JSON) để chứng minh lỗ hổng là có thật.

---

### Các bước Triển khai

#### [MODIFY] `src/review/agents.py`
Viết lại hàm `review_finding` (hoặc `fetch`) từ một prompt duy nhất thành một chuỗi (chain) gọi các agents:
```python
def review_finding_multi_agent(finding, ast_context, cve_context, model):
    # Agent 1: Tóm tắt thông tin tình báo (RAG)
    rag_summary = call_rag_agent(cve_context, model)
    
    # Agent 2: Dò luồng dữ liệu
    data_flow_trace = call_tracer_agent(finding, ast_context, model)
    
    # Agent 3: Rà soát chức năng làm sạch (Sanitization)
    audit_result = call_auditor_agent(data_flow_trace, ast_context, model)
    
    # Agent 4: Viết mã khai thác (PoC) nếu thực sự có lỗi
    if "VULNERABLE" in audit_result:
        poc = call_poc_agent(audit_result, rag_summary, model)
        return format_final_report(audit_result, poc)
    
    return audit_result
```

#### [MODIFY] `main.py`
Cập nhật file điều phối `run_sast` để in ra terminal tiến trình hoạt động của từng agent (như RAG đang chạy, Tracer đang dò...), mang lại cảm giác Multi-Agent thời gian thực rất "ngầu" cho người dùng.

## Kế hoạch Nghiệm thu
1. Chạy quét thử trên một mã nguồn cố tình chứa lỗi (ví dụ: WebGoat hoặc một dự án test).
2. Kiểm tra xem giao diện CLI có in ra đầy đủ các bước (Tracing -> Auditing -> PoC Generation) hay không.
3. Xác nhận rằng tỷ lệ nhận diện nhầm (False Positive) giảm hẳn do Auditor agent hoạt động hiệu quả.
