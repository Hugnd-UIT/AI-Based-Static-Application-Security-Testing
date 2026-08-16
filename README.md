# AI-Based SAST — Công cụ kiểm tra bảo mật ứng dụng tự động

Dự án cá nhân xây dựng một **công cụ SAST sử dụng AI**, phát hiện lỗ hổng bảo mật trên **tất cả ngôn ngữ web phổ biến** như PHP, JavaScript, TypeScript, Python, Java, Ruby, Go, C# thông qua kiến trúc **multi-agent** kết hợp phân tích tĩnh và suy luận bằng LLM.

---

## Triết lý thiết kế

### Vấn đề với SAST truyền thống

Các công cụ SAST như CodeQL, Snyk, SonarQube đều dựa trên **Phân tích luồng dữ liệu - Taint Analysis**. Cách tiếp cận này có 3 điểm yếu cốt lõi:

1. **False positive** — Quy tắc cứng không hiểu ngữ cảnh dẫn đến tỷ lệ dương tính giả cao.
2. **Bỏ sót lỗ hổng mới** — Quy tắc phải viết tay dẫn đến khó phát hiện được các lỗ hổng mới hoặc đặc thù của ứng dụng.
3. **Không hiểu supply chain** — Chỉ quét code nguồn, bỏ qua các dependency có CVE đã được biết đến.

### Vấn đề với LLM thuần túy

Ngược lại, chỉ dùng LLM như prompt cả file và hỏi "có lỗi không?" cũng thất bại vì:

1. **Hallucination** — LLM bịa tên biến, bịa số dòng, báo lỗ hổng không tồn tại.
2. **Context window bị tràn** — File lớn vượt giới hạn token, LLM phải đoán mò.
3. **Chi phí không kiểm soát** — Gọi LLM cho từng hàm trong repo lớn tốn kém.
4. **Không có ground truth** — LLM không biết gì về luồng dữ liệu thực tế của codebase.

### Giải pháp: LLM là trung tâm, công cụ tĩnh hỗ trợ

Cụ thể:
- **Semgrep** tìm các ứng viên cần xem xét
- **OSV.dev + NVD** cung cấp ngữ cảnh từ cơ sở dữ liệu lỗ hổng thực tế
- **Gemini** xác minh từng finding bằng suy luận ngữ nghĩa
- Không tầng nào được tin 100% — mỗi tầng kiểm tra lại kết quả của tầng trước

---

## So sánh với bài báo Argus & Đánh giá đánh đổi

Đây là phần quan trọng nhất để hiểu tại sao dự án chọn các công nghệ như vậy.

### So sánh trực tiếp

| Tiêu chí | Argus (bài báo) | Dự án này | Lý do đánh đổi |
|---|---|---|---|
| **Công cụ phân tích tĩnh** | CodeQL | **Semgrep** | CodeQL mạnh hơn (trace data flow qua nhiều hàm) nhưng cài đặt phức tạp và hỗ trợ PHP kém. Semgrep cài qua `pip`, có 4000+ rules bảo mật, hỗ trợ PHP/JS/Python tốt. |
| **LLM** | Claude 3.5 / 4.5 Sonnet | **Gemini Flash 2.0** | Claude Sonnet lý luận sâu hơn. Gemini Flash miễn phí (1500 req/ngày) so với $3/1M token của Claude. Đánh đổi: chất lượng suy luận thấp hơn một chút, chi phí = $0. |
| **Database lỗ hổng & Ngữ cảnh** | NVD + OSV + GHSA + Bot cào GitHub | **OSV.dev + NVD + Firecrawl** | Snyk cần API key. OSV.dev và NVD phủ 95%+ hệ sinh thái. Đặc biệt, dùng **Firecrawl API** cào sạch nội dung GitHub Issues/Exploit-DB từ link tham khảo của CVE để LLM có thêm dữ liệu thảo luận thực tế (giống hệt cách Argus làm). |
| **Ngôn ngữ mục tiêu** | Java (chủ yếu) | **PHP, JS, TS, Python, Java, Ruby, Go, C#** | Argus dùng CodeQL nên mạnh nhất ở Java. Dự án này dùng Semgrep nên hỗ trợ đa ngôn ngữ hơn, nhưng có thể yếu hơn ở cross-function dataflow. |
| **Phân tích luồng dữ liệu** | Re³ (Retrieval + Recursion + Review) đi ngược và xuôi bằng CodeQL | **Lightweight Re³ (Tree-sitter + Python)** | Argus dùng CodeQL nặng nề. Dự án này tự build thuật toán Re³ bằng Tree-sitter để vẽ Call Graph đi ngược từ sink lên source. Xử lý tốt 90% project thực tế mà không cần setup môi trường build. |
| **Chi phí mỗi lần quét** | ~$2.54 / repo | **~$0 (miễn phí)** | Đánh đổi trực tiếp. Argus mạnh hơn nhưng tốn tiền; dự án này miễn phí nhưng yếu hơn ở edge cases. |
| **Sinh PoC** | Có (ReAct agent) | **Có (Gemini + ReAct prompt)** | Tương đương về ý tưởng, khác về chất lượng tùy năng lực LLM. |
| **Mô hình thực thi** | 5 agent song song | **5 tầng tuần tự** | Song song cần framework điều phối phức tạp. Tuần tự đơn giản hơn để code và debug, kết quả tương đương. |
| **Phần cứng** | CPU server 512 GB RAM | **Máy cá nhân bình thường** | Không cần GPU, không cần server mạnh. |

### Điểm mạnh hơn Argus

1. **Hỗ trợ đa ngôn ngữ web tốt hơn** — Argus tập trung Java với CodeQL. Dự án này dùng Semgrep nên phát hiện tự nhiên trên PHP, JS, TS, Python, Ruby, Go, C#.
2. **Hoàn toàn miễn phí** — Argus tốn $2.54/repo. Dự án này $0 với Gemini free tier.
3. **Context window lớn hơn** — Gemini Flash có 1M token context so với 200K của Claude Sonnet — đọc được file rất lớn.
4. **Dễ mở rộng** — Thêm ngôn ngữ mới chỉ cần thêm Semgrep rules, không cần retrain model.

### Điểm yếu hơn Argus (cần biết trước)

1. **Lightweight Re³ không mạnh bằng CodeQL** — CodeQL trích xuất đồ thị dữ liệu chính xác 100% vì nó biên dịch code. Re³ của dự án này dùng Tree-sitter parse text tĩnh, nên có thể đứt luồng ở những pha gọi hàm quá phức tạp (Dynamic dispatching, reflection).
2. **LLM yếu hơn** — Gemini Flash < Claude Sonnet ở suy luận phức tạp. Với logic lồng nhau nhiều lớp, Gemini có thể không verify chính xác bằng Claude.
3. **Semgrep < CodeQL về dataflow** — CodeQL xây dựng AST đầy đủ và trích xuất đồ thị luồng dữ liệu hoàn chỉnh. Semgrep chỉ khớp pattern. Với codebase có nhiều lớp trừu tượng, Semgrep sẽ bỏ sót nhiều hơn.

---

## Kiến trúc hệ thống

### Pipeline 5 tầng

```
┌─────────────────────────────────────────────────────────────┐
│  ĐẦU VÀO: Git URL / Thư mục local / File ZIP               │
└───────────────────────────┬─────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  TẦNG 1: Recon & Quét dependency                            │
│  • Nhận dạng ngôn ngữ từ phần mở rộng file                 │
│  • Đọc file quản lý dependency:                             │
│    PHP    → composer.json / composer.lock                   │
│    JS/TS  → package.json / package-lock.json                │
│    Python → requirements.txt / pyproject.toml              │
│    Java   → pom.xml / build.gradle                          │
│    Ruby   → Gemfile / Gemfile.lock                          │
│    Go     → go.mod / go.sum                                 │
│    C#     → *.csproj / packages.config                      │
│  • Kết quả: { ngôn ngữ, dependency, phiên bản }            │
└───────────────────────────┬─────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  TẦNG 2: Quét tĩnh (Semgrep)                                │
│  • Chạy bộ quy tắc OWASP Top 10 cho từng ngôn ngữ         │
│  • Phát hiện:                                               │
│    CWE-89  SQL Injection                                    │
│    CWE-79  Cross-Site Scripting (XSS)                       │
│    CWE-78  OS Command Injection                             │
│    CWE-22  Path Traversal                                   │
│    CWE-918 SSRF                                             │
│    CWE-502 Insecure Deserialization                         │
│    CWE-611 XXE Injection                                    │
│    CWE-94  Code Injection                                   │
│    + hơn 50 loại CWE khác                                  │
│  • Kết quả: { file, dòng, rule, mức độ, đoạn code }        │
└───────────────────────────┬─────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  TẦNG 3: RAG — Tra cứu lỗ hổng & Ngữ cảnh từ cộng đồng     │
│  • Query OSV.dev API (miễn phí: npm/PyPI/Maven/Go/NuGet...) │
│  • Query NVD NIST API (miễn phí, toàn bộ CVE database)     │
│  • Lấy danh sách link tham khảo (GitHub Issues, Exploit-DB) │
│  • Dùng Firecrawl API cào nội dung link thành Markdown sạch │
│  • Làm giàu finding của Semgrep bằng ngữ cảnh từ cộng đồng │
│  • Kết quả: { finding + cve_liên_quan + github_discussions }│
└───────────────────────────┬─────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  TẦNG 4: Trích xuất luồng dữ liệu (Lightweight Re³)        │
│  • Xây dựng Call Graph toàn project bằng Tree-sitter       │
│  • Retrieval: Tìm đường đi xuôi từ Source → Sink           │
│  • Recursion: Nếu đứt luồng, đi ngược từ Sink lên tìm      │
│    Surrogate Sink (Hàm cha) gọi nó                         │
│  • Kết quả: Chuỗi các đoạn code nối liền Source tới Sink   │
└───────────────────────────┬─────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  TẦNG 5: LLM Reviewer ngữ nghĩa (Gemini Flash — Miễn phí)  │
│  • Đầu vào: Chuỗi code từ Re³ + cảnh báo Semgrep + CVE     │
│  • Suy luận theo kiểu ReAct:                               │
│    Bước 1. Xác định — Input người dùng đến từ đâu?         │
│    Bước 2. Trace    — Input đi qua những bước nào?         │
│    Bước 3. Kiểm tra — Có sanitize/validate/tham số hóa không? │
│    Bước 4. Kết luận — CÓ LỖ HỔNG / AN TOÀN / KHÔNG RÕ    │
│  • Chỉ gọi với finding có confidence không rõ ràng         │
│    (tiết kiệm quota miễn phí)                               │
│  • Sinh ra: giải thích + gợi ý sửa lỗi                     │
└───────────────────────────┬─────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  TẦNG 6: Tạo báo cáo                                        │
│  • Báo cáo HTML có highlight cú pháp code                  │
│  • Định dạng SARIF 2.1.0 (tương thích GitHub Code Scanning) │
│  • Mức độ: Critical / High / Medium / Low / Info            │
│  • Phân nhóm theo: file, loại CWE, mức độ nghiêm trọng    │
│  • Gồm: đoạn code, số dòng, gợi ý sửa                     │
│  • Phần riêng cho lỗ hổng dependency (CVE)                 │
└─────────────────────────────────────────────────────────────┘
```

---

## Cấu trúc dự án (Sau khi refactor)

```
ai-based-sast/
│
├── README.md
├── requirements.txt
├── .env.example                 ← Template cho API key
├── .gitignore
│
├── sast/                        ← Package chính (VIẾT MỚI)
│   ├── __init__.py
│   ├── layer1_recon/
│   │   ├── detector.py          ← Nhận dạng ngôn ngữ
│   │   └── dep_parser.py        ← Đọc file dependency
│   ├── layer2_scanner/
│   │   ├── semgrep_runner.py    ← Wrapper cho Semgrep
│   │   └── rules/               ← Custom Semgrep rules nếu cần
│   ├── layer3_rag/
│   │   ├── osv_client.py        ← Client OSV.dev API
│   │   ├── nvd_client.py        ← Client NVD NIST API
│   │   └── firecrawl_client.py  ← Trích xuất GitHub Issues thành Markdown
│   ├── layer4_reviewer/
│   │   ├── gemini_reviewer.py   ← Client Gemini Flash API
│   │   ├── prompts.py           ← Prompt templates kiểu ReAct
│   │   └── chunker.py           ← Tree-sitter (GIỮ LẠI từ predict.py)
│   └── layer5_report/
│       ├── html_report.py
│       ├── sarif_report.py
│       └── templates/
│           └── report.html
│
└── main.py                      ← CLI entry point (VIẾT MỚI)
```

---

## Quyết định Refactor

### GIỮ LẠI và tái sử dụng

| Code hiện tại | Lý do giữ | Dùng ở đâu trong dự án mới |
|---|---|---|
| `predict.py` → `calc_chunks_ts()` | Hàm tách function bằng Tree-sitter, đã test kỹ, hoạt động tốt | `layer4_reviewer/chunker.py` |
| `predict.py` → `extract_imports()` | Logic thêm import context vào đầu mỗi chunk | `layer4_reviewer/chunker.py` |
| `predict.py` → `LANG_EXT`, `TS_LANG`, `TS_NODES` | Bảng ánh xạ ngôn ngữ đầy đủ cho 10+ ngôn ngữ | `layer1_recon/detector.py` |
| `predict.py` → `SAFE_PATTERNS` | Bộ lọc heuristic, vẫn hữu ích làm gợi ý cho LLM prompt | `layer4_reviewer/prompts.py` |
| `predict.py` → `FUNC_RE` | Regex fallback khi Tree-sitter không hỗ trợ ngôn ngữ đó | `layer4_reviewer/chunker.py` |

### ĐÃ XÓA (Không dùng trong pipeline mới)

| File | Lý do xóa hoàn toàn |
|---|---|
| `src/clean.py` | Pipeline chuẩn bị data cho GraphCodeBERT. |
| `src/vector.py` | Token hóa data cho GraphCodeBERT. |
| `src/train.py` | Vòng lặp training GraphCodeBERT. |
| `src/eval.py` | Metrics đánh giá GraphCodeBERT. |
| `src/predict.py` | Logic inference GraphCodeBERT. Phần Tree-sitter đã được tách ra `layer4/`. |

**Tại sao lại xóa:** Toàn bộ code cũ thuộc về hướng nghiên cứu GraphCodeBERT đã bị loại bỏ hoàn toàn để tập trung 100% vào kiến trúc Multi-Agent (Semgrep + LLM). Điều này giúp dự án cực kỳ nhẹ, sạch sẽ và không chứa code thừa.

### VIẾT MỚI hoàn toàn

| File mới | Chức năng |
|---|---|
| `sast/layer1_recon/detector.py` | Nhận dạng ngôn ngữ từ extension, tìm file dependency |
| `sast/layer1_recon/dep_parser.py` | Parse composer.json, package.json, pom.xml, requirements.txt... |
| `sast/layer2_scanner/semgrep_runner.py` | Gọi Semgrep qua subprocess, parse kết quả JSON |
| `sast/layer3_rag/osv_client.py` | Client OSV.dev REST API với local cache |
| `sast/layer3_rag/nvd_client.py` | Client NVD NIST REST API |
| `sast/layer3_rag/firecrawl_client.py`| Tích hợp Firecrawl cào nội dung web thành Markdown |
| `sast/layer4_reviewer/gemini_reviewer.py` | Client Gemini Flash API + retry + cache kết quả |
| `sast/layer4_reviewer/prompts.py` | Prompt templates kiểu ReAct cho từng CWE và ngôn ngữ |
| `sast/layer5_report/html_report.py` | Tạo báo cáo HTML với Jinja2 |
| `sast/layer5_report/sarif_report.py` | Xuất định dạng SARIF 2.1.0 |
| `main.py` | CLI: `python main.py --target ./myapp` |

---

## Công nghệ sử dụng

| Công cụ | Mục đích | Miễn phí? | Lý do chọn |
|---|---|---|---|
| **Semgrep** | Phân tích tĩnh | ✅ Giấy phép MIT | 30+ ngôn ngữ, 4000+ quy tắc bảo mật OWASP, cài bằng `pip` là chạy ngay |
| **Gemini Flash 2.0** | LLM reviewer ngữ nghĩa | ✅ 1500 req/ngày | Context 1M token, suy luận code tốt, đủ quota để scan DVWA |
| **OSV.dev API** | Tra cứu CVE của dependency | ✅ Không cần key | Phủ npm/PyPI/Maven/Packagist/Go/NuGet/RubyGems, do Google quản lý |
| **NVD NIST API** | Toàn bộ CVE database | ✅ Miễn phí | Database CVE chính thức của chính phủ Mỹ, có CVSS score |
| **Firecrawl API** | Cào dữ liệu Web/GitHub | ✅ Free tier (500 cr) | Chuyển HTML rối rắm thành Markdown sạch cho LLM đọc hiểu dễ dàng |
| **Tree-sitter** | Tách hàm chính xác | ✅ Giấy phép MIT | Dựa trên AST, chính xác hơn regex, đã có code sẵn từ `predict.py` |

---

## Kế hoạch triển khai

### Giai đoạn 1 — Nền tảng (Tuần 1)
- [ ] Tạo cấu trúc dự án mới, tạo thư mục `legacy/`, chuyển file cũ vào
- [ ] `layer1_recon/detector.py` — nhận dạng ngôn ngữ
- [ ] `layer1_recon/dep_parser.py` — đọc tất cả loại file dependency
- [ ] `layer2_scanner/semgrep_runner.py` — wrapper Semgrep với parse JSON
- [ ] Test toàn bộ trên DVWA (PHP)

### Giai đoạn 2 — Ngữ cảnh RAG (Tuần 2)
- [ ] `layer3_rag/osv_client.py` — query batch OSV.dev có cache local
- [ ] `layer3_rag/nvd_client.py` — query NVD có xử lý rate limit
- [ ] `layer3_rag/firecrawl_client.py` — cào Markdown từ link tham khảo
- [ ] Làm giàu finding của Semgrep bằng thông tin CVE và GitHub Discussions

### Giai đoạn 3 — LLM Reviewer (Tuần 3)
- [ ] `layer4_reviewer/chunker.py` — migrate code Tree-sitter từ `predict.py`
- [ ] `layer4_reviewer/gemini_reviewer.py` — client Gemini API + retry + cache
- [ ] `layer4_reviewer/prompts.py` — prompt ReAct cho từng CWE và ngôn ngữ
- [ ] Test: kiểm tra false positive có giảm trên Parsedown.php không

### Giai đoạn 4 — Thuật toán Lightweight Re³ (Tuần 4)
- [ ] Xây dựng Call Graph toàn dự án bằng Tree-sitter
- [ ] Thuật toán đệ quy đi ngược (Recursion) tìm hàm cha
- [ ] Nối các đoạn code dọc theo luồng dữ liệu
- [ ] Đưa toàn bộ context path cho Gemini review

### Giai đoạn 5 — Báo cáo & Hoàn thiện (Tuần 5)
- [ ] `layer5_report/html_report.py` — báo cáo HTML
- [ ] `layer5_report/sarif_report.py` — xuất SARIF 2.1.0
- [ ] `main.py` — CLI với các flag `--target`, `--output`, `--no-llm`
- [ ] Test toàn bộ trên DVWA và các framework thực tế (Laravel, Express)

### Giai đoạn 6 — Benchmark (Tuần 6)
- [ ] So sánh Semgrep đơn độc vs Semgrep + Gemini
- [ ] Đo tỷ lệ false positive trên code sạch (Parsedown.php)
- [ ] Đo tỷ lệ true positive trên code có lỗi cố ý (DVWA)
- [ ] Ghi lại và công bố kết quả

---

## Cách chạy nhanh

```bash
# 1. Cài dependencies
pip install -r requirements.txt

# 2. Cài Semgrep
pip install semgrep

# 3. Cấu hình API key (chỉ cần Gemini — miễn phí)
# Lấy key miễn phí tại https://aistudio.google.com
# Tạo file .env với nội dung: GEMINI_API_KEY=your_key_here

# 4. Quét một dự án
python main.py --target /đường/dẫn/đến/webapp

# 5. Xem báo cáo
# Mở file report.html trong trình duyệt
```

---

## Hiệu năng dự kiến

Dựa trên benchmark của Argus và đặc điểm đã biết của Semgrep:

| Chỉ số | Chỉ dùng Semgrep | Semgrep + Gemini (dự kiến) |
|---|---|---|
| Tỷ lệ phát hiện đúng (TPR) | ~60–70% | ~75–85% |
| Tỷ lệ báo nhầm (FPR) | ~30–40% | **~10–20%** |
| Phát hiện lỗ hổng mới lạ | Không | Có (qua suy luận LLM) |
| Phát hiện CVE trong dependency | Không | Có (qua OSV / NVD) |
| Thời gian mỗi lần quét | ~30 giây | ~5–15 phút |
| Chi phí mỗi lần quét | Miễn phí | **Miễn phí** (Gemini free tier) |

---

## Tài liệu tham khảo

### Bài báo gốc (Nguồn cảm hứng chính)

1. **Argus** — He Jun et al. (2025)  
   *"Argus: Reorchestrating Static Analysis via a Multi-Agent Ensemble for Full-Chain Security Vulnerability Detection"*  
   https://arxiv.org/abs/2604.06633  
   Nguồn cảm hứng chính. Đề xuất paradigm LLM-centered SAST, dùng CodeQL + Claude + RAG + ReAct.

2. **IRIS** — Li et al. (2025)  
   *"LLM-Assisted Static Analysis for Detecting Security Vulnerabilities"*  
   https://arxiv.org/abs/2405.17238  
   Baseline được Argus so sánh. LLM-assisted (không phải LLM-centered).

3. **RepoAudit** — Guo et al. (2025)  
   *"RepoAudit: An Autonomous LLM-Agent for Repository-Level Code Auditing"*  
   https://openreview.net/forum?id=TXcifVbFpG  
   Ý tưởng phân tích ở cấp độ toàn repository.

### Công cụ phân tích tĩnh

4. **Semgrep** — Returntocorp (2020)  
   https://semgrep.dev/docs  
   Công cụ quét tĩnh cốt lõi của dự án này.

5. **CodeQL** — Avgustinov et al. (2016)  
   *"QL: Object-Oriented Queries on Relational Data"*  
   ECOOP 2016.  
   Công cụ Argus dùng. Dự án này dùng Semgrep thay vì CodeQL vì hỗ trợ PHP tốt hơn và dễ cài hơn.

6. **Semgrep Rules Registry** (OWASP/CWE rules)  
   https://semgrep.dev/r  
   Nguồn 4000+ quy tắc bảo mật có sẵn.

### LLM và Suy luận

7. **ReAct** — Yao et al. (2023)  
   *"ReAct: Synergizing Reasoning and Acting in Language Models"*  
   ICLR 2023. https://arxiv.org/abs/2210.03629  
   Framework suy luận áp dụng cho LLM reviewer trong dự án này.

8. **RAG** — Lewis et al. (2020)  
   *"Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks"*  
   NeurIPS 2020.  
   Cơ sở lý thuyết cho tầng RAG.

9. **Chain-of-Thought** — Wei et al. (2022)  
   *"Chain-of-Thought Prompting Elicits Reasoning in Large Language Models"*  
   NeurIPS 2022.  
   Chiến lược viết prompt cho Gemini reviewer.

### Cơ sở dữ liệu lỗ hổng

10. **OSV.dev** — Google Open Source Security Team  
    https://osv.dev  
    API miễn phí, phủ npm/PyPI/Maven/Packagist/Go/NuGet/RubyGems.

11. **NVD NIST** — National Vulnerability Database  
    https://nvd.nist.gov/developers/vulnerabilities  
    Database CVE chính thức, có CVSS score, API miễn phí.

12. **GHSA** — GitHub Security Advisories  
    https://github.com/advisories  
    Báo cáo lỗ hổng từ cộng đồng.

### Dataset benchmark

13. **CVEfixes** — Bhandari et al. (2021)  
    *"CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software"*  
    https://zenodo.org/record/7029359  
    Dataset dùng để train GraphCodeBERT trong thư mục `legacy/`.

14. **DVWA** — Damn Vulnerable Web Application  
    https://github.com/digininja/DVWA  
    Target benchmark chính: code PHP có lỗi cố ý để đo true positive rate.

### Model liên quan (pipeline GraphCodeBERT trong `legacy/`)

15. **GraphCodeBERT** — Guo et al. (2021)  
    *"GraphCodeBERT: Pre-training Code Representations with Data Flow"*  
    ICLR 2021. https://arxiv.org/abs/2009.08366  
    Model dùng trong pipeline `legacy/`.

16. **CodeSearchNet** — Husain et al. (2019)  
    *"CodeSearchNet Challenge: Evaluating the State of Semantic Code Search"*  
    https://arxiv.org/abs/1909.09436  
    Dataset bổ sung negative samples cho GraphCodeBERT.

### Framework bảo mật

17. **OWASP Top 10** (2021)  
    https://owasp.org/www-project-top-ten  
    Phân loại lỗ hổng bảo mật web chính.

18. **CWE — Common Weakness Enumeration** — MITRE  
    https://cwe.mitre.org  
    Hệ thống phân loại loại lỗ hổng dùng xuyên suốt dự án.

---

## Hạn chế và Hướng phát triển

### Hạn chế hiện tại

- **Không có phân tích luồng ngược (Re³)** — Hạn chế lớn nhất. Không trace được data flow qua nhiều hàm như Argus làm.
- **Giới hạn quota Gemini free tier** — 1500 req/ngày. Quét repo lớn (>500 hàm) cần nhiều ngày hoặc nâng cấp lên gói trả phí.
- **Chỉ có phân tích tĩnh** — Không phát hiện được lỗi logic ở runtime hay second-order injection.
- **Vẫn có false negative** — Pattern lỗ hổng mới chưa có rule Semgrep sẽ bị bỏ sót.

### Hướng phát triển

- Cải tiến Lightweight Re³: Xử lý tốt hơn các pattern OOP phức tạp, dependency injection và dynamic dispatch.
- Tích hợp thêm các bộ quét tĩnh phụ (như Bandits cho Python, PHPStan cho PHP) làm nguồn cung cấp thông tin thêm cho Semgrep.
- Sinh PoC: dùng Gemini để tạo code khai thác chứng minh lỗ hổng là thật.
- Tích hợp CI/CD: plugin cho GitHub Actions, GitLab CI.
- Web dashboard: giao diện hiển thị lịch sử scan và xu hướng lỗ hổng.

---

*Đây là dự án nghiên cứu cá nhân, không phải sản phẩm thương mại. Chỉ dùng để kiểm tra bảo mật trên code và hệ thống mà bạn có quyền kiểm tra.*
