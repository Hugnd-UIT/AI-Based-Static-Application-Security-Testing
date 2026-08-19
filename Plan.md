# SINFUL — Plan: Nâng cấp 4 Agents → True ReAct Agents với Tool Use

## Mục tiêu

Biến toàn bộ 4 AI Agents (Scan, Audit, Hack, Fix) từ mô hình **LLM-as-Judge** (gọi API 1 lần, nhận text) thành **True ReAct Agents** với **OpenAI Function Calling**:

- Agent **tự chủ động gọi tools** để thu thập thêm bằng chứng
- Agent **tự quyết định** cần bao nhiêu bước để kết luận  
- Giải quyết triệt để 3 gap so với CodeQL: **Aliasing**, **CFG**, **Cross-file taint**
- Không cần tên miền hay server — tools chạy hoàn toàn **local** trên máy user

## Cơ chế hoạt động (không cần domain/server)

```
Code Python sếp → Gửi messages + tool_schemas lên API
LLM             → Trả về JSON: "Tôi muốn gọi trace_variable(x, app.py)"
Code Python sếp → Đọc JSON → tự chạy hàm local → gửi kết quả lại LLM
LLM             → Tiếp tục reason → gọi tool tiếp hoặc submit verdict
```

LLM không bao giờ gọi trực tiếp vào code — chỉ trả về JSON "intention", Python code tự execute.

---

## Shared Infrastructure (dùng chung cho cả 4 agents)

### [NEW] `src/audit/tools.py`

Tập hợp tất cả tool executors. Mỗi tool là Python function chạy local.

**6 tools:**

| Tool | Input | Output | Giải quyết gap |
|------|-------|--------|----------------|
| `read_file` | path, start_line, end_line | Nội dung file | Context gathering |
| `trace_variable` | var_name, file_path | Alias chain đầy đủ | **Aliasing gap** |
| `find_function` | function_name | Full source của hàm | Cross-file gap |
| `find_callers` | function_name | Tất cả caller locations | Call graph |
| `search_pattern` | pattern, ext | Matches trong codebase | Sanitizer/CFG check |
| `submit_verdict` | verdict, severity, ... | Kết thúc vòng lặp | Final answer |

### [NEW] `src/audit/tool_schemas.py`

JSON Schema theo chuẩn OpenAI Function Calling. Gửi kèm mỗi API request.

### [NEW] `src/audit/agent_runner.py`

Generic ReAct loop dùng chung cho cả 4 agents:

```python
def run_agent(system_prompt, initial_message, tools, tool_schemas,
              target_dir, ts_module, model, max_steps):
    messages = [system_prompt, initial_message]
    
    for step in range(max_steps):
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=tool_schemas,
            tool_choice="auto"
        )
        msg = response.choices[0].message
        messages.append(msg)
        
        if msg.tool_calls:
            for tool_call in msg.tool_calls:
                result = tools.execute_tool(
                    tool_call.function.name,
                    json.loads(tool_call.function.arguments),
                    target_dir, ts_module
                )
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": str(result)
                })
        else:
            # No tool call → Agent đã kết luận
            return parse_final_response(msg.content)
    
    return fallback_verdict()
```

### [MODIFY] `src/audit/tree-sitter.py`

Thêm 2 functions mới:

- **`resolve_aliases(file_path, var_name, ts_module)`**: AST traversal tìm alias chain
- **`find_sanitizer_on_path(file_path, source_line, sink_line)`**: Tìm sanitizer/validator giữa 2 dòng

---

## Agent 1: Scan Agent (Data Flow Tracer)

**Files:** `src/scan/agents/models.py` + `prompts.py`

**Tools:** `read_file`, `find_function`, `find_callers`, `submit_verdict`

**Max steps:** 8

**submit_verdict output:**
```json
{
  "source_identified": true,
  "source_variable": "user_id",
  "sink_function": "db.execute",
  "data_flow": [
    {"step": 1, "variable": "user_id", "operation": "request.args.get('id')", "line": 12},
    {"step": 2, "variable": "user_id", "operation": "passed to process_query()", "line": 15},
    {"step": 3, "variable": "query", "operation": "f-string → db.execute()", "line": 28}
  ],
  "hops_traced": 3,
  "cross_file": true
}
```

---

## Agent 2: Audit Agent (Vulnerability Verifier) — PRIMARY

**Files:** `src/audit/agents/models.py` + `prompts.py`

**Tools:** `read_file`, `trace_variable`, `find_function`, `find_callers`, `search_pattern`, `submit_verdict`

**Max steps:** 10

**New System Prompt (key points):**
```
MANDATORY STEPS BEFORE VERDICT:

1. ALIAS ANALYSIS: Gọi trace_variable() trên TỪNG biến trong sink call.
   KHÔNG được assume biến là clean khi chưa trace.

2. CFG ANALYSIS: Gọi search_pattern() để tìm sanitizer giữa source và sink.
   Sanitizer phải nằm trên TẤT CẢ paths — không chỉ 1 nhánh if.

3. CROSS-FILE: Nếu sink gọi unknown function, gọi find_function() trước.
   KHÔNG được assume unknown function là safe.

4. Chỉ gọi submit_verdict() khi có BẰNG CHỨNG CỤ THỂ.
```

**submit_verdict output:**
```json
{
  "verdict": "VULNERABLE",
  "severity": "CRITICAL",
  "confidence": 95,
  "cvss_estimate": 9.8,
  "vuln_class": "SQL Injection",
  "reasoning": "request.args('id') → x (alias) → query → db.execute(). Không có sanitizer trên bất kỳ path nào.",
  "attack_vector": "GET /users?id=1' OR '1'='1"
}
```

---

## Agent 3: Hack Agent (PoC Generator)

**Files:** `src/hack/agents/models.py` + `prompts.py`

**Tools:** `read_file`, `search_pattern`, `find_function`, `submit_verdict`

**Max steps:** 5

**Mục đích tool use:** Đọc route handler → biết endpoint URL, HTTP method, auth headers → PoC thực tế hơn.

**submit_verdict output:**
```json
{
  "poc_type": "HTTP REQUEST",
  "description": "SQL injection via id parameter in GET /api/users",
  "payload": "GET /api/users?id=1' UNION SELECT username,password FROM users-- HTTP/1.1\nHost: target.com"
}
```

---

## Agent 4: Fix Agent (Auto Patch Generator)

**Files:** `src/fix/agents/models.py` + `prompts.py`

**Tools:** `read_file`, `search_pattern`, `find_function`, `submit_verdict`

**Max steps:** 5

**Mục đích tool use:** Đọc codebase → biết coding style, existing sanitizer utilities → patch realistic.

**submit_verdict output:**
```json
{
  "explanation": "Use parameterized query. Project's db_utils.safe_query() already handles this.",
  "patches": [
    {
      "file_path": "app.py",
      "old_code": "db.execute(f\"SELECT * WHERE id={user_id}\")",
      "new_code": "db.execute(\"SELECT * WHERE id=?\", (user_id,))"
    }
  ]
}
```

---

## Implementation Order

```
Phase 1 — Shared Infrastructure
  ├─ [NEW] src/audit/tool_schemas.py
  ├─ [NEW] src/audit/tools.py
  ├─ [NEW] src/audit/agent_runner.py
  └─ [MODIFY] src/audit/tree-sitter.py  (+resolve_aliases, +find_sanitizer_on_path)

Phase 2 — Audit Agent (PRIMARY — làm đầu tiên, test kỹ)
  ├─ [MODIFY] src/audit/agents/prompts.py
  └─ [MODIFY] src/audit/agents/models.py

Phase 3 — Scan Agent
  ├─ [MODIFY] src/scan/agents/prompts.py
  └─ [MODIFY] src/scan/agents/models.py

Phase 4 — Hack Agent
  ├─ [MODIFY] src/hack/agents/prompts.py
  └─ [MODIFY] src/hack/agents/models.py

Phase 5 — Fix Agent
  ├─ [MODIFY] src/fix/agents/prompts.py
  └─ [MODIFY] src/fix/agents/models.py

Phase 6 — Wire up
  └─ [MODIFY] main.py
```

---

## Files thay đổi tổng kết

| File | Action | Ghi chú |
|------|--------|---------|
| `src/audit/tool_schemas.py` | NEW | 6 tool JSON schemas |
| `src/audit/tools.py` | NEW | Tool executors + dispatcher |
| `src/audit/agent_runner.py` | NEW | Generic ReAct loop |
| `src/audit/tree-sitter.py` | MODIFY | +resolve_aliases +find_sanitizer_on_path |
| `src/audit/agents/models.py` | MODIFY | → run_agent() |
| `src/audit/agents/prompts.py` | MODIFY | Agentic system prompt |
| `src/scan/agents/models.py` | MODIFY | → run_agent() |
| `src/scan/agents/prompts.py` | MODIFY | Agentic system prompt |
| `src/hack/agents/models.py` | MODIFY | → run_agent() |
| `src/hack/agents/prompts.py` | MODIFY | Agentic system prompt |
| `src/fix/agents/models.py` | MODIFY | → run_agent() |
| `src/fix/agents/prompts.py` | MODIFY | Agentic system prompt |
| `main.py` | MODIFY | Wire up new agent calls |

**Tổng: 3 files mới + 10 files sửa**

---

## Test Cases

```python
# Test 1 — Aliasing chain
user_input = request.args.get("id")
x = user_input          # alias 1
y = x                   # alias 2
db.execute(f"SELECT * WHERE id={y}")
# Expected: trace_variable("y") → chain → VULNERABLE ✅

# Test 2 — Sanitizer chỉ 1 nhánh (vẫn VULNERABLE)
user_input = request.args.get("id")
if condition:
    user_input = escape(user_input)
db.execute(f"SELECT * WHERE id={user_input}")
# Expected: search_pattern tìm escape() → nhưng conditional → VULNERABLE ✅

# Test 3 — Cross-file taint
# file1.py: def get_data(): return request.args.get("id")
# file2.py: data = get_data(); db.execute(f"...{data}")
# Expected: find_function("get_data") → trace → VULNERABLE ✅

# Test 4 — True SAFE
user_id = int(request.args.get("id"))
db.execute("SELECT * WHERE id=?", (user_id,))
# Expected: trace int() sanitizer + parameterized query → SAFE ✅
```
