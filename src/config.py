import os
from pathlib import Path

# Đường dẫn gốc của project
ROOT = Path(__file__).resolve().parent.parent

# File tree-sitter được nạp động
SITTER = ROOT / "src" / "ast" / "tree-sitter.py"

# Thư mục chứa rule mẫu của semgrep
TEMPLATES = ROOT / "src" / "scan" / "rules"

# Thư mục chứa rule sinh ra và report, không ghi vào thư mục quét
WORK = Path(os.getenv("SINFUL_WORK_DIR") or (ROOT / ".sinful"))

# Danh sách model, đọc từ env để deploy không phải sửa code
MODELS = [m.strip() for m in (os.getenv("SINFUL_MODELS") or "deepseek/deepseek-v4-pro").split(",") if m.strip()]

# Endpoint tương thích OpenAI
BASE_URL = os.getenv("AI_BASE_URL") or "https://ai-based-static-application-security.onrender.com/v1"

# Thời gian chờ tối đa của semgrep
TIMEOUT = int(os.getenv("SINFUL_TIMEOUT") or "600")

# Số bước tối đa của mỗi agent
STEPS = int(os.getenv("SINFUL_STEPS") or "20")

# Bỏ qua quét thư viện, dùng khi chỉ cần kiểm tra mã nguồn
def skip_sca() -> bool:
    return os.getenv("SINFUL_SKIP_SCA", "").strip().lower() in ("1", "true", "yes")

# Key dùng thử công khai, chỉ dùng khi chưa cấu hình AI_API_KEY
DEMO_KEY = "pk-z28-zmljaw-eW91cnNlbGY-aGFja2Vy"

# Hàm lấy danh sách API key
def get_keys() -> list:
    env = os.getenv("AI_API_KEY") or os.getenv("MODEL_API_KEY") or ""
    keys = [k.strip() for k in env.split(",") if k.strip()]

    return keys or [DEMO_KEY]

# Hàm tạo thư mục làm việc
def get_work() -> Path:
    WORK.mkdir(parents=True, exist_ok=True)

    return WORK
