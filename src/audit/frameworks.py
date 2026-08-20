import re

# ==========================================
# 1. ENTRYPOINTS (SOURCES) CHO 10 NGÔN NGỮ
# ==========================================
ENTRYPOINTS = {
    ".py": [
        r"@app\.route", r"@blueprint\.route", r"path\(", r"re_path\(", 
        r"@api_view", r"@app\.get", r"@router\.post", r"@app\.post",
        r"@router\.get", r"def main\("
    ],
    ".js": [
        r"app\.get\(", r"app\.post\(", r"router\.get\(", r"router\.post\(", 
        r"app\.use\(", r"export default function\s*\(\s*(req|request)"
    ],
    ".ts": [
        r"@Controller", r"@Get\(", r"@Post\(", r"@RequestMapping", 
        r"app\.get\(", r"app\.post\(", r"router\.get\("
    ],
    ".java": [
        r"@RestController", r"@Controller", r"@GetMapping", r"@PostMapping", 
        r"@RequestMapping", r"@Path\(", r"public static void main\("
    ],
    ".go": [
        r"\.GET\(", r"\.POST\(", r"\.Put\(", r"\.Delete\(", 
        r"http\.HandleFunc\(", r"func main\("
    ],
    ".php": [
        r"Route::get\(", r"Route::post\(", r"#\[Route\(", r"\$app->get\(", 
        r"function main\("
    ],
    ".cs": [
        r"\[HttpGet\]", r"\[HttpPost\]", r"\[Route\]", r"\[ApiController\]", 
        r"static void Main\("
    ],
    ".rb": [
        r"get\s+['\"]/", r"post\s+['\"]/", r"resources\s+:", r"def self\.call"
    ],
    ".c": [
        r"int main\(", r"void main\("
    ],
    ".cpp": [
        r"CROW_ROUTE", r"int main\(", r"void main\("
    ]
}

# ==========================================
# 2. EVENT BUS / PUB-SUB CHO CÁC NGÔN NGỮ
# ==========================================
PUB_SUB = {
    "java": {
        "publish": r"\.publishEvent\(\s*new\s+([a-zA-Z0-9_]+)",
        "subscribe": r"@EventListener\s*\n\s*(?:public|protected|private)\s+void\s+[a-zA-Z0-9_]+\s*\(\s*([a-zA-Z0-9_]+)\s+[a-zA-Z0-9_]+\s*\)"
    },
    "js_ts": {
        "publish": r"(?:\w+)?\.emit\(\s*['\"]([^'\"]+)['\"]",
        "subscribe": r"(?:\w+)?\.on\(\s*['\"]([^'\"]+)['\"]"
    },
    "csharp": {
        "publish": r"\.Publish\(\s*new\s+([a-zA-Z0-9_]+)",
        "subscribe": r"INotificationHandler<([a-zA-Z0-9_]+)>"
    },
    "python": {
        "publish": r"\.send\(\s*(?:sender=)?['\"]?([a-zA-Z0-9_]+)['\"]?",
        "subscribe": r"@receiver\(\s*['\"]?([a-zA-Z0-9_]+)['\"]?"
    }
}

def check_entrypoint(code_text: str, file_ext: str) -> bool:
    patterns = ENTRYPOINTS.get(file_ext, [])

    for pattern in patterns:

        if re.search(pattern, code_text):

            return True

    return False

def extract_events(code_text: str, file_ext: str):
    group_key = None

    if file_ext in (".js", ".ts"):
        group_key = "js_ts"

    elif file_ext == ".java":
        group_key = "java"

    elif file_ext == ".cs":
        group_key = "csharp"

    elif file_ext == ".py":
        group_key = "python"
        
    if not group_key:

        return [], []
        
    pub_pattern = PUB_SUB[group_key]["publish"]
    sub_pattern = PUB_SUB[group_key]["subscribe"]
    
    published = re.findall(pub_pattern, code_text)
    subscribed = re.findall(sub_pattern, code_text)
    
    return published, subscribed
