import re

# ENTRYPOINTS
ENTRIES = {
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

# EVENT BUS / PUB-SUB 
EVENTS = {
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

# Hàm kiểm tra entrypoint
def check_entrypoint(code: str, ext: str) -> bool:
    patterns = ENTRIES.get(ext, [])

    for pattern in patterns:

        if re.search(pattern, code):

            return True

    return False

# Hàm trích xuất events
def extract_events(code: str, ext: str):
    group = None

    if ext in (".js", ".ts"):
        group = "js_ts"

    elif ext == ".java":
        group = "java"

    elif ext == ".cs":
        group = "csharp"

    elif ext == ".py":
        group = "python"
        
    if not group:

        return [], []
        
    pub = EVENTS[group]["publish"]
    sub = EVENTS[group]["subscribe"]
    
    pubs = re.findall(pub, code)
    subs = re.findall(sub, code)
    
    return pubs, subs
