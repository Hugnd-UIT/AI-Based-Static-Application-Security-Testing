import json
import os
from datetime import datetime

# Hàm tạo report dạng JSON
def report_json(result: dict, out: str) -> str:
    os.makedirs(out, exist_ok=True)
    time = datetime.now().strftime("%Y%m%d_%H%M%S")
    report = os.path.join(out, f"sinful_report_{time}.json")
    
    with open(report, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
        
    return report
