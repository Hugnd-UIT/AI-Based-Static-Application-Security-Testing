import json
import os
from datetime import datetime

def to_json(scan_result: dict, report_dir: str) -> str:
    """Exports the scan result to a JSON file."""
    os.makedirs(report_dir, exist_ok=True)
    time_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(report_dir, f"sinful_report_{time_stamp}.json")
    
    with open(report_path, "w", encoding="utf-8") as file_obj:
        json.dump(scan_result, file_obj, indent=2, ensure_ascii=False)
        
    return report_path
