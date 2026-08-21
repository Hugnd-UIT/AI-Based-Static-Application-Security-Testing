import os
import json
import urllib.request
from typing import Optional

URL = "https://ai-based-static-application-security.onrender.com/firecrawl"

import time

# Hàm thu thập dữ liệu firecrawl
def scrape_url(target: str) -> Optional[str]:
    key = "pk-z28-zmljaw-eW91cnNlbGY-aGFja2Vy"

    payload = json.dumps({"url": target, "formats": ["markdown"]}).encode("utf-8")
    
    # Thử 3 lần nếu thất bại
    retries = 3

    for attempt in range(retries):
        req = urllib.request.Request(
            URL,
            data=payload,
            headers={
                "Content-Type": "application/json", 
                "Authorization": f"Bearer {key}",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))

                if data.get("success"):
                    return data.get("data", {}).get("markdown")
                else:
                    return None

        except urllib.error.HTTPError as err:
            if err.code == 429 and attempt < retries - 1:
                time.sleep(2 ** attempt)
                continue
            return None

        except Exception as err:
            return None
            
    return None
