import os
import json
import urllib.request
from typing import Optional

URL = "https://ai-based-static-application-security.onrender.com/firecrawl"

import time

def scrape_url(target_url: str) -> Optional[str]:
    api_key = "pk-z28-zmljaw-eW91cnNlbGY-aGFja2Vy"

    payload_data = json.dumps({"url": target_url, "formats": ["markdown"]}).encode("utf-8")
    
    max_retries = 3

    for attempt in range(max_retries):
        api_req = urllib.request.Request(
            URL,
            data=payload_data,
            headers={
                "Content-Type": "application/json", 
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            },
        )

        try:
            with urllib.request.urlopen(api_req, timeout=30) as api_resp:
                json_data = json.loads(api_resp.read().decode("utf-8"))

                if json_data.get("success"):

                    return json_data.get("data", {}).get("markdown")

                else:

                    return None

        except urllib.error.HTTPError as http_err:

            if http_err.code == 429 and attempt < max_retries - 1:
                # print(f"  [!] HTTP 429 (Rate Limit). Retrying in {2 ** attempt}s...")
                time.sleep(2 ** attempt)
                continue
                
            return None

        except Exception as scrape_err:

            return None
            
    return None

