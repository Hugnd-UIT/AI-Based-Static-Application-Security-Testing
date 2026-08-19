import os
import json
import urllib.request
from typing import Optional

URL = "https://ai-based-static-application-security.onrender.com/firecrawl"

def scrape_firecrawl_url(target_url: str) -> Optional[str]:
    api_key = "pk-z28-zmljaw-eW91cnNlbGY-aGFja2Vy"

    payload_data = json.dumps({"url": target_url, "formats": ["markdown"]}).encode("utf-8")
    api_req = urllib.request.Request(
        URL,
        data=payload_data,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
    )

    try:
        with urllib.request.urlopen(api_req, timeout=30) as api_resp:
            json_data = json.loads(api_resp.read().decode("utf-8"))

            if json_data.get("success"):
                return json_data.get("data", {}).get("markdown")
            else:
                print(f"  [!] Firecrawl failed to scrape: {target_url}")
                return None

    except urllib.error.HTTPError as http_err:
        print(f"  [!] HTTP Error {http_err.code} when scraping {target_url}")
        return None

    except Exception as scrape_err:
        print(f"  [!] Error connecting to Firecrawl: {scrape_err}")
        return None
