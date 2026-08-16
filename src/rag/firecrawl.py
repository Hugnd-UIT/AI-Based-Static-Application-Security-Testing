import os
import json
import urllib.request
from typing import Optional

URL = "https://api.firecrawl.dev/v1/scrape"

def scrape(target_url: str) -> Optional[str]:
    api_key = os.environ.get("FIRECRAWL_API_KEY")

    if not api_key:
        print("[!] Firecrawl api key is not set")
        return None

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
                print(f"    [!] Firecrawl failed to scrape: {target_url}")
                return None

    except urllib.error.HTTPError as http_err:
        print(f"    [!] HTTP Error {http_err.code} when scraping {target_url}")
        return None

    except Exception as scrape_err:
        print(f"    [!] Error connecting to Firecrawl: {scrape_err}")
        return None
