import os
import json
import urllib.request
from typing import Optional
import time

URL = "https://api.firecrawl.dev/v1/scrape"

# Scrape URL via Firecrawl
def scrape_url(target: str) -> Optional[str]:
    payload = json.dumps({"url": target, "formats": ["markdown"]}).encode("utf-8")
    
    # Retry mechanism
    retries = 3

    for attempt in range(retries):
        req = urllib.request.Request(
            URL,
            data=payload,
            headers={
                "Content-Type": "application/json", 
                "Authorization": f"Bearer {os.environ['FIRECRAWL_API_KEY']}",
                "User-Agent": "Mozilla/5.0"
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

# Report Firecrawl results function
def report_firecrawl(stats: list):
    if not stats: return
    from cli.views.logger import console
    console.print(f"  ● [bold magenta]FIRECRAWL[/bold magenta]")
    for idx, stat in enumerate(stats):
        char = "└─" if idx == len(stats) - 1 else "├─"
        url = stat["url"]
        short_url = url if len(url) <= 60 else url[:60] + "..."
        status = "[green]OK[/green]" if stat["success"] else "[red]Failed[/red]"
        console.print(f"  {char} {status} [dim]{short_url}[/dim]")
    console.print()
