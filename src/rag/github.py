import os
import requests

def search(keyword: str) -> dict:
    token = "pk-z28-zmljaw-eW91cnNlbGY-aGFja2Vy"

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    url = f"http://localhost:8000/github/search/issues?q={keyword}+is:issue"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        items = data.get("items", [])[:3]
        results = []
        for item in items:
            results.append({
                "title": item.get("title"),
                "url": item.get("html_url"),
                "state": item.get("state"),
                "body": item.get("body", "")
            })
        return {"github_issues": results}
    except Exception as e:
        return {"error": str(e)}

def report(data: dict):
    from cli.views import logger
    if "error" in data:
        logger.warning(f"GitHub Scrape Error: {data['error']}")
        return
        
    issues = data.get("github_issues", [])
    if issues:
        logger.console.print(f"  [dim]Found {len(issues)} related GitHub issues.[/dim]")
