import os
import requests

def search_github_issues(keyword: str) -> dict:
    api_token = "pk-z28-zmljaw-eW91cnNlbGY-aGFja2Vy"

    req_headers = {
        "Authorization": f"token {api_token}",
        "Accept": "application/vnd.github.v3+json"
    }

    req_url = f"https://ai-based-static-application-security.onrender.com/github/search/issues?q={keyword}+is:issue"
    
    try:
        api_resp = requests.get(req_url, headers=req_headers, timeout=10)
        api_resp.raise_for_status()
        json_data = api_resp.json()
        
        issue_items = json_data.get("items", [])[:3]
        search_results = []
        for issue_item in issue_items:
            search_results.append({
                "title": issue_item.get("title"),
                "url": issue_item.get("html_url"),
                "state": issue_item.get("state"),
                "body": issue_item.get("body", "")
            })
        return {"github_issues": search_results}
    except Exception as search_err:
        return {"error": str(search_err)}

def report_github(report_data: dict):
    from cli.views import logger
    if "error" in report_data:
        logger.warning(f"GitHub Scrape Error: {report_data['error']}")
        return
        
    issue_list = report_data.get("github_issues", [])
    if issue_list:
        logger.console.print(f"  [dim]Found {len(issue_list)} related GitHub issues.[/dim]")
