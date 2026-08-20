import os
import requests

def search_github(keyword: str) -> dict:
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
        
        issue_items = json_data.get("items", [])[:10]
        search_results = []

        for issue_item in issue_items:
            issue_title = issue_item.get("title", "")
            issue_body = issue_item.get("body", "")
            
            try:
                from src.llm import fetch_llm
                score_prompt = f"""
                You are a security analyst evaluating a GitHub issue related to {keyword}.
                Score the relevance of this issue from 0 to 100.
                Only issues containing actual proof of concepts, logs, or technical analysis should get > 70.
                Spam or useless issues should get < 30.
                
                Issue Title: {issue_title}
                Issue Body: {issue_body[:2000]}
                
                Respond in JSON format: {{"score": 85}}
                """
                score_resp = fetch_llm(score_prompt, is_json=True)
                score = score_resp.get("score", 0)

                if isinstance(score, (int, float)) and score < 70:
                    continue

            except Exception:
                pass
                
            search_results.append({
                "title": issue_title,
                "url": issue_item.get("html_url"),
                "state": issue_item.get("state"),
                "body": issue_body
            })
            
            if len(search_results) >= 3:
                break
                
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

