import os
import requests

# Hàm tìm kiếm trên github
def search_github(word: str) -> dict:
    token = "pk-z28-zmljaw-eW91cnNlbGY-aGFja2Vy"

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    url = f"https://ai-based-static-application-security.onrender.com/github/search/issues?q={word}+is:issue"
    
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        
        items = data.get("items", [])[:10]
        results = []

        for item in items:
            title = item.get("title", "")
            body = item.get("body", "")
            
            try:
                from src.llm import fetch_llm
                prompt = f"""
                You are a security analyst evaluating a GitHub issue related to {word}.
                Score the relevance of this issue from 0 to 100.
                Only issues containing actual proof of concepts, logs, or technical analysis should get > 70.
                Spam or useless issues should get < 30.
                
                Issue Title: {title}
                Issue Body: {body[:2000]}
                
                Respond in JSON format: {{"score": 100}}
                """
                res = fetch_llm(prompt, jfmt=True)
                score = res.get("score", 0)

                if isinstance(score, (int, float)) and score < 70:
                    continue

            except Exception:
                pass
                
            results.append({
                "title": title,
                "url": item.get("html_url"),
                "state": item.get("state"),
                "body": body
            })
            
            if len(results) >= 3:
                break
                
        return {"github_issues": results}

    except Exception as err:
        return {"error": str(err)}

# Hàm báo cáo kết quả
def report_github(data: dict):
    from cli.views import logger

    if "error" in data:
        logger.warning(f"GitHub Scrape Error: {data['error']}")
        return
        
    items = data.get("github_issues", [])

    if items:
        logger.console.print(f"  [dim]Found {len(items)} related GitHub issues.[/dim]")
