import os
import requests

# Search GitHub issues
def search_github(word: str) -> dict:
    headers = {
        "Authorization": f"token {os.environ['GITHUB_API_KEY']}",
        "Accept": "application/vnd.github.v3+json"
    }

    url = f"https://api.github.com/search/issues?q={word}+is:issue"
    
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

# Report GitHub results function
def report_github(cve: str, data: dict):
    from cli.views.logger import console

    if "error" in data:
        console.print(f"  ● [bold magenta]GITHUB[/bold magenta] [red]Failed[/red] [dim]{cve}[/dim]")
        return
        
    items = data.get("github_issues", [])

    if items:
        console.print(f"  ● [bold magenta]GITHUB[/bold magenta] [cyan]{cve}[/cyan]")
        for idx, item in enumerate(items):
            char = "└─" if idx == len(items) - 1 else "├─"
            url = item.get("url", "")
            short_url = url if len(url) <= 60 else url[:60] + "..."
            console.print(f"  {char} [dim]{short_url}[/dim]")
        console.print()
