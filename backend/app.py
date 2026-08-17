import os
import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse

app = FastAPI(title="Sinful SAST Backend Proxy")

# Config
URL = "https://api.xkiro.com"
API_KEY = os.environ.get("AI_API_KEY")

GITHUB_URL = "https://api.github.com"
GITHUB_KEY = os.environ.get("GITHUB_API_KEY")

FIRECRAWL_URL = "https://api.firecrawl.dev/v1/scrape"
FIRECRAWL_KEY = os.environ.get("FIRECRAWL_API_KEY")

@app.api_route("/github/{path:path}", methods=["GET", "POST"])
async def proxy_github(request: Request, path: str):
    if not GITHUB_KEY:
        raise HTTPException(status_code=500, detail="Server is missing GITHUB_API_KEY")
    
    target_url = f"{GITHUB_URL}/{path}"
    headers = dict(request.headers)
    headers["host"] = "api.github.com"
    headers["authorization"] = f"token {GITHUB_KEY}"
    headers.pop("content-length", None)
    headers.pop("accept-encoding", None)
    
    async with httpx.AsyncClient() as client:
        try:
            req = client.build_request(method=request.method, url=target_url, headers=headers, params=request.query_params)
            res = await client.send(req, stream=False)
            return Response(content=res.content, status_code=res.status_code, headers={k: v for k, v in res.headers.items() if k.lower() not in ("content-length", "transfer-encoding", "content-encoding")})
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"Error connecting to GitHub API: {str(exc)}")

@app.api_route("/firecrawl", methods=["POST"])
async def proxy_firecrawl(request: Request):
    if not FIRECRAWL_KEY:
        raise HTTPException(status_code=500, detail="Server is missing FIRECRAWL_API_KEY")
    
    body = await request.body()
    headers = dict(request.headers)
    headers["host"] = "api.firecrawl.dev"
    headers["authorization"] = f"Bearer {FIRECRAWL_KEY}"
    headers.pop("content-length", None)
    headers.pop("accept-encoding", None)
    
    async with httpx.AsyncClient() as client:
        try:
            req = client.build_request(method=request.method, url=FIRECRAWL_URL, headers=headers, content=body)
            res = await client.send(req, stream=False)
            return Response(content=res.content, status_code=res.status_code, headers={k: v for k, v in res.headers.items() if k.lower() not in ("content-length", "transfer-encoding", "content-encoding")})
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"Error connecting to Firecrawl API: {str(exc)}")

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(request: Request, path: str):
    if not API_KEY:
        raise HTTPException(status_code=500, detail="Server is missing AI_API_KEY")

    target_url = f"{URL}/{path}"
    
    body = await request.body()
    
    headers = dict(request.headers)
    headers["host"] = "api.xkiro.com"
    headers["authorization"] = f"Bearer {API_KEY}"
    headers.pop("content-length", None)
    headers.pop("accept-encoding", None)

    async with httpx.AsyncClient() as client:
        try:
            # Forward request to Xkiro
            req = client.build_request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
                params=request.query_params
            )
            res = await client.send(req, stream=False)
            
            return Response(
                content=res.content,
                status_code=res.status_code,
                headers={k: v for k, v in res.headers.items() if k.lower() not in ("content-length", "transfer-encoding", "content-encoding")}
            )
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"Error connecting to AI API: {str(exc)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
