import os
import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
import itertools

app = FastAPI(title="Sinful SAST Backend Proxy")

URL = "https://api.xkiro.com"
api_key_env = os.environ.get("AI_API_KEY", "")
API_KEYS = [key_item.strip() for key_item in api_key_env.split(",") if key_item.strip()]

key_iterator = itertools.cycle(API_KEYS) if API_KEYS else None

GITHUB_URL = "https://api.github.com"
GITHUB_KEY = os.environ.get("GITHUB_API_KEY")

FIRECRAWL_URL = "https://api.firecrawl.dev/v1/scrape"
FIRECRAWL_KEY = os.environ.get("FIRECRAWL_API_KEY")

@app.api_route("/github/{path:path}", methods=["GET", "POST"])
async def forward_github_req(request: Request, path: str):
    if not GITHUB_KEY:
        raise HTTPException(status_code=500, detail="Server is missing GITHUB_API_KEY")
    
    target_url = f"{GITHUB_URL}/{path}"
    req_headers = dict(request.headers)
    req_headers["host"] = "api.github.com"
    req_headers["authorization"] = f"token {GITHUB_KEY}"
    req_headers.pop("content-length", None)
    req_headers.pop("accept-encoding", None)
    
    async with httpx.AsyncClient(timeout=120.0) as http_client:
        try:
            http_req = http_client.build_request(method=request.method, url=target_url, headers=req_headers, params=request.query_params)
            api_resp = await http_client.send(http_req, stream=False)
            return Response(content=api_resp.content, status_code=api_resp.status_code, headers={head_k: head_v for head_k, head_v in api_resp.headers.items() if head_k.lower() not in ("content-length", "transfer-encoding", "content-encoding")})
        except httpx.RequestError as req_err:
            raise HTTPException(status_code=502, detail=f"Error connecting to GitHub API: {repr(req_err)}")

@app.api_route("/firecrawl", methods=["POST"])
async def forward_firecrawl_req(request: Request):
    if not FIRECRAWL_KEY:
        raise HTTPException(status_code=500, detail="Server is missing FIRECRAWL_API_KEY")
    
    req_body = await request.body()
    req_headers = dict(request.headers)
    req_headers["host"] = "api.firecrawl.dev"
    req_headers["authorization"] = f"Bearer {FIRECRAWL_KEY}"
    req_headers.pop("content-length", None)
    req_headers.pop("accept-encoding", None)
    
    async with httpx.AsyncClient(timeout=120.0) as http_client:
        try:
            http_req = http_client.build_request(method=request.method, url=FIRECRAWL_URL, headers=req_headers, content=req_body)
            api_resp = await http_client.send(http_req, stream=False)
            return Response(content=api_resp.content, status_code=api_resp.status_code, headers={head_k: head_v for head_k, head_v in api_resp.headers.items() if head_k.lower() not in ("content-length", "transfer-encoding", "content-encoding")})
        except httpx.RequestError as req_err:
            raise HTTPException(status_code=502, detail=f"Error connecting to Firecrawl API: {repr(req_err)}")

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def forward_ai_req(request: Request, path: str):
    if not API_KEYS:
        raise HTTPException(status_code=500, detail="Server is missing AI_API_KEY")

    current_key = next(key_iterator)
    target_url = f"{URL}/{path}"
    req_body = await request.body()
    
    req_headers = dict(request.headers)
    req_headers["host"] = "api.xkiro.com"
    req_headers["authorization"] = f"Bearer {current_key}"
    req_headers.pop("content-length", None)
    req_headers.pop("accept-encoding", None)

    async with httpx.AsyncClient(timeout=120.0) as http_client:
        try:
            http_req = http_client.build_request(
                method=request.method,
                url=target_url,
                headers=req_headers,
                content=req_body,
                params=request.query_params
            )
            api_resp = await http_client.send(http_req, stream=False)
            
            return Response(
                content=api_resp.content,
                status_code=api_resp.status_code,
                headers={head_k: head_v for head_k, head_v in api_resp.headers.items() if head_k.lower() not in ("content-length", "transfer-encoding", "content-encoding")}
            )
        except httpx.RequestError as req_err:
            raise HTTPException(status_code=502, detail=f"Error connecting to AI API: {repr(req_err)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
