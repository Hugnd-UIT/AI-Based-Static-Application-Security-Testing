import os
import httpx
from fastapi import FastAPI, HTTPException, Request, Response
import itertools

app = FastAPI(title="Sinful SAST Backend Proxy")

URL = "https://api.xkiro.com"
env = os.environ.get("AI_API_KEY", "")
KEYS = [k.strip() for k in env.split(",") if k.strip()]
iter = itertools.cycle(KEYS) if KEYS else None

HUB = "https://api.github.com"
HUB_KEY = os.environ.get("GITHUB_API_KEY")

FIRE = "https://api.firecrawl.dev/v1/scrape"
FIRE_KEY = os.environ.get("FIRECRAWL_API_KEY")

# API gọi github
@app.api_route("/github/{path:path}", methods=["GET", "POST"])
async def fwd_hub(req: Request, path: str):
    if not HUB_KEY:
        raise HTTPException(status_code=500, detail="Server is missing GITHUB_API_KEY")
    
    url = f"{HUB}/{path}"
    hdrs = dict(req.headers)
    hdrs["host"] = "api.github.com"
    hdrs["authorization"] = f"token {HUB_KEY}"
    hdrs.pop("content-length", None)
    hdrs.pop("accept-encoding", None)
    
    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            fwd = client.build_request(method=req.method, url=url, headers=hdrs, params=req.query_params)
            res = await client.send(fwd, stream=False)
            
            return Response(content=res.content, status_code=res.status_code, headers={k: v for k, v in res.headers.items() if k.lower() not in ("content-length", "transfer-encoding", "content-encoding")})
        
        except httpx.RequestError as err:
            raise HTTPException(status_code=502, detail=f"Error connecting to GitHub: {repr(err)}")

# API gọi firecrawl
@app.api_route("/firecrawl", methods=["POST"])
async def fwd_fire(req: Request):
    if not FIRE_KEY:
        raise HTTPException(status_code=500, detail="Server is missing FIRECRAWL_API_KEY")
    
    body = await req.body()
    hdrs = dict(req.headers)
    hdrs["host"] = "api.firecrawl.dev"
    hdrs["authorization"] = f"Bearer {FIRE_KEY}"
    hdrs.pop("content-length", None)
    hdrs.pop("accept-encoding", None)
    
    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            fwd = client.build_request(method=req.method, url=FIRE, headers=hdrs, content=body)
            res = await client.send(fwd, stream=False)
            
            return Response(content=res.content, status_code=res.status_code, headers={k: v for k, v in res.headers.items() if k.lower() not in ("content-length", "transfer-encoding", "content-encoding")})
        
        except httpx.RequestError as err:
            raise HTTPException(status_code=502, detail=f"Error connecting to Firecrawl: {repr(err)}")

# API gọi xkiro
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def fwd_ai(req: Request, path: str):
    if not KEYS:
        raise HTTPException(status_code=500, detail="Server is missing AI_API_KEY")
    
    key = next(iter)
    url = f"{URL}/{path}"
    body = await req.body()
    
    hdrs = dict(req.headers)
    hdrs["host"] = "api.xkiro.com"
    hdrs["authorization"] = f"Bearer {key}"
    hdrs.pop("content-length", None)
    hdrs.pop("accept-encoding", None)
    
    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            fwd = client.build_request(method=req.method, url=url, headers=hdrs, content=body, params=req.query_params)
            res = await client.send(fwd, stream=False)
            
            return Response(content=res.content, status_code=res.status_code, headers={k: v for k, v in res.headers.items() if k.lower() not in ("content-length", "transfer-encoding", "content-encoding")})
        
        except httpx.RequestError as err:
            raise HTTPException(status_code=502, detail=f"Error connecting to AI: {repr(err)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
