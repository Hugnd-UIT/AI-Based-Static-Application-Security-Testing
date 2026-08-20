from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.append(str(ROOT))

app = FastAPI(title="Sinful SAST API")

app.mount(
    "/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static"
)

get_tmps = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


class Req(BaseModel):
    u: str


@app.get("/", response_class=HTMLResponse)
async def show_home(get_req: Request):

    return get_tmps.TemplateResponse(request=get_req, name="pages/home.html")


@app.post("/api/scan")
async def api_scan(get_req: Req):

    get_url = get_req.u

    if not get_url.startswith("http"):
        raise HTTPException(status_code=400, detail="Invalid URL")

    try:
        from main import run_scan

        get_res = run_scan(get_url)

        if get_res.get("status") == "error":
            raise HTTPException(status_code=500, detail=get_res.get("message"))

        return get_res

    except Exception as get_err:
        raise HTTPException(status_code=500, detail=str(get_err))
