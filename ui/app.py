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

tmps = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


class Req(BaseModel):
    u: str


@app.get("/", response_class=HTMLResponse)
async def s_home(r: Request):
    return tmps.TemplateResponse(request=r, name="pages/home.html")


@app.post("/api/scan")
async def a_scan(r: Req):

    u = r.u

    if not u.startswith("http"):
        raise HTTPException(status_code=400, detail="Invalid URL")

    try:
        from main import run_sast

        res = run_sast(u)

        if res.get("status") == "error":
            raise HTTPException(status_code=500, detail=res.get("message"))

        return res

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
