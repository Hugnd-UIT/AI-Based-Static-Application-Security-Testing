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
