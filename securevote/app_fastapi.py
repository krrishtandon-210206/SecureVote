"""Optional FastAPI front door (matches the synopsis):  pip install fastapi uvicorn
   uvicorn app_fastapi:app --port 8000        (server.py needs no installs at all)"""
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
import service

app = FastAPI(title="SecureVote")

@app.api_route("/api/{path:path}", methods=["GET", "POST"])
async def api(path: str, request: Request):
    try: body = await request.json() if request.method == "POST" else {}
    except Exception: return JSONResponse({"error": "invalid JSON"}, status_code=400)
    status, obj = await run_in_threadpool(service.handle, request.method, "/api/" + path, body, dict(request.headers))
    return JSONResponse(obj, status_code=status)

app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "web"), html=True), name="web")
