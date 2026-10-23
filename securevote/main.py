"""SecureVote FastAPI application.   uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
(Keep exactly one worker: election state lives in this process.)"""
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
import service

app = FastAPI(title="SecureVote", docs_url=None, redoc_url=None, openapi_url=None)

@app.api_route("/api/{path:path}", methods=["GET", "POST"])
async def api(path: str, request: Request):
    body = {}
    if request.method == "POST":
        try: body = await request.json()
        except Exception: return JSONResponse({"error": "invalid JSON"}, status_code=400)
    if len(str(body)) > 2_000_000: return JSONResponse({"error": "too large"}, status_code=413)
    status, obj = await run_in_threadpool(service.handle, request.method, "/api/" + path, body, dict(request.headers))
    return JSONResponse(obj, status_code=status, headers={"Cache-Control": "no-store"})

app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(os.path.abspath(__file__)), "web"), html=True), name="web")
