"""Local dev entry point: ``uv run uvicorn main:app --reload``."""
from auth.app import build_app

app = build_app()


@app.get("/")
def read_root() -> dict[str, str]:
    return {"service": "auth-session-hardening", "docs": "/docs"}
