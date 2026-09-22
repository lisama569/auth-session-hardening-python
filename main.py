"""本地启动入口：``uv run fastapi dev main.py`` 或 ``uv run python main.py``。"""

from __future__ import annotations

import logging

from auth.bootstrap import build_app

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")

app, container = build_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
