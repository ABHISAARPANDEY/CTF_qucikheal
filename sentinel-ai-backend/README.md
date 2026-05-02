# SentinelAI Backend

Production-ready FastAPI scaffold for the SentinelAI cybersecurity platform.

## Layout

```
app/
  main.py            # FastAPI app factory + lifespan
  core/
    config.py        # Pydantic settings (env-driven)
    logger.py        # Centralized logging config
  api/
    routes.py        # API router + health check
  engine/            # Detection / ML pipeline (placeholder)
  models/            # Domain & persistence models (placeholder)
  services/          # Business orchestration layer (placeholder)
```

## Quickstart

```bash
cd sentinel-ai-backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -m uvicorn app.main:app --reload --reload-dir app --host 0.0.0.0 --port 8000
```

> Use `python -m uvicorn ...` rather than the bare `uvicorn` command. It bypasses
> any `PATH` / shell-hash drift and guarantees the venv's interpreter and packages
> are used. `--reload-dir app` keeps the file watcher off the venv.

If `uvicorn` ever fails with `ModuleNotFoundError: No module named 'pydantic_settings'`
(or similar) despite `(.venv)` being in your prompt, your shell has a cached path
to a globally-installed `uvicorn`. Fix:

```bash
hash -r                       # clear zsh command cache
which uvicorn                 # must point inside .venv/bin
```

## Endpoints

| Method | Path                  | Description           |
| ------ | --------------------- | --------------------- |
| GET    | `/api/v1/health`      | Liveness / readiness  |
| GET    | `/docs`               | Swagger UI (dev only) |
| GET    | `/redoc`              | ReDoc (dev only)      |

## Configuration

All settings are loaded from environment variables (or `.env`). See `.env.example` for the full list. Notable knobs:

- `ENVIRONMENT` — `development` | `staging` | `production`
- `LOG_LEVEL` — `DEBUG` | `INFO` | `WARNING` | `ERROR`
- `ENABLE_DOCS` — disable Swagger/ReDoc in prod
- `CORS_ORIGINS` — comma-separated list of allowed origins
