from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.auth import auth_router
from app.api.routes import router as security_router
from app.services.seed import initialize_database

app = FastAPI(
    title="Singularity API",
    description="AI-powered attack surface, vulnerability prioritization and attack-path analysis platform.",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://hopeful-spontaneity-production-7a3c.up.railway.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(security_router)


@app.on_event("startup")
def startup() -> None:
    initialize_database()


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "singularity-api",
        "version": "0.2.0",
    }


@app.get("/api/v1")
async def api_root():
    return {
        "name": "Singularity",
        "version": "0.2.0",
        "environment": "development",
    }
