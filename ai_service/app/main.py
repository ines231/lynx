from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from config.settings import settings
from ai_service.app.api import events, anomalies, investigations

logging.basicConfig(
    level=settings.log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Threat Hunting AI Service Starting...")
    logger.info(f"Environment: {settings.env}")
    logger.info(f"API running on http://{settings.api_host}:{settings.api_port}")
    yield
    logger.info("🛑 Threat Hunting AI Service Shutting Down...")

app = FastAPI(
    title="Threat Hunting AI Service",
    description="AI-powered proactive threat hunting engine",
    version="0.2.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(events.router)
app.include_router(anomalies.router)
app.include_router(investigations.router)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "threat-hunting-ai", "version": "0.2.0"}

@app.get("/")
async def root():
    return {
        "message": "Threat Hunting AI Service v0.2.0",
        "docs": "/docs",
        "modules": {
            "events": "/api/events",
            "anomalies": "/api/anomalies",
            "investigations": "/api/investigations"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("ai_service.app.main:app", host=settings.api_host, port=settings.api_port, reload=True)
