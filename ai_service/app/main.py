from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from config.settings import settings
from ai_service.app.api import events

# Setup logging
logging.basicConfig(
    level=settings.log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("🚀 Threat Hunting AI Service Starting...")
    logger.info(f"Environment: {settings.env}")
    logger.info(f"Debug: {settings.debug}")
    logger.info(f"API running on http://{settings.api_host}:{settings.api_port}")
    yield
    # Shutdown
    logger.info("🛑 Threat Hunting AI Service Shutting Down...")

# Create FastAPI app
app = FastAPI(
    title="Threat Hunting AI Service",
    description="AI-powered proactive threat hunting engine",
    version="0.1.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(events.router)

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "threat-hunting-ai",
        "version": "0.1.0"
    }

@app.get("/")
async def root():
    return {
        "message": "Threat Hunting AI Service",
        "docs": "/docs",
        "redoc": "/redoc",
        "endpoints": {
            "/api/events/sample": "Get sample mock events",
            "/api/events/attack-scenario": "Get attack scenario",
            "/api/events/enrich": "Enrich event with threat intel",
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "ai_service.app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True,
        log_level=settings.log_level.lower()
    )
