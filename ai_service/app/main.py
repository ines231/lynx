from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from config.settings import settings

# Setup logging
logging.basicConfig(
    level=settings.log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Threat Hunting AI Service",
    description="AI-powered proactive threat hunting engine",
    version="0.1.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    logger.info("🚀 Threat Hunting AI Service Starting...")
    logger.info(f"Environment: {settings.env}")
    logger.info(f"Debug: {settings.debug}")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("🛑 Threat Hunting AI Service Shutting Down...")

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
        "redoc": "/redoc"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=settings.api_host,
        port=settings.api_port,
        workers=settings.api_workers,
        log_level=settings.log_level.lower()
    )
