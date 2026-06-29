from pydantic_settings import BaseSettings
from pathlib import Path

class Settings(BaseSettings):
    # Environment
    env: str = "development"
    debug: bool = True
    log_level: str = "DEBUG"
    
    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_workers: int = 4
    
    # Elasticsearch
    elasticsearch_host: str = "localhost"
    elasticsearch_port: int = 9200
    elasticsearch_index_prefix: str = "wazuh"
    
    # PostgreSQL
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "threat_hunting"
    postgres_user: str = "admin"
    postgres_password: str = "changeme"
    
    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    
    # TI APIs
    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    
    # Ollama
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "mistral"
    
    # Feature extraction
    baseline_days: int = 90
    anomaly_threshold: float = 3.0
    kill_chain_time_window: int = 3600
    
    class Config:
        env_file = "config/.env"
        case_sensitive = False

settings = Settings()
