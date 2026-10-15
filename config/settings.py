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
    
    # Display currency of the risk figures (FAIR engine prices in USD)
    display_currency: str = "TND"      # "TND" or "USD"
    usd_to_tnd_rate: float = 2.9927    # dinars for 1 USD (12/10/2026, to be updated)

    # MITRE ATT&CK knowledge base (official STIX data, cached locally)
    mitre_source_url: str = ""         # URL or local path; empty = official GitHub bundle
    mitre_cache_path: str = ""         # empty = data/mitre/techniques.json
    mitre_cache_ttl_days: float = 7
    mitre_auto_update: bool = True     # False = never use the network

    # Data source of the risk analysis:
    #   "mock"    simulated events (default, works anywhere)
    #   "sensors" real alerts written by Falco (host) and/or Suricata (network)
    data_source: str = "mock"
    falco_events_file: str = "/var/log/falco/events.json"        # falco: json_output + file_output
    suricata_eve_file: str = "/var/log/suricata/eve.json"
    sensor_baseline_days: float = 7        # history used as the baseline
    sensor_window_hours: float = 24        # recent window that is analysed
    sensor_min_severity: str = "low"       # low | medium | high | critical (both sides)
    sensor_max_events: int = 200           # analysed events (the newest ones)
    sensor_baseline_max_events: int = 5000
    sensor_read_max_mb: int = 64           # only the tail of each log file is read
    sensor_default_ip: str = "127.0.0.1"   # host events carry no IP: use the sensor host

    # Feature extraction
    baseline_days: int = 90
    anomaly_threshold: float = 3.0
    kill_chain_time_window: int = 3600
    
    class Config:
        env_file = "config/.env"
        case_sensitive = False

settings = Settings()
