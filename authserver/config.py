import os
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
import requests
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Dict, Any, List
from pydantic import computed_field, BaseModel
from functools import cached_property
 
def fetch_spring_config(configserver_url, config_name, profile):
    url = f"{configserver_url}/{config_name}-{profile}.json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        print(f"{data=}") 
        return data
    except requests.exceptions.RequestException as e:
        print(f"Failed to connect to Spring Config Server: {e}")
        return {}
 
def load_key_file(filepath):
    try:
        with open(filepath, 'r') as file:
            return file.read().strip()
    except FileNotFoundError as err:
        logging.critical(f"failed to load key file at {filepath} (file not found) ")  
    except PermissionError as err:
        logging.critical(f"failed to load key file at {filepath} due to permissions error ")   
        return None

def load_private_key(key_file_path): 
    key_file_data = load_key_file(key_file_path)
    return serialization.load_ssh_private_key(key_file_data.encode(), password=b"")

def load_public_key(key_file_path): 
    key_file_data = load_key_file(key_file_path)
    return serialization.load_ssh_public_key(key_file_data.encode())

class ConfigEnv(BaseSettings):

    PRIVATE_KEY: str | None = None 
    PUBLIC_KEY: str | None = None

    PRIVATE_KEY_PATH: str | None = None 
    PUBLIC_KEY_PATH: str | None = None

    DB_USER: str
    DB_PASSWORD: str
    DB_ENCRYPTION_PASSWORD: str

    CONFIG_SERVER_URL: str = "http://localhost:8888"
    SPRING_CONFIG_NAME: str = "authserver"
    SPRING_CONFIG_PROFILE: str = "default"

    @cached_property
    def SPRING_CONFIG(self) -> Dict[str, Any] | None:
        return fetch_spring_config(self.CONFIG_SERVER_URL, self.SPRING_CONFIG_NAME, self.SPRING_CONFIG_PROFILE)

    # Read variables from a .env file if available
    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8",
        extra="ignore" # Safely ignore extra environment variables
    )

class AppConfig(BaseModel):
    DEBUG: bool = False
    TESTING: bool = False

    PRIVATE_KEY_PATH: str 
    PUBLIC_KEY_PATH: str  
    
    DB_PORT: str = "5432"
    DB_NAME: str 
    DB_HOST: str = "http://localhost" 
    DB_USER: str
    DB_PASSWORD: str
    DB_ENCRYPTION_PASSWORD: str

    JWT_ISSUER: str = "authserver"
    ACCESS_TIMEOUT: int = 30 # 30 minutes after issue 
    REFRESH_TIMEOUT: int = 2880  # 2 days after issue
    REQ_PER_HOUR_LIMIT: int = 80

    AUDIENCE_WHITELIST: List[str]
    CONSUMER_WHITELIST: List[str]
  
    @classmethod
    def load_spring_config(cls, env: ConfigEnv):
        props = env.SPRING_CONFIG
        if not props:
            raise RuntimeError(f"spring config not available")
        c = cls(
            PRIVATE_KEY_PATH=env.PRIVATE_KEY_PATH or props['private_key_path'],
            PUBLIC_KEY_PATH=env.PUBLIC_KEY_PATH or props['public_key_path'], 
            DB_HOST=props['db']['host'],
            DB_NAME=props['db']['name'],
            DB_PORT=str(props['db']['port']),
            DB_USER=env.DB_USER,
            DB_PASSWORD=env.DB_PASSWORD,
            DB_ENCRYPTION_PASSWORD=env.DB_ENCRYPTION_PASSWORD,

            AUDIENCE_WHITELIST=props['audience_whitelist'],
            CONSUMER_WHITELIST=props['consumer_whitelist'],
        )
        return c

config_env = ConfigEnv()
appconfig = AppConfig.load_spring_config(config_env)
 
class TestingConfig(AppConfig):
# Flask-native configuration variables
    DEBUG: bool = True
    TESTING: bool = True   

    DB_PORT: str = ""
    DB_NAME: str = ""
    DB_HOST: str = "http://localhost" 
    DB_USER: str = ""
    DB_PASSWORD: str = ""
    DB_ENCRYPTION_PASSWORD: str  = ""

    JWT_ISSUER: str = "authserver"
    ACCESS_TIMEOUT: int = 30 # 30 minutes after issue 
    REFRESH_TIMEOUT: int = 2880  # 2 days after issue
    REQ_PER_HOUR_LIMIT: int = 80

    PRIVATE_KEY_PATH: str = os.environ.get('PRIVATE_KEY_FILE')
    PUBLIC_KEY_PATH: str = os.environ.get('PUBLIC_KEY_FILE')
 
    AUDIENCE_WHITELIST: List[str] = [  'test_aud' ]
    CONSUMER_WHITELIST: List[str] = [ "test_consumer" ]
 
    # Read variables from a .env file if available
    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8",
        extra="ignore" # Safely ignore extra environment variables
    )       
 