import os
import logging
from cryptography.hazmat.primitives import serialization
import requests
from pydantic_settings import BaseSettings, SettingsConfigDict, YamlConfigSettingsSource 
from typing import Any, List
from pydantic import computed_field
import os
from typing import Any 
import json
from pathlib import Path
from typing import Any
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)
from yaml import safe_load
 

def fetch_spring_config_yml(configserver_url, config_name, profile):
    url = f"{configserver_url}/{config_name}-{profile}.yml"
    try:
        response = requests.get(url, auth=(os.environ.get('CONFIG_CLIENT_USERNAME'), os.environ.get('CONFIG_CLIENT_PASSWORD')))
        response.raise_for_status()
        return response.text
        
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
 
class SpringConfigSettingsSource(PydanticBaseSettingsSource):
    def get_field_value(
        self, field: FieldInfo, field_name: str
    ) -> tuple[Any, str, bool]: ...
    def __call__(self) -> dict[str, Any]: 
        current_state = self.current_state
        # self.settings_cls.
        return YamlConfigSettingsSource(self.settings_cls, yaml_file=fetch_spring_config_yml(current_state.get('CONFIG_SERVER_URL'), current_state.get('CONFIG_SERVER_SOURCE'), 
             current_state.get('CONFIG_SERVER_PROFILE')))()

class ConfigSettings(BaseSettings):
    model_config = SettingsConfigDict(
        yaml_file="config.yml",
        env_file=".env", 
        env_file_encoding="utf-8", 
        extra="ignore" # Safely ignore extra environment variables
    )   
    DEBUG: bool = False
    TESTING: bool = False

    PRIVATE_KEY_PATH: str
    PUBLIC_KEY_PATH: str

    CONFIG_SERVER_URL: str 
    CONFIG_SERVER_SOURCE: str 
    CONFIG_SERVER_PROFILE: str 
    CONFIG_CLIENT_USERNAME: str 
    CONFIG_CLIENT_PASSWORD: str 
 
    DB_PORT: str = "5432"
    DB_NAME: str 
    DB_HOST: str 
    DB_USER: str
    DB_PASSWORD: str
    DB_ENCRYPTION_PASSWORD: str

    JWT_ISSUER: str = "authserver"
    ACCESS_TIMEOUT: int = 30 # 30 minutes after issue 
    REFRESH_TIMEOUT: int = 2880  # 2 days after issue
    REQ_PER_HOUR_LIMIT: int = 80

    AUDIENCE_WHITELIST: List[str] = [ "test_aud" ]
    CONSUMER_WHITELIST: List[str]  = [ "test_consumer" ]
  
    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            YamlConfigSettingsSource(settings_cls), 
            env_settings,
            dotenv_settings, 
            SpringConfigSettingsSource(settings_cls),
            file_secret_settings 
        )


 
appconfig = ConfigSettings()

