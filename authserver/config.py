import os
import logging
from cryptography.hazmat.primitives import serialization

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

class Config:
    
    TESTING = False

    @property
    def PRIVATE_KEY(self):
        PRIVATE_KEY_FILE = os.environ.get('PRIVATE_KEY_FILE') 
        return load_private_key(PRIVATE_KEY_FILE) 

    @property
    def PUBLIC_KEY(self):
        PUBLIC_KEY_FILE = os.environ.get('PUBLIC_KEY_FILE') 
        return load_public_key(PUBLIC_KEY_FILE)

    DB_PORT = os.environ.get("DB_PORT") or 5432
    DB_NAME = os.environ.get("DB_NAME") 
    DB_HOST = os.environ.get("DB_HOST") 
    DB_USER = os.environ.get("DB_USER") 
    DB_PASSWORD = os.environ.get("DB_PASSWORD")
    DB_ENCRYPTION_PASSWORD = os.environ.get("DB_ENCRYPTION_PASSWORD")

    AUDIENCE_WHITELIST = os.environ.get('AUDIENCE_WHITELIST') or [ "huntercbuxton.com" ]
    CONSUMER_WHITELIST = os.environ.get('CONSUMER_WHITELIST') or [ "autherver_demo", "hbns_devops" ] 
    JWT_ISSUER = os.environ.get('JWT_ISSUER') 
    ACCESS_TIMEOUT = 30 # 30 minutes after issue 
    REFRESH_TIMEOUT = 2880  # 2 days after issue
    REQ_PER_HOUR_LIMIT = 80
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class TestingConfig(Config):

    TESTING = True
    DEBUG = True
      
    DB_NAME = "x"
    DB_HOST = "x"
    DB_PORT = "x"
    DB_USER = "x"
    DB_PASSWORD =  "x"
    DB_ENCRYPTION_PASSWORD =  "x"

    AUDIENCE_WHITELIST = [ "test_aud", "api.huntercbuxton.com" ]
    CONSUMER_WHITELIST = [ "test_consumer", "huntercbuxton.com" ] 
       
class DevelopmentConfig(Config):
    DEBUG = True
 
class ProductionConfig(Config):
    DEBUG = False
    # Production specific overrides