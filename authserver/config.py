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

def load_private_key():
    key_file_path = os.environ.get('PRIVATE_KEY_FILE')
    key_file_data = load_key_file(key_file_path)
    return serialization.load_ssh_private_key(key_file_data.encode(), password=b"")

def load_public_key():
    key_file_path = os.environ.get('PUBLIC_KEY_FILE')
    key_file_data = load_key_file(key_file_path)
    return serialization.load_ssh_public_key(key_file_data.encode())

class Config:

    PRIVATE_KEY = load_private_key() 
    PUBLIC_KEY = load_public_key()

    DB_NAME = os.environ["DB_NAME"]
    DB_HOST = os.environ["DB_HOST"]
    DB_PORT = os.environ["DB_PORT"]
    DB_USER = os.environ["DB_USER"]
    DB_PASSWORD = os.environ["DB_PASSWORD"]
    DB_ENCRYPTION_PASSWORD = os.environ["DB_ENCRYPTION_PASSWORD"]

    AUDIENCE_WHITELIST = os.environ.get('AUDIENCE_WHITELIST') or [ "huntercbuxton.com" ]
    CONSUMER_WHITELIST = os.environ.get('CONSUMER_WHITELIST') or [ "autherver_demo", "hbns_devops" ] 
    JWT_ISSUER = os.environ.get('JWT_ISSUER') 
    ACCESS_TIMEOUT = 30 # 30 minutes after issue 
    REFRESH_TIMEOUT = 2880  # 2 days after issue
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    
class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
    # Production specific overrides