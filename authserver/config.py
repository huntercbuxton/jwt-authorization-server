import os

class Config:
    PRIVATE_KEY_FILE = os.environ.get('PRIVATE_KEY_FILE') # or 'hardcoded-fallback-key'
    PUBLIC_KEY_FILE = os.environ.get('PUBLIC_KEY_FILE') 

    DB_NAME = os.environ["DB_NAME"]
    DB_HOST = os.environ["DB_HOST"]
    DB_PORT = os.environ["DB_PORT"]
    DB_USER = os.environ["DB_USER"]
    DB_PASSWORD = os.environ["DB_PASSWORD"]
    DB_ENCRYPTION_PASSWORD = os.environ["DB_ENCRYPTION_PASSWORD"]

    AUDIENCE_WHITELIST = os.environ.get('AUDIENCE_WHITELIST') or [ "huntercbuxton.com" ]
    CONSUMER_WHITELIST = os.environ.get('CONSUMER_WHITELIST') or [ "autherver_demo", "hbns_devops" ] 

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    
class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
    # Production specific overrides