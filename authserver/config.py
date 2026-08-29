import os

class Config:
    PRIVATE_KEY_FILE = os.environ.get('PRIVATE_KEY_FILE') # or 'hardcoded-fallback-key'
    PUBLIC_KEY_FILE = os.environ.get('PUBLIC_KEY_FILE') 
    CONSUMER_WHITELIST = os.environ.get('CONSUMER_WHITELIST') or [ "hbns_devops", "autherver_demo", "crochetedly" ] 

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
    # Production specific overrides