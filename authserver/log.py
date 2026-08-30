import logging
from flask import  request, g
from logging.handlers import RotatingFileHandler
import os
 

log_formatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s \n request_data = %(request_data)s ')

class TrackingFilter(logging.Filter):
    def filter(self, record): 
        request_context = {  }
        if g:
            request_context['trace_id'] = getattr(g, "trace_id", None)
            request_context['consumer_id'] = getattr(g, "consumer_id", None)
        if request:
            request_context['url'] = request.url 
        record.request_data = request_context
        return True

def setup_logger(logger): 

    LOG_FILE = os.environ.get('LOG_FILE') or "authserver.log"

    file_handler = RotatingFileHandler(LOG_FILE, maxBytes=1024 * 1024, backupCount=3, mode="w")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(log_formatter)
    file_handler.addFilter(TrackingFilter()) 
    logger.addHandler(file_handler)
    logger.setLevel(logging.DEBUG)
 