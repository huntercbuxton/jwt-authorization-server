import logging
from flask import  request, g
from logging.handlers import RotatingFileHandler

 

 # 1. Define the log formatting structure
log_formatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s \n request_data = %(request_data)s ')

class TrackingFilter(logging.Filter):
    def filter(self, record): 
        request_context = {  }
        if g:
            request_context['trace_id'] = g.trace_id
            request_context['consumer_id'] = g.consumer_id
        if request:
            request_context['url'] = request.url 
        record.request_data = request_context
        return True
def setup_logger(logger): 
    
    file_handler = RotatingFileHandler('test.log', maxBytes=1024 * 1024, backupCount=3)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(log_formatter)
    file_handler.addFilter(TrackingFilter()) 
    logger.addHandler(file_handler)
    logger.setLevel(logging.DEBUG)
 