import logging
from utils.configuration import Configuration 

def createLogger(scope):
    # Create logger
    logger = logging.getLogger(scope)

    config = Configuration().get_config()
    # Set logger level
    if config["logLevel"] == "DEBUG":
        logger.setLevel(logging.DEBUG)  
    elif config["logLevel"] == "INFO":
        logger.setLevel(logging.INFO)
    elif config["logLevel"] == "ERROR":
        logger.setLevel(logging.ERROR) 
    elif config["logLevel"] == "WARNING":
        logger.setLevel(logging.WARNING)
    else:
        logger.setLevel(logging.INFO)
    # Create formatter
    formatter = logging.Formatter('%(levelname)s %(name)s: %(message)s')

    # Create console handler and set level to INFO
    console_handler = logging.StreamHandler()

    # Add formatter to console handler
    console_handler.setFormatter(formatter)

    # Add console handler to logger
    logger.addHandler(console_handler)
    
    return logger