#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging.handlers
import config

config = config.Config()

logger = logging.getLogger()
# форматирование
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
# ротация
fh = logging.handlers.RotatingFileHandler(config.LOG_FILE,
                                          maxBytes=int(config.LOG_FILE_SIZE),
                                          backupCount=config.LOG_ROTATE_COUNT)
fh.setFormatter(formatter)
ch = logging.StreamHandler()
ch.setFormatter(formatter)
LEVEL = config.LOG_LEVEL.upper()  # в верхний регистр


try:
    logger.setLevel(LEVEL)
    fh.setLevel(LEVEL)
    ch.setLevel(LEVEL)
    if config.LOG_TO_FILE is True:
        logger.addHandler(fh)
    if config.LOG_TO_CONSOLE is True:
        logger.addHandler(ch)
except ValueError as err:
    DEFAULT_LEVEL = 'INFO'
    logger.setLevel(DEFAULT_LEVEL)
    fh.setLevel(DEFAULT_LEVEL)
    ch.setLevel(DEFAULT_LEVEL)
    if config.LOG_TO_FILE is True:
        logger.addHandler(fh)
    if config.LOG_TO_CONSOLE is True:
        logger.addHandler(ch)
    logger.error("Wrong log level in config file! Setting to default level " + DEFAULT_LEVEL + "!")


def function_log_deco(func):
    """
    Logging function
    :param func:    any function
    :return:
    """
    def wrapper(*args, **kwargs):
        func_str = func.__name__
        if args:
            args_str = ', '.join(args)
            logger.info("Function " + func_str + " executed with arguments: " + args_str)
        elif kwargs:
            kwargs_str = ', '.join([':'.join([str(j) for j in i]) for i in kwargs.items()])
            logger.info("Function " + func_str + " executed with arguments: " + kwargs_str)
        else:
            logger.info("Function " + func_str + " executed")
        return func(*args, **kwargs)
    return wrapper()
