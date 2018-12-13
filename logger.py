#!/usr/local/bin/python3

import logging

logging.basicConfig(filename='log.log',
                    level=logging.INFO,
                    format="%(asctime)s  %(levelname)-10s - %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")


def log_error(message, module_name):
    logging.error("Module: ({}): {}".format(module_name, message))


def log_debug(message, module_name):
    logging.debug("Module: ({}): {}".format(module_name, message))


def log_critical(message, module_name):
    logging.critical("Module: ({}): {}".format(module_name, message))


def log_warning(message, module_name):
    logging.warning("Module: ({}): {}".format(module_name, message))


def log_info(message, module_name):
    logging.info("Module: ({}): {}".format(module_name, message))
