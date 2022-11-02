def get_custom_logger():
    import logging
    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger(__name__)
    return log