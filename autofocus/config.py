import logging

try:
    from .gsrt_config import GSRTConfig
except ImportError:
    from gsrt_config import GSRTConfig


def get_logger():
    """ To change log level from calling code, use something like
        logging.getLogger("autofocus").setLevel(logging.DEBUG)
    """
    logger = logging.getLogger("autofocus")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


AF_APIKEY = None
SHOW_WARNINGS = False
SSL_VERIFY = True
SSL_CERT = None

defaults = {
    "apikey": "",
    "ssl_verify": 'true',
    "api_base": "https://autofocus.paloaltonetworks.com/api/v1.0",
    "ignore_warnings": 'false',
}
gconfig = GSRTConfig("autofocus", defaults=defaults)
AF_APIKEY = gconfig.get("apikey")
SSL_VERIFY = gconfig.getboolean("ssl_verify")
_BASE_URL = gconfig.get("api_base")
ignore_warnings = gconfig.getboolean("ignore_warnings")
SHOW_WARNINGS = False if ignore_warnings else True

if SHOW_WARNINGS:
    get_logger().setLevel(logging.WARNING)
else:
    get_logger().setLevel(logging.ERROR)

try:
    SSL_CERT = gconfig.get("autofocus", "ssl_cert")
except Exception:
    pass
