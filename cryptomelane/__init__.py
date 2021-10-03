import logging
import logging.config


def setup_loggers():
    # half stolen from cloudbot, half hand written
    conf = {
        'version': 1,
        'formatters': {
            'short': {
                'format': '[%(asctime)s][%(levelname)s][%(filename)s:%(lineno)d]\t%(message)s',
                'datefmt': '%H:%M:%S'
            }
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'formatter': 'short',
                'level': logging.DEBUG,
                'stream': 'ext://sys.stdout'
            }
        },
        'loggers': {
            'irc': {'level': logging.DEBUG, 'handlers': ['console']},
            'cryptomelane': {'level': logging.DEBUG, 'handlers': ['console']},
        }
    }

    logging.config.dictConfig(conf)


setup_loggers()
