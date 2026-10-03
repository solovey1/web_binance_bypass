from datetime import datetime

from utils.paths import LOGS_DIR

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'console': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S',
            'log_colors': {
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            }
        },
        'file': {
            'format': '[%(asctime)s] %(name)-6s %(levelname)-4s — %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'console'
        },
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'formatter': 'file',
            'filename': LOGS_DIR / f"{datetime.now().strftime('%d-%m-%Y')}.log",
            'when': 'midnight',
            'interval': 1,
            'backupCount': 10,
            'encoding': 'utf-8',
        },
    },
    'loggers': {
        'httpcore': {
            'level': 'WARNING',
            'handlers': ['console', 'file'],
            'propagate': False
        },
        'httpx': {
            'level': 'WARNING',
            'handlers': ['console', 'file'],
            'propagate': False
        },
        '': {
            'level': 'INFO',
            'handlers': ['file', 'console'],
            'propagate': False,
        }
    }
}
