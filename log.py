# coding: utf-8

import logging, time, os
from logging.handlers import RotatingFileHandler
from logging import handlers

path = os.getcwd()

e_path = os.path.join(path, 'logs')
r_path = os.path.join(path, 'logs')

# time_now = time.strftime('%y%m%d', time.localtime(time.time()))
time_now = str(int(time.time()))
elog_name = os.path.join(e_path, 'excute') + time_now + '.log'
rlog_name = os.path.join(r_path, 'excute') + time_now + '.log'

if os.path.exists(os.path.dirname(elog_name)):
    pass
else:
    os.mkdir(os.path.dirname(elog_name))

if os.path.exists(os.path.dirname(rlog_name)):
    pass
else:
    os.mkdir(os.path.dirname(rlog_name))


def excute_log(info_msg='', error_msg='', warning_msg=''):
    logger = logging.getLogger(__name__)
    logger.setLevel(level=logging.INFO)
    log_handle = RotatingFileHandler(elog_name, maxBytes=100 * 1024 * 1024, backupCount=20, )
    format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    log_handle.setFormatter(format)
    logger.addHandler(log_handle)
    try:
        if info_msg:
            logger.info(info_msg)
        elif error_msg:
            logger.error(error_msg)
        elif warning_msg:
            logger.warning(warning_msg)
    except Exception as e:
        print(e)

    logger.removeHandler(log_handle)


def result_log(msg):
    logger = logging.getLogger(__name__)
    logger.setLevel(level=logging.INFO)
    log_handle = logging.FileHandler(rlog_name, mode='a')
    format = logging.Formatter('%(asctime)s - %(message)s')
    log_handle.setFormatter(format)
    logger.addHandler(log_handle)

    try:
        logger.info(msg)
        print('\n')
    except Exception as e:
        print(e)

    logger.removeHandler(log_handle)

# msg = 'this is msg'
# excute_log(msg)
# print get_cases()[0]
