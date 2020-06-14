import traceback
import log
from functools import wraps

'''
装饰器模块，目前提供打印完整错误日志功能
'''


# 打印日志，用于有返回值的函数
def excute_log_return(func):
	@wraps(func)
	def wrapper(*args, **kwargs):
		try:
			ret = func(*args, **kwargs)
		except Exception:
			msg = traceback.format_exc()
			log.excute_log(error_msg='error is in {}: {}'.format(func.__name__, msg))
		else:
			return ret
	
	return wrapper


# 打印日志，用于无返回值的函数
def excute_log(func):
	@wraps(func)
	def wrapper(*args, **kwargs):
		try:
			func(*args, **kwargs)
		except Exception:
			msg = traceback.format_exc()
			log.excute_log(error_msg='error is in {}: {}'.format(func.__name__, msg))
	
	return wrapper


# 打印日志，专用于mysqldb的析构
def dbclose_log(func):
	@wraps(func)
	def wrapper(*args, **kwargs):
		try:
			func(*args, **kwargs)
		except Exception:
			msg = traceback.format_exc()
			log.excute_log(info_msg='error is in {}'.format(func.__name__), error_msg=msg)
		else:
			log.excute_log(info_msg='DB Connect closed!')
	
	return wrapper
