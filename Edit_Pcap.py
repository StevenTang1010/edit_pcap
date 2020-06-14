# from scapy.all import *
import time, os, dpkt, configparser
import decorator
import sys
import binascii
import random

sys.setrecursionlimit(2000)


# 配置文件读取类
class GetConfig:
	'''
	读取配置文件
	'''
	
	def __init__(self):
		self.Path_Info = {}
		self.Editor = {}
		self.Edit_Msg = {}
		self.pro_info = {}
		conf = configparser.ConfigParser()
		# config_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
		config_dir = os.path.dirname(os.path.abspath(__file__))
		conf.read(config_dir + os.path.sep + 'config.ini', encoding='utf-8')
		self.Path_Info['path'] = conf.get('Path_Info', 'path')
		self.Path_Info['save_path'] = conf.get('Path_Info', 'save_path')
		
		self.Editor['smac'] = conf.get('Editor', 'smac')
		self.Editor['dmac'] = conf.get('Editor', 'dmac')
		self.Editor['sip'] = conf.get('Editor', 'sip')
		self.Editor['dip'] = conf.get('Editor', 'dip')
		self.Editor['sport'] = conf.get('Editor', 'sport')
		self.Editor['dport'] = conf.get('Editor', 'dport')
		self.Editor['re_str'] = conf.get('Editor', 're_str')
		self.Editor['string'] = conf.get('Editor', 'string')
		self.Editor['tcp'] = conf.getboolean('Editor', 'tcp')
		self.Editor['udp'] = conf.getboolean('Editor', 'udp')
		self.Editor['pcap_offset'] = conf.get('Editor', 'pcap_offset')
		self.Editor['raw_offset'] = conf.get('Editor', 'raw_offset')
		
		self.Edit_Msg['change_mac'] = conf.getboolean('Edit_Msg', 'change_mac')
		self.Edit_Msg['change_ip'] = conf.getboolean('Edit_Msg', 'change_ip')
		self.Edit_Msg['change_port'] = conf.getboolean('Edit_Msg', 'change_port')
		self.Edit_Msg['change_raw'] = conf.getboolean('Edit_Msg', 'change_raw')
		self.Edit_Msg['conv_extract'] = conf.getboolean('Edit_Msg', 'conv_extract')
		self.Edit_Msg['change_time'] = conf.getboolean('Edit_Msg', 'change_time')
		self.Edit_Msg['start_time'] = conf.get('Edit_Msg', 'start_time')
		self.Edit_Msg['time_int'] = conf.get('Edit_Msg', 'time_int')
		self.Edit_Msg['is_hex'] = conf.getboolean('Edit_Msg', 'is_hex')
		self.Edit_Msg['repeat_num'] = conf.get('Edit_Msg', 'repeat_num')
		
		self.pro_info['Syn_Edit'] = conf.getboolean('pro_info', 'Syn_Edit')
		self.pro_info['Editor'] = conf.getboolean('pro_info', 'Editor')
		self.pro_info['Merge_conversation'] = conf.getboolean('pro_info', 'Merge_conversation')
		self.pro_info['EditTime'] = conf.getboolean('pro_info', 'EditTime')


# 基类
class Base:
	'''
	所有类的基类
	'''
	
	def __init__(self, config):
		print('\033[32m开始新的任务……!\033[0m')
		self.Path_Info, self.Editor, self.Edit_Msg = config.Path_Info, config.Editor, config.Edit_Msg
	
	# 自动生成MAC
	@staticmethod
	@decorator.excute_log_return
	def set_mac():
		'''
		:return: 随机生成的MAC地址
		'''
		import random
		maclist = []
		for i in range(1, 7):
			randstr = ''.join(random.sample('0123456789abcdef', 2))
			maclist.append(randstr)
		return ":".join(maclist)
	
	# 自动生成IP
	@staticmethod
	@decorator.excute_log_return
	def set_ip():
		'''
		:return: 随机生成的IP地址
		'''
		import random
		a = random.randint(1, 255)
		b = random.randint(1, 255)
		c = random.randint(1, 255)
		d = random.randint(1, 255)
		ip = '%d.%d.%d.%d' % (a, b, c, d)
		return ip
	
	# 自动生成PORT
	@staticmethod
	@decorator.excute_log_return
	def set_port():
		'''
		:return: 随机生成的PORT地址
		'''
		import random
		return random.randint(1024, 36535)
	
	# 将获取到的MAC对象转换为标准的MAC地址字符串
	@staticmethod
	@decorator.excute_log_return
	def hex_to_mac(mac):
		'''
		:param mac: 16进制的MAC地址对象
		:return: 转码后的常规MAC地址
		'''
		import binascii
		mac = binascii.b2a_hex(mac).decode('utf-8')
		mac_list = list(mac)
		mac_list.insert(2, ':')
		mac_list.insert(5, ':')
		mac_list.insert(8, ':')
		mac_list.insert(11, ':')
		mac_list.insert(14, ':')
		MAC = ''.join(mac_list)
		return MAC
	
	# 将标准的MAC地址字符串转换为MAC对象
	@staticmethod
	@decorator.excute_log_return
	def mac_to_hex(data):
		'''
		:param data: 常规MAC地址
		:return: 转码后的16进制的MAC地址对象
		'''
		import binascii
		mac_str = data.replace(':', '')
		return binascii.a2b_hex(mac_str)
	
	# 将32位打包的IPV4地址转换成标准的IPV4地址字符串
	@staticmethod
	@decorator.excute_log_return
	def ip_to_str(packet_ip):
		'''
		:param packet_ip: 获取到的数据包ip地址对象
		:return: 标准ipv4地址，str
		'''
		import socket
		try:
			return socket.inet_ntoa(packet_ip)
		except:
			return False
	
	# 将标准的IPV4地址字符串转换成32位打包的IPV4地址
	@staticmethod
	@decorator.excute_log_return
	def str_to_ip(string):
		'''
		:param string: 标准ipv4地址，str
		:return: 数据包ip地址对象
		'''
		import socket
		try:
			return socket.inet_aton(string)
		except:
			return False
	
	# 随机生成任意长度字符串
	@decorator.excute_log_return
	def random_str(self):
		'''randomlength:需要生成的字符串长度'''
		import random
		string = ''
		chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
		length = len(chars) - 1
		for i in range(int(self.Syn_Edit['length'])):
			string += chars[random.randint(0, length)]
		return string
	
	# 随机生成匹配正则表达式的字符串
	@decorator.excute_log_return
	def random_re(self):
		import exrex
		re_list = []
		for i in range(int(self.Edit_Msg['repeat_num'])):
			re_list.append(exrex.getone(self.Editor['re_str']))
		return re_list
	
	# 字符串转成标准格式的16进制
	@decorator.excute_log_return
	def str_to_hex(self, string):
		# return ''.join([hex(ord(c)).replace('0x', ' ') for c in string])
		return ''.join([hex(ord(c)) for c in string])
	
	# 提取目录下所有pcap文件
	@decorator.excute_log_return
	def get_file(self, path):
		pcap_list = []
		files = os.listdir(path)
		for file in files:
			if os.path.isdir(os.path.join(path, file)):
				pathx = os.path.join(path, file)
				pcap_listx = self.get_file(pathx)
				for pcap in pcap_listx:
					filepath = os.path.join(pathx, pcap)
					pcap_list.append(filepath)
			else:
				if os.path.splitext(file)[-1][1:] == 'pcap':
					filepath = os.path.join(path, file)
					pcap_list.append(filepath)
		
		return pcap_list
	
	# 通过目录拼接的方式
	@decorator.excute_log_return
	def pathwork(self, path, pcap, newpath):
		old_pathlen = len(path.split('\\'))
		new_pathlen = len(pcap.split('\\'))
		pcap.split('\\')[-1] = '改_' + pcap.split('\\')[-1]
		i = 0
		new_pcap = newpath
		while i < new_pathlen - old_pathlen:
			new_pcap = os.path.join(new_pcap, pcap.split('\\')[old_pathlen + i])
			i += 1
		return new_pcap
	
	# @decorator.excute_log_return
	# def get_pcap(self):
	# 	pcap_list = self.get_file()
	# 	# i = 0
	# 	print('\033[33mThere has %d files \033[0m' % len(pcap_list))
	# 	for pcap in pcap_list:
	# 		pcap_index = pcap_list.index(pcap)
	# 		# t, s, = "|/-\\", (">" * ((pcap_index + 1) % 100)) + (" " * ((len(pcap_list) - (pcap_index + 1)) % 100))
	# 		# t, s, = "|/-\\", (">" * int(((pcap_index + 1) / len(pcap_list)) * 100)) + (
	# 		# 		" " * (100 - int(((pcap_index + 1) / len(pcap_list)) * 100)))
	# 		# i += 1
	# 		# print(pcap)
	# 		yield pcap
	# 		# print("\r[%s][%s][%.2f" % (t[i % 4], s, ((pcap_index + 1) / len(pcap_list) * 100)), "%]", end='')
	# 		print('\r当前处理第 {} / {} 个文件'.format(pcap_list.index(pcap) + 1, len(pcap_list)), end='')
	# 		time.sleep(0.1)
	
	# 获取一个pcap文件中的所有会话（排除非tcp\udp数据），保存在字典中
	@decorator.excute_log_return
	def get_conversation(self):
		'''
		需要传入数据包文件
		:param : 单个数据包文件名
		:return: 返回提取出的tcp会话字典
		'''
		path = self.Path_Info['path']
		pcap_list = self.get_file(path)
		print('\033[33m共包含{}个文件待处理…… \033[0m'.format(len(pcap_list)))
		for file in pcap_list:
			with open(file, 'rb') as f:
				pkts = dpkt.pcap.Reader(f)  # 使用dpkt库读取pcap文件
				conversations = {}  # 申明会话字典
				i = 0
				for ts, buf in pkts:
					i += 1
					eth = dpkt.ethernet.Ethernet(buf)  # 提取链路层内容
					
					if not isinstance(eth.data, dpkt.ip.IP):  # 排除非IP协议的包
						continue
					ip_data = eth.data
					# 提取ip
					sip = self.ip_to_str(ip_data.src)
					dip = self.ip_to_str(ip_data.dst)
					
					if isinstance(ip_data.data, dpkt.tcp.TCP) or isinstance(ip_data.data,
					                                                        dpkt.udp.UDP):  # 排除非TCP\UDP协议的包
						transf_data = ip_data.data
					else:
						continue
					# 提取port
					sport = transf_data.sport
					dport = transf_data.dport
					conv_key = str({'sip': sip, 'dip': dip, 'sport': sport, 'dport': dport})  # 提取一个包的五元组
					if conversations == {}:
						conversations[conv_key] = [list((ts, buf)), ]  # 将五元组和对应的包内容存入字典
					else:
						a = 0
						# 判断五元组是否已存在于字典中
						for key_str in list(conversations.keys()):
							key = eval(key_str)
							if (sip == key['sip'] or sip == key['dip']) and (
									dip == key['sip'] or dip == key['dip']) and (
									sport == key['sport'] or sport == key['dport']) and (
									dport == key['sport'] or dport == key['dport']):
								conversations[key_str].append(list((ts, buf)))  # 如果五元组已存在于字典中，则对此四元组追加数据
								a += 1
								break
						try:
							if a == 0:
								conversations[conv_key] = [list((ts, buf)), ]  # 若不在字典中则新增key数据
						
						# print('\r第%d个包新增会话，Total conversation:%d' % (i, len(conversations)), end='')
						except Exception as e:
							print('\033[1;4;41m%s\033[0m' % e)
			print('当前处理第 {} / {} 个文件,{}'.format(pcap_list.index(file) + 1, len(pcap_list), file))
			
			yield conversations, file
	
	def __del__(self):
		print('')
		print('\033[32m任务执行结束，释放内存……!\033[0m')


# 基于单条TCP会话修改SYN与ACK值
class SynEdit(Base):
	'''
	基于单条会话修改SYN和ACK值
	'''
	
	# 以会话为单位构造每个数据包的seq与ack的值，并写入新文件
	@decorator.excute_log
	def __call__(self):
		'''
		需要传入已修改负载值和负载长度的数据包文件
		:return: 无
		'''
		a = 0
		for conversations, file in self.get_conversation():
			new_file = open(os.path.join(self.Path_Info['save_path'], str(time.time()) + '.pcap'), 'wb')
			# 创建写包对象
			new_file = self.pathwork(self.Path_Info['path'], file, self.Path_Info['save_path'])
			new_file_dir = os.path.split(new_file)[0]
			with open(new_file, 'wb') as new_pcap:
				writer = dpkt.pcap.Writer(new_pcap)
				if not os.path.isdir(new_file_dir):
					os.makedirs(new_file_dir)
				for conversation in conversations.items():
					a += 1
					sort_list = sorted(conversation[1], key=lambda c: c[0])  # 将会话中的包按包头时间排序
					sip, dip, seq, ack, length = '', '', 0, 0, 0
					i = 0
					for ts, pkt in sort_list:  # 提取时间与包内容
						i += 1
						eth = dpkt.ethernet.Ethernet(pkt)  # 获取链路层数据
						ip_data = eth.data  # 获取ip层数据
						
						if not isinstance(eth.data.data, dpkt.tcp.TCP):
							continue
						tcp_data = ip_data.data  # 获取通信层的tcp数据
						
						if sip == '':
							sip = self.ip_to_str(ip_data.src)  # 获取首个包的sip
						
						if dip == '':
							dip = self.ip_to_str(ip_data.dst)  # 获取首个包的dip
						
						if seq == 0:
							seq = tcp_data.seq  # 获取首个包的seq
						if ack == 0:
							ack = tcp_data.ack  # 获取首个包的ack
						
						# 根据ip的方向修改seq和ack的值
						if self.ip_to_str(ip_data.src) == sip:
							tcp_data.seq = seq + length
							tcp_data.ack = ack
						else:
							tcp_data.seq = ack
							tcp_data.ack = seq + length
						
						# 获取当前包的seq和ack值和负载长度，提供给下一个包使用
						seq = tcp_data.seq
						ack = tcp_data.ack
						length = len(tcp_data.data)
						# print(length)
						if self.Edit_Msg['change_time']:
							writer.writepkt(eth)  # 调用写包对象，将修改后的数据和包时间写入新文件，ts不填则写入当前时间
						else:
							writer.writepkt(eth, ts=ts)
						new_pcap.flush()
			# print("\r[%s][%s][%.2f" % (t[i % 4], s, ((con_index + 1) / len(conversations) * 100)), "%]", end='')
			new_pcap.close()


# 基于单条会话修改包内容
class Editor(Base):
	'''
	目前支持修改mac，ip，port，负载
	'''
	
	# 以会话为单位修改每个数据包的seq与ack的值
	@decorator.excute_log
	def syn_edit(self, sip, seq, ack, length, ip_data, tcp_data):
		'''
		执行修改单个包的seq与ack值
		'''
		if seq == 0:
			seq = tcp_data.seq  # 获取首个包的seq
		if ack == 0:
			ack = tcp_data.ack  # 获取首个包的ack
		
		# 根据ip的方向修改seq和ack的值
		if ip_data.src == sip:
			tcp_data.seq = seq + length
			tcp_data.ack = ack
		else:
			tcp_data.seq = ack
			tcp_data.ack = seq + length
	
	# 修改负载内容函数
	@decorator.excute_log
	def raw_edit(self, data):
		try:
			old_data = binascii.b2a_hex(data.data.data).decode(encoding='utf-8')  # 解码十六进制负载数据
		except:
			old_data = data.data.data.decode(encoding='utf-8')  # 解码bytes格式负载数据
		if self.Editor['re_str'] != '':
			string = random.choice(self.random_re())  # 获取生成的符合正则表达式的字符串
		else:
			# string = self.str_to_hex(self.Editor['string'])  # 获取配置的需要修改的字符串
			string = self.Editor['string']  # 获取配置的需要修改的字符串
		# string = 'HTTP/1.1 200 OK\r\nConnection: Keep-Alive\r\nContent-Length: 38\r\nContent-Type: text/plain\r\nDate: Fri, 12 Oct 2018 17: 45: 25 GMT\r\nExpires: 0\r\n\r\n' + '\x85\xf3?O\xab\'$\xd43M\x0b\xeb\xd0rMC5\xcex\x8b1\xad\x976|\x0f\r\n\r\n'  # 获取配置的需要修改的字符串
		try:
			# new_str = old_data[:int(self.Editor['raw_offset'])] + string + old_data[
			#                                                                int(self.Editor['raw_offset']) + len(
			# 	                                                               string):]
			new_str = string
		except:
			new_str = self.str_to_hex(string)  # 如果原始负载长度不够，则直接拼接原始负载
		try:
			data.data.data = binascii.a2b_hex(new_str.encode(encoding='utf-8'))
			data.len = len(string)
		except:
			data.data.data = new_str.encode(encoding='utf8')
			data.len = len(string)
	
	# 改包
	# @decorator.excute_log
	def __call__(self):
		'''
		:return: 修改完成写入新文件
		'''
		# 获取目标pcap文件的所有tcp会话
		# if self.Edit_Msg['start_time']:
		# 	edit_time = time.mktime(time.strptime(self.Edit_Msg['start_time'], '%Y-%m-%d %H:%M:%S'))
		# else:
		# 	edit_time = None
		for conversations, file in self.get_conversation():
			# 创建写包对象
			new_file = self.pathwork(self.Path_Info['path'], file, self.Path_Info['save_path'])
			new_file_dir = os.path.split(new_file)[0]
			if not os.path.isdir(new_file_dir):
				os.makedirs(new_file_dir)
			with open(new_file, 'wb') as new_pcap:
				writer = dpkt.pcap.Writer(new_pcap)
				# 循环遍历会话字典中的每个会话
				print('共计{}条会话'.format(len(conversations)))
				for conversation in conversations.items():
					
					smac = self.mac_to_hex(self.set_mac())
					dmac = self.mac_to_hex(self.set_mac())
					sip = self.str_to_ip(self.set_ip())
					dip = self.str_to_ip(self.set_ip())
					
					sport = self.set_port()
					dport = self.set_port()
					s_mac, d_mac, s_ip, d_ip, s_port, d_port = '', '', '', '', 0, 0
					seq, ack, length = 0, 0, 0
					sort_list = sorted(conversation[1], key=lambda c: c[0])  # 将会话中的包按包头时间排序
					i = 0
					for ts, buf in sort_list:
						pkt = buf
						i += 1
						# if i == 21:
						# 	continue
						eth = dpkt.ethernet.Ethernet(pkt)  # 从链路层提取包内容
						# 修改mac地址
						if self.Edit_Msg['change_mac']:
							# 判断是否为第一个包，如果是，则提取mac
							if s_mac == '' and d_mac == '':
								s_mac = eth.src
								# 判断smac是否有指定需要修改的mac，若没有，则使用随机mac
								if self.Editor['smac'] != '':
									eth.src = self.Editor['smac']
								else:
									eth.src = smac
								# 判断dmac，规则同smac
								d_mac = eth.dst
								if self.Editor['dmac'] != '':
									eth.dst = self.Editor['dmac']
								else:
									eth.dst = dmac
							# 若不是第一个包，直接修改
							else:
								# 判断smac是否为上一个包的smac
								if eth.src == s_mac:
									if self.Editor['smac'] != '':
										eth.src = self.Editor['smac']
									else:
										eth.src = smac
								# 判断smac是否为上一个包的dmac
								elif eth.src == d_mac:
									if self.Editor['dmac'] != '':
										eth.src = self.Editor['dmac']
									else:
										eth.src = dmac
								# 判断dmac是否为上一个包的smac
								if eth.dst == s_mac:
									if self.Editor['smac'] != '':
										eth.dst = self.Editor['smac']
									else:
										eth.dst = smac
								# 判断dmac是否为上一个包的dmac
								elif eth.dst == d_mac:
									if self.Editor['dmac'] != '':
										eth.dst = self.Editor['dmac']
									else:
										eth.dst = dmac
						
						if not isinstance(eth.data, dpkt.ip.IP):  # 这里过滤掉没有IP段的包
							continue
						ip_data = eth.data  # 从IP层提取内容
						
						# 排除非TCP和UDP的数据
						if isinstance(ip_data.data, dpkt.tcp.TCP):
							tcp_data = ip_data.data  # 提取tcp协议负载
						if isinstance(ip_data.data, dpkt.udp.UDP):
							udp_data = ip_data.data  # 提取udp协议负载
						
						# 修改IP地址
						if self.Edit_Msg['change_ip']:
							# print('检测到需要修改IP地址，正在执行……')
							
							# 判断是否为第一个包，如果是，则提取ip
							if s_ip == '' and d_ip == '':
								s_ip = ip_data.src
								d_ip = ip_data.dst
								# 判断sip是否有指定需要修改的ip，若没有，则使用随机ip
								if self.Editor['sip'] != '':
									ip_data.src = self.str_to_ip(self.Editor['sip'])
								else:
									ip_data.src = sip
								
								# 判断dip，规则同sip
								if self.Editor['dip'] != '':
									ip_data.dst = self.str_to_ip(self.Editor['dip'])
								else:
									ip_data.dst = dip
							# 若不是第一个包，直接修改ip
							else:
								# 判断sip是否为上一个包的sip
								if ip_data.src == s_ip:
									if self.Editor['sip'] != '':
										ip_data.src = self.str_to_ip(self.Editor['sip'])
									else:
										ip_data.src = sip
								
								# 判断sip是否为上一个包的dip
								elif ip_data.src == d_ip:
									if self.Editor['dip'] != '':
										ip_data.src = self.str_to_ip(self.Editor['dip'])
									else:
										ip_data.src = dip
								# 判断dip是否为上一个包的sip
								if ip_data.dst == s_ip:
									if self.Editor['sip'] != '':
										ip_data.dst = self.str_to_ip(self.Editor['sip'])
									else:
										ip_data.dst = sip
								# 判断dip是否为上一个包的dip
								elif ip_data.dst == d_ip:
									if self.Editor['dip'] != '':
										ip_data.dst = self.str_to_ip(self.Editor['dip'])
									else:
										ip_data.dst = dip
						
						# 修改端口
						if self.Edit_Msg['change_port']:
							if not len(ip_data.data):  # 排除无传输层及以上数据的包
								continue
							# 排除非TCP和UDP的数据
							if not isinstance(ip_data.data, dpkt.tcp.TCP) and not isinstance(ip_data.data,
							                                                                 dpkt.udp.UDP):
								continue
							transf_data = ip_data.data  # 提取传输层负载
							# 判断是否为第一个包，如果是，则提取port
							if s_port == '' and d_port == '':
								s_port = transf_data.src
								# 判断sport是否有指定需要修改的port，若没有，则使用随机port
								if self.Editor['sport'] != '':
									transf_data.src = int(self.Editor['sport'])
								else:
									transf_data.src = sport
								# 判断dport，规则同sport
								d_ip = transf_data.dst
								if self.Editor['dport'] != '':
									transf_data.dst = int(self.Editor['dport'])
								else:
									transf_data.dst = dport
							# 若不是第一个包，直接修改
							else:
								# 判断sport是否为上一个包的sport
								if transf_data.src == s_port:
									if self.Editor['sport'] != '':
										transf_data.src = int(self.Editor['sport'])
									else:
										transf_data.src = sport
								# 判断sport是否为上一个包的dport
								elif transf_data.src == d_ip:
									if self.Editor['dport'] != '':
										transf_data.src = int(self.Editor['dport'])
									else:
										transf_data.src = dport
								# 判断dport是否为上一个包的sport
								if transf_data.dst == s_port:
									if self.Editor['sport'] != '':
										transf_data.dst = int(self.Editor['sport'])
									else:
										transf_data.dst = sport
								# 判断dport是否为上一个包的dport
								elif transf_data.dst == d_ip:
									if self.Editor['dport'] != '':
										transf_data.dst = int(self.Editor['dport'])
									else:
										transf_data.dst = dport
						
						# 修改负载信息
						if self.Edit_Msg['change_raw']:
							if s_ip == '' and d_ip == '':
								s_ip = ip_data.src
								d_ip = ip_data.dst
							
							# if self.Editor['re_str'] != '':
							# 	string = random.choice(self.random_re())  # 获取生成的符合正则表达式的字符串
							# else:
							# 	string = self.Editor['string']  # 获取配置的需要修改的字符串
							
							if not isinstance(ip_data.data, dpkt.tcp.TCP) and not isinstance(ip_data.data,
							                                                                 dpkt.udp.UDP):
								continue
							
							# if len(tcp_data) <= len(string):  # 判断负载长度是否大于需要修改的负载长度，反之跳过
							# 	continue
							#
							# if len(udp_data) <= len(string):  # 判断负载长度是否大于需要修改的负载长度，反之跳过
							# 	continue
							
							if not self.Editor['tcp'] and not self.Editor['udp']:
								print('\033[1;4;41mplease chose "tcp" or "udp" conversation!\033[0m')
								break
							
							if self.Editor['tcp'] and self.Editor['pcap_offset'] != '':  # 判断是否根据包偏移修改负载
								if int(self.Editor['pcap_offset']) == i:
									self.raw_edit(ip_data)  # 调用修改负载内容
									seq = tcp_data.seq
									ack = tcp_data.ack
									length = len(tcp_data.data)
								
								if int(self.Editor['pcap_offset']) < i:
									self.syn_edit(s_ip, seq, ack, length, ip_data, tcp_data)  # TCP会话修改负载后调用修改syn值函数
									
									# 获取当前包的seq和ack值和负载长度，提供给下一个包使用
									seq = tcp_data.seq
									ack = tcp_data.ack
									length = len(tcp_data.data)
							# writer.writepkt(buf, ts=ts)
							# new_pcap.flush()
							# continue
							elif self.Editor['tcp'] and self.Editor['pcap_offset'] == '':
								self.raw_edit(tcp_data)
								self.syn_edit(s_ip, seq, ack, length, ip_data, tcp_data)
								
								# 获取当前包的seq和ack值和负载长度，提供给下一个包使用
								seq = tcp_data.seq
								ack = tcp_data.ack
								length = len(tcp_data.data)
							
							# else:
							# 	self.raw_edit(tcp_data)
							elif self.Editor['udp'] and self.Editor['pcap_offset'] != '':
								if int(self.Editor['pcap_offset']) == i:
									self.raw_edit(udp_data)
							
							elif self.Editor['udp'] and self.Editor['pcap_offset'] == '':
								self.raw_edit(udp_data)
							else:
								writer.writepkt(buf, ts=ts)
								new_pcap.flush()
								continue
							
							s_ip = ip_data.src
							d_ip = ip_data.dst
						
						# # 获取当前包的seq和ack值和负载长度，提供给下一个包使用
						# seq = tcp_data.seq
						# ack = tcp_data.ack
						# length = len(tcp_data.data)
						
						temp = dpkt.ethernet.Ethernet(src=eth.src, dst=eth.dst, type=eth.type, data=ip_data)
						
						# if self.Edit_Msg['change_time']:
						# 	if edit_time:
						# 		writer.writepkt(buf, ts=edit_time)  # 调用写包对象，将修改后的数据和包时间写入新文件，ts为获取到的需要修改的时间起点
						# 		edit_time += float(self.Edit_Msg['time_int'])
						# 	else:
						# 		writer.writepkt(buf)  # 将修改后的数据和包时间写入新文件，ts不填则写入当前时间
						# 		time.sleep(0.001)
						# else:
						writer.writepkt(temp, ts=ts)
						new_pcap.flush()


# new_pcap.close()


# 负载检测插件
class RawGeter(Base):  # (暂未加入配置)
	'''
	用于提取包含指定负载的包
	'''
	
	# 执行
	@decorator.excute_log
	def find_raw(self, data, string):
		import binascii
		try:
			rawdata = binascii.b2a_hex(data.data).decode(encoding='utf-8')  # 解码十六进制负载数据
		except:
			rawdata = data.data.decode(encoding='utf-8')  # 解码bytes格式负载数据
		
		if string in rawdata:
			return True
		else:
			return False
	
	@decorator.excute_log
	def __call__(self):
		'''
		:return: 完成写入新文件
		'''
		# 获取目标pcap文件的所有tcp会话
		for conversations in self.get_conversation():
			# 创建写包对象
			new_pcap = open(os.path.join(self.Path_Info['save_path'], str(time.time()) + '.pcap'), 'wb')
			writer = dpkt.pcap.Writer(new_pcap)
			# 循环遍历会话字典中的每个会话
			i = 0
			for conversation in conversations.items():
				sort_list = sorted(conversation[1], key=lambda c: c[0])  # 将会话中的包按包头时间排序
				for ts, buf in sort_list:
					eth = dpkt.ethernet.Ethernet(buf)  # 从链路层提取包内容
					ip_data = eth.data  # 从IP层提取内容
					
					# 排除非TCP和UDP的数据
					if isinstance(ip_data.data, dpkt.tcp.TCP):
						tcp_data = ip_data.data  # 提取tcp协议负载
						
						if self.find_raw(tcp_data, ''):
							writer.writepkt(pkt=buf, ts=ts)
							i += 1
						else:
							pass
					
					elif isinstance(ip_data.data, dpkt.udp.UDP):
						udp_data = ip_data.data  # 提取udp协议负载
						
						if self.find_raw(udp_data, ''):
							writer.writepkt(pkt=buf, ts=ts)
							i += 1
						else:
							pass
					
					new_pcap.flush()
			new_pcap.close()
			from . import log
			log.excute_log(info_msg=r'共计提取 {} 条会话！'.format(i))


# 单独修改数据包IP地址(未实现)
class EditIP(Base):
	def __call__(self):
		
		path = self.Path_Info['path']
		pcap_list = self.get_file(path)
		print('共包含{}个文件待处理……'.format(len(pcap_list)))
		print('\033[33mThere has %d files \033[0m' % len(pcap_list))
		
		# 循环遍历会话字典中的每个会话
		for file in pcap_list:
			new_file = self.pathwork(self.Path_Info['path'], file, self.Path_Info['save_path'])
			new_file_dir = os.path.split(new_file)[0]
			if not os.path.isdir(new_file_dir):
				os.makedirs(new_file_dir)
			with open(new_file, 'wb') as new_pcap:
				writer = dpkt.pcap.Writer(new_pcap)
				with open(file, 'rb') as f:
					pkts = dpkt.pcap.Reader(f)
					
					sip = self.str_to_ip(self.set_ip())
					dip = self.str_to_ip(self.set_ip())
					
					s_mac, d_mac, s_ip, d_ip, s_port, d_port = '', '', '', '', 0, 0
					for ts, buf in pkts:
						eth = dpkt.ethernet.Ethernet(buf)  # 从链路层提取包内容
						
						if not isinstance(eth.data, dpkt.ip.IP):  # 这里过滤掉没有IP段的包
							continue
						ip_data = eth.data  # 从IP层提取内容
						
						# 修改IP地址
						if self.Edit_Msg['change_ip']:
							# 判断是否为第一个包，如果是，则提取ip
							if s_ip == '' and d_ip == '':
								s_ip = ip_data.src
								d_ip = ip_data.dst
								# 判断sip是否有指定需要修改的ip，若没有，则使用随机ip
								if self.Editor['sip'] != '':
									ip_data.src = self.str_to_ip(self.Editor['sip'])
								else:
									ip_data.src = sip
								
								# 判断dip，规则同sip
								if self.Editor['dip'] != '':
									ip_data.dst = self.str_to_ip(self.Editor['dip'])
								else:
									ip_data.dst = dip
							# 若不是第一个包，直接修改ip
							else:
								# 判断sip是否为上一个包的sip
								if ip_data.src == s_ip:
									if self.Editor['sip'] != '':
										ip_data.src = self.str_to_ip(self.Editor['sip'])
									else:
										ip_data.src = sip
								
								# 判断sip是否为上一个包的dip
								elif ip_data.src == d_ip:
									if self.Editor['dip'] != '':
										ip_data.src = self.str_to_ip(self.Editor['dip'])
									else:
										ip_data.src = dip
								# 判断dip是否为上一个包的sip
								if ip_data.dst == s_ip:
									if self.Editor['sip'] != '':
										ip_data.dst = self.str_to_ip(self.Editor['sip'])
									else:
										ip_data.dst = sip
								# 判断dip是否为上一个包的dip
								elif ip_data.dst == d_ip:
									if self.Editor['dip'] != '':
										ip_data.dst = self.str_to_ip(self.Editor['dip'])
									else:
										ip_data.dst = dip
						temp = dpkt.ethernet.Ethernet(src=eth.src, dst=eth.dst, type=eth.type, data=ip_data)
						writer.writepkt(temp, ts=ts)
						new_pcap.flush()


# 修改数据包时间
class EditTime(Base):
	'''
	逐个修改数据包包头时间，支持自定义时间
	'''
	
	@decorator.excute_log
	def __call__(self):
		# save_path = os.path.join(self.Path_Info['save_path'], (str(int(time.time())) + '.pcap'))
		# i = 1
		for pcap in self.get_file(self.Path_Info['path']):
			new_file = self.pathwork(self.Path_Info['path'], pcap, self.Path_Info['save_path'])
			new_file_dir = os.path.split(new_file)[0]
			if not os.path.isdir(new_file_dir):
				os.makedirs(new_file_dir)
			with open(new_file, 'wb') as new_pcap:
				writer = dpkt.pcap.Writer(new_pcap)  # 创建写包对象
				with open(pcap, 'rb') as f:
					try:
						pkts = dpkt.pcap.Reader(f)
					except ValueError as e:
						print('')
						print('\033[1;4;41m%s\033[0m%s ,%s is not "pcap" file' % e, pcap)
						continue
					if self.Edit_Msg['start_time']:
						edit_time = time.mktime(time.strptime(self.Edit_Msg['start_time'], '%Y-%m-%d %H:%M:%S'))
					else:
						edit_time = None
					for ts, buf in pkts:
						if self.Edit_Msg['change_time']:
							if edit_time:
								writer.writepkt(buf, ts=edit_time)  # 调用写包对象，将修改后的数据和包时间写入新文件，ts为获取到的需要修改的时间起点
								edit_time += float(self.Edit_Msg['time_int'])
							else:
								writer.writepkt(buf)  # 将修改后的数据和包时间写入新文件，ts不填则写入当前时间
								time.sleep(0.001)
						else:
							writer.writepkt(buf, ts=ts)
						new_pcap.flush()


# 将修改后的单会话数据包合并
class MergeConversation(Base):
	'''
	将修改后的单会话数据包文件合并成一个文件
	'''
	
	@decorator.excute_log
	def __call__(self):
		with open(os.path.join(self.Path_Info['save_path'], str(int(time.time())) + '.pcap'), 'wb') as new_pcap:
			writer = dpkt.pcap.Writer(new_pcap)  # 创建写包对象
			# save_path = os.path.join(self.Path_Info['save_path'], (str(int(time.time())) + '.pcap'))
			path = self.Path_Info['path']
			pcap_list = self.get_file(path)
			for pcap in pcap_list:
				print('当前处理第 {} / {} 个文件,{}'.format(pcap_list.index(pcap) + 1, len(pcap_list), pcap))
				with open(pcap, 'rb') as f:
					pkts = dpkt.pcap.Reader(f)
					for ts, buf in pkts:
						if self.Edit_Msg['change_time']:
							writer.writepkt(buf)  # 调用写包对象，将修改后的数据和包时间写入新文件，ts不填则写入当前时间
						else:
							writer.writepkt(buf, ts=ts)  # 调用写包对象，将修改后的数据和包时间写入新文件，ts不填则写入当前时间
						new_pcap.flush()


if __name__ == '__main__':
	
	config = GetConfig()
	
	if config.pro_info['Syn_Edit']:
		print('检测到需要单独修改syn，正在执行……')
		SynEdit(config)()  # 修改TCP流的SYNACK
	
	elif config.pro_info['Editor']:
		print('检测到修改包内容启用，正在执行……')
		Editor(config)()  # 修改TCP\UDP会话的内容
	
	elif config.pro_info['Merge_conversation']:
		print('检测到需要单独合并会话包，正在执行……')
		MergeConversation(config)()  # 合并多个单条会话为一个文件
	
	elif config.pro_info['EditTime']:
		print('检测到需要单独修改包时间，正在执行……')
		EditTime(config)()  # 仅修改数据包时间
