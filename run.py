from SMB_asyncio_comm import SMBServer
from SMB_logging import *
import multiprocessing
import socket
import time
import os
import binascii

if __name__ == '__main__':
	#os.environ['PYTHONASYNCIODEBUG'] = 'YESPLEASE!' 

	#Setting up logger
	logconfig = {}
	logconfig['log'] = {
		'version': 1,
		'formatters': {
			'detailed': {
				'class': 'logging.Formatter',
					'format': '%(asctime)s %(name)-15s %(levelname)-8s %(processName)-10s %(message)s'
			}
		},
		'handlers': {
			'console': {
				'class': 'logging.StreamHandler',
				'level': 'DEBUG',
			}
		},
		'root': {
			'level': 'DEBUG',
			'handlers': ['console']
		}
	}

	logQ = multiprocessing.Queue()
	logger = LogProcessor(logconfig, logQ)
	logger.daemon = True
	logger.start()
	#Setting up server!

	srv = SMBServer(1445, logQ)
	srv.daemon = True
	srv.start()

	input('Press for test!\r\n')

	#connecting to server
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('127.0.0.1', 1445))

	with open('test_data_SMBv3_enc.hex','r') as f:
		ctr = 0
		for line in f:
			input('Packet #%d' % ctr )
			data = bytes.fromhex(line.strip())
			#print(repr(data))
			s.sendall(data)
			ctr += 1

	"""
	smb_data = binascii.unhexlify('0000009bff534d4272000000001853c8000000000000000000000000fffffffe00000000007800025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e31320002534d4220322e3030320002534d4220322e3f3f3f00')
	s.sendall(smb_data)

	input('Press for test2222!\r\n')

	smb_data_response = binascii.unhexlify('000001c0fe534d4240000000000000000000010001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041000100ff0200002cd03d3fb200e14fbdd4c8b70c27566603000000000001000000010000000100d5e3309b8427d20107b3628d6527d20180004001000000006082013c06062b0601050502a08201303082012ca01a3018060a2b06010401823702021e060a2b06010401823702020aa282010c048201084e45474f45585453010000000000000060000000700000002e3c2a3ac72b3ca96dac3874a7dd1d5b0148bc69e7138869cc545f23927e2cbfbde8e0211f749ca3099b93c895e97b0c0000000000000000600000000100000000000000000000005c33530deaf90d4db2ec4ae3786ec3084e45474f45585453030000000100000040000000980000002e3c2a3ac72b3ca96dac3874a7dd1d5b5c33530deaf90d4db2ec4ae3786ec30840000000580000003056a05430523027802530233121301f06035504031318546f6b656e205369676e696e67205075626c6963204b65793027802530233121301f06035504031318546f6b656e205369676e696e67205075626c6963204b6579')
	s.sendall(smb_data_response)
	"""
	s.close()
	time.sleep(10)