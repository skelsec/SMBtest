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

	smb_data = binascii.unhexlify('ff534d4272000000001843c80000000000000000000000000000fffe00000000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200')
	s.sendall(smb_data)

	input('Press for test2222!\r\n')

	smb_data_response = binascii.unhexlify('ff534d4272000000009843c80000000000000000000000000000fffe00000000110500030a000100041100000000010000000000fce301801d63369b8427d20188ff0050012cd03d3fb200e14fbdd4c8b70c2756666082013c06062b0601050502a08201303082012ca01a3018060a2b06010401823702021e060a2b06010401823702020aa282010c048201084e45474f4558545301000000000000006000000070000000313c2a3ac72b3ca96dac3874a7dd1d5bf4526b17038a4b91c2097d9a8fe62c965c51242f904d47c7ad8f876b2202bfc60000000000000000600000000100000000000000000000005c33530deaf90d4db2ec4ae3786ec3084e45474f4558545303000000010000004000000098000000313c2a3ac72b3ca96dac3874a7dd1d5b5c33530deaf90d4db2ec4ae3786ec30840000000580000003056a05430523027802530233121301f06035504031318546f6b656e205369676e696e67205075626c6963204b65793027802530233121301f06035504031318546f6b656e205369676e696e67205075626c6963204b6579')
	s.sendall(smb_data_response)

	s.close()
	time.sleep(10)