import asyncio
import logging
import datetime
import enum
import socket
import multiprocessing
import logging
import traceback

from SMB_packets import *
from SMB2_packets import *
from SMB_logging import LogEntry

class SMBServer(multiprocessing.Process):
	def __init__(self, port, logQ):
		multiprocessing.Process.__init__(self)
		#logging.basicConfig(level=logging.DEBUG)
		self.port     = port
		self.loop     = None
		self.logQ     = logQ
		self.peername = None #this is set when a connection is made!
		self.peerport = None
		self.SMBSession = None #this should hold the session related info, not yet implemented

	def setup(self):
		self.loop     = asyncio.get_event_loop()

	def log(self, level, message):
		if self.peername == None:
			message = '[INIT] %s' %  message
		else:	
			message = '[%s:%d] %s' % (self.peername, self.peerport, message)
		self.logQ.put(LogEntry(level, self.modulename(), message))

	def modulename(self):
		return 'SMBServer'
	
	def run(self):
		self.setup()
		self.log(logging.INFO,'setup done')
		coro = self.loop.create_server(
							protocol_factory=lambda: SMBProtocolTCP(self),
							host="",
							port=self.port
		)

		self.log(logging.INFO,'Starting server!')
		self.loop.run_until_complete(coro)
		self.loop.run_forever()

	def handle(self, message):
		try:
			print(repr(message))
		except Exception as e:
			self.log(logging.INFO,'Exception! %s' % (str(e),))
			traceback.print_exc()
			return

class SMBProtocolTCP(asyncio.Protocol):
	
	def __init__(self, server):
		#SMB session parameters should be stored in self._server.SMBSession object!
		#asyncio.Protocol.__init__(self)
		self._server = server
		self._netbios_session_recv = False
		self._buffer_maxsize = 10*1024
		self._buffer_minsize = 4
		self._remaining_bytes = self._buffer_minsize
		self._request_data_size = self._buffer_maxsize #TODO: this should be set based on the SMB flags in the _SMBHeader
		self._transport = None
		self._buffer = b''
		self._SMBMessage = SMBMessage()
		self._SMB2Message = SMB2Message()


	def connection_made(self, transport):
		try:
			self._server.peername, self._server.peerport = transport.get_extra_info('socket').getpeername()
			self._server.log(logging.INFO, 'New connection opened from %s:%d' % (self._server.peername, self._server.peerport))
			self._transport = transport
		except Exception as e:
			self._server.log(logging.INFO,'Exception! %s' % (str(e),))
			traceback.print_exc()

	def data_received(self, raw_data):
			self._buffer += raw_data
			self._parsebuff()

	def connection_lost(self, exc):
		self._server.log(logging.INFO, 'Connection lost!')



	## Override this to start handling the buffer, the data is in self._buffer as a string!
	def _parsebuff(self):
		try:
			if not self._netbios_session_recv:
				if len(self._buffer) <= self._buffer_minsize:
					self._server.log(logging.DEBUG, 'Need moar data!!!')
					return

				if len(self._buffer) > self._buffer_minsize:
					assert self._buffer[0] == 0, "This is not SMB data"
					self._buffer_maxsize = int.from_bytes(self._buffer[1:4],byteorder='big') + 4
					self._netbios_session_recv = True

			if len(self._buffer) >= self._buffer_maxsize:
				#check version of SMB
				if self._buffer[4] == 0xFE:
					self._parse_SMBv2(self._buffer[4:self._buffer_maxsize])
					self._clean_buffer()

				elif self._buffer[4] == 0xFF:
					self._parse_SMBv1(self._buffer[4:self._buffer_maxsize])
					self._clean_buffer()
				else:
					raise Exception('Not SMB traffic!')

		except Exception as e:
			self._server.log(logging.INFO,'Exception! %s' % (str(e),))
			traceback.print_exc()

	def _clean_buffer(self):
		self._SMBMessage = SMBMessage()
		self._buffer = self._buffer[self._buffer_maxsize:]
		self._netbios_session_recv = False
		self._buffer_maxsize = 10*1024
		self._parsebuff()


	def _parse_SMBv2(self, buff):
		self._SMB2Message.parse_header(buff[:64])
		self._server.log(logging.DEBUG, 'SMB header parsed')
		self._SMB2Message.command.parse(buff[64:])

		self._server.handle(self._SMB2Message)
		self._clean_buffer()

	def _parse_SMBv1(self, buff):
		try:
			self._SMBMessage.parse_header(buff[:32])
			self._server.log(logging.DEBUG, 'SMB header parsed')

			wordcount = buff[32]
			parameter_size = wordcount*2
			self._server.log(logging.DEBUG, 'SMB parsing params')
			self._SMBMessage.command.params.parse(buff[32:33+parameter_size])

			bytecountPos = 33+(2*self._SMBMessage.command.params.WordCount)
			bytecount = int.from_bytes(buff[bytecountPos:bytecountPos+1], byteorder='little')
			self._server.log(logging.DEBUG, 'SMB parsing data')
			
			self._SMBMessage.command.data.parse(buff[bytecountPos:])
			
			#we send the self._SMBMessage to the SMBServer's handle function to deal with higher-layer 
			self._server.handle(self._SMBMessage)
		
			self._clean_buffer()
			

		except Exception as e:
			self._server.log(logging.INFO,'Exception! %s' % (str(e),))
			traceback.print_exc()
