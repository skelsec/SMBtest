import asyncio
import logging
import datetime
import enum
import socket
import multiprocessing
import logging
import traceback

from SMB_packets import *
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
		self._buffer_maxsize = 10*1024
		self._buffer_minsize = 33
		self._remaining_bytes = self._buffer_minsize
		self._request_data_size = self._buffer_maxsize #TODO: this should be set based on the SMB flags in the _SMBHeader
		self._transport = None
		self._buffer = b''
		self._SMBMessage = SMBMessage()


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
			if len(self._buffer) <= self._buffer_minsize:
				self._server.log(logging.DEBUG, 'Need moar data!!!')
				return

			if self._SMBMessage.header is None:
				self._SMBMessage.parse_header(self._buffer[:32])
				self._server.log(logging.DEBUG, 'SMB header parsed')

			#BE CAREFUL DO NOT WRITE IT AS 'ELSE' because it will stop the processing of remaining data and break the comms!!!
			if self._SMBMessage.header is not None:
				if self._SMBMessage.command.params.WordCount is None:
					wordcount = self._buffer[32]
					parameter_size = wordcount*2
					if parameter_size > len(self._buffer[33:]):
						self._server.log(logging.DEBUG, 'Need moar data for params!!!')
						return

					self._server.log(logging.DEBUG, 'SMB parsing params')
					self._SMBMessage.command.params.parse(self._buffer[32:33+parameter_size])

				if self._SMBMessage.command.params.WordCount is not None:
					bytecountPos = 33+(2*self._SMBMessage.command.params.WordCount)
					bytecount = int.from_bytes(self._buffer[bytecountPos:bytecountPos+1], byteorder='little')
					if bytecount > len(self._buffer[bytecountPos:]):
						self._server.log(logging.DEBUG, 'Need moar data for data!!!')
						return

					self._server.log(logging.DEBUG, 'SMB parsing data')
					self._SMBMessage.command.data.parse(self._buffer[bytecountPos:])

					#all parts of the message is recieved, clearing out buffer!
					self._buffer = b''
					#we send the self._SMBMessage to the SMBServer's handle function to deal with higher-layer 
					self._server.handle(self._SMBMessage)
					#re clear out the self._SMBMessage as it is not needed anymore
					self._SMBMessage = SMBMessage()

		except Exception as e:
			self._server.log(logging.INFO,'Exception! %s' % (str(e),))
			traceback.print_exc()





