import multiprocessing
import logging
import logging.config
import logging.handlers

class LogEntry():
	def __init__(self, level, name, msg):
		self.level = level
		self.name  = name
		self.msg   = msg

	def __str__(self):
		return "[%s] %s" % (self.name, self.msg)

class LogProcessor(multiprocessing.Process):
	def __init__(self, logsettings, resultQ):
		multiprocessing.Process.__init__(self)
		self.resultQ     = resultQ
		self.logsettings = logsettings

	def log(self, level, message):
		self.handleLog(LogEntry(level, self.name, message))

	def setup(self):
		logging.config.dictConfig(self.logsettings['log'])
	
	def run(self):
		self.setup()		
		self.log(logging.INFO,'setup done')
		while True:
			resultObj = self.resultQ.get()
			if isinstance(resultObj, LogEntry):
				self.handleLog(resultObj)
			else:
				raise Exception('Unknown object in queue!')

	def handleLog(self, log):
		logging.log(log.level, str(log))