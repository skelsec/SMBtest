import enum
import binascii
import datetime
import sys
from SMB_logging import LogEntry

def wintime2datetime(timeint):
	return datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=(timeint/ 10.))

#www.codemachine.com/downloads/win71/ntstatus.h
class NTStatus(enum.Enum):
	STATUS_SUCCESS = 0x00000000

#https://msdn.microsoft.com/en-us/library/ee441774.aspx
class SMBHeader():
	def __init__(self, data = None, isSigning=False):
		self.Protocol = ''
		self.isSigning = isSigning
		self.Command  = None
		self.Status   = None
		self.Flags    = None
		self.Flags2   = None
		self.PIDHigh  = None
		self.SecurityFeatures = None
		self.Reserved = None
		self.TID      = None
		self.PIDLow   = None
		self.UID      = None
		self.MID      = None

		if data is not None:
			self.parse(data)

	def parse(self,data):
		"""
		data is expected to be bytes class
		"""
		self.Protocol = data[:4] #This field MUST contain the 4-byte literal string '\xFF', 'S', 'M', 'B',
		self.Command  = SMBCommand(data[4])
		#print(binascii.hexlify(data[5:9]))
		self.Status   = NTStatus(int.from_bytes(data[5:8], byteorder='little'))
		self.Flags    = SMBHeaderFlagsEnum(data[9])
		self.Flags2   = SMBHeaderFlags2Enum(int.from_bytes(data[10:12], byteorder='little'))
		self.PIDHigh  = int.from_bytes(data[12:14], byteorder='little')

		if not self.isSigning:
			self.SecurityFeatures = data[14:22]

		self.Reserved = int.from_bytes(data[22:24], byteorder='little')
		self.TID      = int.from_bytes(data[24:26], byteorder='little')
		self.PIDLow   = int.from_bytes(data[26:28], byteorder='little')
		self.UID      = int.from_bytes(data[28:30], byteorder='little')
		self.MID      = int.from_bytes(data[30:32], byteorder='little')

	def __repr__(self):
		t = '===SMBHeader===\r\n'
		t += 'Command: %s\r\n' % self.Command.name
		t += 'Flags:   %s\r\n' % repr(self.Flags)
		t += 'Flags2:  %s\r\n' % repr(self.Flags2)
		t += 'PIDHigh: %d\r\n' % self.PIDHigh
		t += 'SecurityFeatures: %s\r\n' % self.SecurityFeatures.hex()
		t += 'Reserved: %d\r\n' % self.Reserved
		t += 'TID: %d\r\n' % self.TID
		t += 'PIDLow: %d\r\n' % self.PIDLow
		t += 'UID: %d\r\n' % self.UID
		t += 'MID: %d\r\n' % self.MID
		return t

#https://msdn.microsoft.com/en-us/library/ee441946.aspx
class SMB_COM_NEGOTIATE_REPLY_PARAMS():
	def __init__(self, data = None):
		self.WordCount     = None
		
		self.DialectIndex  = None
		self.SecurityMode  = None
		self.MaxMpxCount   = None
		self.MaxNumberVcs  = None
		self.MaxBufferSize = None
		self.MaxRawSize    = None
		self.SessionKey    = None
		self.Capabilities  = None
		self.SystemTime    = None
		self.ServerTimeZone = None
		self.ChallengeLength= None

		if data is not None:
			self.parse(data)

	def parse(self, data):
		self.WordCount       = data[0]
		self.DialectIndex    = int.from_bytes(data[1:3], byteorder='little')
		self.SecurityMode    = SMBSecurityMode(data[4])
		self.MaxMpxCount     = int.from_bytes(data[5:6], byteorder='little')
		self.MaxNumberVcs    = int.from_bytes(data[6:8], byteorder='little')
		self.MaxBufferSize   = int.from_bytes(data[8:12], byteorder='little')
		self.MaxRawSize      = int.from_bytes(data[12:16], byteorder='little')
		self.SessionKey      = data[16:20]

		self.Capabilities    = SMBCapabilities(int.from_bytes(data[20:24], byteorder='little'))
		self.SystemTime      = wintime2datetime(int.from_bytes(data[24:32], byteorder='little'))
		self.ServerTimeZone  = int.from_bytes(data[32:34], byteorder='little')
		self.ChallengeLength = data[34]


	def __repr__(self):
		t = '===SMB_COM_NEGOTIATE_REPLY_PARAMS===\r\n'
		t += 'WordCount:     %d\r\n' % self.WordCount
		t += 'DialectIndex:  %d\r\n' % self.DialectIndex
		t += 'SecurityMode:  %s\r\n' % repr(self.SecurityMode)
		t += 'MaxMpxCount:   %d\r\n' % self.MaxMpxCount
		t += 'MaxNumberVcs:  %d\r\n' % self.MaxNumberVcs
		t += 'MaxBufferSize: %d\r\n' % self.MaxBufferSize
		t += 'MaxRawSize:    %d\r\n' % self.MaxRawSize
		t += 'SessionKey:    %s\r\n' % self.SessionKey.hex()
		t += 'Capabilities:  %s\r\n' % repr(self.Capabilities)
		t += 'SystemTime:    %s\r\n' % self.SystemTime.isoformat()
		t += 'ServerTimeZone:    %s\r\n' % self.ServerTimeZone
		t += 'ChallengeLength:    %d\r\n' % self.ChallengeLength

		return t

#https://msdn.microsoft.com/en-us/library/ee441946.aspx
class SMB_COM_NEGOTIATE_REPLY_DATA():
	def __init__(self, data = None):
		self.ByteCount     = None
		self.data = None

		if data is not None:
			self.parse(data)

	def parse(self, data):
		self.ByteCount       = int.from_bytes(data[0:2], byteorder='little')
		self.data = data[2:2+self.ByteCount]

	def __repr__(self):
		t = '===SMB_COM_NEGOTIATE_REPLY_DATA===\r\n'
		t += 'ByteCount:     %d\r\n' % self.ByteCount
		t += 'data:     %s\r\n' % self.data.hex()
		return t

class SMB_COM_NEGOTIATE_REPLY():
	def __init__(self):
		self.params = SMB_COM_NEGOTIATE_REPLY_PARAMS()
		self.data   = SMB_COM_NEGOTIATE_REPLY_DATA()

	def __repr__(self):
		t = '===SMB_COM_NEGOTIATE_REPLY===\r\n'
		t += repr(self.params)
		t += repr(self.data)	
		return t


class SMB_COM_NEGOTIATE_REQ_DATA():
	def __init__(self, data = None):
		self.ByteCount = None
		self.Dialects  = []

		if data is not None:
			self.parse(data)

	def parse(self, data):
		self.ByteCount = int.from_bytes(data[0:2], byteorder='little')
		for raw in data[2:].split(b'\x00'):
			if raw == b'':
				continue
			self.Dialects.append(SMB_Dialect(raw))


	def __repr__(self):
		t  = 'ByteCount: %d\r\n' % self.ByteCount
		t += 'Dialects:\r\n'
		for dialect in self.Dialects:
			t += '\t%s\r\n' % repr(dialect)
		
		return t


#https://msdn.microsoft.com/en-us/library/ee441913.aspx
class SMB_COM_NEGOTIATE_REQ_PARAMS():
	def __init__(self, data = None):
		self.WordCount = None

		if data is not None:
			self.parse(data)

	def parse(self, data):
		self.WordCount = data[0]
		
	def __repr__(self):
		t = ''
		t += 'WordCount: %d\r\n' % self.WordCount		
		return t

class SMB_COM_NEGOTIATE_REQ():
	def __init__(self):
		self.params = SMB_COM_NEGOTIATE_REQ_PARAMS()
		self.data   = SMB_COM_NEGOTIATE_REQ_DATA()

	def __repr__(self):
		t = '===SMB_COM_NEGOTIATE_REQ===\r\n'
		t += repr(self.params)
		t += repr(self.data)	
		return t

#https://msdn.microsoft.com/en-us/library/ee441616.aspx
class SMBCommand(enum.Enum): #SMB_COM
	SMB_COM_CREATE_DIRECTORY = 0x00
	SMB_COM_DELETE_DIRECTORY = 0x01
	SMB_COM_OPEN = 0x02
	SMB_COM_CREATE  = 0x03
	SMB_COM_CLOSE = 0x04
	SMB_COM_FLUSH = 0x05
	SMB_COM_DELETE = 0x06
	SMB_COM_RENAME = 0x07
	SMB_COM_QUERY_INFORMATION = 0x08
	SMB_COM_SET_INFORMATION = 0x09
	SMB_COM_READ = 0x0A
	SMB_COM_WRITE = 0x0B
	SMB_COM_LOCK_BYTE_RANGE = 0x0C
	SMB_COM_UNLOCK_BYTE_RANGE = 0x0D
	SMB_COM_CREATE_TEMPORARY = 0x0E
	SMB_COM_CREATE_NEW = 0x0F
	SMB_COM_CHECK_DIRECTORY = 0x10
	SMB_COM_PROCESS_EXIT = 0x11
	SMB_COM_SEEK = 0x12
	SMB_COM_LOCK_AND_READ = 0x13
	SMB_COM_WRITE_AND_UNLOCK = 0x14
	#Unused 0x15-0x19
	SMB_COM_READ_RAW = 0x1A
	SMB_COM_READ_MPX = 0x1B
	SMB_COM_READ_MPX_SECONDARY = 0x1C
	SMB_COM_WRITE_RAW = 0x1D
	SMB_COM_WRITE_MPX = 0x1E
	SMB_COM_WRITE_MPX_SECONDARY = 0x1F
	SMB_COM_WRITE_COMPLETE = 0x20
	SMB_COM_QUERY_SERVER  = 0x21
	SMB_COM_SET_INFORMATION2 = 0x22
	##### TODODODODODODODO!!!!!!!!!!!!!!!!!
	SMB_COM_NEGOTIATE = 0x72
	SMB_COM_SESSION_SETUP_ANDX = 0x73
	SMB_COM_LOGOFF_ANDX = 0x74
	SMB_COM_TREE_CONNECT_ANDX = 0x75

class SMBHeaderFlagsEnum(enum.IntFlag):
	SMB_FLAGS_LOCK_AND_READ_OK = 0x01
	SMB_FLAGS_BUF_AVAIL = 0x02
	Reserved = 0x04
	SMB_FLAGS_CASE_INSENSITIVE = 0x08
	SMB_FLAGS_CANONICALIZED_PATHS = 0x10
	SMB_FLAGS_OPLOCK = 0x20
	SMB_FLAGS_OPBATCH = 0x40
	SMB_FLAGS_REPLY = 0x80

class SMBHeaderFlags2Enum(enum.IntFlag):
	SMB_FLAGS2_LONG_NAMES = 0x0001
	SMB_FLAGS2_EAS = 0x0002
	SMB_FLAGS2_SMB_SECURITY_SIGNATURE = 0x0004
	SMB_FLAGS2_IS_LONG_NAME = 0x0040
	SMB_FLAGS2_DFS = 0x1000
	SMB_FLAGS2_PAGING_IO = 0x2000
	SMB_FLAGS2_NT_STATUS = 0x4000
	SMB_FLAGS2_UNICODE = 0x8000

class SMBSecurityMode(enum.IntFlag):
	NEGOTIATE_USER_SECURITY = 0x01
	NEGOTIATE_ENCRYPT_PASSWORDS = 0x02
	NEGOTIATE_SECURITY_SIGNATURES_ENABLED = 0x04
	NEGOTIATE_SECURITY_SIGNATURES_REQUIRED = 0x08
	#others are Reserved

class SMBCapabilities(enum.IntFlag):
	CAP_RAW_MODE         = 0x00000001
	CAP_MPX_MODE         = 0x00000002
	CAP_UNICODE          = 0x00000004
	CAP_LARGE_FILES      = 0x00000008
	CAP_NT_SMBS          = 0x00000010
	CAP_RPC_REMOTE_APIS  = 0x00000020
	CAP_STATUS32         = 0x00000040
	CAP_LEVEL_II_OPLOCKS = 0x00000080
	CAP_LOCK_AND_READ    = 0x00000100
	CAP_NT_FIND          = 0x00000200
	CAP_BULK_TRANSFER    = 0x00000400
	CAP_COMPRESSED_DATA  = 0x00000800
	CAP_DFS              = 0x00001000
	CAP_QUADWORD_ALIGNED = 0x00002000
	CAP_LARGE_READX      = 0x00004000

class SMB_Dialect():
	def __init__(self, data = None):
		self.BufferFormat = None
		self.DialectString = None

		if data is not None:
			self.parse(data)

	def parse(self, data):
		self.BufferFormat  = data[0]
		self.DialectString = data[1:].decode('ascii')

	def __repr__(self):
		t = ''
		t += 'DialectString: %s' % self.DialectString
		return t

class SMBMessage():
	def __init__(self):
		self.header    = None
		self.command   = None

	def parse_header(self, data):
		self.header = SMBHeader(data[:32])
		classname = self.header.Command.name
		if SMBHeaderFlagsEnum.SMB_FLAGS_REPLY in self.header.Flags:
			classname += '_REPLY'
		else:
			classname += '_REQ'
		class_ = getattr(sys.modules[__name__], classname)
		self.command = class_()


	def __repr__(self):
		t = repr(self.header)
		t += repr(self.command)
		return t



"""
if __name__ == '__main__':

	smb_data = binascii.unhexlify('ff534d4272000000001843c80000000000000000000000000000fffe00000000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200')
	#print(header_data)
	hdr = SMBHeader(smb_data[:32])
	print(repr(hdr))
	nego = SMB_COM_NEGOTIATE_RQ(smb_data[32:])
	print(repr(nego))

	smb_data_response = binascii.unhexlify('ff534d4272000000009843c80000000000000000000000000000fffe00000000110500030a000100041100000000010000000000fce301801d63369b8427d20188ff0050012cd03d3fb200e14fbdd4c8b70c2756666082013c06062b0601050502a08201303082012ca01a3018060a2b06010401823702021e060a2b06010401823702020aa282010c048201084e45474f4558545301000000000000006000000070000000313c2a3ac72b3ca96dac3874a7dd1d5bf4526b17038a4b91c2097d9a8fe62c965c51242f904d47c7ad8f876b2202bfc60000000000000000600000000100000000000000000000005c33530deaf90d4db2ec4ae3786ec3084e45474f4558545303000000010000004000000098000000313c2a3ac72b3ca96dac3874a7dd1d5b5c33530deaf90d4db2ec4ae3786ec30840000000580000003056a05430523027802530233121301f06035504031318546f6b656e205369676e696e67205075626c6963204b65793027802530233121301f06035504031318546f6b656e205369676e696e67205075626c6963204b6579')
	#print(header_data)
	hdr = SMBHeader(smb_data_response[:32])
	print(repr(hdr))
	nego = SMB_COM_NEGOTIATE_RES(smb_data_response[32:])
	print(repr(nego))
"""