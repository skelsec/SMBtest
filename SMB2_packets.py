import sys
import enum
import uuid

from NTStatus import *
from SMB_utils import *

class SMB2HeaderFlag(enum.IntFlag):
	SMB2_FLAGS_SERVER_TO_REDIR    = 0x00000001 #When set, indicates the message is a response rather than a request. This MUST be set on responses sent from the server to the client, and MUST NOT be set on requests sent from the client to the server.
	SMB2_FLAGS_ASYNC_COMMAND      = 0x00000002 #When set, indicates that this is an ASYNC SMB2 header. Always set for headers of the form described in this section.
	SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004
	SMB2_FLAGS_SIGNED             = 0x00000008 #When set, indicates that this packet has been signed. The use of this flag is as specified in section 3.1.5.1.
	SMB2_FLAGS_PRIORITY_MASK      = 0x00000070 #This flag is only valid for the SMB 3.1.1 dialect. It is a mask for the requested I/O priority of the request, and it MUST be a value in the range 0 to 7.
	SMB2_FLAGS_DFS_OPERATIONS     = 0x10000000 #When set, indicates that this command is a Distributed File System (DFS) operation. The use of this flag is as specified in section 3.3.5.9.
	SMB2_FLAGS_REPLAY_OPERATION   = 0x20000000

#https://msdn.microsoft.com/en-us/library/cc246528.aspx
class SMB2Command(enum.Enum):
	NEGOTIATE       = 0x0000
	SESSION_SETUP   = 0x0001
	LOGOFF          = 0x0002
	TREE_CONNECT    = 0x0003
	TREE_DISCONNECT = 0x0004
	CREATE          = 0x0005
	CLOSE           = 0x0006
	FLUSH           = 0x0007
	READ            = 0x0008
	WRITE           = 0x0009
	LOCK            = 0x000A
	IOCTL           = 0x000B
	CANCEL          = 0x000C
	ECHO            = 0x000D
	QUERY_DIRECTORY = 0x000E
	CHANGE_NOTIFY   = 0x000F
	QUERY_INFO      = 0x0010
	SET_INFO        = 0x0011
	OPLOCK_BREAK    = 0x0012


#https://msdn.microsoft.com/en-us/library/cc246528.aspx
class SMB2Header_ASYNC():
	def __init__(self, data = None):
		self.ProtocolId    = None
		self.StructureSize = None
		self.CreditCharge  = None
		self.Status        = None
		self.Command       = None
		self.Credit        = None
		self.Flags         = None
		self.NextCommand   = None
		self.MessageId     = None
		self.AsyncId       = None
		self.SessionId     = None
		self.Signature     = None

		if data is not None:
			self.parse(data)

	def parse(self, data):
		self.ProtocolId = data[:4]
		assert self.ProtocolId == b'\xFESMB'
		self.StructureSize = int.from_bytes(data[4:6], byteorder='little')
		assert self.StructureSize == 64
		self.CreditCharge = int.from_bytes(data[6:8], byteorder='little')
		self.Status = NTStatus(int.from_bytes(data[8:12], byteorder='little'))
		self.Command = SMB2Command(int.from_bytes(data[12:14], byteorder='little'))
		self.Credit =  int.from_bytes(data[14:16], byteorder='little')
		self.Flags =  SMB2HeaderFlag(int.from_bytes(data[16:20], byteorder='little'))
		self.NextCommand = int.from_bytes(data[20:24], byteorder='little')
		self.MessageId = data[24:32]
		self.AsyncId = data[32:40]
		self.SessionId = data[40:48]
		self.Signature = data[48:64]

	def __repr__(self):
		t = '===SMB2 HEADER ASYNC===\r\n'
		t += 'ProtocolId: %s\r\n' % self.ProtocolId
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'CreditCharge: %s\r\n' % self.CreditCharge
		t += 'Status: %s\r\n' % self.Status.name
		t += 'Command: %s\r\n' % self.Command.name
		t += 'Credit: %s\r\n' % self.Credit
		t += 'Flags: %s\r\n' % self.Flags
		t += 'NextCommand: %s\r\n' % self.NextCommand
		t += 'MessageId: %s\r\n' % self.MessageId
		t += 'AsyncId: %s\r\n' % self.AsyncId
		t += 'SessionId: %s\r\n' % self.SessionId
		t += 'Signature: %s\r\n' % self.Signature
		return t

class SMB2Header_SYNC():
	def __init__(self, data = None):
		self.ProtocolId    = None
		self.StructureSize = None
		self.CreditCharge  = None
		self.Status        = None
		self.Command       = None
		self.Credit        = None
		self.Flags         = None
		self.NextCommand   = None
		self.MessageId     = None
		self.Reserved      = None
		self.TreeId        = None
		self.SessionId     = None
		self.Signature     = None

		if data is not None:
			self.parse(data)

	def parse(self, data):
		self.ProtocolId = data[:4]
		assert self.ProtocolId == b'\xFESMB'
		self.StructureSize = int.from_bytes(data[4:6], byteorder='little')
		assert self.StructureSize == 64
		self.CreditCharge = int.from_bytes(data[6:8], byteorder='little')
		self.Status      = NTStatus(int.from_bytes(data[8:12], byteorder='little'))
		self.Command     = SMB2Command(int.from_bytes(data[12:14], byteorder='little'))
		self.Credit      = int.from_bytes(data[14:16], byteorder='little')
		self.Flags       = SMB2HeaderFlag(int.from_bytes(data[16:20], byteorder='little'))
		self.NextCommand = int.from_bytes(data[20:24], byteorder='little')
		self.MessageId   = data[24:32]
		self.Reserved    = data[32:36]
		self.TreeId      = data[36:40]
		self.SessionId   = data[40:48]
		self.Signature   = data[48:64]

	def __repr__(self):
		t = '===SMB2 HEADER SYNC===\r\n'
		t += 'ProtocolId:    %s\r\n' % self.ProtocolId
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'CreditCharge:  %s\r\n' % self.CreditCharge
		t += 'Status:    %s\r\n' % self.Status.name
		t += 'Command:   %s\r\n' % self.Command.name
		t += 'Credit:    %s\r\n' % self.Credit
		t += 'Flags:     %s\r\n' % self.Flags
		t += 'NextCommand: %s\r\n' % self.NextCommand
		t += 'MessageId: %s\r\n' % self.MessageId
		t += 'Reserved:  %s\r\n' % self.Reserved
		t += 'TreeId:    %s\r\n' % self.TreeId
		t += 'SessionId: %s\r\n' % self.SessionId
		t += 'Signature: %s\r\n' % self.Signature
		return t

class SMB2NotImplementedCommand():
	def __init__(self):
		self.data = None

	def parse(self,data):
		self.data = data

	def __repr__(self):
		t = '=== SMB2NotImplementedCommand ===\r\n'
		t += 'Data: %s\r\n' % repr(self.data)
		return t



class SMB2Message():
	def __init__(self):
		self.header    = None
		self.command   = None

	def parse_header(self, data):
		if self.header_isAsync(data):
			self.header = SMB2Header_ASYNC(data[:64])
		else:
			self.header = SMB2Header_SYNC(data[:64])
		
		classname = self.header.Command.name
		try:
			if SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR in self.header.Flags:
				classname += '_REPLY'
			else:
				classname += '_REQ'
			class_ = getattr(sys.modules[__name__], classname)
			self.command = class_()
		except Exception as e:
			print(str(e))
			self.command = SMB2NotImplementedCommand()

	def header_isAsync(self,data):
		flags = SMB2HeaderFlag(int.from_bytes(data[16:20], byteorder='little'))
		print(repr(flags))
		return SMB2HeaderFlag.SMB2_FLAGS_ASYNC_COMMAND in flags


	def __repr__(self):
		t = repr(self.header)
		t += repr(self.command)
		return t

#https://msdn.microsoft.com/en-us/library/cc246543.aspx
class NegotiateSecurityMode(enum.IntFlag):
	SMB2_NEGOTIATE_SIGNING_ENABLED  = 0x0001
	SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002

#https://msdn.microsoft.com/en-us/library/cc246543.aspx
class NegotiateCapabilities(enum.IntFlag):
	SMB2_GLOBAL_CAP_DFS = 0x00000001 #When set, indicates that the client supports the Distributed File System (DFS).
	SMB2_GLOBAL_CAP_LEASING = 0x00000002 #When set, indicates that the client supports leasing.
	SMB2_GLOBAL_CAP_LARGE_MTU = 0x00000004 #When set, indicates that the client supports multi-credit operations.
	SMB2_GLOBAL_CAP_MULTI_CHANNEL = 0x00000008 #When set, indicates that the client supports establishing multiple channels for a single session.
	SMB2_GLOBAL_CAP_PERSISTENT_HANDLES = 0x00000010 #When set, indicates that the client supports persistent handles.
	SMB2_GLOBAL_CAP_DIRECTORY_LEASING = 0x00000020 #When set, indicates that the client supports directory leasing.
	SMB2_GLOBAL_CAP_ENCRYPTION = 0x00000040 #When set, indicates that the client supports encryption.

class NegotiateDialects(enum.Enum):
	SMB202 = 0x0202 #SMB 2.0.2 dialect revision number.
	SMB210 = 0x0210 #SMB 2.1 dialect revision number.<10>
	SMB300 = 0x0300 #SMB 3.0 dialect revision number. <11>
	SMB302 = 0x0302 #SMB 3.0.2 dialect revision number.<12>
	SMB311 = 0x0311 #SMB 3.1.1 dialect revision number.<13>

#https://msdn.microsoft.com/en-us/library/cc246543.aspx
class NEGOTIATE_REQ():
	def __init__(self, data = None):
		self.StructureSize   = None
		self.DialectCount    = None
		self.SecurityMode    = None
		self.Reserved        = None
		self.Capabilities    = None
		self.ClientGuid      = None
		self.MultiData1      = None #This field is interpreted in different ways depending on the SMB2 Dialects field.
		self.Dialects        = None
		self.Padding         = None
		self.NegotiateContextList = None

	def parse(self, data):
		self.StructureSize = int.from_bytes(data[:2], byteorder='little')
		assert self.StructureSize == 36
		self.DialectCount = int.from_bytes(data[2:4], byteorder='little')
		assert self.DialectCount > 0
		self.SecurityMode = NegotiateSecurityMode(int.from_bytes(data[4:6], byteorder='little'))
		self.Reserved = data[6:8]
		self.Capabilities = NegotiateCapabilities(int.from_bytes(data[8:12], byteorder='little'))
		self.ClientGuid = uuid.UUID(bytes=data[12:28])
		self.MultiData1 = data[28:36]
		self.Dialects = []		
		for i in range(0, self.DialectCount,2):
			self.Dialects.append(NegotiateDialects(int.from_bytes(data[i+36:i+38], byteorder = 'little')))

		if self.Dialects == NegotiateDialects.SMB311:
			self.NegotiateContextOffset = int.from_bytes(self.MultiData1[:4],byteorder = 'little')
			self.NegotiateContextCount  = int.from_bytes(self.MultiData1[4:6], byteorder = 'little')
			self.Reserved2 = self.MultiData1[6:8]

			self.NegotiateContextList = []
			
			#TODO
			#i = 0
			#while i < len(data):
			#	data[self.NegotiateContextOffset:self.NegotiateContextOffset+]

		else:
			self.ClientStartTime = wintime2datetime(int.from_bytes(self.MultiData1, byteorder = 'little'))
		
		return


	def __repr__(self):
		t = '==== SMB2 NEGOTIATE REQ ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'DialectCount:  %s\r\n' % self.DialectCount
		t += 'SecurityMode:  %s\r\n' % self.SecurityMode.name
		t += 'Reserved:      %s\r\n' % self.Reserved
		t += 'Capabilities:  %s\r\n' % repr(self.Capabilities)
		t += 'ClientGuid:    %s\r\n' % self.ClientGuid
		t += 'MultiData1:    %s\r\n' % self.MultiData1
		for dialect in self.Dialects:
			t += '\t Dialect: %s\r\n' % dialect.name

		return t

class SMB2ContextType(enum.Enum):
	SMB2_PREAUTH_INTEGRITY_CAPABILITIES = 0x0001
	SMB2_ENCRYPTION_CAPABILITIES = 0x0002

class SMB2HashAlgorithm(enum.Enum):
	SHA_512 = 0x0001

#https://msdn.microsoft.com/en-us/library/mt208834.aspx
class SMB2NegotiateContext():
	def __init__(self, data=None):
		self.ContextType = None
		self.DataLength  = None
		self.Reserved    = None
		self.Data        = None

		if data is not None:
			self.parse(data)

	def parse(self,data):
		self.ContextType = SMB2ContextType(int.from_bytes(data[:2], byteorder = 'little'))
		self.DataLength  = int.from_bytes(data[2:4], byteorder = 'little')
		self.Reserved    = data[4:8]
		if self.ContextType == SMB2ContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
			self.Data        = SMB2PreauthIntegrityCapabilities(data[8:8+self.DataLength])
		elif self.ContextType == SMB2ContextType.SMB2_ENCRYPTION_CAPABILITIES:
			self.Data        = SMB2EncryptionCapabilities(data[8:8+self.DataLength])

	def __repr__(self):
		t = '==== SMB2 Negotiate Context ====\r\n'
		t += 'ConextType: %s\r\n' % self.ContextType.name
		t += 'DataLength: %s\r\n' % self.DataLength
		t += 'Data: %s\r\n' % repr(self.Data)

		return t

class SMB2PreauthIntegrityCapabilities():
	def __init__(self, data=None):
		self.HashAlgorithmCount = None
		self.SaltLength         = None
		self.HashAlgorithms     = None
		self.Salt               = None

	def parse(self, data):
		self.HashAlgorithmCount = int.from_bytes(data[:2], byteorder='little')
		self.SaltLength = int.from_bytes(data[2:4], byteorder = 'little')
		self.HashAlgorithms = []
		for i in range(self.HashAlgorithmCount,2):
			self.HashAlgorithms.append(SMB2HashAlgorithm(int.from_bytes(data[4+i:6+i], byteorder ='little')))

		self.Salt = data[-self.SaltLength:]

	def __repr__(self):
		t = '==== SMB2 Preauth Integrity Capabilities ====\r\n'
		t += 'HashAlgorithmCount: %s\r\n' % self.HashAlgorithmCount
		t += 'SaltLength: %s\r\n' % self.SaltLength
		t += 'Salt: %s\r\n' % self.Salt
		
		for algo in self.HashAlgorithms:
			t += 'HashAlgo: %s\r\n' % algo.name

		return t

class SMB2Cipher(enum.Enum):
	AES_128_CCM = 0x0001
	AES_128_GCM = 0x0002

class SMB2EncryptionCapabilities():
	def __init__(self, data = None):
		self.CipherCount = None
		self.Ciphers = None

	def parse(self, data):
		self.CipherCount = int.from_bytes(data[:2], byteorder='little')
		self.Ciphers = []
		for i in range(self.CipherCount,2):
			self.Ciphers.append(SMB2Cipher(int.from_bytes(data[2+i:4+i])))

	def __repr__(self):
		t = '==== SMB2 Encryption Capabilities ====\r\n'
		t += 'CipherCount: %s\r\n' % self.CipherCount
		for cipher in self.Ciphers:
			t += 'Cipher: %s\r\n' % cipher.name

		return t

#https://msdn.microsoft.com/en-us/library/cc246561.aspx
class NEGOTIATE_REPLY():
	def __init__(self, data = None):
		self.StructureSize = None
		self.SecurityMode = None
		self.DialectRevision = None
		self.MultiData1 = None
		self.ServerGuid = None
		self.Capabilities = None
		self.MaxTransactSize = None
		self.MaxReadSize = None
		self.MaxWriteSize = None
		self.SystemTime = None
		self.ServerStartTime = None
		self.SecurityBufferOffset = None
		self.SecurityBufferLength = None
		self.Multidata2 = None
		self.Buffer = None
		self.Padding = None
		self.NegotiateContextList = None

		if data is not None:
			self.parse(data)

	def parse(self, data):
		self.StructureSize   = int.from_bytes(data[:2], byteorder='little')
		assert self.StructureSize == 65
		self.SecurityMode    = NegotiateSecurityMode(int.from_bytes(data[2:4], byteorder='little'))
		self.DialectRevision = NegotiateDialects(int.from_bytes(data[4:6], byteorder='little'))
		self.Multidata1      = data[6:8]
		self.ServerGuid      = uuid.UUID(bytes=data[8:24])
		self.Capabilities    = NegotiateCapabilities(int.from_bytes(data[24:28], byteorder='little'))
		self.MaxTransactSize = int.from_bytes(data[28:32], byteorder = 'little')
		self.MaxReadSize     = int.from_bytes(data[32:36], byteorder = 'little')
		self.MaxWriteSize    = int.from_bytes(data[36:40], byteorder = 'little')
		self.SystemTime      = wintime2datetime(int.from_bytes(data[40:48], byteorder = 'little'))
		self.ServerStartTime = wintime2datetime(int.from_bytes(data[48:56], byteorder = 'little'))
		self.SecurityBufferOffset = int.from_bytes(data[56:58], byteorder = 'little')
		self.SecurityBufferLength = int.from_bytes(data[58:60], byteorder = 'little')
		
		self.Multidata2 = int.from_bytes(data[60:64], byteorder = 'little')
		
		if self.SecurityBufferLength != 0:
			self.Buffer = data[64:64+self.SecurityBufferLength]
		
		if self.DialectRevision == NegotiateDialects.SMB311:
			self.NegotiateContextList = data[self.Multidata2:]

	def __repr__(self):
		t = '==== SMB2 NEGOTIATE REPLY ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'SecurityMode: %s\r\n' % repr(self.SecurityMode)
		t += 'DialectRevision: %s\r\n' % self.DialectRevision.name
		t += 'Multidata1: %s\r\n' % self.Multidata1
		t += 'ServerGuid: %s\r\n' % self.ServerGuid
		t += 'Capabilities: %s\r\n' % repr(self.Capabilities)
		t += 'MaxTransactSize: %s\r\n' % self.MaxTransactSize
		t += 'MaxReadSize: %s\r\n' % self.MaxReadSize
		t += 'MaxWriteSize: %s\r\n' % self.MaxWriteSize
		t += 'SystemTime: %s\r\n' % self.SystemTime.isoformat()
		t += 'ServerStartTime: %s\r\n' % self.ServerStartTime.isoformat()
		t += 'SecurityBufferOffset: %s\r\n' % self.SecurityBufferOffset
		t += 'SecurityBufferLength: %s\r\n' % self.SecurityBufferLength
		t += 'Multidata2: %s\r\n' % self.Multidata2
		t += 'Buffer: %s\r\n' % self.Buffer
		t += 'NegotiateContextList: %s\r\n' % self.NegotiateContextList
		return t

class SessionSetupFlag(enum.IntFlag):
	SMB2_SESSION_FLAG_BINDING = 0x01

class SessionSetupCapabilities(enum.IntFlag):
	SMB2_GLOBAL_CAP_DFS     = 0x00000001 #When set, indicates that the client supports the Distributed File System (DFS).
	SMB2_GLOBAL_CAP_UNUSED1 = 0x00000002 #SHOULD be set to zero, and server MUST ignore.
	SMB2_GLOBAL_CAP_UNUSED2 = 0x00000004 #SHOULD be set to zero and server MUST ignore.
	SMB2_GLOBAL_CAP_UNUSED3 = 0x00000008 #

#https://msdn.microsoft.com/en-us/library/cc246563.aspx
class SESSION_SETUP_REQ():
	def __init__(self, data = None):
		self.StructureSize = None
		self.Flags = None
		self.SecurityMode = None
		self.Capabilities = None
		self.Channel = None
		self.SecurityBufferOffset = None
		self.SecurityBufferLength = None
		self.PreviousSessionId = None
		self.Buffer = None

		if data is not None:
			self.parse(data)

	def parse(self, data):
		self.StructureSize   = int.from_bytes(data[:2], byteorder='little')
		assert self.StructureSize == 25
		self.Flags = SessionSetupFlag(data[2])
		self.SecurityMode = NegotiateSecurityMode(data[3])
		self.Capabilities = SessionSetupCapabilities(int.from_bytes(data[4:8], byteorder = 'little'))
		self.Channel      = int.from_bytes(data[8:12], byteorder = 'little')
		self.SecurityBufferOffset = int.from_bytes(data[12:14], byteorder = 'little')
		self.SecurityBufferLength = int.from_bytes(data[14:16], byteorder = 'little')
		self.PreviousSessionId    = int.from_bytes(data[16:24], byteorder = 'little')
		self.Buffer= data[24:24+self.SecurityBufferLength]

	def __repr__(self):
		t = '==== SMB2 SESSION SETUP REQ ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'Flags: %s\r\n' % repr(self.Flags)
		t += 'SecurityMode: %s\r\n' % self.SecurityMode
		t += 'Capabilities: %s\r\n' % self.Capabilities
		t += 'Channel: %s\r\n' % self.Channel
		t += 'SecurityBufferOffset: %s\r\n' % self.SecurityBufferOffset
		t += 'SecurityBufferLength: %s\r\n' % self.SecurityBufferLength
		t += 'PreviousSessionId: %s\r\n' % self.PreviousSessionId
		t += 'Buffer: %s\r\n' % self.Buffer
		return t

#https://msdn.microsoft.com/en-us/library/cc246564.aspx
class SessionFlags(enum.IntFlag):
	SMB2_SESSION_FLAG_IS_GUEST = 0x0001 #If set, the client has been authenticated as a guest user.
	SMB2_SESSION_FLAG_IS_NULL = 0x0002 #If set, the client has been authenticated as an anonymous user.
	SMB2_SESSION_FLAG_ENCRYPT_DATA = 0x0004 #If set, the server requires encryption of messages on this session, per the conditions specified in section 3.3.5.2.9. This flag is only valid for the SMB 3.x dialect family.

#https://msdn.microsoft.com/en-us/library/cc246564.aspx
class SESSION_SETUP_REPLY():
	def __init__(self, data = None):
		self.StructureSize = None
		self.SessionFlags = None
		self.SecurityBufferOffset = None
		self.SecurityBufferLength = None
		self.Buffer = None

		if data is not None:
			self.parse(data)

	def parse(self, data):
		self.StructureSize   = int.from_bytes(data[:2], byteorder='little')
		assert self.StructureSize == 9
		self.SessionFlags = SessionFlags(int.from_bytes(data[2:4], byteorder = 'little'))
		self.SecurityBufferOffset = int.from_bytes(data[4:6], byteorder = 'little')
		self.SecurityBufferLength = int.from_bytes(data[6:8], byteorder = 'little')
		self.Buffer= data[8:8+self.SecurityBufferLength]

	def __repr__(self):
		t = '==== SMB2 SESSION SETUP REPLY ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'SessionFlags: %s\r\n' % repr(self.SessionFlags)
		t += 'SecurityBufferOffset: %s\r\n' % self.SecurityBufferOffset
		t += 'SecurityBufferLength: %s\r\n' % self.SecurityBufferLength
		t += 'Buffer: %s\r\n' % self.Buffer
		return t


class SMB2TreeConnectRQFlag(enum.IntFlag):
	SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT = 0x0001 #When set, indicates that the client has previously connected to the specified cluster share using the SMB dialect of the connection on which the request is received.
	SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER = 0x0002 #When set, indicates that the client can handle synchronous share redirects via a Share Redirect error context response as specified in section 2.2.2.2.2.
	SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT = 0x0004 #When set, indicates that a tree connect request extension, as specified in section 2.2.9.1, is present, starting at the Buffer field of this tree connect request. 

#https://msdn.microsoft.com/en-us/library/cc246567.aspx
class TREE_CONNECT_REQ():
	def __init__(self, data = None):
		### FIX THIS!!!!
		self.Dialect = NegotiateDialects.SMB300
		#######################################
		self.StructureSize = None
		self.Flags = None #only in SMB311
		self.PathOffset = None
		self.PathLength = None
		
		self.PathName = None
		self.Reserved = None

		self.Buffer = None

		if data is not None:
			self.parse(data)

	def parse(self, data):
		self.StructureSize   = int.from_bytes(data[:2], byteorder='little')
		assert self.StructureSize == 9
		if self.Dialect == NegotiateDialects.SMB311:
			self.Flags = SMB2TreeConnectRQFlag(int.from_bytes(data[2:4], byteorder = 'little'))
		else:
			self.Reserved = data[2:4]
		self.PathOffset = int.from_bytes(data[4:6], byteorder = 'little')
		self.PathLength = int.from_bytes(data[6:8], byteorder = 'little')

		if self.Dialect == NegotiateDialects.SMB311:
			self.Buffer = data[8:8+self.PathLength] 

		else:
			self.PathName = data[8:8+self.PathLength].decode('utf-16')

	def __repr__(self):
		t = '==== SMB2 TREE CONNECT REQ ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		if self.Dialect == NegotiateDialects.SMB311:
			t += 'Flags: %s\r\n' % repr(self.Flags)
		else:
			t += 'Reserved: %s\r\n' % repr(self.Reserved)
		t += 'PathOffset: %s\r\n' % self.PathOffset
		t += 'PathLength: %s\r\n' % self.PathLength
		if self.Dialect == NegotiateDialects.SMB311:
			t += 'Buffer: %s\r\n' % self.Buffer
		else:
			t += 'PathName: %s\r\n' % repr(self.PathName)
		
		return t

class SMB2ShareType(enum.Enum):
	SMB2_SHARE_TYPE_DISK  = 0x01 #Physical disk share.
	SMB2_SHARE_TYPE_PIPE  = 0x02 #Named pipe share.
	SMB2_SHARE_TYPE_PRINT = 0x03 #Printer share.

class SMB2ShareFlags(enum.IntFlag):
	SMB2_SHAREFLAG_MANUAL_CACHING = 0x00000000 #The client can cache files that are explicitly selected by the user for offline use.
	SMB2_SHAREFLAG_AUTO_CACHING = 0x00000010 #The client can automatically cache files that are used by the user for offline access.
	SMB2_SHAREFLAG_VDO_CACHING = 0x00000020 #The client can automatically cache files that are used by the user for offline access and can use those files in an offline mode even if the share is available.
	SMB2_SHAREFLAG_NO_CACHING = 0x00000030 #Offline caching MUST NOT occur.
	SMB2_SHAREFLAG_DFS = 0x00000001 #The specified share is present in a Distributed File System (DFS) tree structure. The server SHOULD set the SMB2_SHAREFLAG_DFS bit in the ShareFlags field if the per-share property Share.IsDfs is TRUE.
	SMB2_SHAREFLAG_DFS_ROOT = 0x00000002 #The specified share is present in a DFS tree structure. The server SHOULD set the SMB2_SHAREFLAG_DFS_ROOT bit in the ShareFlags field if the per-share property Share.IsDfs is TRUE.
	SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS = 0x00000100#The specified share disallows exclusive file opens that deny reads to an open file.
	SMB2_SHAREFLAG_FORCE_SHARED_DELETE = 0x00000200#The specified share disallows clients from opening files on the share in an exclusive mode that prevents the file from being deleted until the client closes the file.
	SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING = 0x00000400#The client MUST ignore this flag.
	SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM = 0x00000800#The server will filter directory entries based on the access permissions of the client.
	SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK = 0x00001000#The server will not issue exclusive caching rights on this share.<27>
	SMB2_SHAREFLAG_ENABLE_HASH_V1 = 0x00002000#The share supports hash generation for branch cache retrieval of data. For more information, see section 2.2.31.2. This flag is not valid for the SMB 2.0.2 dialect.
	SMB2_SHAREFLAG_ENABLE_HASH_V2 = 0x00004000#The share supports v2 hash generation for branch cache retrieval of data. For more information, see section 2.2.31.2. This flag is not valid for the SMB 2.0.2 and SMB 2.1 dialects.
	SMB2_SHAREFLAG_ENCRYPT_DATA = 0x00008000#The server requires encryption of remote file access messages on this share, per the conditions specified in section 3.3.5.2.11. This flag is only valid for the SMB 3.x dialect family.
	SMB2_SHAREFLAG_IDENTITY_REMOTING = 0x00040000#The share supports identity remoting. The client can request remoted identity access for the share via the SMB2_REMOTED_IDENTITY_TREE_CONNECT context as specified in section 2.2.9.2.1.

class SMB2ShareCapabilities(enum.IntFlag):
	SMB2_SHARE_CAP_DFS = 0x00000008 #The specified share is present in a DFS tree structure. The server MUST set the SMB2_SHARE_CAP_DFS bit in the Capabilities field if the per-share property Share.IsDfs is TRUE.
	SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY = 0x00000010 #The specified share is continuously available. This flag is only valid for the SMB 3.x dialect family.
	SMB2_SHARE_CAP_SCALEOUT = 0x00000020#The specified share is present on a server configuration which facilitates faster recovery of durable handles. This flag is only valid for the SMB 3.x dialect family.
	SMB2_SHARE_CAP_CLUSTER = 0x00000040#The specified share is present on a server configuration which provides monitoring of the availability of share through the Witness service specified in [MS-SWN]. This flag is only valid for the SMB 3.x dialect family.
	SMB2_SHARE_CAP_ASYMMETRIC = 0x00000080#The specified share is present on a server configuration that allows dynamic changes in the ownership of the share. This flag is not valid for the SMB 2.0.2, 2.1, and 3.0 dialects.
	SMB2_SHARE_CAP_REDIRECT_TO_OWNER = 0x00000100#The specified share is present on a server configuration that supports synchronous share level redirection via a Share Redirect error context response (section 2.2.2.2.2). This flag is not valid for SMB 2.0.2, 2.1, 3.0, and 3.0.2 dialects.

#https://msdn.microsoft.com/en-us/library/cc246801.aspx
class DirectoryAccessMask(enum.IntFlag):
	FILE_LIST_DIRECTORY = 0x00000001 #This value indicates the right to enumerate the contents of the directory.
	FILE_ADD_FILE = 0x00000002 #This value indicates the right to create a file under the directory.
	FILE_ADD_SUBDIRECTORY = 0x00000004 #This value indicates the right to add a sub-directory under the directory.
	FILE_READ_EA = 0x00000008 #This value indicates the right to read the extended attributes of the directory.
	FILE_WRITE_EA = 0x00000010 #This value indicates the right to write or change the extended attributes of the directory.
	FILE_TRAVERSE = 0x00000020 #This value indicates the right to traverse this directory if the server enforces traversal checking.
	FILE_DELETE_CHILD = 0x00000040 #This value indicates the right to delete the files and directories within this directory.
	FILE_READ_ATTRIBUTES = 0x00000080 #This value indicates the right to read the attributes of the directory.
	FILE_WRITE_ATTRIBUTES = 0x00000100 #This value indicates the right to change the attributes of the directory.
	DELETE = 0x00010000 #This value indicates the right to delete the directory.
	READ_CONTROL = 0x00020000 #This value indicates the right to read the security descriptor for the directory.
	WRITE_DAC = 0x00040000 #This value indicates the right to change the DACL in the security descriptor for the directory. For the DACL data structure, see ACL in [MS-DTYP].
	WRITE_OWNER = 0x00080000#This value indicates the right to change the owner in the security descriptor for the directory.
	SYNCHRONIZE = 0x00100000 #SMB2 clients set this flag to any value.<43> SMB2 servers SHOULD<44> ignore this flag.
	ACCESS_SYSTEM_SECURITY = 0x01000000 #This value indicates the right to read or change the SACL in the security descriptor for the directory. For the SACL data structure, see ACL in [MS-DTYP].<45>
	MAXIMUM_ALLOWED = 0x02000000 #This value indicates that the client is requesting an open to the directory with the highest level of access the client has on this directory. If no access is granted for the client on this directory, the server MUST fail the open with STATUS_ACCESS_DENIED.
	GENERIC_ALL = 0x10000000 #This value indicates a request for all the access flags that are listed above except MAXIMUM_ALLOWED and ACCESS_SYSTEM_SECURITY.
	GENERIC_EXECUTE = 0x20000000 #This value indicates a request for the following access flags listed above: FILE_READ_ATTRIBUTES| FILE_TRAVERSE| SYNCHRONIZE| READ_CONTROL.
	GENERIC_WRITE = 0x40000000 #This value indicates a request for the following access flags listed above: FILE_ADD_FILE| FILE_ADD_SUBDIRECTORY| FILE_WRITE_ATTRIBUTES| FILE_WRITE_EA| SYNCHRONIZE| READ_CONTROL.
	GENERIC_READ = 0x80000000 #This value indicates a request for the following access flags listed above: FILE_LIST_DIRECTORY| FILE_READ_ATTRIBUTES| FILE_READ_EA| SYNCHRONIZE| READ_CONTROL.

#https://msdn.microsoft.com/en-us/library/cc246802.aspx
class FilePipePrinterAccessMask(enum.IntFlag):
	FILE_READ_DATA = 0x00000001 #This value indicates the right to read data from the file or named pipe.
	FILE_WRITE_DATA = 0x00000002 #This value indicates the right to write data into the file or named pipe beyond the end of the file.
	FILE_APPEND_DATA = 0x00000004 #This value indicates the right to append data into the file or named pipe.
	FILE_READ_EA = 0x00000008 #This value indicates the right to read the extended attributes of the file or named pipe.
	FILE_WRITE_EA = 0x00000010 #This value indicates the right to write or change the extended attributes to the file or named pipe.
	FILE_DELETE_CHILD = 0x00000040 # This value indicates the right to delete entries within a directory.
	FILE_EXECUTE = 0x00000020 #This value indicates the right to execute the file.
	FILE_READ_ATTRIBUTES = 0x00000080 #This value indicates the right to read the attributes of the file.
	FILE_WRITE_ATTRIBUTES = 0x00000100 #This value indicates the right to change the attributes of the file.
	DELETE = 0x00010000 #This value indicates the right to delete the file.
	READ_CONTROL = 0x00020000 #This value indicates the right to read the security descriptor for the file or named pipe.
	WRITE_DAC = 0x00040000 #This value indicates the right to change the discretionary access control list (DACL) in the security descriptor for the file or named pipe. For the DACL data structure, see ACL in [MS-DTYP].
	WRITE_OWNER = 0x00080000 #This value indicates the right to change the owner in the security descriptor for the file or named pipe.
	SYNCHRONIZE = 0x00100000 #SMB2 clients set this flag to any value.<40> SMB2 servers SHOULD<41> ignore this flag.
	ACCESS_SYSTEM_SECURITY = 0x01000000 #This value indicates the right to read or change the system access control list (SACL) in the security descriptor for the file or named pipe. For the SACL data structure, see ACL in [MS-DTYP].<42>
	MAXIMUM_ALLOWED = 0x02000000 #This value indicates that the client is requesting an open to the file with the highest level of access the client has on this file. If no access is granted for the client on this file, the server MUST fail the open with STATUS_ACCESS_DENIED.
	GENERIC_ALL = 0x10000000 #This value indicates a request for all the access flags that are previously listed except MAXIMUM_ALLOWED and ACCESS_SYSTEM_SECURITY.
	GENERIC_EXECUTE = 0x20000000 #This value indicates a request for the following combination of access flags listed above: FILE_READ_ATTRIBUTES| FILE_EXECUTE| SYNCHRONIZE| READ_CONTROL.
	GENERIC_WRITE = 0x40000000 #This value indicates a request for the following combination of access flags listed above: FILE_WRITE_DATA| FILE_APPEND_DATA| FILE_WRITE_ATTRIBUTES| FILE_WRITE_EA| SYNCHRONIZE| READ_CONTROL.
	GENERIC_READ = 0x80000000 #This value indicates a request for the following combination of access flags listed above: FILE_READ_DATA| FILE_READ_ATTRIBUTES| FILE_READ_EA| SYNCHRONIZE| READ_CONTROL.



#https://msdn.microsoft.com/en-us/library/cc246499.aspx
class TREE_CONNECT_REPLY():
	def __init__(self, data = None):
		self.StructureSize = None
		self.ShareType     = None
		self.Reserved      = None
		self.ShareFlags    = None
		self.Capabilities  = None
		self.MaximalAccess = None

		if data is not None:
			self.parse(data)

	def parse(self, data):
		self.StructureSize   = int.from_bytes(data[:2], byteorder='little')
		assert self.StructureSize == 16
		self.ShareType = SMB2ShareType(data[2])
		self.Reserved   = data[3]
		self.ShareFlags = SMB2ShareFlags(int.from_bytes(data[4:8],byteorder= 'little'))
		self.Capabilities = SMB2ShareCapabilities(int.from_bytes(data[8:12],byteorder = 'little'))
		
		##### TODO! somehow get the info wether we are accessing a file OR a directory OR a pipe OR a printer!!!
		temp_sharetype = 'file'
		if temp_sharetype == 'file':
			self.MaximalAccess = FilePipePrinterAccessMask(int.from_bytes(data[12:16],byteorder = 'little'))
		else:
			self.MaximalAccess = DirectoryAccessMask(int.from_bytes(data[12:16],byteorder = 'little'))

	def __repr__(self):
		t = '==== SMB2 TREE CONNECT REPLY ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'ShareType: %s\r\n' % self.ShareType.name
		t += 'Reserved: %s\r\n' % self.Reserved
		t += 'ShareFlags: %s\r\n' % repr(self.ShareFlags)
		t += 'Capabilities: %s\r\n' % repr(self.Capabilities)
		t += 'MaximalAccess: %s\r\n' % self.MaximalAccess		
		return t

