_backendsNames = ("bouncyCastle", "pgpy")

from pathlib import Path
from os.path import expanduser
from enum import IntFlag
from abc import ABC, abstractmethod

keyringPath = Path(expanduser("~/.gnupg/pubring.kbx"))

class SecurityIssues(IntFlag):
	OK = 0
	wrongSig = (1 << 0)
	expired = (1 << 1)
	disabled = (1 << 2)
	revoked = (1 << 3)
	invalid = (1 << 4)
	brokenAssymetricFunc = (1 << 5)
	hashFunctionNotCollisionResistant = (1 << 6)
	hashFunctionNotSecondPreimageResistant = (1 << 7)
	assymetricKeyLengthIsTooShort = (1 << 8)
	insecureCurve = (1 << 9)
	noSelfSignature = (1 << 10)

class Backend(ABC):
	__slots__ = ()

	@abstractmethod
	def verifyBlob(signedData: bytes, signature: bytes, *, keyFingerprint: str = None, keyFile: Path = None, subkeyFingerprint: str = None):
		raise NotImplementedError

	def isConsideredInsecure(k):
		raise NotImplementedError
