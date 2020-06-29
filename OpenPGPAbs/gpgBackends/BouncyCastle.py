import typing
from pathlib import Path
from codecs import encode, decode
import warnings
from datetime import datetime, timedelta, timezone
from fsutilz import MMap
from JAbs import JVMInitializer

from . import *

# SHIT SHIT SHIT SHIT verify fails always!!!


def bin2hex(b:bytes) -> str:
	return encode(b, "hex").decode("ascii")

def hex2bin(h: str) -> bytes:
	return decode(encode(h, "ascii"), "hex")

def javaDateToDate(d):
	return datetime.fromtimestamp(d.time // 1000, tz=timezone.utc)

def javaBytes2Bytes(jb):
	return bytes((0x100 + n) & 0xFF for n in jb)

bcBase = "org.bouncycastle"
bcGpgBase = bcBase + ".openpgp"



class BouncyCastle(Backend):
	__slots__ = ("j",)

	def __init__(self, gpgme_home: typing.Optional[typing.Union[str, int]], otherArgs = None):
		self.j = JVMInitializer(["/usr/share/maven-repo/org/bouncycastle/bcpg/debian/bcpg-debian.jar"], [
			"java.io.FileInputStream",
			"java.io.ByteArrayInputStream",
			"java.security.Security",

			bcBase + ".bcpg.ArmoredInputStream",
			bcBase + ".jce.provider.BouncyCastleProvider",
			bcGpgBase + ".PGPPublicKey",
			bcGpgBase + ".PGPSignature",
			bcGpgBase + ".PGPSignatureList",
			bcGpgBase + ".PGPKeyRing",
			bcGpgBase + ".PGPPublicKeyRingCollection",
			bcGpgBase + ".BCPGInputStream",
			bcGpgBase + ".operator.jcajce.JcaKeyFingerprintCalculator",
			bcGpgBase + ".PGPUtil",
			bcGpgBase + ".jcajce.JcaPGPObjectFactory",
			bcGpgBase + ".operator.jcajce.JcaPGPContentVerifierBuilderProvider",
		])

		bcp = BouncyCastleProvider()
		self.j.Security.addProvider(bcp)

		#keyIn = self.j.FileInputStream(str(kp));
		#pgpPub = self.j.PGPPublicKeyRingCollection(self.j.PGPUtil.getDecoderStream(keyIn), self.j.JcaKeyFingerprintCalculator())



	def bytes2JavaBytes(b):
		a = jpype.JArray(jpype.JByte)(len(b))
		for i, n in enumerate(b):
			if 0x80 & n:
				n = n - 0x100
			a[i] = jpype.JByte(n)
		return a

	def getExpirationDate(k):
		vs = int(k.validSeconds)
		if vs:
			cr = javaDateToDate(k.getCreationTime())
			return  cr + timedelta(seconds=vs)

	def importSignatures(sig: typing.Union[Path, str, bytes]):
		if isinstance(sig, (Path, str)):
			sigFile = Path(sig)
			sigIn = self.j.FileInputStream(str(sigFile))
		else:
			sigIn = self.j.ByteArrayInputStream(bytes2JavaBytes(sig))
		
		armIn = self.j.ArmoredInputStream(sigIn)
		for l in self.j.JcaPGPObjectFactory(armIn):
			for sig in l:
				yield sig

	def importSignature(signature: typing.Union[Path, bytes]):
		return next(importSignatures(signature))

	def _verify(sig, key, signedData):
		sig.init(self.j.JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key)

		sig.update(bytes2JavaBytes(signedData))
		return sig.verify()

	def findKeyByFingerprint(fp: str, keyFile: typing.Optional[Path] = None):
		if keyFile is None:
			keyFile = keyringPath
		keyIn = self.j.FileInputStream(str(keyFile));
		pgpPub = self.j.PGPPublicKeyRingCollection(self.j.PGPUtil.getDecoderStream(keyIn), self.j.JcaKeyFingerprintCalculator())

		fpB = hex2bin(fp)
		for kr in pgpPub.getKeyRings():
			for k in kr.getPublicKeys():
				kFpB = javaBytes2Bytes(k.fingerprint)
				if kFpB == fpB:
					return k

	def verifyBlob(signedData: bytes, signature: bytes, *, keyFingerprint: str = None, keyFile: Path = None, subkeyFingerprint: str = None):
		allowedFingerprints = set()
		if keyFingerprint:
			key = findKeyByFingerprint(keyFingerprint.upper(), keyFile)
			for sk in key.subkeys:
				allowedFingerprints.add(hex2bin(sk.fingerprint))
		
		elif subkeyFingerprint:
			allowedFingerprints.add(hex2bin(subkeyFingerprint))

		#selfVerifBadSignatures = list(key.verify(key).bad_signatures)
		#if selfVerifBadSignatures:
		#	raise Exception("Key is invalid", selfVerifBadSignatures)

		signature = importSignature(signature)
		
		if isinstance(signedData, Path):
			with MMap(signedData) as m:
				res = _verify(signature, key, m)
		else:
			res = _verify(signature, key, signedData)
		
		if not res:
			return SecurityIssues.wrongSig
		else:
			return SecurityIssues.OK

	def getExpirationDate(k):
		vs = int(k.validSeconds)
		if vs:
			cr = javaDateToDate(k.getCreationTime())
			return  cr + timedelta(seconds=vs)

keys = []
for kr in pgpPub.getKeyRings():
	for k in kr.getPublicKeys():
		keys.append(k)
		print(hex((0x10000000000000000 + k.keyID) & 0xFFFFFFFFFFFFFFFF)[2:].upper(), getExpirationDate(k))
