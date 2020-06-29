from pathlib import Path
from os.path import expanduser
import typing
import pgpy
from fsutilz import MMap


def pgpyFp2UsualFp(fp: str) -> str:
	return fp.replace(" ", "") # .upper() is already applied


def importSignature(signature: typing.Union[Path, bytes]):
	if isinstance(signature, Path):
		with MMap(signature) as m:
			return importSignature(m)
	else:
		s = pgpy.PGPSignature()
		return s.parse(signature)


class PGPy(Backend):
	__slots__ = ()

	def findKeyByFingerprint(self, fp: str, keyFile: typing.Optional[Path] = None):
		if keyFile is None:
			keyFile = keyringPath
		k = pgpy.PGPKey.from_file(keyFile)[0]
		print(k)
		for sk in k.subkeys.values():
			print("sk.fingerprint", sk.fingerprint)
			kfp = pgpyFp2UsualFp(sk.fingerprint)
			if fp == kfp:
				return sk

	def verifyBlob(self, signedData: bytes, signature: bytes, *, keyFingerprint: str = None, keyFile: Path = None, subkeyFingerprint: str = None):
		allowedFingerprints = set()
		if keyFingerprint:
			key = findKeyByFingerprint(keyFingerprint.upper(), keyFile)
			for sk in key.subkeys:
				allowedFingerprints.add(pgpyFp2UsualFp(sk.fingerprint))
		
		elif subkeyFingerprint:
			allowedFingerprints.add(subkeyFingerprint.upper())

		selfVerifBadSignatures = list(key.verify(key).bad_signatures)
		if selfVerifBadSignatures:
			raise Exception("Key is invalid", selfVerifBadSignatures)

		signature = importSignature(signature)
		
		if isinstance(signedData, Path):
			with MMap(signedData) as m:
				res = key.verify(m, s)
		else:
			res = key.verify(signedData, signature)
		
		#print(res)
		bad = list(res.bad_signatures)
		if bad:
			raise Exception("GPG verification error: the signatures for following keys are wrong: " + ", ".join(pgpyFp2UsualFp(s1.by.fingerprint) for s1 in bad))
		
		goodFprs = []
		for s1 in res.good_signatures:
			fpr = pgpyFp2UsualFp(s1.by.fingerprint)
			goodFprs.append(fpr)
		
		for fpr in goodFprs:
			if fpr in allowedFingerprints:
				return True
		raise Exception("Wrong public keys used: " + " ".join(goodFprs))
