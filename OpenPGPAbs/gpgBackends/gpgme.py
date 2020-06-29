#!/usr/bin/env python3
import typing
import sys
import tempfile
from io import StringIO, BytesIO
from pathlib import Path, PurePath
import _io
import enum
from os import urandom
import gpg
from fsutilz import MMap
from enum import IntFlag

from . import *

class SignAlgo(enum.IntEnum):
	RSA_encrypt_sign = 1
	RSA_sign = 3
	ElGamal = 16
	DSA = 17
	ECDSA = 19
	EdDSA = 22
	AEDSA = 24
	ECDH = 18

class HashAlgo(enum.IntEnum):
	sha256 = 8
	sha384 = 9
	sha512 = 10



# https://safecurves.cr.yp.to/
safeCurves = {
	"Curve25519",
	"Ed25519",
}

minimumAssymetricKeyLegths = {
	SignAlgo.RSA_encrypt_sign: 2048,
	SignAlgo.RSA_sign: 2048,
	SignAlgo.ElGamal: 2048,
	SignAlgo.DSA: 2048,
	
	SignAlgo.ECDSA: safeCurves,
	SignAlgo.EdDSA: safeCurves,
	SignAlgo.ECDH: safeCurves,
}



def isHashConsideredSecure(hash):
	try:
		HashAlgo(hash)
		return SecurityIssues.OK
	except:
		return SecurityIssues.hashFunctionNotCollisionResistant


def checkAssymetricAlgoAndItsParameters(algo, curve, size):
	if algo in minimumAssymetricKeyLegths:
		minLOrSetOfSecureCurves = minimumAssymetricKeyLegths[algo]
		if isinstance(minLOrSetOfSecureCurves, set): # ECC
			safeCurvesForThisAlg = minLOrSetOfSecureCurves
			if curve in safeCurvesForThisAlg:
				return SecurityIssues.OK
			else:
				warnings.warn("Curve " + repr(curve) + " is not considered secure for " + repr(algo))
				return SecurityIssues.insecureCurve
		else:
			minL = minLOrSetOfSecureCurves
			if size < minL:
				warnings.warn("Assymetric algo " + repr(algo) + " needs key at least of " + repr(minL) + " bits effective length to be considered secure")
				return SecurityIssues.assymetricKeyLengthIsTooShort
			else:
				return SecurityIssues.OK
	else:
		warnings.warn("Assymetric algo " + repr(algo) + " is not considered secure")
		return SecurityIssues.brokenAssymetricFunc


def checkKeyFingerprint(keyBytes, fp):
	fp = fp.upper()
	imps = tempCtx.key_import(keyBytes)
	j = 0
	for ik in imps.imports:
		k = tempCtx.get_key(ik.fpr)
		insecurity = isConsideredInsecure(k)
		if insecurity:
			raise Exception("Key " + k.fpr + " ( " + generateHumanName(k) + " ) from " + str(kf) + " is considered insecure (" + str(insecurity) + ")!")
		if ik.fpr != fp:
			raise Exception("The key has fingerprint " + ik.fpr + " but the requested fingerprint was " + fp)
		j += 1
	return j





class GPGMe(Backend):
	__slots__ = ("ctx",)

	def __init__(self, gpgme_home: typing.Optional[typing.Union[str, int]]=None, otherArgs = None):
		if gpgme_home is not None:
			gpgme_home = str(gpgme_home)

		self.ctx = gpg.Context(armor=True, offline=True, home_dir=gpgme_home)

	def _importKey(self, key: typing.Union[Path, bytes]):
		if isinstance(key, Path):
			return self._importKey(key.read_bytes())
		else:
			return self.ctx.key_import(key)

	def importKey(self, key: typing.Union[Path, bytes]):
		return tuple(self.ctx.get_key(k.fpr) for k in self._importKey(key).imports)

	@classmethod
	def isConsideredInsecure(cls, k):
		res = k.invalid * SecurityIssues.invalid | k.disabled * SecurityIssues.disabled | k.expired * SecurityIssues.expired | k.revoked * SecurityIssues.revoked
		for sk in k.subkeys:
			res |= cls.isSubkeyConsideredInsecure(sk)
		return SecurityIssues(res)

	@staticmethod
	def isSubkeyConsideredInsecure(k):
		res = k.invalid * SecurityIssues.invalid | k.disabled * SecurityIssues.disabled | k.expired * SecurityIssues.expired | k.revoked * SecurityIssues.revoked
		res |= checkAssymetricAlgoAndItsParameters(k.pubkey_algo, k.curve, k.length)
		return SecurityIssues(res)

	def findKeyByFingerprint(self, fp: str, keyFile: typing.Optional[Path] = None):
		self._importKey(keyFile)
		return self.ctx.get_key(fp)

	def verifyBlob(self, signedData: bytes, signature: bytes, *, keyFingerprint: str = None, keyFile: Path = None, subkeyFingerprint: str = None):
		k = self.findKeyByFingerprint(keyFingerprint, keyFile)
		allowedFingerprints = set()
		for sk in k.subkeys:
			if not self.isSubkeyConsideredInsecure(sk):
				allowedFingerprints |= {sk.fpr}
		#if keyFingerprint is not None:
		#	allowedFingerprints &= {keyFingerprint}

		verResult = self.ctx.verify(signedData, signature)[1]
		if not verResult or not verResult.signatures:
			return SecurityIssues.wrongSig


		for s in verResult.signatures:
			if s.fpr in allowedFingerprints:
				hashIssues = isHashConsideredSecure(s.hash_algo)
				if not hashIssues:
					return hashIssues
		return hashIssues

	def extractFingerprintsFromASignature(self, sig: bytes) -> typing.Iterator[str]:
		"""IDK the API to extract the keys fingerprints from a signature, so have to do nasty hacks: verify the blob that must not be verified"""
		b = urandom(128)
		try:
			self.ctx.verify(b, sig)
		except gpg.errors.BadSignatures as ex:
			for el in ex.results:
				if isinstance(el, gpg.results.VerifyResult):
					for sig in el.signatures:
						yield sig.fpr
