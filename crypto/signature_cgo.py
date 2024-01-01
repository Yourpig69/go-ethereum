import ecdsa
from ecdsa.util import sigencode_string, sigdecode_string
from ecdsa.curves import SECP256k1
from hashlib import sha3
import math
from typing import List

DigestLength = 32
secp256k1N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
secp256k1halfN = secp256k1N // 2


def ecrecover(hash, sig):
    try:
        return secp256k1.recover_pubkey(hash, sig)
    except Exception as e:
        return None, str(e)


def sig_to_pub(hash, sig):
    s, err = ecrecover(hash, sig)
    if err:
        return None, err

    x, y = SECP256k1.curve._from_bytes(s)
    return ecdsa.Public_key(SECP256k1, SECP256k1.generator * SECP256k1.order, x, y), None


def sign(digest_hash, prv):
    if len(digest_hash) != DigestLength:
        return None, ValueError(f"hash is required to be exactly {DigestLength} bytes ({len(digest_hash)})")

    seckey = math.number_to_string(prv.secret, SECP256k1.order)
    signature = secp256k1.sign(digest_hash, seckey, sigencode=sigencode_string)

    return signature, None


def verify_signature(pubkey, digest_hash, signature):
    return secp256k1.verify(pubkey, digest_hash, signature, sigdecode=sigdecode_string)


def decompress_pubkey(pubkey):
    x, y = SECP256k1.curve._from_bytes(pubkey)
    return ecdsa.Public_key(SECP256k1, SECP256k1.generator * SECP256k1.order, x, y)


def compress_pubkey(pubkey):
    return pubkey.to_string()


class ecdsa_PublicKey(ecdsa.Public_key):
    def to_string(self):
        return sigencode_string(sigencode_string(self.point, self.pubkey.order), self.pubkey.order)

    def verify(self, digest, signature):
        return verify_signature(self.to_string(), digest, signature)


class ecdsa_PrivateKey(ecdsa.Private_key):
    def sign(self, digest):
        return sign(digest, self)


def zero_bytes(bytes_array):
    for i in range(len(bytes_array)):
        bytes_array[i] = 0


# Example Usage:
# priv = ecdsa.Private_key()
# pub = priv.get_verifying_key()
# msg = sha3('hello world'.encode('utf-8')).digest()
# signature, _ = sign(msg, priv)
# print(f"Signature: {signature}")
# valid = verify_signature(pub, msg, signature)
# print(f"Signature is valid: {valid}")
