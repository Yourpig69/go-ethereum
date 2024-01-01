import ecdsa
from ecdsa import SigningKey, VerifyingKey
from hashlib import sha3
from btclib import ssa
from btclib.curve import mult
from btclib.ellipticcurve import secp256k1, bytes_from_point, point_from_octets
from typing import List

DigestLength = 32
SignatureLength = 64
RecoveryIDOffset = 0


def ecrecover(hash, sig):
    try:
        pub = sig_to_pub(hash, sig)
        bytes_pub = bytes_from_point(pub)
        return bytes_pub, None
    except Exception as e:
        return None, str(e)


def sig_to_pub(hash, sig):
    if len(sig) != SignatureLength:
        raise ValueError("invalid signature")

    # Convert to btclib input format with 'recovery id' v at the beginning.
    btcsig = bytearray(SignatureLength)
    btcsig[RecoveryIDOffset] = sig[RecoveryIDOffset] + 27
    btcsig[1:] = sig[1:]

    # Use btclib to recover public key
    x, y = ssa.ecdsa_recover(hash, btcsig, secp256k1)
    return point_from_octets(secp256k1, x, y)


def sig_to_pub(hash, sig):
    if len(sig) != SignatureLength:
        raise ValueError("invalid signature")

    # Convert to btclib input format with 'recovery id' v at the beginning.
    btcsig = bytearray(SignatureLength)
    btcsig[RecoveryIDOffset] = sig[RecoveryIDOffset] + 27
    btcsig[1:] = sig[1:]

    # Use btclib to recover public key
    x, y = ssa.ecdsa_recover(hash, btcsig, secp256k1)
    return point_from_octets(secp256k1, x, y)


def sig_to_pub(hash, sig):
    if len(sig) != SignatureLength:
        raise ValueError("invalid signature")

    # Convert to btclib input format with 'recovery id' v at the beginning.
    btcsig = bytearray(SignatureLength)
    btcsig[RecoveryIDOffset] = sig[RecoveryIDOffset] + 27
    btcsig[1:] = sig[1:]

    # Use btclib to recover public key
    x, y = ssa.ecdsa_recover(hash, btcsig, secp256k1)
    return point_from_octets(secp256k1, x, y)


def sign(digest_hash, prv):
    if len(digest_hash) != DigestLength:
        return None, ValueError(f"hash is required to be exactly {DigestLength} bytes ({len(digest_hash)})")

    if prv.curve() != secp256k1:
        return None, ValueError("private key curve is not secp256k1")

    # Convert to btclib input format
    secexp = prv.secret
    seckey = ssa.int_from_Scalar(secexp, secp256k1.n)
    priv_key = SigningKey.from_secret_exponent(seckey, curve=secp256k1)
    
    # Use btclib to calculate the signature
    btcsig = ssa.ecdsa_sign(digest_hash, priv_key, secp256k1)
    btcsig = bytes(btcsig)
    
    # Convert to Ethereum signature format with 'recovery id' v at the end.
    v = btcsig[0] - 27
    btcsig = btcsig[1:] + bytes([v])
    
    return btcsig, None


def verify_signature(pubkey, hash, signature):
    if len(signature) != SignatureLength:
        return False

    # Convert to btclib input format
    x, y = bytes_to_point(pubkey, secp256k1)
    pub_key = VerifyingKey.from_public_point((x, y), curve=secp256k1)

    # Reject malleable signatures
    s = ssa.int_from_Scalar(signature[32:], secp256k1.n)
    if s > secp256k1.half_n:
        return False

    # Use btclib to verify the signature
    btcsig = signature[1:] + signature[:1]  # Swap 'recovery id' v to the beginning
    return ssa.ecdsa_verify(hash, btcsig, pub_key, secp256k1)


def decompress_pubkey(pubkey):
    if len(pubkey) != 33:
        raise ValueError("invalid compressed public key length")

    # Convert to btclib input format
    x, y = bytes_to_point(pubkey, secp256k1)
    return VerifyingKey.from_public_point((x, y), curve=secp256k1)


def compress_pubkey(pubkey):
    return bytes_from_point(pubkey.pubkey.point, compressed=True)


def bytes_to_point(pubkey, curve):
    return pubkey[1:], pubkey[0] if pubkey[0] % 2 == 0 else curve.p + pubkey[0]


# Example Usage:
# priv = SigningKey.generate(curve=secp256k1)
# pub = priv.get_verifying_key()
# msg = sha3('hello world'.encode('utf-8')).digest()
# signature, _ = sign(msg, priv)
# print(f"Signature: {signature}")
# valid = verify_signature(pub, msg, signature)
# print(f"Signature is valid: {valid}")
