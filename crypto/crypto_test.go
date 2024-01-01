import os
import hashlib
import ecdsa
import binascii
import codecs

# SignatureLength indica la lunghezza in byte richiesta per contenere una firma con ID di recupero.
SignatureLength = 64 + 1  # 64 byte firma ECDSA + 1 byte ID di recupero

# RecoveryIDOffset punta all'offset in byte all'interno della firma che contiene l'ID di recupero.
RecoveryIDOffset = 64

# DigestLength imposta la lunghezza esatta del digest della firma
DigestLength = 32

# secp256k1N e secp256k1halfN sono valori preimpostati necessari per l'ellittografia secp256k1.
secp256k1N = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
secp256k1halfN = secp256k1N // 2

# errInvalidPubkey indica un errore di chiave pubblica non valida.
errInvalidPubkey = ValueError("Chiave pubblica secp256k1 non valida")


def NewKeccakState():
    # Crea un nuovo oggetto per lo stato di Keccak (SHA3).
    return hashlib.sha3_256()


def HashData(kh, data):
    # Calcola l'hash dei dati forniti usando lo stato di Keccak e restituisce un hash di 32 byte.
    kh.update(data)
    return kh.digest()


def Keccak256(*data):
    # Calcola e restituisce l'hash Keccak256 dei dati di input.
    d = hashlib.sha3_256()
    for b in data:
        d.update(b)
    return d.digest()


def CreateAddress(b, nonce):
    # Crea un indirizzo Ethereum dato i byte e il nonce.
    data = rlp_encode([b, nonce])
    return bytes_to_address(Keccak256(data)[12:])


def CreateAddress2(b, salt, inithash):
    # Crea un indirizzo Ethereum dato i byte dell'indirizzo, l'hash iniziale del contratto e un salt.
    return bytes_to_address(Keccak256([bytes([0xff]), b, salt, inithash])[12:])


def ToECDSA(d):
    # Crea una chiave privata con il valore D fornito.
    priv = ecdsa.SigningKey.from_string(d, curve=ecdsa.SECP256k1)
    return priv


def ToECDSAUnsafe(d):
    # Converte in modo non sicuro un blob binario in una chiave privata.
    return ecdsa.SigningKey.from_string(d, curve=ecdsa.SECP256k1)


def FromECDSA(priv):
    # Esporta una chiave privata in una sequenza binaria.
    return priv.to_string()


def UnmarshalPubkey(pub):
    # Converte byte in una chiave pubblica secp256k1.
    try:
        pub = ecdsa.VerifyingKey.from_string(pub[1:], curve=ecdsa.SECP256k1)
        return pub
    except binascii.Error:
        raise errInvalidPubkey


def FromECDSAPub(pub):
    # Esporta una chiave pubblica in una sequenza binaria.
    return b"\x04" + pub.to_string()


def HexToECDSA(hexkey):
    # Analizza una chiave privata secp256k1 da una stringa esadecimale.
    b = codecs.decode(hexkey, "hex")
    return ToECDSA(b)


def LoadECDSA(file):
    # Carica una chiave privata secp256k1 dal file fornito.
    with open(file, "r") as f:
        key_hex = f.read().strip()
    return HexToECDSA(key_hex)


def SaveECDSA(file, key):
    # Salva una chiave privata secp256k1 nel file fornito.
    with open(file, "w") as f:
        f.write(FromECDSA(key).hex())


def GenerateKey():
    # Genera una nuova chiave privata secp256k1.
    return ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)


def ValidateSignatureValues(v, r, s, homestead):
    # Verifica se i valori della firma sono validi secondo le regole della catena.
    if r < 1 or s < 1:
        return False
    # reject upper range of s values (ECDSA malleability)
    if homestead and s > secp256k1halfN:
        return False
    return r < secp256k1N and s < secp256k1N and (v == 0 or v == 1)


def PubkeyToAddress(p):
    # Converte una chiave pubblica in un indirizzo Ethereum.
    pub_bytes = FromECDSAPub(p)
    return bytes_to_address(Keccak256(pub_bytes[1:])[12:])


def zero_bytes(bytes):
    # Imposta tutti i byte in una sequenza di byte a zero.
    for i in range(len(bytes)):
        bytes[i] = 0


def rlp_encode(data):
    # Implementa la codifica RLP.
    # (Nota: questa è un'implementazione semplificata, può non essere completa)
    result = b""
    for item in data:
        if isinstance(item, list):
            result += b"\xc0" + rlp_encode(item)
        elif isinstance(item, int):
            if item < 128:
                result += bytes([item])
            else:
                length = len(hex(item)) // 2
                result += bytes([128 + length]) + item.to_bytes(length, "big")
        else:
            raise ValueError("Tipo di dato non supportato per RLP")
    return result


def bytes_to_address(b):
    # Converte byte in un indirizzo Ethereum.
    return codecs.encode(b, "hex")[24:]


# Esempio di utilizzo:
# key = GenerateKey()
# print("Chiave privata:", key.to_string().hex())
# print("Indirizzo Ethereum:", PubkeyToAddress(key.get_verifying_key()))
