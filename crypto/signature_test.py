import unittest
from hashlib import sha3
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.util import string_to_number
from binascii import hexlify, unhexlify

class TestCrypto(unittest.TestCase):

    testmsg = unhexlify("0xce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008")
    testsig = unhexlify("0x90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e549984a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc9301")
    testpubkey = unhexlify("0x04e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a0a2b2667f7e725ceea70c673093bf67663e0312623c8e091b13cf2c0f11ef652")
    testpubkeyc = unhexlify("0x02e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a")

    def test_ecrecover(self):
        pubkey, _ = ecrecover(self.testmsg, self.testsig)
        self.assertEqual(pubkey, self.testpubkey)

    def test_verify_signature(self):
        sig = self.testsig[:-1]  # remove recovery id
        self.assertTrue(verify_signature(self.testpubkey, self.testmsg, sig))
        self.assertTrue(verify_signature(self.testpubkeyc, self.testmsg, sig))

        with self.assertRaises(ValueError):
            verify_signature(None, self.testmsg, sig)
        with self.assertRaises(ValueError):
            verify_signature(self.testpubkey, None, sig)
        with self.assertRaises(ValueError):
            verify_signature(self.testpubkey, self.testmsg, None)
        with self.assertRaises(ValueError):
            verify_signature(self.testpubkey, self.testmsg, sig + b'\x01\x02\x03')
        with self.assertRaises(ValueError):
            verify_signature(self.testpubkey, self.testmsg, sig[:-2])
        
        wrongkey = bytearray(self.testpubkey)
        wrongkey[10] += 1
        self.assertFalse(verify_signature(wrongkey, self.testmsg, sig))

    def test_decompress_pubkey(self):
        key = decompress_pubkey(self.testpubkeyc)
        uncompressed = from_ecdsa_pub(key)
        self.assertEqual(uncompressed, self.testpubkey)

        with self.assertRaises(ValueError):
            decompress_pubkey(None)
        with self.assertRaises(ValueError):
            decompress_pubkey(self.testpubkeyc[:5])
        with self.assertRaises(ValueError):
            decompress_pubkey(self.testpubkeyc + b'\x01\x02\x03')

    def test_compress_pubkey(self):
        key = VerifyingKey.from_string(self.testpubkey[1:], curve=SECP256k1)
        compressed = compress_pubkey(key)
        self.assertEqual(compressed, self.testpubkeyc)

    def test_pubkey_random(self):
        runs = 200

        for _ in range(runs):
            key = SigningKey.generate(curve=SECP256k1)
            compressed = compress_pubkey(key.get_verifying_key())
            uncompressed = decompress_pubkey(compressed)
            self.assertEqual(key.get_verifying_key(), uncompressed)

    def test_ecrecover_benchmark(self):
        for _ in range(200):
            ecrecover(self.testmsg, self.testsig)

    def test_verify_signature_benchmark(self):
        sig = self.testsig[:-1]
        for _ in range(200):
            verify_signature(self.testpubkey, self.testmsg, sig)

    def test_decompress_pubkey_benchmark(self):
        for _ in range(200):
            decompress_pubkey(self.testpubkeyc)

if __name__ == '__main__':
    unittest.main()

