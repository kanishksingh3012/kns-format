import base64
import unittest
from pathlib import Path

from kns.crypto import CryptoError, decrypt_block, derive_key, encrypt_block, new_file_header
from kns.format import parse


def fast_header():
    # Fewer rounds than a real file, so the tests run quickly.
    return {**new_file_header(), "iterations": "1000"}


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.header = fast_header()
        self.key = derive_key("correct horse", self.header)

    def test_round_trip(self):
        content = "Meet at 6pm é 😀".encode("utf-8")
        block = encrypt_block(self.key, 1, content, sender="kanishk", date="2026-10-07")
        self.assertEqual(decrypt_block(self.key, 1, block), content)

    def test_real_iteration_count_works(self):
        header = new_file_header()
        self.assertEqual(header["iterations"], "600000")
        key = derive_key("pw", header)
        self.assertEqual(decrypt_block(key, 1, encrypt_block(key, 1, b"hi")), b"hi")

    def test_same_password_and_salt_give_the_same_key(self):
        self.assertEqual(derive_key("correct horse", self.header), self.key)

    def test_same_message_twice_looks_different(self):
        first = encrypt_block(self.key, 1, b"hello")
        second = encrypt_block(self.key, 1, b"hello")
        self.assertNotEqual(first.payload, second.payload)

    def test_wrong_password_fails(self):
        block = encrypt_block(self.key, 1, b"secret")
        wrong = derive_key("wrong horse", self.header)
        with self.assertRaises(CryptoError):
            decrypt_block(wrong, 1, block)

    def test_changed_payload_fails(self):
        block = encrypt_block(self.key, 1, b"secret")
        raw = bytearray(base64.b64decode(block.payload))
        raw[0] ^= 1
        block.payload = base64.b64encode(bytes(raw)).decode("ascii")
        with self.assertRaises(CryptoError):
            decrypt_block(self.key, 1, block)

    def test_changed_public_fields_fail(self):
        for field, value in [("from", "someone else"), ("date", "1999-01-01"), ("type", "image")]:
            with self.subTest(field):
                block = encrypt_block(self.key, 1, b"secret", sender="kanishk", date="2026-10-07")
                block.header[field] = value
                with self.assertRaises(CryptoError):
                    decrypt_block(self.key, 1, block)

    def test_image_round_trip_and_renamed_image_fails(self):
        data = bytes(range(256)) * 40
        block = encrypt_block(self.key, 1, data, type="image", name="photo.png")
        self.assertEqual(decrypt_block(self.key, 1, block), data)
        block.header["name"] = "other.png"
        with self.assertRaises(CryptoError):
            decrypt_block(self.key, 1, block)

    def test_name_added_to_a_text_block_fails(self):
        block = encrypt_block(self.key, 1, b"secret")
        block.header["name"] = "photo.png"
        with self.assertRaises(CryptoError):
            decrypt_block(self.key, 1, block)

    def test_moved_block_fails(self):
        block = encrypt_block(self.key, 2, b"second message")
        with self.assertRaises(CryptoError):
            decrypt_block(self.key, 1, block)

    def test_example_files_decrypt_with_the_documented_password(self):
        examples = Path(__file__).parent.parent / "examples"
        kns = parse((examples / "valid_three_messages.kns").read_text(encoding="utf-8"))
        key = derive_key("example-password", kns.header)
        texts = [decrypt_block(key, i, b).decode("utf-8") for i, b in enumerate(kns.blocks, start=1)]
        self.assertEqual(texts[:2], ["Meet at 6pm", "See you there 😀"])
        self.assertEqual(len(texts), 3)

    def test_bad_file_header_is_rejected(self):
        bad_values = [
            ("cipher", "rot13"),
            ("kdf", "scrypt"),
            ("iterations", "many"),
            ("iterations", "0"),
            ("iterations", "99999999999"),
            ("salt", "not base64!"),
            ("salt", "c2hvcnQ="),
        ]
        for field, value in bad_values:
            with self.subTest(field=field, value=value):
                with self.assertRaises(CryptoError):
                    derive_key("pw", {**self.header, field: value})

    def test_bad_nonce_or_payload_is_rejected(self):
        for field, value in [("nonce", "c2hvcnQ="), ("nonce", "***"), ("payload", "***"), ("payload", "c2hvcnQ=")]:
            with self.subTest(field=field, value=value):
                block = encrypt_block(self.key, 1, b"secret")
                if field == "nonce":
                    block.header["nonce"] = value
                else:
                    block.payload = value
                with self.assertRaises(CryptoError):
                    decrypt_block(self.key, 1, block)


if __name__ == "__main__":
    unittest.main()
