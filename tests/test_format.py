import unittest
from pathlib import Path

from kns.format import KnsError, check_image_name, parse, serialize

EXAMPLES = Path(__file__).parent.parent / "examples"

# Each invalid example must be rejected with a message containing this text.
REASONS = {
    "invalid_no_magic": "magic line",
    "invalid_missing_salt": "missing required file header field 'salt'",
    "invalid_missing_iterations": "missing required file header field 'iterations'",
    "invalid_duplicate_key": "duplicate key 'from'",
    "invalid_bad_key": "invalid key 'Sent By'",
    "invalid_no_colon": "expected 'key: value'",
    "invalid_no_separator": "separator",
    "invalid_missing_nonce": "missing required field 'nonce'",
    "invalid_missing_type": "missing required field 'type'",
    "invalid_empty_payload": "empty payload",
    "invalid_repeated_nonce": "same nonce",
}


def read(name):
    return (EXAMPLES / name).read_text(encoding="utf-8")


class FormatTests(unittest.TestCase):
    def test_valid_files_parse(self):
        files = sorted(EXAMPLES.glob("valid_*.kns"))
        self.assertTrue(files)
        for path in files:
            with self.subTest(path.name):
                parse(path.read_text(encoding="utf-8"))

    def test_invalid_files_are_rejected_for_the_right_reason(self):
        files = sorted(EXAMPLES.glob("invalid_*.kns"))
        self.assertEqual({path.stem for path in files}, set(REASONS))
        for path in files:
            with self.subTest(path.name):
                with self.assertRaises(KnsError) as caught:
                    parse(path.read_text(encoding="utf-8"))
                self.assertIn(REASONS[path.stem], str(caught.exception))

    def test_three_messages_keep_their_order(self):
        kns = parse(read("valid_three_messages.kns"))
        self.assertEqual(kns.header["kdf"], "pbkdf2-sha256")
        self.assertEqual([b.header["from"] for b in kns.blocks], ["kanishk", "asha", "kanishk"])

    def test_wrapped_payload_is_joined(self):
        payload = parse(read("valid_three_messages.kns")).blocks[2].payload
        self.assertGreater(len(payload), 64)
        self.assertNotIn("\n", payload)
        self.assertNotIn(" ", payload)

    def test_file_with_no_messages(self):
        self.assertEqual(parse(read("valid_no_messages.kns")).blocks, [])

    def test_error_reports_the_line(self):
        with self.assertRaises(KnsError) as caught:
            parse("#KNS v1\ncipher: a\ncipher: b\n")
        self.assertEqual(caught.exception.line, 3)

    def test_image_names(self):
        # tests/web_check.mjs checks the same names against the web page.
        names = {
            "photo.jpg": True, "IMG_1234.JPEG": True, "a-b.c.webp": True, "a" * 96 + ".png": True,
            "../x.png": False, "a/b.png": False, ".hidden.png": False, "photo.svg": False,
            "png": False, "": False, None: False, "has space.png": False, "a" * 97 + ".png": False,
            "x.png\n": False,
        }
        for name, good in names.items():
            with self.subTest(name=name):
                if good:
                    check_image_name(name)
                else:
                    with self.assertRaises(KnsError):
                        check_image_name(name)

    def test_write_then_read_gives_the_same_file(self):
        for path in sorted(EXAMPLES.glob("valid_*.kns")):
            with self.subTest(path.name):
                kns = parse(path.read_text(encoding="utf-8"))
                self.assertEqual(parse(serialize(kns)), kns)


if __name__ == "__main__":
    unittest.main()
