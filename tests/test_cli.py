import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kns.cli import main


def run(*argv, password="correct horse"):
    """Run the tool. Returns (exit code, what it printed, what it printed as errors)."""
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, {"KNS_PASSWORD": password}):
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


@mock.patch("kns.crypto.ITERATIONS", 1000)  # keep the tests fast
class CliTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "chat.kns"
        self.file = str(self.path)

    def test_add_list_read(self):
        self.assertEqual(run("add", self.file, "--from", "kanishk", "-m", "Meet at 6pm")[0], 0)
        self.assertEqual(run("add", self.file, "--from", "asha", "-m", "See you there 😀")[0], 0)

        code, out, _ = run("list", self.file, password="")
        self.assertEqual(code, 0)
        self.assertIn("[1] kanishk", out)
        self.assertIn("[2] asha", out)
        self.assertIn("2 message(s)", out)
        self.assertNotIn("6pm", out)

        code, out, _ = run("read", self.file)
        self.assertEqual(code, 0)
        self.assertIn("Meet at 6pm", out)
        self.assertIn("See you there 😀", out)

    def test_message_text_is_not_in_the_file(self):
        run("add", self.file, "-m", "Meet at 6pm")
        self.assertNotIn("6pm", self.path.read_text(encoding="utf-8"))

    def test_read_with_wrong_password_fails(self):
        run("add", self.file, "-m", "secret")
        code, out, err = run("read", self.file, password="wrong")
        self.assertEqual(code, 1)
        self.assertNotIn("secret", out)
        self.assertIn("wrong password", err)

    def test_add_with_wrong_password_leaves_the_file_alone(self):
        run("add", self.file, "-m", "first")
        before = self.path.read_text(encoding="utf-8")
        self.assertEqual(run("add", self.file, "-m", "second", password="wrong")[0], 1)
        self.assertEqual(self.path.read_text(encoding="utf-8"), before)

    def test_add_keeps_existing_text_and_comments(self):
        run("add", self.file, "-m", "first")
        text = self.path.read_text(encoding="utf-8")
        before = text.replace("#KNS v1\n", "#KNS v1\n# a note someone typed by hand\n")
        self.path.write_text(before, encoding="utf-8")
        run("add", self.file, "-m", "second")
        after = self.path.read_text(encoding="utf-8")
        self.assertTrue(after.startswith(before))
        self.assertIn("second", run("read", self.file)[1])

    def test_edited_sender_is_detected(self):
        run("add", self.file, "--from", "kanishk", "-m", "hello")
        text = self.path.read_text(encoding="utf-8")
        self.path.write_text(text.replace("from: kanishk", "from: someone else"), encoding="utf-8")
        self.assertEqual(run("read", self.file)[0], 1)

    def add_image(self, file_name="my photo (1).PNG", data=b"\x89PNG not really an image \x00\xff" * 50):
        source = self.path.parent / file_name
        source.write_bytes(data)
        self.assertEqual(run("add", self.file, "--from", "asha", "--image", str(source))[0], 0)
        return data

    def test_image_is_saved_only_when_asked(self):
        run("add", self.file, "-m", "look at this")
        data = self.add_image()
        self.assertIn("(image: my_photo__1_.PNG)", run("list", self.file)[1])

        code, out, _ = run("read", self.file)
        self.assertEqual(code, 0)
        self.assertIn("--images", out)

        folder = self.path.parent / "out"
        code, out, _ = run("read", self.file, "--images", str(folder))
        self.assertEqual(code, 0)
        self.assertEqual((folder / "2-my_photo__1_.PNG").read_bytes(), data)

    def test_saving_never_overwrites(self):
        self.add_image()
        folder = self.path.parent / "out"
        folder.mkdir()
        (folder / "1-my_photo__1_.PNG").write_bytes(b"mine")
        code, out, _ = run("read", self.file, "--images", str(folder))
        self.assertEqual(code, 0)
        self.assertIn("already exists", out)
        self.assertEqual((folder / "1-my_photo__1_.PNG").read_bytes(), b"mine")

    def test_unsafe_image_name_in_a_file_is_refused(self):
        self.add_image()
        text = self.path.read_text(encoding="utf-8")
        self.path.write_text(text.replace("name: my_photo__1_.PNG", "name: ../../evil.png"), encoding="utf-8")
        folder = self.path.parent / "out"
        code, _, err = run("read", self.file, "--images", str(folder))
        self.assertEqual(code, 1)
        self.assertIn("image name", err)
        self.assertFalse(folder.exists())

    def test_only_image_files_can_be_added(self):
        source = self.path.parent / "notes.txt"
        source.write_text("hello")
        self.assertEqual(run("add", self.file, "--image", str(source))[0], 1)
        self.assertFalse(self.path.exists())

    def test_broken_file_reports_the_line(self):
        self.path.write_text("#KNS v1\ncipher: a\ncipher: b\n", encoding="utf-8")
        code, _, err = run("list", self.file)
        self.assertEqual(code, 1)
        self.assertIn("line 3", err)

    def test_missing_file(self):
        self.assertEqual(run("read", self.file)[0], 1)


if __name__ == "__main__":
    unittest.main()
