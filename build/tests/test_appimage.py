"""Exercise the actual packaging script without downloading linuxdeploy."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "linux/appimage/build.sh"


class AppImageOutputTests(unittest.TestCase):
    def run_package(self, outputs, previous=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = root / "commands"
            commands.mkdir()
            for name, body in {
                "uname": "echo x86_64\n",
                "wget": "exit 0\n",
            }.items():
                executable = commands / name
                executable.write_text("#!/bin/sh\n" + body)
                executable.chmod(0o755)
            deploy = root / "linuxdeploy-x86_64.AppImage"
            deploy.write_text("#!/bin/sh\n" + "".join(
                f"printf new > '{name}'\n" for name in outputs))
            for name in ("wireguide", "icon.png", "wireguide.desktop"):
                (root / name).write_text("fixture")
            if previous:
                (root / "wireguide.AppImage").write_text("old")
            env = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ["PATH"],
                       APP_NAME="wireguide", APP_BINARY="wireguide",
                       ICON_PATH="icon.png", DESKTOP_FILE="wireguide.desktop")
            result = subprocess.run(["bash", str(SCRIPT)], cwd=root, env=env,
                                    capture_output=True, text=True)
            final = root / "wireguide.AppImage"
            return result.returncode, final.read_text() if final.exists() else None, result.stderr

    def test_generated_capitalized_name(self):
        code, content, log = self.run_package(["WireGuide-x86_64.AppImage"])
        self.assertEqual(code, 0, log)
        self.assertEqual(content, "new")

    def test_exact_name(self):
        code, content, log = self.run_package(["wireguide.AppImage"])
        self.assertEqual(code, 0, log)
        self.assertEqual(content, "new")

    def test_rebuild_replaces_previous_output(self):
        code, content, log = self.run_package(["WireGuide-x86_64.AppImage"], previous=True)
        self.assertEqual(code, 0, log)
        self.assertEqual(content, "new")

    def test_missing_output(self):
        self.assertNotEqual(self.run_package([])[0], 0)

    def test_missing_output_does_not_reuse_previous_build(self):
        code, content, _ = self.run_package([], previous=True)
        self.assertNotEqual(code, 0)
        self.assertEqual(content, "old")

    def test_exact_name_replaces_previous_output(self):
        code, content, log = self.run_package(["wireguide.AppImage"], previous=True)
        self.assertEqual(code, 0, log)
        self.assertEqual(content, "new")

    def test_ambiguous_output(self):
        self.assertNotEqual(self.run_package(["wireguide-a.AppImage", "wireguide-b.AppImage"])[0], 0)


if __name__ == "__main__":
    unittest.main()
