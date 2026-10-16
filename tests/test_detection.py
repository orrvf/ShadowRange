
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DETECTOR = PROJECT_ROOT / "detection_engine" / "detect.py"


class DetectionTests(unittest.TestCase):

    def run_detector(self, permissions):
        region = {
            "pid": 9999,
            "start": 4096,
            "end": 8192,
            "offset": 0,
            "inode": 0,
            "permissions": permissions,
            "device": "00:00",
            "path": "[test]",
        }

        with tempfile.TemporaryDirectory() as directory:
            input_file = Path(directory) / "test.telemetry"
            input_file.write_text(
                json.dumps(region) + "\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [sys.executable, str(DETECTOR), str(input_file)],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Invalid records: 0", result.stdout)

            alerts_file = PROJECT_ROOT / "alerts.jsonl"
            lines = alerts_file.read_text(encoding="utf-8").splitlines()

            return [json.loads(line) for line in lines]

    def test_writable_executable_memory(self):
        alerts = self.run_detector("rwxp")

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "MEMORY_WX")
        self.assertEqual(alerts[0]["pid"], 9999)

    def test_read_only_memory(self):
        alerts = self.run_detector("r--p")
        self.assertEqual(len(alerts), 0)

    def test_executable_memory(self):
        alerts = self.run_detector("r-xp")
        self.assertEqual(len(alerts), 0)

    def test_writable_memory(self):
        alerts = self.run_detector("rw-p")
        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
