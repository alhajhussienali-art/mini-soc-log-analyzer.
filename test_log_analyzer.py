import tempfile
import unittest
from pathlib import Path

from src.log_analyzer import analyze_log


class TestLogAnalyzer(unittest.TestCase):
    def make_log(self, content: str) -> str:
        temp = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False
        )
        temp.write(content)
        temp.close()
        self.addCleanup(lambda: Path(temp.name).unlink(missing_ok=True))
        return temp.name

    def test_detects_suspicious_ip(self):
        log = "\n".join(
            f"Jul 28 09:00:0{i} server sshd[10{i}]: "
            f"Failed password for admin from 192.0.2.10 port 500{i} ssh2"
            for i in range(5)
        )
        result = analyze_log(self.make_log(log), threshold=5)

        self.assertEqual(result["failed_logins"], 5)
        self.assertEqual(result["suspicious_ips"]["192.0.2.10"], 5)

    def test_successful_login_is_counted(self):
        log = (
            "Jul 28 09:00:01 server sshd[100]: "
            "Accepted password for ali from 192.0.2.20 port 5000 ssh2\n"
        )
        result = analyze_log(self.make_log(log))

        self.assertEqual(result["successful_logins"], 1)
        self.assertEqual(result["failed_logins"], 0)

    def test_threshold_validation(self):
        with self.assertRaises(ValueError):
            analyze_log(self.make_log(""), threshold=0)


if __name__ == "__main__":
    unittest.main()
