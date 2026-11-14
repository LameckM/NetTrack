import unittest

from nettrack_ui.formatting import format_bytes, format_speed


class DashboardFormattingTests(unittest.TestCase):
    def test_formats_bytes_across_units(self):
        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(1024), "1.00 KB")
        self.assertEqual(format_bytes(1024 ** 2), "1.00 MB")

    def test_negative_bytes_are_clamped(self):
        self.assertEqual(format_bytes(-10), "0 B")

    def test_formats_speed(self):
        self.assertEqual(format_speed(1.25), "1.250 Mbps")
        self.assertEqual(format_speed(-1), "0.000 Mbps")


if __name__ == "__main__":
    unittest.main()
