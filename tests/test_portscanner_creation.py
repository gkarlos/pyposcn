import unittest
import sys
import os

sys.path.append(os.path.abspath("../pyposcn"))

from api.networking import PortScanner


class TestPortScannerConstructor(unittest.TestCase):
    def test_invalid_workload_input(self):
        self.assertRaises(TypeError, lambda: PortScanner("invalid_workload", 0, 0))
        self.assertRaises(TypeError, lambda: PortScanner(None, 0, 0))

    def test_invalid_type_scan_type(self):
        self.assertRaises(TypeError, lambda: PortScanner({}, "invalid_scan_type", 0))
        self.assertRaises(TypeError, lambda: PortScanner({}, None, 0))

    def test_invalid_value_scan_type(self):
        self.assertRaises(ValueError, lambda: PortScanner({}, 15, 0))

        correct_exception = False
        try:
            PortScanner({}, 15, 0)
        except ValueError, msg:
            correct_exception = 'scan_type' in str(msg)
        self.assertTrue(correct_exception)

        self.assertRaises(TypeError, lambda: PortScanner({}, None, 0))

    def test_invalid_type_scanner_type(self):
        self.assertRaises(TypeError, lambda: PortScanner({}, 0, "invalid_scanner_type"))
        correct_exception = False
        try:
            PortScanner({}, 0, "invalid_scanner_type")
        except TypeError, msg:
            correct_exception = 'scanner_type' in str(msg)
        self.assertTrue(correct_exception)

        self.assertRaises(TypeError, lambda: PortScanner({}, 0, None))

    def test_invalid_value_scanner_type(self):
        self.assertRaises(ValueError, lambda: PortScanner({}, 0, 15))

        correct_exception = False
        try:
            PortScanner({}, 0, 15)
        except ValueError, msg:
            correct_exception = 'scanner_type' in str(msg)
        self.assertTrue(correct_exception)

        self.assertRaises(TypeError, lambda: PortScanner({}, None, 0))
