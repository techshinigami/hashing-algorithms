import unittest
import hashlib
from sha256 import sha256

class Testsha256(unittest.TestCase):
    
    def test_known_hashes(self):
        # Known test cases for SHA-256
        test_cases = [
            ("", ""),
            ("hello", "hello"),
            ("The quick brown fox jumps over the lazy dog", "The quick brown fox jumps over the lazy dog"),
            ("The quick brown fox jumps over the lazy dog.", "The quick brown fox jumps over the lazy dog.")
        ]
        
        for message, _ in test_cases:
            with self.subTest(message=message):
                # Compare the custom sha256 function with hashlib's sha256
                expected_hash = hashlib.sha256(message.encode()).hexdigest()
                self.assertEqual(sha256(message), expected_hash)

    def test_empty_string(self):
        # Test for empty string
        self.assertEqual(sha256(""), hashlib.sha256("".encode()).hexdigest())

    def test_single_character(self):
        # Test for single character string
        self.assertEqual(sha256("a"), hashlib.sha256("a".encode()).hexdigest())

    def test_large_input(self):
        # Test for large input (e.g., 1MB string)
        large_input = "a" * 1024 * 1024  # 1MB of 'a'
        expected_hash = hashlib.sha256(large_input.encode()).hexdigest()
        self.assertEqual(sha256(large_input), expected_hash)

if __name__ == "__main__":
    unittest.main()