import unittest
import hashlib
from md5 import md5, md5_file

class Testmd5(unittest.TestCase):
    
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
                # Compare the custom md5 function with hashlib's md5
                expected_hash = hashlib.md5(message.encode()).hexdigest()
                self.assertEqual(md5(message), expected_hash)

    def test_empty_string(self):
        # Test for empty string
        self.assertEqual(md5(""), hashlib.md5("".encode()).hexdigest())

    def test_single_character(self):
        # Test for single character string
        self.assertEqual(md5("a"), hashlib.md5("a".encode()).hexdigest())

    def test_large_input(self):
        # Test for large input (e.g., 1MB string)
        large_input = "a" * 1024 * 1024  # 1MB of 'a'
        expected_hash = hashlib.md5(large_input.encode()).hexdigest()
        self.assertEqual(md5(large_input), expected_hash)

    def test_file_hash(self):
        # Test for file hashing
        file_path = 'md5.py'
        with open(file_path, 'rb') as f:
            file_content = f.read()
        expected_hash = hashlib.md5(file_content).hexdigest()
        self.assertEqual(md5_file(file_path), expected_hash)

if __name__ == "__main__":
    unittest.main()
