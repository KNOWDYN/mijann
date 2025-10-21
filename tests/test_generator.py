# tests/test_generator.py
# Contains unit tests for the Mijann shield generator.

import unittest
from unittest.mock import patch
import sys
import os

# Add the tools directory to the Python path to import the generator module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tools')))

# The generator script is not structured as a module, so we import its functions carefully.
# For a more testable structure, the core logic could be moved out of the `if __name__ == "__main__"` block.
# Here, we will test the parts we can, like the helper function.

from mijann_generator import fmt_list

class TestGeneratorHelpers(unittest.TestCase):
    """Tests the helper functions in the generator."""

    def test_fmt_list_with_items(self):
        """Tests that a list of strings is formatted correctly."""
        items = ["answer_questions", "search_web"]
        expected_output = '["answer_questions", "search_web"]'
        self.assertEqual(fmt_list(items), expected_output)

    def test_fmt_list_with_empty_list(self):
        """Tests that an empty list is formatted as '[]'."""
        items = []
        expected_output = '[]'
        self.assertEqual(fmt_list(items), expected_output)

    def test_fmt_list_with_single_item(self):
        """Tests that a single-item list is formatted correctly."""
        items = ["web.search"]
        expected_output = '["web.search"]'
        self.assertEqual(fmt_list(items), expected_output)

if __name__ == '__main__':
    unittest.main()
