#!/usr/bin/env python3

# These are unit tests for the tlslib.  It verifies the keys and
# certificates are copied correctly.

import os
import pwd
import shutil
import unittest
import tempfile

import tlslib


class TestLib(unittest.TestCase):
    """A unittest class to test the copy commands of the tls library."""

    def setUp(self):
        """Create a temporary directory for the test."""
        self.temporary_directory = tempfile.mkdtemp()

    def tearDown(self):
        """Delete the temporary directory for the test."""
        shutil.rmtree(self.temporary_directory)

    def test_ca(self):
        """Test the CA copy method."""
        directory = os.path.join(self.temporary_directory, 'ca')
        user = pwd.getpwuid(os.getuid())[0]
        group = pwd.getpwuid(os.getuid())[0]
        destination = os.path.join(directory, 'ca.crt')
        tlslib.ca('unit_tests/tls-test.crt', destination, user, group)
        assert os.path.isdir(directory)
        assert os.path.isfile(destination)

    def test_client_cert(self):
        """Test the copy client cert."""
        directory = os.path.join(self.temporary_directory, 'client_cert')
        destination = os.path.join(directory, 'client.crt')
        tlslib.client_cert('unit_tests/tls-client-test.crt', destination)
        assert os.path.isdir(directory)
        assert os.path.isfile(destination)

    def test_client_key(self):
        """Test the copy client key."""
        directory = os.path.join(self.temporary_directory, 'client_key')
        destination = os.path.join(directory, 'client.key')
        tlslib.client_key('unit_tests/tls-client-test.key', destination)
        assert os.path.isdir(directory)
        assert os.path.isfile(destination)

    def test_server_cert(self):
        """Test the copy server cert."""
        directory = os.path.join(self.temporary_directory, 'server_cert')
        destination = os.path.join(directory, 'server.crt')
        tlslib.client_cert('unit_tests/tls-test.crt', destination)
        assert os.path.isdir(directory)
        assert os.path.isfile(destination)

    def test_server_key(self):
        """Test the copy server key."""
        directory = os.path.join(self.temporary_directory, 'server_key')
        destination = os.path.join(directory, 'server.key')
        tlslib.client_key('unit_tests/tls-test.key', destination)
        assert os.path.isdir(directory)
        assert os.path.isfile(destination)


if __name__ == '__main__':
    unittest.main()
