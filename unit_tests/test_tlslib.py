#!/usr/bin/python3
import os
import tlslib
import shutil
from mock import patch


def test_ca():
    tlslib.ca('/tmp/tls', 'unit_tests/tls-test.crt')
    assert os.path.isdir('/tmp/tls')
    assert os.path.isfile('/tmp/tls/ca.crt')
    shutil.rmtree('/tmp/tls')


def test_client_cert():
    tlslib.client_cert('/tmp/tls/client', 'unit_tests/tls-client-test.crt',
                       'unit_tests/tls-client-test.key')
    assert os.path.isdir('/tmp/tls/client')
    assert os.path.isfile('/tmp/tls/client/client.crt')
    assert os.path.isfile('/tmp/tls/client/client.key')
    shutil.rmtree('/tmp/tls')


def test_server_cert():
    with patch('tlslib.unitdata.kv') as kvpatch:
        os.environ['JUJU_UNIT_NAME'] = 'tls-unit-name'
        with open('unit_tests/tls-test.crt', 'r') as fp:
            certificate_data = fp.read()
        # Mock up the return values with the certificate data.
        kvpatch.return_value.get.return_value = certificate_data
        tlslib.server_cert('/tmp/tls/server', 'unit_tests/tls-test.key')
        assert os.path.isdir('/tmp/tls/server')
        assert os.path.isfile('/tmp/tls/server/server.key')
        assert os.path.isfile('/tmp/tls/server/server.crt')
        shutil.rmtree('/tmp/tls')
