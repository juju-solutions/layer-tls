#!/usr/bin/python3
import pytest
import sys
import os
import tlslib

from mock import patch

def test_ca():
    tlslib.ca('/tmp/tls', 'unit_tests/tls-test.crt')
    assert os.path.isdir('/tmp/tls/')
    assert os.path.isfile('/tmp/tls/ca.crt')


def test_client_cert():
    tlslib.client_cert('/tmp/tls/client', 'unit_tests/tls-client-test.crt',
                       'unit_tests/tls-client-test.key')
    assert os.path.isdir('/tmp/tls/client')
    assert os.path.isfile('/tmp/tls/client/client.crt')
    assert os.path.isfile('/tmp/tls/client/client.key')


def test_server_cert():
    with patch('tlslib.unitdata.kv') as kvpatch:
        os.environ['JUJU_UNIT_NAME'] = 'tls-unit-name'
        with open('unit_tests/tls-test.crt', 'r') as fp:
            certificate_data = fp.read()
        kvpatch.return_value.get.return_value = certificate_data
        tlslib.server_cert('/tmp/tls/server', 'unit_tests/tls-test.key')
        assert os.path.isdir('/tmp/tls/server')
        assert os.path.isfile('/tmp/tls/server/server.key')
        assert os.path.isfile('/tmp/tls/server/server.crt')
#
# @pytest.fixture
# def client_cert():
#     from tlslib import client_cert as cc
#     cc("/tmp", 'tls-client-test.crt', 'tls-client-test.key')
#
# def test_client_cert(monkeypatch):
#     monkeypatch.setenv('JUJU_UNIT_NAME', 'test-tls')
#     client_cert()
#     assert os.path.isfile('/tmp/client.crt')
#     assert os.path.isfile('/tmp/client.key')
#
# @pytest.fixture
# def server_cert():
#     from tlslib import server_cert as sc
#     sc("/tmp", '/tmp/client.key')
#
# def test_server_cert(monkeypatch):
#     monkeypatch.setenv('JUJU_UNIT_NAME', 'test-tls')
#     server_cert()
#     assert os.path.isfile('/tmp/client.key')
