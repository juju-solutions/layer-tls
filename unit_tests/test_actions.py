#!/usr/bin/python3
import pytest
import sys
import os
from pkg_resources import resource_filename

# allow importing actions from the lib directory
sys.path.append(resource_filename(__name__, '../lib'))


@pytest.fixture
def ca():
    from tlslib import ca as cert_auth
    cert_auth("/tmp", 'tls-test.crt')

def test_ca(monkeypatch):
    monkeypatch.setenv('JUJU_UNIT_NAME', 'test-tls')
    ca()
    assert os.path.isfile('/tmp/tls-test.crt')
 
@pytest.fixture
def client_cert():
    from tlslib import client_cert as cc
    cc("/tmp", 'tls-client-test.crt', 'tls-client-test.key')

def test_client_cert(monkeypatch):
    monkeypatch.setenv('JUJU_UNIT_NAME', 'test-tls')
    client_cert()
    assert os.path.isfile('/tmp/client.crt')
    assert os.path.isfile('/tmp/client.key')

@pytest.fixture
def server_cert():
    from tlslib import server_cert as sc
    sc("/tmp", '/tmp/client.key')

def test_server_cert(monkeypatch):
    monkeypatch.setenv('JUJU_UNIT_NAME', 'test-tls')
    server_cert()
    assert os.path.isfile('/tmp/client.key')
