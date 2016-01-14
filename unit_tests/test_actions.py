#!/usr/bin/python3
import pytest
import sys
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

@pytest.fixture
def client_cert():
    from tlslib import client_cert as cc
    cc("/tmp", 'tls-test.crt', 'tls-test.key')

def test_client_cert(monkeypatch):
    monkeypatch.setenv('JUJU_UNIT_NAME', 'test-tls')
    client_cert()

@pytest.fixture
def server_cert():
    from tlslib import server_cert as sc
    sc("/tmp", 'tls-test.key')

def test_server_cert(monkeypatch):
    monkeypatch.setenv('JUJU_UNIT_NAME', 'test-tls')
    server_cert()
