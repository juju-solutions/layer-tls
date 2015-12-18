#!/usr/bin/env python3

import amulet
import requests
import unittest


seconds = 990
class TestDeployment(unittest.TestCase):
    test_config = {'ca': None}

    @classmethod
    def setUpClass(cls):
        ''' Set up the deployment in the class.'''
        cls.deployment = amulet.Deployment(series='trusty')
        cls.deployment.add('tls', units=3)
        #cls.deploy.configre('tls', config)
        try:
            cls.deployment.setup(timeout=seconds)
            cls.deployment.sentry.wait()
        except amulet.helpers.TimeoutError:
            msg='The environment did not set up in {0} seconds!'.format(seconds)
            amulet.raise_status(amulet.SKIP, msg=msg)
        except:
            raise

    def test_all_units(self):
        for unit in self.deployment.sentry['tls']:
            output, rc = unit.run('pwd')
            print(output)
            if is_leader(unit):
                leader_tests(unit, self.test_config['ca'])
            else:
                follower_tests(unit, self.test_config['ca'])

def follower_tests(unit, ca=None):
    '''Run tests on a follower unit, optionally sending in the CA to
    verify that it is indeed installed on the unit's trust ring.'''
    certificate = verify_unit_data(unit, 'tls.server.certificate')
    public_ip = unit.info['public-address']
    private_ip = unit.info['private-address']
    verify_san(certificate, public_ip, private_ip)
    verify_tls_pem(unit, ca)


def leader_tests(unit, ca=None):
    '''Run tests on a leader unit, optionally sending in the CA to verify
    that it is installed on the unit's trust ring.'''
    assert is_leader(unit), 'This unit is not the leader.'
    print('Verify the Certifiicate Authority (CA) exits on the leader.')
    # Read the CA file, this tests if the leader created the CA file.
    ca_file = 'easy-rsa/easyrsa3/pki/ca.crt'
    ca_cert = unit.file_contents(ca_file)
    assert ca_cert, 'The Certificate Authority file is empty.'
    if ca:
        assert ca == ca_cert, 'The CAs do not match.'
    certificate = verify_unit_data(unit, 'tls.server.certificate')
    public_ip = unit.info['public-address']
    private_ip = unit.info['private-address']
    verify_san(certificate, public_ip, private_ip)
    print('Verify the leader generated server certificate contains SANs')
    # Read the server certificate, testing if the leader created the file.
    server_file = 'easy-rsa/easyrsa3/pki/issued/{0}.crt'.format(public_ip)
    server_cert = unit.file_contents(server_file)
    assert server_cert, 'Server certificate is empty.'
    verify_sans(server_cert, public_ip, private_ip)
    assert server_cert == certificate

    verify_tls_pem(unit, ca)


def is_leader(unit):
    '''Return True if this unit is the leader.'''
    output, exit_code = unit.run('is-leader')
    return exit_code == 0

def get_leader(deployment, service_name):
    '''Return the leader unit for the give service name.'''
    for unit in deployment.sentry[service_name]:
        if is_leader(unit):
            return sentry
    return None

def verify_unitdata(unit, key):
    '''Verify the key is available on the unitdata.'''
    print('Verifying {0} is available on unitata.'.format(key))
    # Get the server cert from the unitdata key value store.
    chlp_command = 'chlp unitdata get {0}'.format(key)
    print(chlp_command)
    output, exit_code = unit.run(chlp_command)
    assert exit_code == 0, 'The chlp command was not successful'
    assert output, 'The key {0} has no value.'.format(key)
    return output

def verify_san(cert, public_ip, private_ip):
    '''Verify the certificate contains the public and private address in the
    Subject Alternate Names (SANs) field.'''
    print('Verifying the addresses are in SANs in the certficate.')
    if public_ip:
        pub_san = 'IP Address:{0}'.format(public_ip)
        assert cert.contains(pub_san), 'Cert does not contain public ip address'
    if private_ip:
        pri_san = 'IP Address:{0}'.format(private_ip)
        assert cert.contains(pri_sans), 'Cert does not contain private ip address'

def verify_tls_pem(unit, ca=None):
    '''Verify that this system contains the trusted certificate.'''
    print('Verifying the certificate is trusted on the unit.')
    # Ensure that the tls.pem file was trusted on this machine.
    tls_pem_file = '/etc/ssl/certs/tls.pem'
    tls_pem = unit.file_contents(tls_pem_file)
    assert tls_pem, 'The trusted PEM file is empty.'
    if ca:
        assert tls_pem.contains(ca), 'The PEM does not match the CA.'


if __name__ == '__main__':
    unittest.main()
