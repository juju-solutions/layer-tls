#!/usr/bin/env python3

# This is a functional test for the tls layer.  It verifies the keys and
# certificates are generated correctly.  This test is written without hard
# coding the charm name so this will work with charms that are created from
# the tls layer.

import amulet
import os
import unittest

seconds = 990


class TestDeployment(unittest.TestCase):
    '''A unittest class to test the results of deploying the tls layer.'''
    test_config = {'ca': None}

    @classmethod
    def setUpClass(cls):
        '''Set up the deployment in the class.'''
        cls.deployment = amulet.Deployment(series='trusty')
        charm_name = cls.deployment.charm_name
        print('Starting tests for {0}'.format(charm_name))
        # Specify charm_name because this layer could be named something else.
        cls.deployment.add(charm_name, units=3)
        try:
            cls.deployment.setup(timeout=seconds)
            cls.deployment.sentry.wait()
        except amulet.helpers.TimeoutError:
            msg = 'The model did not set up in {0} seconds!'.format(seconds)
            amulet.raise_status(amulet.SKIP, msg=msg)
        except:
            raise

    def test_all_units(self):
        service = self.deployment.charm_name
        for unit in self.deployment.sentry[service]:
            print('Testing unit {service}/{unit}'.format(**unit.info))
            if is_leader(unit):
                tls_leader_tests(unit)
            else:
                tls_follower_tests(unit)


def tls_follower_tests(unit, ca=None):
    '''Run tests on a follower unit, optionally sending in the CA to
    verify that it is installed on the unit.'''
    charm_dir = '/var/lib/juju/agents/unit-{service}-{unit}/charm'.format(
        **unit.info)
    key_name = '{service}_{unit}.key'.format(**unit.info)
    print('Verify pki/private/{0} exists and is not empty.'.format(key_name))
    key_path = 'easy-rsa/easyrsa3/pki/private/{0}'.format(key_name)
    key = unit.file_contents(os.path.join(charm_dir, key_path))
    assert key, 'The {0} was empty'.format(key_path)
    print('Verify the server certificate is on the unitdata.')
    server_certificate = verify_unitdata(unit, 'tls.server.certificate')
    cn = 'CN={public-address}'.format(**unit.info)
    assert cn in server_certificate, 'The public-address is not in the cert!'
    print('Verify the CA certificate exists and is not empty.')
    # The CA path on followers is different than on the leader.
    path = '/usr/local/share/ca-certificates/{service}.crt'.format(**unit.info)
    ca_cert = unit.file_contents(path)
    assert ca_cert, 'The CA was empty, should be at {0}'.format(path)
    assert 'BEGIN CERTIFICATE' in ca_cert, 'CA is not a valid certificate.'
    assert 'END CERTIFICATE' in ca_cert, 'CA is not a valid certificate'


def tls_leader_tests(unit, ca=None):
    '''Run tests on a leader unit, optionally sending in the CA to verify
    that it is installed on the unit's trust ring.'''
    assert is_leader(unit), 'This unit is not the leader.'
    charm_dir = '/var/lib/juju/agents/unit-{service}-{unit}/charm'.format(
        **unit.info)
    print('Verify the Certifiicate Authority (CA) exits on the leader.')
    ca_path = os.path.join(charm_dir, 'easy-rsa/easyrsa3/pki/ca.crt')
    # Read the CA file, this tests if the leader created the CA file.
    ca_cert = unit.file_contents(ca_path)
    assert ca_cert, 'The CA was empty, should be at {0}'.format(ca_path)
    assert 'BEGIN CERTIFICATE' in ca_cert, 'CA is not a valid certificate.'
    assert 'END CERTIFICATE' in ca_cert, 'CA is not a valid certificate'

    print('Verify the server certificate ')
    certificate = verify_unitdata(unit, 'tls.server.certificate')
    public_ip = unit.info['public-address']
    private_ip = None
    verify_san(certificate, public_ip, private_ip)

    print('Verify the client key and certificate were created.')
    client_key_name = 'easy-rsa/easyrsa3/pki/private/client.key'
    client_key_path = os.path.join(charm_dir, client_key_name)
    client_key = unit.file_contents(client_key_path)
    assert client_key, 'The client key should not be empty.'
    assert 'PRIVATE KEY' in client_key, 'The client key is not valid.'
    client_cert_name = 'easy-rsa/easyrsa3/pki/issued/client.crt'
    client_cert_path = os.path.join(charm_dir, client_cert_name)
    client_cert = unit.file_contents(client_cert_path)
    assert client_cert, 'The client certificate should not be empty.'
    assert 'Subject: CN=client' in client_cert, 'The Subject name was invalid.'
    verify_san(client_cert, public_ip, private_ip)


def is_leader(unit):
    '''Return True if this unit is the leader.'''
    output, exit_code = unit.run('is-leader')
    assert exit_code == 0, 'The is-leader command failed.'
    assert output, 'The output of is-leader was empty.'
    return output == 'True'


def get_leader(deployment, service_name):
    '''Return the leader unit for the give service name.'''
    for unit in deployment.sentry[service_name]:
        if is_leader(unit):
            return unit
    return None


def verify_unitdata(unit, key):
    '''Verify the key is available on the unitdata.'''
    print('Verify that "{0}" is available on unitdata.'.format(key))
    # Get the server cert from the unitdata key value store.
    chlp_command = 'chlp unitdata get {0}'.format(key)
    output, exit_code = unit.run(chlp_command)
    assert exit_code == 0, 'The chlp command was not successful'
    assert output, 'The key {0} has no value.'.format(key)
    return output


def verify_san(cert, public_ip, private_ip):
    '''Verify the certificate contains the public and private address in the
    Subject Alternate Names (SANs) field.'''
    print('Verifying the addresses are in SANs in the certficate.')
    if public_ip:
        public_san = 'IP Address:{0}'.format(public_ip)
        assert public_san in cert, 'Cert does not contain public ip address'
    if private_ip:
        private_san = 'IP Address:{0}'.format(private_ip)
        assert private_san in cert, 'Cert does not contain private ip address'


if __name__ == '__main__':
    unittest.main()
