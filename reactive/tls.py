import os

from shlex import split
from subprocess import check_call

from charms.reactive import hook
from charms.reactive import remove_state
from charms.reactive import set_state
from charms.reactive import when
from charms.reactive import when_not

from charmhelpers.core import hookenv
from charmhelpers.core import unitdata
from charmhelpers.core.hookenv import status_set
from charmhelpers.core.hookenv import is_leader
from charmhelpers.core.hookenv import leader_set
from charmhelpers.core.hookenv import leader_get


@hook('install')
def install():
    '''Install the software required for this layer.'''
    apt = 'apt-get install -y git openssl'
    check_call(split(apt))
    git = 'git clone https://github.com/OpenVPN/easy-rsa.git'


@hook('config-changed')
def config_changed():
    '''If the configuration values have changed. '''
    config = hookenv.config()
    if config.changed('root_certificate'):
        root_cert = config.get('root_certificate')
        if is_leader():
            if not root_cert:
                hookenv.log('root_cert is empty generate a self signed certificate.')
                root_cert = generate_ca()
            else:
                hookenv.log('Using certificate from configuration.')
            leader_set({'certificate_authority': root_cert})


@hook('leader-settings-changed')
def leader_settings_changed():
    '''When the leader settings changes the followers can get the certificate
    and install the certificate on their own system.'''
    # Get the current CA value from leader_get.
    ca = leader_get('certificate_authority')
    cert_dir = '/usr/local/share/ca-certificates/'
    ca_file = os.path.join(cert_dir, '{0}.crt'.format(service_name())
    # Install the CA file from the leader settings.
    with open(ca_file, 'w') as fp:
        fp.write(ca)
    # Update the Certificate Authorities on this system.
    check_call(split('update-ca-certificates'))


@when('create certificate signing request')
def create_csr(tls):
    if not is_leader():
        csr = create_csr()
        tls.set_csr(csr)

@when('sign certificate signing request')
def import_sign(tls):
    if is_leader():
        csr_map = tls.get_csr_map()
        for name, csr in csr_map.items():
            # easy-rsa import-req /tmp/temporary.csr name
            # certificate = easy-rsa sign-req server name
            tls.set_cert(name, certifcate)


@when('signed certificate available')
def write_cert(tls):
    ''' '''
    cert = tls.get_signed_cert()
    cert_file = 'server.crt'
    unitdata.kv().set('tls.certificate', cert)
    set_state('tls.certificate.available')


def create_ca(common_name=None):
    '''Create a self signed certificate of authority for this system.'''
    with chdir('easy-rsa/easyrsa3')
        # Initialize easy-rsa (by deleting old pki) so you can create a new cert.
        init = 'echo yes | ./easyrsa init-pki --batch 2>&1'
        check_call(split(init))
        # Create the Certificate Authority, select a name called the Common Name (CN).
        if not common_name:
            common_name = unit_public_ip()
        # This name is purely for display purposes and can be set as you like.
        build_ca = './easyrsa --batch "--req-cn=${0}" build-ca nopass 2>&1'
        check_call(split(build_ca.format(common_name)))


@contextmanager
def chdir(path):
    '''Change the current working directory to a different directory for a code
    block and return the previous directory after the block exits.'''
    old_dir = os.getcwd()
    os.chdir(path)
    yield
    os.chdir(old_dir)
