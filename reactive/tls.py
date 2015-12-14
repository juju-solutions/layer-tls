import os
import shutil
import socket
import tempfile

from shlex import split
from subprocess import check_call

from charms.reactive import hook
from charms.reactive import remove_state
from charms.reactive import set_state
from charms.reactive import when
from charms.reactive import when_not

from charmhelpers.core import hookenv
from charmhelpers.core import unitdata
from charmhelpers.core.hookenv import is_leader
from charmhelpers.core.hookenv import leader_set
from charmhelpers.core.hookenv import leader_get
from contextlib import contextmanager


@hook('install')
def install():
    '''Install the easy-rsa software that is required for this layer.'''
    apt = 'apt-get install -y git openssl'
    check_call(split(apt))
    if os.path.isdir('easy-rsa'):
        shutil.rmtree('easy-rsa')
    git = 'git clone https://github.com/OpenVPN/easy-rsa.git'
    hookenv.log(git)
    check_call(split(git))
    with chdir('easy-rsa/easyrsa3'):
        check_call(split('./easyrsa --batch init-pki 2>&1'))


@hook('config-changed')
def config_changed():
    '''Called when the configuration values have changed.'''
    config = hookenv.config()
    if config.changed('root_certificate'):
        root_cert = config.get('root_certificate')
        if is_leader():
            hookenv.log('Creating the certificates.')
            root_cert = create_certificates(root_cert)
            # The leader created its own signed certificate.
            set_state('signed certificate available')
            hookenv.log('The leader is setting certificate_authority.')
            leader_set({'certificate_authority': root_cert})


@hook('leader-settings-changed')
def leader_settings_changed():
    '''When the leader settings changes the followers can get the certificate
    and install the certificate on their own system.'''
    # Get the current CA value from leader_get.
    ca = leader_get('certificate_authority')
    if ca:
        hookenv.log('Installing the CA.')
        install_ca(ca)


@when('create certificate signing request')
def create_csr(tls):
    '''Create a certificate signing request (CSR). Only the followers need to
    run this operation.'''
    if not is_leader():
        # Must remove the path characters from the unit name.
        path_name = _path_safe_name(hookenv.local_unit())
        # The Common Name is the public address of the system.
        cn = hookenv.unit_public_ip()
        hookenv.log('Creating the CSR for {0}'.format(cn))
        with chdir('easy-rsa/easyrsa3'):
            sans = get_sans()
            # Create a CSR for this system with the subject and SANs.
            gen_req = './easyrsa --batch --req-cn={0} --subject-alt-name={1} ' \
                      'gen-req {2} nopass 2>&1'.format(cn, sans, path_name)
            check_call(split(gen_req))
            # Read the CSR file.
            req_file = 'pki/reqs/{0}.req'.format(path_name)
            with open(req_file, 'r') as fp:
                csr = fp.read()
            # Set the CSR on the relation object.
            tls.set_csr(csr)
    else:
        hookenv.log('The leader does not need to create a CSR.')


@when('sign certificate signing request')
def import_sign(tls):
    '''Import and sign the certificate signing request (CSR). Only the leader
    can sign the requests.'''
    if is_leader():
        hookenv.log('The leader needs to sign the csr requests.')
        # Get all the requests that are queued up to sign.
        csr_map = tls.get_csr_map()
        # Iterate over the unit names related to CSRs.
        for unit_name, csr in csr_map.items():
            path_name = _path_safe_name(unit_name)
            with chdir('easy-rsa/easyrsa3'):
                temp_file = tempfile.NamedTemporaryFile(suffix='.csr')
                with open(temp_file.name, 'w') as fp:
                    fp.write(csr)
                if not os.path.isfile('pki/reqs/{0}.req'.format(path_name)):
                    hookenv.log('Importing csr from {0}'.format(path_name))
                    # Create the command to import the request using path name.
                    import_req = './easyrsa --batch import-req {0} {1} 2>&1'
                    # easy-rsa import-req /tmp/temporary.csr path_name
                    check_call(split(import_req.format(temp_file.name,
                                                       path_name)))
                if not os.path.isfile('pki/issued/{0}.crt'.format(path_name)):
                    hookenv.log('Signing csr from {0}'.format(path_name))
                    # Create a command that signs the request.
                    sign_req = './easyrsa --batch sign-req server {0} 2>&1'
                    check_call(split(sign_req.format(path_name)))
                # Read in the signed certificate.
                cert_file = 'pki/issued/{0}.crt'.format(path_name)
                with open(cert_file, 'r') as fp:
                    certificate = fp.read()
                hookenv.log('Leader sending signed certificate over relation.')
                # Send the certificate over the relation.
                tls.set_cert(unit_name, certificate)


@when('signed certificate available')
@when_not('server certificate available')
def server_cert(tls):
    '''Copy the certificate to the key value store of the unit for other
    layers to consume.'''
    if is_leader():
        # The leader signed its own server certificate named public-ip.crt
        cert_name = '{0}.crt'.format(hookenv.unit_public_ip())
        # The leader stored the server certificate in pki/issued/ directory.
        cert_file = 'easy-rsa/easyrsa3/pki/issued/{0}'.format(cert_name)
        with open(cert_file, 'r') as fp:
            cert = fp.read()
    else:
        # Get the signed certificate from the relation object.
        cert = tls.get_signed_cert()
    if cert:
        # Set cert on the unitdata key value store so other layers can get it.
        unitdata.kv().set('tls.server.certificate', cert)
        remove_state('signed certificate available')
        # Set the final state for the other layers to know when they can
        # retrieve the server certificate.
        set_state('server certificate available')


def create_certificates(certificate_authority=None):
    '''Return the CA and server certificates for this system. If the CA is
    empty, generate a self signged certificate authority.'''
    with chdir('easy-rsa/easyrsa3'):
        if not os.path.exists('pki/ca.crt'):
            # Initialize easy-rsa (by deleting old pki) so a new ca can be created.
            init = 'echo yes | ./easyrsa init-pki 2>&1'
            check_call(split(init))
            # Idempotency guard for the CA certificate. DO not regenerate if it
            # exists on disk. Assume we want to read and return this
        if os.path.exists('pki/ca.crt'):
            with open('pki/ca.crt', 'r') as fp:
                certificate_authority = fp.read()
        # The Common Name for a certificate must be an IP or hostname.
        cn = hookenv.unit_public_ip()
        if not certificate_authority:
            # Create a CA with the a common name, stored in pki/ca.crt
            build_ca = './easyrsa --batch "--req-cn={0}" build-ca nopass 2>&1'
            check_call(split(build_ca.format(cn)))
            # Read the CA so we can return the contents from this method.
            with open('pki/ca.crt', 'r') as fp:
                certificate_authority = fp.read()
        else:
            # write the CA that was passed in.
            with open('pki/ca.crt', 'w') as fp:
                fp.write(certificate_authority)
        # Do not regenerate the server certificate if it exists
        if not os.path.exists('pki/issued/{}.crt'.format(cn)):
            # Create a server certificate for the server based on the CA.
            server = './easyrsa --batch --req-cn={0} --subject-alt-name={1} ' \
                     'build-server-full {0} nopass 2>&1'.format(cn, get_sans())
            check_call(split(server))
        return certificate_authority


def install_ca(certificate_authority):
    '''Install a certificiate authority on the system.'''
    ca_file = '/usr/local/share/ca-certificates/{0}.crt'.format(
        hookenv.service_name())
    # Write the contents of certificate authority to the file.
    with open(ca_file, 'w') as fp:
        fp.write(certificate_authority)
    # Update the trusted CAs on this system.
    check_call(split('update-ca-certificates 2>&1'))


def get_sans(ip_list=None, dns_list=None):
    '''Return a string suitable for the easy-rsa subjectAltNames, if both
    ip_list and dns_list parameters are empty the method will generate a valid
    sans string with the public IP, private IP, and hostname of THIS system.'''
    sans = []
    for ip in ip_list or []:
        sans.append('IP:{0}'.format(ip))
    for dns in dns_list or []:
        sans.append('DNS:{0}'.format(dns))
    if not sans:
        # Create a default subject alternate name (SAN) string for this system.
        sans.append('IP:{0},IP:{1},DNS:{2}'.format(hookenv.unit_public_ip(),
                                                   hookenv.unit_private_ip(),
                                                   socket.gethostname()))
    return ','.join(sans)


def _path_safe_name(unit_name):
    '''Remove the special characters in a unit name (eg. tls/1 -> tls_1)'''
    return unit_name.replace('/', '_')


@contextmanager
def chdir(path):
    '''Change the current working directory to a different directory for a code
    block and return the previous directory after the block exits.'''
    old_dir = os.getcwd()
    os.chdir(path)
    yield
    os.chdir(old_dir)
