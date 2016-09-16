import base64
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

from charmhelpers.core.host import chdir
from charmhelpers.core import hookenv
from charmhelpers.core import unitdata
from charmhelpers.core.hookenv import is_leader
from charmhelpers.core.hookenv import leader_set
from charmhelpers.core.hookenv import leader_get
from charmhelpers.core.hookenv import resource_get


@when_not('easyrsa installed')
def install():
    '''Install the easy-rsa software that is used by this layer.'''
    charm_dir = hookenv.charm_dir()
    # Create an absolute path to easy-rsa that is not affected by cwd.
    easy_rsa_directory = os.path.join(charm_dir, 'easy-rsa')
    if os.path.isdir(easy_rsa_directory):
        shutil.rmtree(easy_rsa_directory)
    # Try to get the resource from Juju.
    path = resource_get('easyrsa')
    if path:
        # Expand the archive in the charm directory creating an easy-rsa dir.
        untar = 'tar -xvzf {0} -C {1}'.format(path, charm_dir)
        check_call(split(untar))
    else:
        hookenv.log('Resource easyrsa unavailable.')
        # TODO: Remove this git code completely after we trust resources.
        git = 'git clone https://github.com/OpenVPN/easy-rsa.git'
        hookenv.log(git)
        check_call(split(git))
    # Create an absolute path to the easyrsa3 directory.
    easyrsa3_directory = os.path.join(easy_rsa_directory, 'easyrsa3')
    with chdir(easyrsa3_directory):
        check_call(split('./easyrsa --batch init-pki 2>&1'))
    set_state('easyrsa installed')


@when('easyrsa installed')
@when_not('easyrsa configured')
def configure_easyrsa():
    ''' Transitional state, allowing other layer(s) to modify config before we
        proceed generating the certificates and working with PKI. '''
    charm_dir = hookenv.charm_dir()
    # Create an absolute path to the file which will not be impacted by cwd.
    openssl_file = os.path.join(charm_dir, 'easy-rsa/easyrsa3/openssl-1.0.cnf')
    # Update EasyRSA configuration with the capacity to copy CSR Requested
    # Extensions through to the resulting certificate. This can be tricky,
    # and the implications are not fully clear on this.
    with open(openssl_file, 'r') as f:
        conf = f.readlines()
    # idempotency is a thing
    if 'copy_extensions = copy' not in conf:
        for idx, line in enumerate(conf):
            if '[ CA_default ]' in line:
                conf.insert(idx + 1, "copy_extensions = copy")
        with open(openssl_file, 'w+') as f:
            f.writelines(conf)

    set_state('easyrsa configured')


@when('easyrsa configured')
def check_ca_status(force=False):
    '''Called when the configuration values have changed.'''
    config = hookenv.config()
    if config.changed('root_certificate') or force:
        remove_state('certificate authority available')
        if is_leader():
            root_cert = config.get('root_certificate')
            if root_cert:
                decoded_cert = _decode(root_cert)
            else:
                decoded_cert = None
            hookenv.log('Leader is creating the certificate authority.')
            certificate_authority = create_certificate_authority(decoded_cert)
            leader_set({'certificate_authority': certificate_authority})
            install_ca(certificate_authority)
            # The leader can create the server certificate based on CA.
            hookenv.log('Leader is creating the server certificate.')
            # Remove the path characters from the unit name tls/0 -> tls_0.
            path_safe_name = hookenv.local_unit().replace('/', '_')
            create_server_certificate(path_safe_name)
            # The leader can create a client certificate one time.
            hookenv.log('Leader is creating the client certificate.')
            create_client_certificate()


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
        # Create an absolute path to easyrsa3 to change to that directory.
        easyrsa3_dir = os.path.join(hookenv.charm_dir(), 'easy-rsa/easyrsa3')
        # Use an absolute path for this context manager.
        with chdir(easyrsa3_dir):
            # Must remove the path characters from the unit name.
            path_name = hookenv.local_unit().replace('/', '_')
            # The reqest will be named with unit_name.req
            req_file = 'pki/reqs/{0}.req'.format(path_name)
            # If the request already exists do not generate another one.
            if os.path.isfile(req_file):
                remove_state('create certificate signing request')
                return

            # The Common Name is the public address of the system.
            cn = hookenv.unit_public_ip()
            hookenv.log('Creating the CSR for {0}'.format(path_name))
            sans = get_sans()
            # Create a CSR for this system with the subject and SANs.
            gen_req = './easyrsa --batch --req-cn={0} --subject-alt-name={1}' \
                      ' gen-req {2} nopass 2>&1'.format(cn, sans, path_name)
            check_call(split(gen_req))
            # Read the CSR file.
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
        # Create an absolute path to easyrsa3 to change to that directory.
        easyrsa3_dir = os.path.join(hookenv.charm_dir(), 'easy-rsa/easyrsa3')
        # Iterate over the unit names related to CSRs.
        for unit_name, csr in csr_map.items():
            # Use an absolute path for this context manager.
            with chdir(easyrsa3_dir):
                temp_file = tempfile.NamedTemporaryFile(suffix='.csr')
                with open(temp_file.name, 'w') as fp:
                    fp.write(csr)
                # Must remove the path characters from the unit_name.
                path_name = unit_name.replace('/', '_')
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
@when_not('tls.server.certificate available')
def copy_server_cert(tls):
    '''Copy the certificate from the relation to the key value store.'''
    # Get the signed certificate from the relation object.
    cert = tls.get_signed_cert()
    if cert:
        # The key name is also used to set the reactive state.
        set_cert('tls.server.certificate', cert)
        # Remove this state so this method does not run all the time.
        remove_state('signed certificate available')


@when('easyrsa configured')
@when_not('certificate authority available')
def create_certificate_authority(certificate_authority=None):
    '''Return the CA and server certificates for this system. If the CA is
    empty, generate a self signged certificate authority.'''
    # followers are not special, do not generate a ca
    if not is_leader():
        return
    # Create an absolute path so current directory does not affect the result.
    easyrsa3_dir = os.path.join(hookenv.charm_dir(), 'easy-rsa/easyrsa3')
    with chdir(easyrsa3_dir):
        ca_file = 'pki/ca.crt'
        # Check if an old CA exists.
        if os.path.isfile(ca_file):
            # Initialize easy-rsa (by deleting old pki) so a CA can be created.
            init = './easyrsa --batch init-pki 2>&1'
            check_call(split(init))
        # When the CA is not None write the CA file.
        if certificate_authority:
            # Write the certificate authority from configuration.
            with open(ca_file, 'w') as fp:
                fp.write(certificate_authority)
        else:
            # The Certificate Authority does not exist build a self signed one.
            # The Common Name (CN) for a certificate must be an IP or hostname.
            cn = hookenv.unit_public_ip()
            # Create a self signed CA with the CN, stored pki/ca.crt
            build_ca = './easyrsa --batch "--req-cn={0}" build-ca nopass 2>&1'
            check_call(split(build_ca.format(cn)))
            # Read the CA so we can return the contents from this method.
            with open(ca_file, 'r') as fp:
                certificate_authority = fp.read()
    set_state('certificate authority available')
    return certificate_authority


@when('easyrsa installed', 'tls.client.authorization.required')
@when_not('tls.client.authorization.added')
def add_client_authorization():
    '''easyrsa has a default OpenSSL configuration that does not support
    client authentication. Append "clientAuth" to the server ssl certificate
    configuration. This is not default, to enable this in your charm set the
    reactive state 'tls.client.authorization.required'.
    '''
    if not is_leader():
        return
    else:
        hookenv.log('Configuring SSL PKI for clientAuth')

    # Get the absolute path to the charm directory.
    charm_dir = hookenv.charm_dir()
    # Create the relative path to the server file.
    server_file = 'easy-rsa/easyrsa3/x509-types/server'
    # Use an absolute path so current directory does not affect the result.
    openssl_config = os.path.join(charm_dir, server_file)
    hookenv.log('Updating {0}'.format(openssl_config))
    # Read the file in.
    with open(openssl_config, 'r') as f:
        existing_template = f.readlines()

    # Enable client and server authorization for certificates
    xtype = [w.replace('serverAuth', 'serverAuth, clientAuth') for w in existing_template]  # noqa
    # Write the configuration file back out.
    with open(openssl_config, 'w+') as f:
        f.writelines(xtype)

    set_state('tls.client.authorization.added')


def create_server_certificate(name='server'):
    '''Create the server certificate and server key.'''
    # Use the public ip as the Common Name for the server certificate.
    cn = hookenv.unit_public_ip()
    # Create an absolute path so current directory does not affect the result.
    easyrsa3_dir = os.path.join(hookenv.charm_dir(), 'easy-rsa/easyrsa3')
    with chdir(easyrsa3_dir):
        server_file = 'pki/issued/{0}.crt'.format(name)
        # Get a list of extra sans from the unitdata kv module.
        extra_sans = unitdata.kv().get('extra_sans')
        # Get a string compatible with easyrsa for the subject-alt-names.
        sans = get_sans(extra_sans)
        # Do not regenerate the server certificate if it already exists.
        if not os.path.isfile(server_file):
            # Create a server certificate for the server based on the CN.
            server = './easyrsa --batch --req-cn={0} --subject-alt-name={1} ' \
                     'build-server-full {2} nopass 2>&1'.format(cn, sans, name)
            check_call(split(server))
            # Read the server certificate from the filesystem.
            with open(server_file, 'r') as fp:
                server_cert = fp.read()
            # The key name is also used to set the reactive state.
            set_cert('tls.server.certificate', server_cert)


def create_client_certificate(name='client'):
    '''Create the client certificate and client key.'''
    # Create an absolute path so current directory does not affect the result.
    easyrsa3_dir = os.path.join(hookenv.charm_dir(), 'easy-rsa/easyrsa3')
    with chdir(easyrsa3_dir):
        client_file = 'pki/issued/{0}.crt'.format(name)
        # Do not regenerate the client certificate if it already exists.
        if not os.path.isfile(client_file):
            # Create a client certificate and key.
            client = './easyrsa build-client-full {0} nopass 2>&1'.format(name)
            check_call(split(client))
            # Read the client certificate from the filesystem.
            with open(client_file, 'r') as fp:
                client_cert = fp.read()
            # The key name is also used to set the reactive state.
            set_cert('tls.client.certificate', client_cert)
            set_state('client certificate available')


def install_ca(certificate_authority):
    '''Install a certificiate authority on the system.'''
    ca_file = '/usr/local/share/ca-certificates/{0}.crt'.format(
        hookenv.service_name())
    hookenv.log('Writing CA to {0}'.format(ca_file))
    # Write the contents of certificate authority to the file.
    with open(ca_file, 'w') as fp:
        fp.write(certificate_authority)
    # Update the trusted CAs on this system.
    check_call(['update-ca-certificates'])
    # Notify other layers that the certificate authority is available.
    set_state('tls.certificate.authority available')


def get_sans(address_list=None):
    '''Return a string suitable for the easy-rsa subjectAltNames. This method
    will add a valid SANs string with the public IP, private IP, and hostname
    of THIS system.'''
    # The unit_public_ip could be a FQDN or IP address depending on provider.
    public = hookenv.unit_public_ip()

    # unitdata returns None if not found. Handle the occurrence of no
    # addresses passed, and initialize to an empty array
    if not address_list:
        address_list = []

    if public not in address_list:
        address_list.append(public)
    # The unit_private_ip could be a FQDN or IP address depending on provider.
    private = hookenv.unit_private_ip()
    if private not in address_list:
        address_list.append(private)
    # The hostname is usually a string, not an IP address.
    hostname = socket.gethostname()
    if hostname not in address_list:
        address_list.append(hostname)

    sans = []
    for address in address_list:
        if _is_ip(address):
            sans.append('IP:{0}'.format(address))
        else:
            sans.append('DNS:{0}'.format(address))
    return ','.join(sans)


def set_cert(key, certificate):
    '''Set the certificate on the key value store of the unit, and set
    the corresponding state for layers to consume.'''
    # Set cert on the unitdata key value store so other layers can get it.
    unitdata.kv().set(key, certificate)
    # Set the final state for the other layers to know when they can
    # retrieve the server certificate.
    set_state('{0} available'.format(key))


def _is_ip(address):
    '''Return True if the address is an IP address, false otherwise.'''
    import ipaddress
    try:
        # This method will raise a ValueError if argument is not an IP address.
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def _decode(encoded):
    '''Base64 decode a string by handing any decoding errors.'''
    try:
        return base64.b64decode(encoded)
    except:
        hookenv.log('Error decoding string {0}'.format(encoded))
        raise
