import os

from shutil import copy2

from charms.reactive import hook
from charms.reactive import set_state

from charmhelpers.core import hookenv
from charmhelpers.core.hookenv import status_set
from charmhelpers.core import unitdata


def server_cert(destination_directory):
    # Save the server certificate from unitdata to dest_dir
    save_certificate(destination_directory, 'server')
    # Copy the unitname.key to dest_dir/server.key
    copy_key(destination_directory, 'server')
    set_state('webapp.server.certificate available')


def client_cert(destination_directory):
    if not os.path.isdir(destination_directory):
        os.makedirs(destination_directory)
        os.chmod(destination_directory, 0o770)
    # The client certificate is also available on charm unitdata.
    client_cert_path = 'easy-rsa/easyrsa3/pki/issued/client.crt'
    webapp_cert_path = os.path.join(destination_directory, 'client.crt')
    if os.path.isfile(client_cert_path):
        # Copy the client.crt to dest_dir/client.crt
        copy2(client_cert_path, kube_cert_path)
    # The client key is only available on the leader.
    client_key_path = 'easy-rsa/easyrsa3/pki/private/client.key'
    webapp_key_path = os.path.join(destination_directory, 'client.key')
    if os.path.isfile(client_key_path):
        # Copy the client.key to dest_dir/client.key
        copy2(client_key_path, kube_key_path)


def ca(directory):
    '''When the Certificate Authority is available, copy the CA from the
    /usr/local/share/ca-certificates/<service_name>.crt to the proper directory. '''
    # Ensure the dest_dir exists.
    if not os.path.isdir(directory):
        os.makedirs(directory)
        os.chmod(directory, 0o770)
    # Normally the CA is just on the leader, but the tls layer installs the
    # CA on all systems in the /usr/local/share/ca-certificates directory.
    ca_path = '/usr/local/share/ca-certificates/{0}.crt'.format(
              hookenv.service_name())
    # The CA should be copied to the destination directory and named 'ca.crt'.
    destination_ca_path = os.path.join(directory, 'ca.crt')
    if os.path.isfile(ca_path):
        copy2(ca_path, destination_ca_path)
        set_state('webapp.certificate.authority available')


def copy_key(directory, prefix):
    '''Copy the key from the easy-rsa/easyrsa3/pki/private directory to the
    specified directory. '''
    if not os.path.isdir(directory):
        os.makedirs(directory)
        os.chmod(directory, 0o770)
    # Must remove the path characters from the local unit name.
    path_name = hookenv.local_unit().replace('/', '_')
    # The key is not in unitdata it is in the local easy-rsa directory.
    local_key_path = 'easy-rsa/easyrsa3/pki/private/{0}.key'.format(path_name)
    key_name = '{0}.key'.format(prefix)
    # The key should be copied to this directory.
    destination_key_path = os.path.join(directory, key_name)
    # Copy the key file from the local directory to the destination.
    copy2(local_key_path, destination_key_path)


def save_certificate(directory, prefix):
    '''Get the certificate from the charm unitdata, and write it to the proper
    directory. The parameters are: destination directory, and prefix to use
    for the key and certificate name.'''
    if not os.path.isdir(directory):
        os.makedirs(directory)
        os.chmod(directory, 0o770)
    # Grab the unitdata key value store.
    store = unitdata.kv()
    certificate_data = store.get('tls.{0}.certificate'.format(prefix))
    certificate_name = '{0}.crt'.format(prefix)
    # The certificate should be saved to this directory.
    certificate_path = os.path.join(directory, certificate_name)
    # write the server certificate out to the correct location
    with open(certificate_path, 'w') as fp:
        fp.write(certificate_data)
