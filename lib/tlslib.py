import os
from shutil import copy2

from charmhelpers.core import hookenv
from charmhelpers.core import unitdata


def server_cert(directory, key_path=None):
    """
    Store the server certificate and server key in the destination directory.

    :param string directory: The directory to save the server certificate.
    :param string key_path: The optional path to the source server key.
    """

    # Must remove the path characters from the local unit name.
    path_name = hookenv.local_unit().replace('/', '_')

    # When not specified create the server key path.
    if not key_path:
        server_key_path = 'easy-rsa/easyrsa3/pki/private/{0}.key'.format(
            path_name)
    else:
        server_key_path = key_path

    # Save the server certificate from unitdata to directory.
    _save_certificate(directory, 'server')
    # Copy the unitname.key to directory/server.key
    _copy_key(directory, 'server', server_key_path)


def client_cert(directory, cert_path=None, key_path=None):
    """
    Copy the client certificate and client key to the destination directory.

    :param string directory: The directory to save the client certificate.
    :param string cert_path: The optional path to the client certificate.
    :param string key_path: The optional path to the source client key.
    """

    # When not specified create the client certificate path.
    if not cert_path:
        client_cert_path = 'easy-rsa/easyrsa3/pki/issued/client.crt'
    else:
        client_cert_path = cert_path

    # When not specified create the client certificate path.
    if not key_path:
        client_key_path = 'easy-rsa/easyrsa3/pki/private/client.key'
    else:
        client_key_path = key_path

    # Ensure the destination directory exists.
    if not os.path.isdir(directory):
        os.makedirs(directory)
        os.chmod(directory, 0o770)

    # Create the destination path for client certificate.
    webapp_client_cert_path = os.path.join(directory, 'client.crt')

    # Check for client certificate
    if os.path.isfile(client_cert_path):
        # Copy the client.crt to dest_dir/client.crt
        copy2(client_cert_path, webapp_client_cert_path)
        # Store the path to the key in unitdata
        unitdata.kv().set('client-cert-path', webapp_client_cert_path)
    # Call the method to copy the client key.
    _copy_key(directory, 'client', client_key_path)
    # Create the destination path for client key.
    webapp_client_key_path = os.path.join(directory, 'client.key')
    # Set the destination path for the client key on the unitdata.
    unitdata.kv().set('client-key-path', webapp_client_key_path)


def ca(directory, cert_path=None):
    """
    Copy the CA from the source to the destination directory. The tls layer
    installs the CA on all the peers in /usr/loca/share/ca-certificates/.

    :param string directory: The directory to store the ca.crt file.
    :param string cert_path: The optional path to the source CA certificate.
    """

    # When not specified create the path to the default location.
    if not cert_path:
        ca_path = '/usr/local/share/ca-certificates/{0}.crt'.format(
                  hookenv.service_name())
    else:
        ca_path = cert_path

    # Ensure the destination directory exists.
    if not os.path.isdir(directory):
        os.makedirs(directory)
        os.chmod(directory, 0o770)

    # The CA should be copied to the destination directory and named 'ca.crt'.
    destination_ca_path = os.path.join(directory, 'ca.crt')
    if os.path.isfile(ca_path):
        copy2(ca_path, destination_ca_path)
    else:
        print('The CA file {0} does not exist.'.format(ca_path))


def _copy_key(directory, prefix, key_path):
    """
    Copy the key from the easy-rsa/easyrsa3/pki/private directory to the
    specified directory.

    :param string directory:The destination directory to store the key.
    :param string prefix: The prefix to name the key file prefix.key.
    :param string key_path: The path to the source key to copy.
    """
    # Ensure the destination directory exists.
    if not os.path.isdir(directory):
        os.makedirs(directory)
        os.chmod(directory, 0o770)
    # The key is not in unitdata it is in the local easy-rsa directory.
    key_name = '{0}.key'.format(prefix)
    # The key should be copied to this directory.
    destination_key_path = os.path.join(directory, key_name)
    if os.path.isfile(key_path):
        # Copy the key file from the local directory to the destination.
        copy2(key_path, destination_key_path)
    else:
        print('The key file {0} does not exist.'.format(key_path))


def _save_certificate(directory, prefix):
    """
    Get the certificate from the charm unitdata, and write it to the
    desination directory.

    :param string directory: The destination directory to save the certificate.
    :param string prefix: The prefix used to look up the certificate in the
    unitdata and to name the destination file prefix.crt.
    """
    # Ensure the destination directory exists.
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
        fp.write(str(certificate_data))
