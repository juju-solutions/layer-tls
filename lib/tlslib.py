import os
from shutil import copy2

from charmhelpers.core import hookenv
from charmhelpers.core import unitdata


def server_cert(destination_directory, key_path=None):
    """
    Copy server cert to destination_directory

    @param string destination_directory dest dir for server cert
    """

    # Must remove the path characters from the local unit name.
    path_name = hookenv.local_unit().replace('/', '_')

    # Optional key_path for unit tests
    if not key_path:
        local_key_path = 'easy-rsa/easyrsa3/pki/private/{0}.key'.format(
                         path_name)
    else:
        local_key_path = key_path

    #Save the server certificate from unitdata to dest_dir
    save_certificate(destination_directory, 'server')
    # Copy the unitname.key to dest_dir/server.key
    copy_key(destination_directory, 'server', local_key_path)


def client_cert(destination_directory, cert_path=None, key_path=None):
    """
    Copy client cert to destination_directory

    @param string destination_directory dest dir for client cert
    """

    # Optional cert path for unit tests 
    if not cert_path:
        client_cert_path = 'easy-rsa/easyrsa3/pki/issued/client.crt'
    else:
        client_cert_path = cert_path

    # Optional key path for unit tests 
    if not key_path:
        client_key_path = 'easy-rsa/easyrsa3/pki/private/client.key'
    else:
        client_key_path = key_path

    # Check for directory existence
    if not os.path.isdir(destination_directory):
        os.makedirs(destination_directory)
        os.chmod(destination_directory, 0o770)

    # The client certificate is also available on charm unitdata.
    webapp_cert_path = os.path.join(destination_directory, 'client.crt')

    # Check for client cert
    if os.path.isfile(client_cert_path):
        # Copy the client.crt to dest_dir/client.crt
        copy2(client_cert_path, webapp_cert_path)

    # The client key is only available on the leader.
    webapp_key_path = os.path.join(destination_directory, 'client.key')

    if os.path.isfile(client_key_path):
        # Copy the client.key to dest_dir/client.key
        copy2(client_key_path, webapp_key_path)


def ca(directory, cert_path=None):
    """
    When the Certificate Authority is available, copy the CA from the
    /usr/local/share/ca-certificates/<service_name>.crt to the proper directory.

    @param string directory dest dir for crt
    @param string cert_path source cert path
    """

    # Normally the CA is just on the leader, but the tls layer installs the
    # CA on all systems in the /usr/local/share/ca-certificates directory.
    # Optional cert_path for unit test
    if not cert_path:
        ca_path = '/usr/local/share/ca-certificates/{0}.crt'.format(
                  hookenv.service_name())
    else:
        ca_path = cert_path

    # Ensure the dest_dir exists.
    if not os.path.isdir(directory):
        os.makedirs(directory)
        os.chmod(directory, 0o770)

    # The CA should be copied to the destination directory and named 'ca.crt'.
    destination_ca_path = os.path.join(directory, 'ca.crt')
    if os.path.isfile(ca_path):
        copy2(ca_path, destination_ca_path)

def copy_key(directory, prefix, key_path):
    """
    Copy the key from the easy-rsa/easyrsa3/pki/private directory to the
    specified directory.
    
    @param string directory dest dir for key
    @param string prefix prefix for key
    @param string key_path source key path
    """

    # Ensure the dest_dir exists.
    if not os.path.isdir(directory):
        os.makedirs(directory)
        os.chmod(directory, 0o770)

    # The key is not in unitdata it is in the local easy-rsa directory.
    key_name = '{0}.key'.format(prefix)
    # The key should be copied to this directory.
    destination_key_path = os.path.join(directory, key_name)
    # Copy the key file from the local directory to the destination.
    copy2(key_path, destination_key_path)


def save_certificate(directory, prefix):
    """
    Get the certificate from the charm unitdata, and write it to the proper
    directory. The parameters are: destination directory, and prefix to use
    for the key and certificate name.

    @param string directory dest dir to save cert
    @param string prefix prefix for cert
    """
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
