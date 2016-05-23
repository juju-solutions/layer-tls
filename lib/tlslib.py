import grp
import os
import pwd
from shutil import copy2

from charmhelpers.core import hookenv
from charmhelpers.core import unitdata


def server_cert(source, destination, user=None, group=None):
    """
    Copy the server certificate to the destination, creating directories if
    needed and assign ownership if set.

    :param string source: The directory to look for the certificate, if None
    the certificate will be copied from unit data.
    :param string destination: The path to save the certificate.
    :param string user: The optional name of the user to own the certificate.
    :param string group: The optional name of the group to own certificate.
    """
    _ensure_directory(destination, user, group)

    if not source:
        # Must remove the path characters from the local unit name.
        key_name = hookenv.local_unit().replace('/', '_')
        # The location of server certificate is easy-rsa/easyrsa3/pki/issued
        source = 'easy-rsa/easyrsa3/pki/issued/{0}.crt'.format(key_name)

    if os.path.isfile(source):
        # Copy the server certificate to the destination.
        copy2(source, destination)
    else:
        # No source server certificate, get the value from unit data.
        server_cert_key = 'tls.server.certificate'
        # Save the certificate data to the destination directory.
        _save_unitdata(server_cert_key, destination)

    chown(destination, user, group)
    # Set the destination path for the client certificate path on the unitdata.
    unitdata.kv().set('server-cert-path', destination)


def server_key(source, destination, user=None, group=None):
    """
    Copy the server key to the destination, creating directories if needed and
    assign ownership if set.

    :param string source: The directory to look for the key, if None the key
    will be copied from default location.
    :param string destination: The path to save the key.
    :param string user: The optional name of the user to own the key.
    :param string group: The optional name of the group to own key.
    """
    _ensure_directory(destination, user, group)

    if not source:
        # Must remove the path characters from the local unit name.
        key_name = hookenv.local_unit().replace('/', '_')
        # The location of server key is easy-rsa/easyrsa3/pki/private
        source = 'easy-rsa/easyrsa3/pki/private/{0}.key'.format(key_name)

    # Copy the key to the destination.
    copy2(source, destination)
    chown(destination, user, group)

    # Set the destination path for the client key path on the unitdata.
    unitdata.kv().set('server-key-path', destination)


def client_cert(source, destination, user=None, group=None):
    """
    Copy the client certificate to the destination creating directories if
    needed and assign ownership if set.

    :param string source: The path to look for the certificate, if None
    the certificate will be copied from the default location.
    :param string destination: The path to save the certificate.
    :param string user: The optional name of the user to own the certificate.
    :param string group: The optional name of the group to own certificate.
    """
    _ensure_directory(destination, user, group)

    if not source:
        # When source not specified use the default client certificate path.
        source = 'easy-rsa/easyrsa3/pki/issued/client.crt'

    # Check for the client certificate.
    if os.path.isfile(source):
        # Copy the client certificate to the destination.
        copy2(source, destination)
    else:
        # No client certificate file, get the value from unit data.
        client_cert_key = 'tls.client.certificate'
        # Save the certificate data to the destination.
        _save_unitdata(client_cert_key, destination)

    chown(destination, user, group)

    # Set the destination path for the client certificate path on the unitdata.
    unitdata.kv().set('client-cert-path', destination)


def client_key(source, destination, user=None, group=None):
    """
    Copy the client key to the destination, creating directories if needed and
    assign ownership if set.

    :param string source: The path to look for the key, if None the key
    will be copied from default location.
    :param string destination: The path to save the key.
    :param string user: The optional name of the user to own the certificates.
    :param string group: The optional name of the group to own certificates.
    """
    _ensure_directory(destination, user, group)

    if not source:
        # When source not specified use the default client key path.
        source = 'easy-rsa/easyrsa3/pki/private/client.key'

    # Copy the key to the destination directory.
    copy2(source, destination)
    chown(destination, user, group)

    # Set the destination path for the client key path on the unitdata.
    unitdata.kv().set('client-key-path', destination)


def ca(source, destination, user=None, group=None):
    """
    Copy the Certificate Authority (CA) to the destination, creating parent
    directories if needed and assign owner if set. The tls layer installs the
    CA on all the peers in /usr/local/share/ca-certificates/.

    :param string source: The path to look or the certificate, if None the
    CA will be copied from the default location.
    :param string destination: The path to save the CA certificate.
    :param string user: The optional user name to own the CA certificate.
    :param string group: The optional group name to own the CA certificate.
    """
    _ensure_directory(destination, user, group)

    if not source:
        # When source not specified use the default CA path.
        source = '/usr/local/share/ca-certificates/{0}.crt'.format(
            hookenv.service_name())

    # Copy the ca certificate to the destination directory.
    copy2(source, destination)
    chown(destination, user, group)

    # Set the destination path for the ca certificate path on the unitdata.
    unitdata.kv().set('ca-cert-path', destination)


def chown(path, user, group):
    """
    Change the owner and group of a file or directory.
    """
    if user:
        uid = pwd.getpwnam(user).pw_uid
    else:
        uid = -1
    if group:
        gid = grp.getgrnam(group).gr_gid
    else:
        gid = -1
    os.chown(path, uid, gid)


def _ensure_directory(path, user, group):
    """
    Ensure the parent directory exists, creating the directories if necessary.
    """
    directory = os.path.dirname(path)
    if not os.path.isdir(directory):
        os.makedirs(directory)
        os.chmod(directory, 0o770)
        chown(directory, user, group)


def _save_unitdata(key, destination):
    """
    Get the key in unit data and save the value to a destination file.
    :param string key: The string key to look up in unit data.
    :param stirng destination: The string path to save the value.
    """
    # Get the value from the unit's key/value store.
    value = unitdata.kv().get(key)
    if value:
        with open(destination, 'w') as stream:
            stream.write(str(value))
    else:
        print('The {0} does not exist in the unit data'.format(key))
