# tls

Transport Layer Security (TLS) is a protocol that ensures privacy between
communicating applications and their users on the Internet. When a server
and client communicate, TLS ensures that no third party may eavesdrop or
tamper with any message. TLS is the successor to the Secure Sockets Layer
(SSL).

## Deployment
Charms using the tls layer can be deployed with multiple units using the
peer relation to create signed certificates.

```
juju deploy trusty/tls
juju add-unit tls -n 2
```

## Using the tls layer

The tls layer uses easy-rsa to generate the public key infrastructure (PKI).
The tls layer knows where the certificates and keys are located. Upper layers
do not need to know the underlying implementation, they simple need the keys
and certificates saved in service specific locations.

## tlslib
This layer contains a python library named `tlslib` that has methods to copy
the keys and certificates. Use the methods in `tlslib` to copy the tls pki
to directories that that other layers can use.

### server_cert
Copy the server certificate to the destination, creating directories if
needed and assign ownership if set.

```python
import tlslib
# Copy the server certificate from the default location to swarm directory.
tlslib.server_cert(None, '/etc/swarm/server.crt', user='ubuntu', group='docker')
```

### server_key
Copy the server key to the destination, creating directories if needed and
assign ownership if set.

```python
import tlslib
# Copy the server key from the default location to the swarm directory.
tlslib.server_key(None, '/etc/swarm/server.key', user='ubuntu', group='docker')
```

### client_cert
Copy the client certificate to the destination creating directories if
needed and assign ownership if set.

```python
import tlslib
# Save the client certificate from the default location to the kubernetes directory.
tlslib.client_cert(None, '/srv/kubernetes/client.crt', user='ubuntu', group='ubuntu')
```

### client_key
Copy the client key to the destination, creating directories if needed and
assign ownership if set.

```python
import tlslib
# Copy the client key from the default location to the kubernetes directory.
tlslib.client_key(None, '/srv/kubernetes/client.key', user='ubuntu', group='ubuntu')
```

### ca
Copy the Certificate Authority (CA) to the destination, creating parent
directories if needed and assign owner if set. The tls layer installs the
CA on all the peers in /usr/local/share/ca-certificates/.

```python
import tlslib
# Copy the CA from the default location to the swarm directory.
tlslib.ca(None, '/etc/swarm/ca.crt', user='ubuntu', group='docker')

```

## State Events
This charm makes use of the reactive framework where states are set or removed.
The charm code can respond to these layers appropriately. Some states
are meant to be internal to the tls layer all the external states start with
"tls."

### tls.client.authorization.required
By default the tls layer does not generate server certificate that can be used
with client authentication. If your layer needs certificates configured with
`clientAuth` then the layer should set the `tls.client.authorization.required`
state.

```python
from charms.reactive import set_state
# My service requires clientAuth set when generating the server certificate.
set_state('tls.client.authorization.required')
```

### tls.server.certificate available
The server certificate is available in the unitdata of this charm using the  
`tls.server.certificate` key.

```python
@when('tls.server.certificate available')
def secure_my_sevice():
  from charmhelpers.core import unitdata
  database = unitdata.kv()
  server_cert = database.get('tls.server.certificate')
```

### tls.client.certificate available
The client certificates are available in the unitdata of this charm using the
`tls.client.certificate` key.

```python
@when('tls.client.certificate available')
def client_certificate():
  from charmhelpers.core import unitdata
  database = unitdata.kv()
  client_cert = database.get('tls.client.certificate')
```

## Contact

 * Author: Matthew Bruzek &lt;Matthew.Bruzek@canonical.com&gt;
 * Contributor: Charles Butler &lt;Charles.Butler@canonical.com&gt;
 * Contributor: Cory Johns &lt;Cory.Johns@canonical.com&gt;
