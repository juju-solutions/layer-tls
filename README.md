# tls

Transport Layer Security (TLS) is a protocol that ensures privacy between
communicating applications and their users on the Internet. When a server
and client communicate, TLS ensures that no third party may eavesdrop or
tamper with any message. TLS is the successor to the Secure Sockets Layer
(SSL).

# Deployment
Charms using the tls layer can be deployed with multiple units using the
peer relation to create signed certificates.

```
juju deploy trusty/tls
juju add-unit tls -n 2
```

# State Events
This charm makes use of the reactive framework where states are set or removed.
The charm code can respond to these layers appropriately. Some states
are meant to be internal to the tls layer all the external states start with
"tls."

## tls.server.certificate available
The server certificate is available in the unitdata of this charm using the  
`tls.server.certificate` key.

```python
@when('tls.server.certificate available')
def secure_my_sevice():
  from charmhelpers.core import unitdata
  database = unitdata.kv()
  server_cert = database.get('tls.server.certificate')
```

## tls.client.certificate available
The client certificates are available in the unitdata of this charm using the
`tls.client.certificate` key.

```python
@when('tls.client.certificate available')
def client_certificate():
  from charmhelpers.core import unitdata
  database = unitdata.kv()
  client_cert = database.get('tls.client.certificate')
```

## tls.client.authorization.required
By default the certificates do not get generated with client authentication
enabled. If your certificates need this option set the
`tls.client.authorization.required` state.

```python
from charms.reactive import set_state

set_state('tls.client.authorization.required')
```

# Contact

 * Charm Author: Matthew Bruzek &lt;Matthew.Bruzek@canonical.com&gt;
 * Charm Contributor: Charles Butler &lt;Charles.Butler@canonical.com&gt;
 * Charm Contributor: Cory Johns &lt;Cory.Johns@canonical.com&gt;
