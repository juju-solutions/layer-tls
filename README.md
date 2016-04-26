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
The charm code can respond to these layers appropriately.

## tls.server.certificate available
The certificate for this server is available in the unitdata of this charm as `tls.certificate`.

```python
@when('tls.server.certificate available')
def secure_my_sevice():
  from charmhelpers.core import unitdata
  database = unitdata.kv()
  cert = database.get('tls.server.certificate')
```

From here you write the cert to disk and do configure your app.


# Contact

 * Charm Author: Matthew Bruzek &lt;Matthew.Bruzek@canonical.com&gt;
 * Charm Contributor: Charles Butler &lt;Charles.Butler@canonical.com&gt;
 * Charm Contributor: Cory Johns &lt;Cory.Johns@canonical.com&gt;
