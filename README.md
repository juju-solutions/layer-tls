# tls

Transport Layer Security (TLS) is a protocol that ensures privacy between
communicating applications and their users on the Internet. When a server
and client communicate, TLS ensures that no third party may eavesdrop or
tamper with any message. TLS is the successor to the Secure Sockets Layer
(SSL).

# Deployment
Charms using the tls layer can be deployed with multiple units use the
leadership Juju feature and peer relations to exchange certificates.

```
juju deploy trusty/tls
juju add-unit tls
```

## State Events
This charm makes use of the reactive framework where states are set or removed.
The charm code can respond to these layers appropriately.

 **ca.available** - The Certificate Authority (CA) has been created and is
 available on the leadership communications channel.

 **sign.csr** - The layer reacts to other peers or relations sending the
 a Certificate Signing Request (CSR) that the CA can sign. The CSR is named
 'csr' on the peer relation.

 **tls.certificate.available** - The certificate for this server is
available in the unitdata of this charm as `tls.certificate`.

# Contact

 * Charm Author: Matthew Bruzek &lt;Matthew.Bruzek@canonical.com&gt;
 * Charm Contributor: Charles Butler &lt;Charles.Butler@canonical.com&gt;
 * Charm Contributor: Cory Johns &lt;Cory.Johns@canonical.com&gt;

