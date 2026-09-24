# Postly staging connectivity

Observed Middleware Server A topology:

- public: `65.109.65.169/32` on `enp41s0`;
- private: `10.40.0.1/24` on VLAN interface `enp41s0.4001`;
- VLAN ID: `4001`;
- VLAN MTU: `1400`;
- verified Postly peer: `10.40.0.3`;
- public default route: `65.109.65.129` on `enp41s0`, unchanged.

The private peer answered ICMP, supported a 1372-byte ICMP payload (1400-byte IP MTU), and accepted TCP on private ports 80 and 443. Port 5000 was closed. The HTTPS listener responds, while unauthenticated Postiz public API access correctly returns `401`. No firewall, route, VLAN, proxy, or public exposure change was made; the public default route is unchanged.

Before setting `POSTIZ_INTERNAL_BASE_URL`, provision a dedicated staging identity and verify the private TLS hostname/SAN contract plus source-restricted ingress. Do not use the existing production organization credential.
