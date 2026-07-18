# Brief: exactly-one internal registry

Provide an internal container registry for the platform.  Exactly one registry
host is allowed per deployment, and clients must use its declared endpoint.
TLS material is supplied through an existing vault reference; no certificate or
password may appear in the bundle.  Define provider/client contracts, cardinality,
endpoint binding, backup policy, and failure behavior if two registry hosts are
selected.

