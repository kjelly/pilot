# Brief: log collector and central receiver

Deploy a central log receiver and collectors on application hosts.  A collector
may only be applied after a receiver endpoint has been selected explicitly; it
must not silently pick the first host in an inventory group.  Verify a real
end-to-end delivered log event, not just configuration files.  Describe network
ports, same-host versus provider-endpoint placement, and rollback residual risk.

