# Brief: single-host metrics exporter

Install a metrics exporter on one Ubuntu 24.04 host.  It must listen only on
loopback, survive reboot, and expose a health metric.  The exporter package and
port are not yet decided.  The bundle must state that decision, acceptance
checks against effective service state, rollback behavior, and resource
assumptions.

