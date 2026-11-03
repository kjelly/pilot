These JSON fixtures capture python-apt origin metadata from Ubuntu 24.04.4
(unattended-upgrades 2.9.1+nmu4ubuntu1) and Debian 12 bookworm
(unattended-upgrades 2.9.1+nmu3), collected for issue #172 on 2026-11-03.

Ubuntu uses archive `noble-security` with codename `noble`; Debian uses
archive `oldstable-security` with codename `bookworm-security` and label
`Debian-Security`. The regression executes both discovery and the committed
effective-policy query against these shapes. Full native evidence is linked
from `docs/evidence/os-patch-sla/LATEST.md`.
