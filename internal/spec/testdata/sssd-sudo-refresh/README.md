Real captures (2026-10-31, issue #214) used by the freeipa-identity sudo refresh
regression tests: `ldbsearch` against `/var/lib/sss/db/cache_<domain>.ldb` on an
Ubuntu 24.04 client (SSSD 2.9.4, ldb-tools 2.8.0) and an AlmaLinux 9.8 client
(SSSD 2.9.8). `ldbsearch-no-container` is rc 0 with zero records; `ldbsearch-no-db`
is rc 1 (stdout and stderr were captured together; shown here as stderr). The fakes only substitute the epoch in `sudoLastFullRefreshTime`.
