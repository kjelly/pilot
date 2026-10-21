# Verification Spec — issue98 disposable nameserver classifier regression

## 1. Target

Single disposable Ubuntu VM. The fixture binds only loopback port 15353 and never changes the OS resolver.

## 2. Verification checklist

| ID | Check | Command | Expected | Severity |
|----|-------|---------|----------|----------|
| C1 | Real tier fails upstream resolution | `dig +time=2 +tries=2 +noall +comments +answer -p 15353 @127.0.0.2 ipa1.ipa.pilot.internal. A` | `~status: SERVFAIL` | critical |
| C2 | Healthy fallback returns an address | `dig +time=2 +tries=2 +short -p 15353 @127.0.0.3 ipa1.ipa.pilot.internal. A` | `192.0.2.10` | critical |
| C3 | Production gate passed both runtime assertions | `sudo cat /var/tmp/pilot-issue98/result` | `healthy-fallback=pass all-servfail=blocked` | critical |
