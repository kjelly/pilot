# Verification Spec — issue98 disposable nameserver classifier regression

## 1. Target

Single disposable Ubuntu VM. The fixture binds only loopback port 15353 and never changes the OS resolver.

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|-------|---------|----------|----------|
| C1 | service | Real tier fails upstream resolution | ~status: SERVFAIL | dig +time=2 +tries=2 +noall +comments +answer -p 15353 @127.0.0.2 ipa1.ipa.pilot.internal. A |
| C2 | service | Healthy fallback returns an address | 192.0.2.10 | dig +time=2 +tries=2 +short -p 15353 @127.0.0.3 ipa1.ipa.pilot.internal. A |
| C3 | service | Production gate passed both runtime assertions | healthy-fallback=pass all-servfail=blocked | sudo cat /var/tmp/pilot-issue98/result |
