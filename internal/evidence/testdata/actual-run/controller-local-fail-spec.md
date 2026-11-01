# Native whole verifier failure control

A bounded non-SSH native controller regression target.

## 2. Checklist

| ID | Category | Check | Expected | Command |
| --- | --- | --- | --- | --- |
| C1 | command | Effective native command result | deliberately-wrong-native-expected | `printf ControllerRowDiagnosticSentinel` |
