# Delivery-bundle authoring evaluation

This corpus evaluates a coding agent's delivery bundle without putting a model
or prompt loop inside `pilot`.  Each brief is intentionally incomplete: an
author must surface assumptions, unknowns, destructive boundaries, and a
verification/evidence plan before writing an apply playbook.

Run the deterministic gate from the repository root:

```bash
eval/run.sh
```

The harness writes `tmp/eval-scorecard.json`. Without a target command the
scorecard is honestly marked `incomplete`; static checks are not presented as
delivery proof. Set `PILOT_EVAL_TARGET_TEST` to an already-authorized
`docker-target test` or `vm-target test` command. Set
`PILOT_EVAL_REQUIRE_TARGET=1` in the production promotion gate so a missing
actual-run/idempotency test is a hard failure. The harness is model-independent
and never provisions a target by itself.
