# Delivery-bundle authoring evaluation

This corpus evaluates a coding agent's delivery bundle without putting a model
or prompt loop inside `pilot`.  Each brief is intentionally incomplete: an
author must surface assumptions, unknowns, destructive boundaries, and a
verification/evidence plan before writing an apply playbook.

Run the deterministic gate from the repository root:

```bash
eval/run.sh
```

Set `PILOT_EVAL_TARGET_TEST` to an already-authorized target-test command when
the candidate bundle has a disposable target.  The script never provisions or
mutates a target itself.  Its static gates are repeatable and model-neutral;
the optional target command supplies the actual-run and idempotency evidence
required before a bundle can be promoted.

