# CLU Governance Examples

These files show the source-mutation policy-gate schemas used by the local demo.
They are illustrative static examples. The executable demo generates fresh
workspace-bound requests and rollback artifacts with real absolute paths and
hashes at runtime:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -B -m clu_governance.source_mutation_policy_gate demo-run-all --json
```

The eligible example is not an approval or authorization. The executable demo
uses a separate scripted approval artifact and does not authenticate identity.
