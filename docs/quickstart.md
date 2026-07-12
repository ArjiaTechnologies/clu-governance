# Quick Start

CLU Governance `0.1.0a1` is a local pre-alpha developer tool. The core CLI has no runtime third-party dependencies.

## Install from a local checkout

```bash
python -m pip install .
clu-governance --version
clu-governance --help
```

For development, use the supported standard setuptools editable command:

```bash
python -m pip install -e .
clu-governance protected-source-manifest --json
```

That diagnostic should report `result: ready` and `distribution_mode: editable_install`. Standard editable installation generates source-adjacent egg-info as disposable build metadata; it is classified for ownership but is not protected. This project does not claim every editable backend or `--no-build-isolation` layout is supported.

`pipx install .` and `uv tool install .` are also local-checkout installation options when those tools are installed. No PyPI installation is claimed yet.

## Run the deterministic demo

```bash
clu-governance demo-run-all --json
```

The demo uses a temporary marker-owned repository. It produces a denied request, an eligible request, a separate scripted approval artifact, rollback-readiness evidence, a temporary apply-and-rollback sequence, and a final source-fingerprint check. It does not mutate your repository.

An allow result is policy eligibility for a separate approval step, not approval or authorization to apply a change.

## Inspect a policy decision

The fixtures under `examples/` are readable local JSON inputs. Use the policy and allowed request with an explicit source root and output path:

```bash
clu-governance evaluate \
  --policy examples/example_source_mutation_policy.json \
  --request examples/example_allowed_mutation_request.json \
  --source-root /path/to/controlled/source \
  --output /path/to/decision.json \
  --json
```

The command evaluates and writes evidence; it does not apply a requested mutation.

## Experimental Git adapter

`git-adapt` is experimental and only for trusted local, single-user repositories. Read [the adapter boundary](git-diff-adapter.md) before using it.
