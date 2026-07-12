# Security Boundaries

CLU Governance is a local developer tool, not a production security boundary.

## Core policy and demo

The policy gate evaluates structured input against local rules and emits evidence. It is effective only when an integration calls and honors it. Actor IDs and approval input are caller-supplied, so they do not authenticate identity or prove human presence. The deterministic demo uses a temporary marker-owned workspace and checks its bounded rollback path; it does not mutate a user repository.

## Protected-source manifest

The manifest identifies the currently imported CLU package, project metadata where applicable, and relevant active distribution metadata. It excludes neighboring packages and the rest of `site-packages`. In the documented standard setuptools editable workflow, a source-adjacent generated egg-info record is recognized as disposable companion metadata and is not protected. Exact recorded CLU editable bridge files may be protected individually.

The manifest is current-installation evidence, not a signature, sandbox, trust root, or defense against arbitrary concurrent same-user modification.

## Bundle verification

`verify-bundle` checks an observed local bundle's file set, checksums, and internal bindings. It is point-in-time verification. It does not authenticate bundle origin or policy provenance, sign data, make a filesystem immutable, or prevent later modification.

## Experimental Git adapter

`git-adapt` is experimental and intended for trusted local repositories in single-user workflows. It is not a sandbox and does not defend against a malicious Git executable, hostile local process, operating-system administrator, concurrent same-user filesystem modification, or tampering after point-in-time verification.

The supported adapter surface is a bounded macOS/Python/Git workflow for one tracked, unstaged UTF-8 text modification. It does not apply a mutation, create approval, stage, commit, push, fetch, or provide full-repository governance.
