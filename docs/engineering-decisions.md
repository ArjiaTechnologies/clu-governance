# Engineering Decisions

## Policy eligibility is not approval

The policy gate answers whether a request is eligible under local rules. Approval is a separate artifact, and neither result authenticates a person. This avoids presenting a policy allow as permission to mutate source.

## Verify rollback readiness before mutation

The deterministic workflow constructs and validates rollback evidence before its bounded temporary apply path. This does not guarantee recovery in every environment; it makes the demonstrated operation and expected restoration state explicit before applying it.

## Keep the Git adapter experimental

`git-adapt` handles one narrow working-tree change under a trusted-local macOS/Python/Git boundary. Git and filesystem behavior are broad and environment-dependent, so the adapter is deliberately not presented as a generic repository security control or sandbox.

## Use exact distribution ownership

The protected-source manifest identifies the imported package and relevant distribution metadata rather than treating an entire `site-packages` directory as application source. In the documented editable workflow it reconciles the active editable distribution record with its generated source-adjacent companion metadata while keeping that disposable build metadata outside the protected set.

## Treat bundle verification as point-in-time

Bundle verification checks currently observed files, checksums, and cross-artifact bindings. It does not sign data, authenticate an origin, make storage immutable, or prevent later modification. Consumers should verify a bundle at the point of use.
