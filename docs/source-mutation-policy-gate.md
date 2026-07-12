# Source-Mutation Policy Gate

The source-mutation policy gate evaluates an explicit request against a local policy. Its default posture is deny: a request must match an allowed rule and pass structure, path, hash, and source-state checks before it can be eligible.

The decision artifact records the request, policy, proposal, checked paths, relevant hashes, and reason. A separate approval artifact is required by the demonstration workflow. Policy allow is not approval, authorization, or mutation application.

The deterministic demo demonstrates this boundary with one denied request and one allowed-for-approval request. It verifies rollback readiness before the bounded temporary demo operation and restores the demo target before reporting success.

The gate is a local integration component. It does not authenticate identities, guarantee rollback outside its demonstrated path, or force another tool to honor its output.
