# Development Methodology

CLU Governance was designed and directed by Gabriel Williams using an AI-assisted engineering workflow. Product scope, architecture direction, threat boundaries, test strategy, release decisions, and claim discipline were human-directed; Codex and ChatGPT were used extensively for implementation and review.

AI assistance does not establish correctness. Changes were subjected to focused tests, package checksums, clean-install checks, adversarial review of bounded failure modes, and explicit claim boundaries. Contributors and users should judge the executable code, tests, documented evidence, and limitations rather than assuming that AI assistance proves correctness.

The project favors small, inspectable local workflows: deterministic fixtures, strict JSON parsing, exact hash comparisons where implemented, and narrow documented support claims. New behavior should add focused tests and an honest explanation of its boundary before broadening a claim.

The workflow is human-directed engineering supported by AI tools, not unattended autonomous software development.

The CI workflow deliberately uses maintained major-version tags for the official `actions/checkout` and `actions/setup-python` actions so the public pre-alpha candidate remains readable and easy to adopt. A maintainer may replace those tags with reviewed immutable commit pins when repository dependency-update ownership is established; CI never receives publication credentials or performs a release action.
