# Provenance and Integrity

This repository distributes source code under Apache-2.0. The package contains no runtime import from a separate monolith and declares no runtime third-party dependencies.

`CHECKSUMS.sha256` covers the public candidate files. It is a convenient integrity check for a local checkout, not a signature or a cryptographic trust anchor.

Generated policy decisions and adapter bundles include hashes and strict JSON structures that bind the local artifacts observed by the tool. `verify-bundle` checks current internal consistency at the current path. It does not authenticate a policy author, repository owner, remote, commit signature, or bundle origin.

No `NOTICE` file is included because this candidate's file-level review found no established third-party attribution obligation. That assessment should be revisited if dependencies, copied material, or assets are added.
