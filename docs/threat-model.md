# Threat Model (STRIDE)

Spoofing: invalid SVID or trust domain is denied. Tampering: attestation must be valid and policy files are committed artifacts. Repudiation: benchmark artifacts include per-trial logs and SHA256 manifests. Information disclosure: egress tools deny secret markers and untrusted-origin side effects. Denial of service: PDP fails closed on exceptions. Elevation of privilege: ReBAC and scope gates block unauthorized relations and missing tool scopes.
