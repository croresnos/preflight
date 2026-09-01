# Security policy

## Supported versions

Security fixes are made on the current release line. Until Preflight 1.0, users
should upgrade to the newest published version before reporting a suspected
regression.

## Report a vulnerability

Use GitHub private vulnerability reporting for this repository. Do not open a
public issue for a vulnerability, suspected sandbox escape, credential leak, or
artifact-tampering weakness. Include the affected version, platform, proof of
concept, impact, and any suggested mitigation.

We aim to acknowledge a report within three business days. We will coordinate
disclosure after a fix or mitigation is available and credit reporters who want
to be named.

## Current security boundary

Version 0.7 validates plugin declarations before import. It is not a sandbox,
malware scanner, signature verifier, or containment system. Once accepted code
is imported, it has the permissions of the host Python process. Reports that
show the gate violating its documented pre-import checks are security relevant;
reports that require post-import isolation describe planned functionality, not
a guarantee made by 0.7.
