# Threat model (through Phase 4)

This threat model covers the local classroom prototype through Phase 4: private PKI, detached signatures, authenticated web workflows and recipient-targeted encryption. It records design assumptions and testable attack scenarios; it does not claim production CA assurance.

## Scope, assets, and security objectives

Actors are end users, CA administrators, and the local operator. An attacker may control browser input, uploaded documents, signature packages, ciphertext or metadata. The attacker is not assumed to already control the operating-system account, CA-key password, or trusted Root CA file.

Protected assets are:

- account passwords and sessions;
- user and CA private keys;
- certificates, CSRs, and CRLs;
- documents, detached signatures, and encrypted packages;
- certificate lifecycle and audit records.

The main objectives are confidentiality of private material, correct identity-to-key binding, integrity and authenticity of the certificate chain and CRL, strict certificate-purpose enforcement, safe rejection of malformed input, and authorization of every private object operation.

## Trust and resource boundaries

| Boundary or resource | Effective location / trust decision | Readers and writers | Current enforcing control | Evidence |
|---|---|---|---|---|
| Browser to Flask | HTTP request boundary | Public verifier and authenticated users | Request-size limit, CSRF, sessions, owner/role checks, error handlers | `app/config.py`, `app/auth/`, `app/documents/` |
| Flask to SQLite | `instance/macs902.db` unless `DATABASE_URL` overrides it | Application process | SQLAlchemy constraints and migrations | `app/config.py:55`, `app/models/certificate.py:20` |
| CA private keys | `CA_KEY_DIR`, under private runtime storage by default | Local PKI service and operator | Encrypted PKCS#8; environment-provided password; ignored runtime directory | `app/pki/service.py:591`, `app/config.py:67`, `.gitignore:29` |
| Public CA material | `CA_CERT_DIR` | Local PKI service; verifiers may read it | X.509 signatures and key-identifier checks | `app/pki/service.py:552` |
| Trust anchor | Configured Root CA certificate | Validator | Exact SHA-256 fingerprint match to configured root | `app/pki/service.py:452` |
| Certificate status | Signed, current Issuing-CA CRL | PKI service and verifier | CRL issuer, signature, AKI, time window, and serial checks | `app/pki/service.py:474` |
| Local CLI administration | Shell access plus environment and database access | Local operator | No public CA routes; commands suppress key bytes and passwords | `app/pki/cli.py:21` |
| Private runtime files | `STORAGE_ROOT`, outside `app/static` | Document and PKI services | Factory rejects public storage; generated opaque IDs; authorized routes | `app/__init__.py`, `app/documents/` |

Process environment values take precedence over `.env` values through `python-dotenv`. The application creates private runtime directories, while host permissions and backup protection remain operator responsibilities. SQLite and PEM files on a compromised host are outside the protection boundary.

## Implemented Phase 2 PKI controls

- RSA-3072 keys and SHA-256 signatures are used for the Root CA, Issuing CA, CSRs, end-entity certificates, and CRLs (`app/pki/service.py:154`, `app/pki/service.py:196`, `app/pki/service.py:385`).
- Root and Issuing CA certificates have critical Basic Constraints and Key Usage. Path lengths are one and zero respectively, which prevents the Issuing CA from creating another CA tier (`app/pki/service.py:153`, `app/pki/service.py:187`).
- CSR policy restricts subjects, key type and size, and requested extensions; invalid CSR signatures fail before issuance (`app/pki/service.py:254`).
- End-entity certificates are limited to document signing, cannot be CAs, use secure random serial numbers, and cannot outlive the Issuing CA (`app/pki/service.py:296`).
- Validation separates signature validity, chain validity, time validity, purpose, revocation coverage, revocation state, and the final trust result (`app/pki/types.py:29`, `app/pki/service.py:389`).
- CA private keys are encrypted at rest. The database stores encrypted user private-key material only in the development issuance helper; public certificates and lifecycle metadata are persisted separately (`app/pki/service.py:591`, `app/pki/cli.py:68`, `app/pki/lifecycle.py:15`).

## Threat scenarios and treatment

The priority reflects impact within the stated local prototype assumptions. Each row describes a plausible attacker action, the affected asset, controls, residual limits, and the phase that owns the remaining work.

| Priority | Threat and affected asset | Attack description | Implemented / planned mitigation | Residual limitation | Phase |
|---|---|---|---|---|---|
| High | Credential theft; passwords and sessions | Guessing, phishing, or disclosure enables account use. | Argon2id hashes, generic login failures, CSRF, owner checks and password recheck before user-key use. | No production rate limiter/MFA; phishing and endpoint compromise remain possible. | Phase 4 |
| High | User private-key theft | Database or file disclosure exposes a signing or X25519 key. | Scrypt-derived AES-256-GCM key envelopes use per-key salt/nonce and purpose AAD; plaintext exists only during an operation. | A weak password or compromised process can expose an unlocked key. | Phase 4 |
| Critical | CA key compromise | An attacker signs fraudulent certificates or CRLs. | CA keys are RSA-3072 encrypted PKCS#8 under an environment secret and private ignored directory. Root and Issuing roles are separated. | No HSM, offline ceremony, dual control, or audited backup; host compromise can defeat file encryption and environment secrecy. | Phase 2 control; Phase 5 procedure |
| High | Fake or substituted certificate | A self-issued, wrong-chain, or wrong-purpose certificate impersonates a signer. | Validator checks signatures, issuer relationships, trusted-root fingerprint, CA constraints, KU/EKU, SKI/AKI, nesting, and validity. | Enrollment identity proofing remains a local administrator responsibility. | Phase 2 |
| High | Invalid or malicious CSR | A requester asks for CA privileges, unsupported names/extensions, or a weak key. | Verify CSR signature; allow exactly one common name and email; require RSA at least 3072 bits; allowlist extensions and enforce signing use. | The service does not prove the real-world identity behind the fields. | Phase 2 |
| High | Revoked certificate accepted | A compromised signing key remains acceptable. | Issuing CA signs a full CRL; validator fails closed for missing, invalid, stale, or mismatched CRLs and checks serial revocation. | CRL distribution is local and manual; no OCSP and no trusted historical signing time. | Phase 2; consume in Phase 3 |
| Medium | Expired or not-yet-valid certificate | A certificate is used outside its allowed period. | Validate every chain certificate at an explicit UTC time and enforce child validity inside issuer validity. | Correct local clock is assumed; application signing time is not a trusted timestamp. | Phase 2 |
| High | Malformed certificate or CRL | Crafted PEM/DER triggers a crash or bypass. | Parse defensively and return structured failure reasons without trusting parse success. Tests cover malformed certificates, tampered CSRs, and tampered CRLs. | Third-party parser defects remain possible. | Phase 2; fuzz in Phase 5 |
| High | Modified documents or signatures | Bytes or signature metadata change after signing. | Phase 3 hashes exact bytes, signs a canonical manifest, and verifies before reporting trust. | A signer can originally sign misleading content. | Phase 3 |
| High | Malformed upload packages | Oversized, ambiguous, or path-bearing packages cause denial of service or parsing confusion. | A 16 MiB request cap, strict package schema, version and algorithm allowlists, duplicate-field rejection, bounded file types, and safe errors. | Third-party parser defects remain possible. | Phases 3–4 |
| High | Path traversal | User-supplied names or identifiers escape private storage. | Storage is outside static; services generate opaque identifiers and never use original filenames as paths. | Host-level file access bypasses application checks. | Phase 3–4 |
| High | Insecure direct-object access and unauthorized download | A user guesses another user's private object identifier. | Login-required routes enforce signer/recipient ownership; CA lifecycle routes enforce administrator role; public verification accepts caller-supplied bytes only. | Local host administrators remain outside the application boundary. | Phase 4 |
| High | Secret leakage through Git, logs, or terminal output | Keys, passwords, databases, or uploaded content are committed or printed. | Git exclusions cover runtime material; CLI output contains identifiers and fingerprints only; tests inspect output and stored formats. | Ignore rules do not remove a secret already committed; local backups and shell history need operator protection. | Phases 1–2; review each phase |
| Medium | Audit deletion or forgery | A user or operator changes lifecycle history. | Certificate, authentication and document workflows write privacy-conscious audit events. | Local SQLite is not an append-only audit log. | Phase 4 |
| High | Ciphertext or recipient-metadata manipulation | Altered encryption metadata changes who can decrypt or what is authenticated. | AES-256-GCM authenticates ciphertext and canonical metadata; HKDF context binds recipient and ephemeral material; negative tests alter both. | Endpoint compromise and recipient redistribution remain outside ciphertext protection. | Phase 4 |

## Residual risks and review triggers

The classroom PKI depends on one local machine, an operator-supplied password, filesystem permissions, correct wall-clock time, and manual CRL publication. It does not provide external identity proofing, hardware-backed keys, trusted timestamps, online revocation, immutable audit storage, or legal non-repudiation.

Phase 3 mitigates upload path traversal by rejecting path-bearing names and writing only generated opaque storage IDs outside static files. It does not parse uploaded content, limits demo types to PDF/plain text, uses Flask's 16 MiB request limit and strictly parses package JSON/Base64/PEM. Mathematical signature success is never a trust success without current certificate, chain, key-usage and CRL checks.

## Phase 4 authentication and confidentiality update

| Threat | Phase 4 control | Remaining limitation |
|---|---|---|
| Account/password compromise | Argon2id verifier, minimum 12-character passwords, generic login failures, CSRF, owner/role checks | No production rate limiter, MFA, external IdP or account recovery |
| Database or key-record theft | Per-key random Scrypt salt and AES-256-GCM nonce; purpose/version AAD; CA keys remain separately protected | Offline password guessing remains possible; strong passwords are essential |
| Cross-user document access | Server-side sender/recipient/owner checks on every sensitive route; opaque public IDs | Local host/administrator compromise remains out of scope |
| Ciphertext or metadata alteration | AES-256-GCM authenticates exact ciphertext and canonical metadata; HKDF info binds metadata | No anti-replay ledger or delivery receipt |
| Recipient substitution | Recipient ID and ephemeral public key are authenticated and included in HKDF context | X25519 public key binding relies on the local account database, not a separate certificate |
| Disabled recipient targeted by a crafted request | Recipient selection and the encryption route both require an active account with an active X25519 key | Administrative account-state changes remain local-operator policy |
| Nonce/salt/key reuse | Fresh OS-random nonce and salt plus fresh ephemeral X25519 key for every encryption | Random-generator or host compromise remains out of scope |
| Password reset causing key loss | No reset/recovery path is exposed | Losing the password makes protected private keys unrecoverable |

The decrypted document is streamed from memory as an authenticated download and is not written to the decrypted temporary directory. Multi-recipient encryption, trusted timestamps, HSM-backed CA/user keys, production session deployment and durable rate-limiting infrastructure remain out of scope.
