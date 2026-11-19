# ADR-001: Private PKI trust model

**Status:** Accepted and implemented through Phase 4, updated 27 October 2026.

## Decision

- A locally configured Root CA certificate is the trust anchor. Its protected private key is held by the local operator and should remain offline except for signing the Issuing CA certificate.
- The Root CA signs the Issuing CA certificate; the Issuing CA signs user certificates. CA private keys are never placed in Git or public storage.
- Users own separate signing and key-agreement key pairs. Users submit CSRs proving possession of the signing private key. Administrators review identity and CSR information, issue certificates, and revoke them when necessary.
- A signed Certificate Revocation List (CRL) communicates revocation. Verification requires chain signatures, validity period, CA/basic constraints, key usage, and a fresh trusted CRL. Missing or stale revocation information should fail the final trust decision.
- User signing certificates are for document signatures. Phase 3 signs a canonical manifest containing the SHA-256 document hash and certificate identifier with RSA-PSS/SHA-256. A valid mathematical signature proves possession of the private key, subject to compromise and enrollment assumptions; it is never itself a current trust decision.
- An application-recorded signing time is metadata, **not** a trusted timestamp. It cannot prove the signature existed before revocation or expiry. The prototype does not claim legal non-repudiation or proof of delivery.
- Confidential documents use a separate authenticated key-establishment design: recipient X25519 key, HKDF-SHA256, AES-256-GCM, and authenticated package metadata. Signing and key-agreement keys are kept distinct.
- Each user private key is wrapped with AES-256-GCM under a Scrypt-derived key and purpose/version AAD. The current password must be supplied again for signing or decryption; plaintext private keys exist only transiently in process memory. There is deliberately no recovery mechanism.
- X25519 public keys are bound to identities by the authenticated local database account rather than a separate X.509 key-agreement certificate. Consequently, encrypted packages establish the intended local recipient and protect confidentiality/integrity, but do not independently prove sender authorship. Users sign before encryption when origin evidence is required.

Implementation choices through Phase 4:

- CA and user signing keys are RSA-3072 with public exponent 65537. X.509 certificates and CRLs use SHA-256. Phase 3 document signatures use RSA-PSS/SHA-256 independently of the certificate signature encoding.
- Root Basic Constraints use `CA=TRUE, path_length=1`; Issuing CA uses `CA=TRUE, path_length=0`; end entities use `CA=FALSE`. Only CA certificates receive `keyCertSign` and `cRLSign`.
- End-entity certificates receive `digitalSignature`, `contentCommitment`, and the Microsoft document-signing EKU OID `1.3.6.1.4.1.311.10.3.12`. This vendor-defined EKU is suitable for this controlled classroom PKI but is an interoperability limitation.
- End-entity validity is limited to 397 days and cannot exceed the Issuing CA validity. Secure random X.509 serial numbers are stored as decimal strings.
- A missing, malformed, incorrectly signed, stale or wrong-issuer CRL prevents a trusted result. Revocation does not change whether the certificate signatures are mathematically valid.

## Key ownership and storage

The Root CA private key belongs to the local operator; the Issuing CA private key belongs to the CA administration workflow. Both are encrypted PKCS#8 files protected by a strong `PKI_CA_KEY_PASSWORD` supplied through the environment. The current local process can unlock both, so the “offline Root” property is procedural rather than process-isolated. Phase 4 user signing and X25519 private keys use individual password-derived Scrypt/AES-GCM envelopes; the older shared development-key password is retained only for Phase 2/3 regression compatibility.

## Consequences and limits

The browser application and local host can access metadata and, during an authorized operation, plaintext key material in process memory. A compromised host or CA key can defeat this classroom private PKI. There is no public CA assurance, external identity proofing, trusted timestamp authority, independent delivery receipt, or production HSM. Certificate-policy and package-format details must be checked against actual `cryptography` behavior and negative tests during Phases 2–4.
