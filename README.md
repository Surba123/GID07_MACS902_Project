# PKI-Based Secure Digital Document Signing and Verification System

This MACS902 Modern Cryptography project is a local Flask/Jinja academic prototype for
certificate-backed document security. It demonstrates a two-level public-key infrastructure
(PKI), authenticated certificate issuance and revocation, detached document signatures,
detailed trust verification, and recipient-only document encryption.

The system deliberately separates two questions:

- **Is the signature mathematically valid?** RSA-PSS verification and SHA-256 digest comparison
  determine whether the supplied document and signed manifest match.
- **Is the signer currently trusted?** The signer is trusted only when the certificate has a
  valid chain to the configured Root CA, is within its validity period, is authorised for
  document signing, and is not listed as revoked in the current signed CRL.

A signature can therefore remain mathematically valid while the signer is no longer trusted,
for example after certificate revocation or expiry.

## Features

- Local registration, login, logout, CSRF protection, and administrator role checks.
- Administrator-reviewed signing-certificate requests, issuance, rejection, and revocation.
- RSA-3072 Root CA, Issuing CA, and end-entity signing keys.
- X.509 certificate chains, certificate signing requests, signed certificate revocation lists
  (CRLs), validity checks, Key Usage, and Extended Key Usage enforcement.
- Detached document signatures using RSA-PSS, MGF1-SHA-256, SHA-256, and a 32-byte PSS salt.
- Verification results that report document integrity, signature mathematics, certificate
  dates, chain, revocation status, signing authorisation, and final trust separately.
- Argon2id password hashing.
- Per-user private keys protected at rest using Scrypt-derived keys and AES-256-GCM.
- A separate X25519 key-agreement identity for each user; RSA signing keys are not reused for
  encryption.
- One-recipient encryption using an ephemeral X25519 key pair, HKDF-SHA-256, and AES-256-GCM
  with authenticated metadata.
- Private runtime storage with generated identifiers, conservative file types, a 16 MiB upload
  limit, path-containment checks, and privacy-conscious audit records.

## Cryptographic design summary

| Purpose | Design |
| --- | --- |
| Password storage | Argon2id through `argon2-cffi` |
| CA and signing keys | RSA-3072 |
| Document signatures | RSA-PSS, MGF1-SHA-256, SHA-256, 32-byte PSS salt |
| PKI | Self-signed Root CA, Issuing CA, X.509 CSRs/certificates, signed CRLs |
| User private-key storage | Scrypt (`N=16384`, `r=8`, `p=1`) plus AES-256-GCM |
| Recipient key agreement | Fresh ephemeral X25519 key pair per encrypted document |
| Content-key derivation | HKDF-SHA-256 with a fresh salt and protocol/context binding |
| Document encryption | AES-256-GCM with a fresh nonce and authenticated metadata |

The application-recorded signing time is ordinary metadata, not a trusted third-party
timestamp. Encryption provides confidentiality for the selected recipient; it does not by
itself prove authorship.

## Requirements

- Windows PowerShell
- Git
- Python 3.12 or 3.13
- Internet access while installing packages and running `pip-audit`

No Docker, Node.js, external database server, or cloud account is required.

## Fresh Windows PowerShell setup

Use `python -m ...` command forms where possible. They are more reliable in OneDrive-managed
folders and environments where Windows Controlled Folder Access blocks executable wrappers.

### 1. Clone the repository

```powershell
git clone https://github.com/Surba123/MACS902-PKI-Document-System.git
Set-Location .\MACS902-PKI-Document-System
```

### 2. Create and activate the virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

### 3. Configure local secrets

Choose either an ignored `.env` file or terminal-session environment variables. Never commit
real secret values.

For an `.env` file:

```powershell
Copy-Item .\.env.example .\.env
```

Open `.env` locally and replace every `replace-with-...` value with a separately generated
random value. Keep the file untracked.

Alternatively, configure the current PowerShell session without printing the generated values:

```powershell
$env:SECRET_KEY = & python -c "import secrets; print(secrets.token_urlsafe(48))"
$env:PKI_CA_KEY_PASSWORD = & python -c "import secrets; print(secrets.token_urlsafe(48))"
$env:PKI_DEVELOPMENT_USER_KEY_PASSWORD = & python -c "import secrets; print(secrets.token_urlsafe(48))"
```

The development-user password variable supports legacy Phase 2/3 CLI records. Authenticated
Phase 4 user keys are protected by their account passwords.

### 4. Create the database and PKI for a fresh runtime

Run these commands only for a new local runtime:

```powershell
python -m flask --app run.py db upgrade
python -m flask --app run.py pki init
python -m flask --app run.py pki generate-crl
```

> **Important:** do not rerun `pki init` as a reset or regeneration command against a populated
> runtime. The database, CA certificates, CA private keys, and configured CA password form one
> trust hierarchy. Preserve them together. If you already have an initialized runtime, skip
> initialization and proceed to database migration, CRL generation if required, and application
> startup. A missing or mismatched CA component must be investigated rather than silently
> replaced.

### 5. Bootstrap the first administrator

This command prompts securely for the administrator password twice. There is no hard-coded
default administrator.

```powershell
python -m flask --app run.py users bootstrap-admin `
  --name "Local CA Administrator" `
  --email "admin@example.com"
```

Use a strong local demonstration password and do not place it in scripts, screenshots, or Git.

### 6. Start the application

```powershell
python -m flask --app run.py run --host 127.0.0.1 --port 5000
```

Open <http://127.0.0.1:5000/> in the browser. The local Flask development server must not be
exposed to the public Internet. A production deployment would require HTTPS, secure cookies, a
production WSGI server, managed secrets, monitoring, and additional operational controls.

## Testing and quality checks

Run these commands from the activated virtual environment. Disposable cache locations avoid
common OneDrive write and locking problems.

```powershell
$env:COVERAGE_FILE = Join-Path $env:TEMP "macs902-final.coverage"
$env:RUFF_CACHE_DIR = Join-Path $env:TEMP "macs902-final-ruff-cache"

python -m flask --app run.py db upgrade
python -m flask --app run.py db check
python -m pytest -p no:cacheprovider --cov=app --cov-report=term-missing
python -m ruff check .
python -m ruff format --check .
python -m pip_audit -r requirements-lock.txt
```

Tests use isolated temporary databases and storage directories. The dependency audit requires
network access to its vulnerability data source.

## Five-minute browser demonstration

Use browser-valid demonstration addresses such as `alice@example.com`, `bob@example.com`, and
`admin@example.com`.

1. Register Alice and Bob as normal users.
2. From each dashboard, enter the current password and request a signing certificate.
3. Log in as the administrator, open **Admin**, and issue both pending certificates.
4. Log in as Alice, upload a small `.txt` document, and sign it with Alice's password.
5. Verify the unchanged document using its stored signature record or downloaded JSON package.
   Show that integrity, RSA-PSS mathematics, certificate chain, dates, usage, revocation, and
   current signer trust all pass.
6. Change one harmless word in a copy and verify it with the original signature package. The
   integrity/overall decision must fail.
7. As Alice, encrypt a small document for Bob. Log in as Bob, open the received-document list,
   and decrypt/download it with Bob's password.
8. Log in as the administrator and revoke Alice's signing certificate. Verify Alice's original
   unchanged document again: signature mathematics remains valid, but certificate status and
   current signer trust fail.

## Project structure

```text
app/
  auth/                         Registration, login, sessions, access checks, admin bootstrap
  admin/                        Certificate-request review and certificate lifecycle routes
  crypto/                       Private-key protection and recipient encryption
  documents/                    Signing, verification, encryption, and document routes
  models/                       Users, certificates, documents, keys, and audit metadata
  pki/                          CA hierarchy, issuance, CRL, revocation, validation, and CLI
docs/                           Architecture, trust model, threat model, and project documents
migrations/                     Reproducible database schema changes
tests/                          Application, PKI, cryptographic, route, and negative tests
```

## Team Members and Contributions

| Team Member | Student ID | Primary Technical Contributions |
|---|---:|---|
| Saurabh Narayanan | 8929208 | PKI architecture; Root and Issuing CA setup; CSR processing; certificate issuance, revocation, CRL generation, and certificate-chain validation; contributed to report sections covering the project context, architecture, PKI design, trust model, and limitations. |
| Muhammed Ihsan | 1618350 | RSA-PSS and SHA-256 document-signing and verification workflow; Argon2id password protection; Scrypt and AES-256-GCM private-key protection; cryptographic validation and testing; contributed to implementation details, cryptographic design, and security testing sections. |
| Osama Siddiqui | 1750677 | Flask user interface; authentication and access control; SQLite database integration; X25519, HKDF, and AES-256-GCM recipient-encryption workflow; README documentation; contributed to implementation details, application workflow, future improvements, and presentation preparation. |

All team members contributed to compiling, reviewing, and refining the final technical report and presentation materials.

## Security and Git hygiene

Never commit `.env`, `instance/`, databases, private keys, generated runtime certificates or
CRLs, uploads, encrypted/decrypted documents, virtual environments, caches, or test runtime
material. Private keys, passwords, derived keys, plaintext confidential content, and raw storage
paths must not appear in pages, logs, errors, screenshots, or portable signature packages.

## Known limitations

- Local academic prototype, not a production PKI or production deployment.
- No trusted timestamping; certificate status is evaluated at verification time.
- No OCSP service or Internet-scale revocation infrastructure.
- One recipient per encrypted document; no multi-recipient envelope encryption.
- No safe private-key recovery or password-reset mechanism for encrypted user keys.
- No production account recovery, MFA, external identity provider, or external identity proofing.
- No HSM-backed keys, offline Root CA ceremony, multi-person CA approval, or immutable audit log.
- No production-grade distributed rate limiting, malware scanning, backup process, or operational
  monitoring.
- No claim of legal non-repudiation or suitability for public Internet deployment.

AI-assisted development disclosure: OpenAI Codex was used as an implementation support tool for UI refinement, development assistance, debugging, testing support, and documentation refinement. The team reviewed, tested, validated, and takes responsibility for the final submitted system.
