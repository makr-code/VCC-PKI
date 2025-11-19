Project: VCC-PKI (Public Key Infrastructure)
Language: Python

Purpose:
- CA management, certificate issuance, code signing and service certificate lifecycle.

What Copilot should help with:
- Implement secure certificate generation, revocation lists, and certificate renewal automation.
- Suggest safe defaults for key storage and use of hardware/security modules when available.

Coding style and constraints:
- Never embed private keys in source code or store them in plain text. Update `docs/secrets.md` for key handling policies.
- Use established cryptography libraries (cryptography.io) and follow best practices.

Documentation duties (./docs):
- `docs/pki-architecture.md` must describe CA hierarchy, key storage and recovery procedures.
- Document every endpoint and admin workflow used to issue or revoke certificates.

Todo.md continuation:
- Add operational runbooks to `todo.md` and link to `docs/` for detailed steps.

Examples for Copilot prompts:
- "Add an endpoint to issue a service certificate given CSR and validate input permissions."
- "Create a CLI tool to sign artifacts and verify signatures with examples in docs."

Testing & CI:
- Add unit tests for certificate parsing and validation logic and integration tests for issuance flow.

Security:
- Add guidance to rotate keys and test recovery; mention compliance checks in `docs/compliance.md`.
