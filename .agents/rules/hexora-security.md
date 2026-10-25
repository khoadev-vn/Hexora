# Hexora Security Guardrails for Antigravity

- **Zero Leaked Secrets Policy**: Never commit or hardcode private keys, AWS tokens, OpenAI/Gemini keys, Solana secret keys, or database credentials.
- **Continuous Single-File Audit**: When editing sensitive files (auth, payments, crypto, API handlers, prompts), invoke Hexora `audit_scan_file` before completing turns.
- **Input Sanitization & Injection Defense**: Prevent SQL, NoSQL, SSTI, Command Injection, and Prompt Injection (OWASP LLM01).
- **Smart Contract Safety**: Enforce reentrancy protection, CEI pattern, Solana account owner/signer checks, and safe math.
- **Automated Verification**: Challenge any candidate finding with Hexora Adversarial Verifier before presenting reports to users.
