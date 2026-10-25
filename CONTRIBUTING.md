# Contributing to Hexora

Thank you for your interest in contributing to **Hexora** — the Next-Gen Universal Security Engine!

## Development Setup

1. Fork & clone the repository:
   ```bash
   git clone https://github.com/<your-username>/hexora.git
   cd hexora
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Build the project:
   ```bash
   npm run build
   ```
4. Run the global benchmark suite:
   ```bash
   npm run benchmark
   ```

## Adding New Security Rules or Threat Intelligence

- Rule definitions are located in `src/rules/ruleDatabase.ts`.
- Built-in Threat Intelligence incident writeups are located in `src/intelligence/threatKnowledgeBase.ts`.
- Adversarial challenge logic is located in `src/core/adversarialVerifier.ts`.

## Commit & PR Guidelines

- Use clear commit messages following Conventional Commits (`feat:`, `fix:`, `docs:`, `perf:`).
- Ensure all benchmark cases pass before opening a Pull Request.
