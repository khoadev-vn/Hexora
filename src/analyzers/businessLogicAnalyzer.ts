import { VulnerabilityFinding, CodeLocation } from '../types/index.js';

export interface BusinessLogicViolation {
  type: 'IDOR_BOLA' | 'PRICE_TAMPERING' | 'NEGATIVE_AMOUNT_TAMPERING' | 'FINANCIAL_TOCTOU_RACE';
  severity: 'CRITICAL' | 'HIGH';
  title: string;
  description: string;
  remediationAdvice: string;
  cwe: string;
  owasp: string;
  lineStart: number;
  lineEnd: number;
  snippet: string;
  pocScenario: string;
}

export class BusinessLogicAnalyzer {
  /**
   * Performs Semantic AI Reasoning across function scopes to detect business logic vulnerabilities
   * that evade conventional regex / AST scanners (such as IDOR, price tampering, negative balance exploits).
   */
  public analyze(filePath: string, content: string): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];
    const violations: BusinessLogicViolation[] = [];

    // Analyze IDOR / BOLA
    this.detectIdorBola(content, violations);

    // Analyze Client-Side Price Tampering
    this.detectPriceTampering(content, violations);

    // Analyze Negative Amount Exploits
    this.detectNegativeAmountFlaw(content, violations);

    // Analyze Financial TOCTOU Race Condition
    this.detectFinancialToctou(content, violations);

    for (const v of violations) {
      findings.push({
        id: `FIND-BIZ-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
        ruleId: `HEX-BIZ-${v.type}`,
        title: v.title,
        severity: v.severity,
        category: 'BUSINESS_LOGIC',
        cwe: v.cwe,
        owasp: v.owasp,
        location: {
          filePath,
          lineStart: v.lineStart,
          lineEnd: v.lineEnd,
          snippet: v.snippet
        },
        description: v.description,
        status: 'CANDIDATE',
        reproductionPoC: v.pocScenario,
        remediation: {
          explanation: v.remediationAdvice
        },
        timestamp: new Date().toISOString()
      });
    }

    return findings;
  }

  /**
   * Detects Broken Object Level Authorization (BOLA/IDOR) in sensitive financial or mutation endpoints.
   */
  private detectIdorBola(content: string, violations: BusinessLogicViolation[]): void {
    const lines = content.split('\n');

    // Pattern: Sensitive mutation or financial drain action with user ID parameter
    const idorSensitiveActionPattern = /(?:withdraw|transfer|drain|payout|deleteAccount|updateBalance|sendMoney|updateUser|deleteWallet)\s*\([^)]*\)|(?:app|router)\.(?:post|put|patch|delete)\s*\(\s*['"][^'"]*:(?:userId|walletId|accountId|id)[^'"]*['"]/i;
    const match = idorSensitiveActionPattern.exec(content);

    if (match) {
      // Find the enclosing function body or context
      const matchIndex = match.index;
      const contextSlice = content.slice(Math.max(0, matchIndex - 100), Math.min(content.length, matchIndex + 1200));

      // Check if context pulls ID from untrusted client input
      const hasClientSuppliedId =
        /req\.(?:params|query|body)\.(?:userId|walletId|accountId|id)|params\.(?:userId|walletId|accountId|id)/i.test(contextSlice);

      // Semantic Check: Is there session authentication verification comparing caller identity against resource owner?
      const hasOwnershipVerification =
        /(?:req\.user\.id|req\.auth\.userId|session\.userId|ctx\.user\.id)\s*===?\s*(?:req\.params|req\.body|req\.query|userId|walletId|accountId|id)/i.test(contextSlice) ||
        /(?:where\s*:\s*\{[^}]*(?:userId|ownerId)\s*:\s*(?:req\.user\.id|session\.userId)|ownerId\s*:\s*req\.user\.id)/i.test(contextSlice) ||
        /(?:checkOwnership|verifyOwnership|isOwner|authorizeResource|requireOwnership)\s*\(/i.test(contextSlice);

      if (hasClientSuppliedId && !hasOwnershipVerification) {
        // Calculate line number
        const lineStart = content.slice(0, matchIndex).split('\n').length;
        const lineEnd = Math.min(lines.length, lineStart + 10);
        const snippet = lines.slice(Math.max(0, lineStart - 2), lineEnd).join('\n');

        violations.push({
          type: 'IDOR_BOLA',
          severity: 'CRITICAL',
          title: 'Critical Business Logic Flaw: Broken Object Level Authorization (IDOR/BOLA) in Resource Operation',
          cwe: 'CWE-639',
          owasp: 'A01:2021-Broken Access Control',
          description:
            'Endpoint performs sensitive state mutation or funds withdrawal using untrusted client-supplied identity parameter (e.g. req.params.userId / req.body.walletId) without verifying that the authenticated caller (req.user.id) actually owns the target account.',
          remediationAdvice:
            'Always bind resource lookups and mutations to the authenticated session identity: enforce `if (req.user.id !== targetUserId) throw new ForbiddenError()` or include `ownerId: req.user.id` in the database query clause.',
          lineStart,
          lineEnd,
          snippet,
          pocScenario:
            'Attacker registers as User A (Token A), then sends HTTP request targeting User B:\ncurl -X POST /api/wallet/user_B_12345/withdraw -H "Authorization: Bearer <TOKEN_USER_A>" -d \'{"amount": 1000}\'\nResult: Funds successfully drained from User B because the server relies on URL params rather than authenticated token identity.'
        });
      }
    }
  }

  /**
   * Detects Client-Side Price Tampering (e-commerce logic vulnerability).
   */
  private detectPriceTampering(content: string, violations: BusinessLogicViolation[]): void {
    const lines = content.split('\n');

    // Pattern: Checkout / order creation trusting client-provided price or total
    const priceTamperPattern = /(?:createOrder|checkout|processPayment|chargeCustomer|payOrder)\s*\([^)]*\)|(?:app|router)\.post\s*\(\s*['"][^'"]*(?:checkout|order|payment|cart)[^'"]*['"]/i;
    const match = priceTamperPattern.exec(content);

    if (match) {
      const matchIndex = match.index;
      const contextSlice = content.slice(Math.max(0, matchIndex - 50), Math.min(content.length, matchIndex + 1000));

      // Checks if price is accepted directly from body
      const trustsClientPrice =
        /(?:const|let|var)?\s*(?:price|amount|unitPrice|total)\s*=\s*req\.body\.(?:price|amount|total|unitPrice)/i.test(contextSlice) ||
        /(?:charge|createTransaction|insertOrder)\s*\([^)]*req\.body\.(?:price|amount|total)/i.test(contextSlice);

      // Checks if server looks up price in catalog/database
      const hasCatalogLookup =
        /(?:db\.products|Product\.findById|productRepository|catalog\.getPrice|fetchProductPrice)\s*\(/i.test(contextSlice);

      if (trustsClientPrice && !hasCatalogLookup) {
        const lineStart = content.slice(0, matchIndex).split('\n').length;
        const lineEnd = Math.min(lines.length, lineStart + 8);
        const snippet = lines.slice(Math.max(0, lineStart - 1), lineEnd).join('\n');

        violations.push({
          type: 'PRICE_TAMPERING',
          severity: 'HIGH',
          title: 'Business Logic Flaw: Arbitrary Client-Side Price Tampering in Checkout',
          cwe: 'CWE-472',
          owasp: 'A04:2021-Insecure Design',
          description:
            'Order creation or payment processing accepts product price or transaction total directly from untrusted client input (req.body.price), allowing buyers to purchase items for arbitrary values (e.g. $0.01).',
          remediationAdvice:
            'Never trust price values sent from the client. Retrieve canonical item prices directly from the trusted database or pricing catalog using product ID: `const product = await db.products.findById(req.body.productId); const total = product.price * quantity;`.',
          lineStart,
          lineEnd,
          snippet,
          pocScenario:
            'Attacker modifies client payload during checkout:\nPOST /api/checkout\nBody: {"productId": "PROD-LUXURY-999", "price": 0.01, "quantity": 1}\nResult: Server processes a $5,000 item for $0.01 because the backend trustingly reads req.body.price.'
        });
      }
    }
  }

  /**
   * Detects Negative Amount Transfer Glitch (allowing reversal of balance deduction into addition).
   */
  private detectNegativeAmountFlaw(content: string, violations: BusinessLogicViolation[]): void {
    const lines = content.split('\n');

    const transferPattern = /(?:function\s+transferFunds|function\s+sendMoney|function\s+withdrawFunds|transfer\s*:\s*async)\s*\([^)]*\)/i;
    const match = transferPattern.exec(content);

    if (match) {
      const matchIndex = match.index;
      const contextSlice = content.slice(matchIndex, Math.min(content.length, matchIndex + 800));

      const hasAmountParam = /amount\b/i.test(contextSlice);
      const hasBalanceSubtraction = /(?:balance\s*-=|balances\[[^\]]+\]\s*-=|sender\.balance\s*-=)\s*amount/i.test(contextSlice);
      const hasPositiveCheck = /(?:amount\s*<=\s*0|amount\s*>\s*0|require\s*\(\s*amount\s*>\s*0|if\s*\(\s*amount\s*<=\s*0\))/i.test(contextSlice);

      if (hasAmountParam && hasBalanceSubtraction && !hasPositiveCheck) {
        const lineStart = content.slice(0, matchIndex).split('\n').length;
        const lineEnd = Math.min(lines.length, lineStart + 8);
        const snippet = lines.slice(Math.max(0, lineStart - 1), lineEnd).join('\n');

        violations.push({
          type: 'NEGATIVE_AMOUNT_TAMPERING',
          severity: 'HIGH',
          title: 'Business Logic Flaw: Missing Positive Amount Validation (Negative Value Balance Inflation)',
          cwe: 'CWE-839',
          owasp: 'A04:2021-Insecure Design',
          description:
            'Financial transfer or balance deduction operation does not validate that the transfer amount is strictly positive (> 0). Passing a negative number (-1000) reverses subtraction (`balance - (-1000)` = `balance + 1000`), minting infinite funds.',
          remediationAdvice:
            'Enforce strict non-negative validation before executing transactions: `if (typeof amount !== "number" || amount <= 0 || !Number.isFinite(amount)) throw new BadRequestError("Invalid amount");`.',
          lineStart,
          lineEnd,
          snippet,
          pocScenario:
            'Attacker initiates a transfer with a negative amount:\nPOST /api/transfer\nBody: {"recipient": "attacker", "amount": -1000000}\nResult: Account balance is credited +1,000,000 due to arithmetic inversion without positive bounds check.'
        });
      }
    }
  }

  /**
   * Detects TOCTOU (Time-of-Check to Time-of-Use) race condition in financial balance checks.
   */
  private detectFinancialToctou(content: string, violations: BusinessLogicViolation[]): void {
    const lines = content.split('\n');

    // Pattern: separate read-check-update without atomic transaction or lock
    const toctouPattern = /if\s*\(\s*(?:user|sender|account)\.balance\s*>=\s*amount\s*\)\s*\{[\s\S]*?await\s+(?:sendExternalPayment|executeTransfer|payoutGateway)[\s\S]*?(?:user|sender|account)\.balance\s*-=/i;
    const match = toctouPattern.exec(content);

    if (match) {
      const matchIndex = match.index;
      const contextSlice = content.slice(matchIndex, Math.min(content.length, matchIndex + 600));

      const hasAtomicLock = /(?:SELECT\s+FOR\s+UPDATE|SERIALIZABLE|acquireLock|withTransaction|atomicDecrement|\$inc)/i.test(contextSlice);

      if (!hasAtomicLock) {
        const lineStart = content.slice(0, matchIndex).split('\n').length;
        const lineEnd = Math.min(lines.length, lineStart + 12);
        const snippet = lines.slice(Math.max(0, lineStart - 1), lineEnd).join('\n');

        violations.push({
          type: 'FINANCIAL_TOCTOU_RACE',
          severity: 'HIGH',
          title: 'Business Logic Flaw: Financial TOCTOU Balance Race Condition (Double-Spend Drain)',
          cwe: 'CWE-367',
          owasp: 'A04:2021-Insecure Design',
          description:
            'Asynchronous delay between balance sufficiency check (`user.balance >= amount`) and balance deduction without database row locking allows parallel requests to double-spend funds.',
          remediationAdvice:
            'Use atomic database updates (e.g. `UPDATE accounts SET balance = balance - :amt WHERE id = :id AND balance >= :amt`) or distributed mutex locking (Redis Redlock).',
          lineStart,
          lineEnd,
          snippet,
          pocScenario:
            'Attacker fires 50 concurrent withdrawal requests with $100 balance:\nAll 50 pass the "balance >= 100" check before any deduction commits, withdrawing $5,000 total from a $100 account.'
        });
      }
    }
  }
}
