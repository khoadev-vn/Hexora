<div align="center">
  <img src="../assets/banner.png" alt="Hexora Guide" width="100%" />
</div>

# 📖 HƯỚNG DẪN SỬ DỤNG HEXORA TỪ A ĐẾN Z (STEP-BY-STEP USER GUIDE)
> **Dành cho mọi đối tượng:** Developer, Security Auditor, Tech Lead, DevOps & AI Agent Enthusiast.

---

## 🌟 MỤC LỤC
1. [Yêu cầu hệ thống](#1-yêu-cầu-hệ-thống)
2. [Cách 1: Chạy ngay lập tức không cần cài đặt (Khuyên dùng)](#2-cách-1-chạy-ngay-lập-tức-không-cần-cài-đặt-khuyên-dùng)
3. [Cách 2: Cài đặt toàn hệ thống (Global CLI)](#3-cách-2-cài-đặt-toàn-hệ-thống-global-cli)
4. [Hướng dẫn quét chi tiết các loại mục tiêu](#4-hướng-dẫn-quét-chi-tiết-các-loại-mục-tiêu)
5. [Đọc và sử dụng các file Báo cáo (PDF, TXT, HTML, SARIF)](#5-đọc-và-sử-dụng-các-file-báo-cáo-pdf-txt-html-sarif)
6. [Tích hợp 1-Click vào Cursor, Claude Desktop & AI Agents](#6-tích-hợp-1-click-vào-cursor-claude-desktop--ai-agents)
7. [Chế độ Vệ sĩ canh gác tự động khi Save (Watch Mode)](#7-chế-độ-vệ-sĩ-canh-gác-tự-động-khi-save-watch-mode)
8. [Cài đặt Git Pre-commit Gate (Chặn rò rỉ khóa bí mật)](#8-cài-đặt-git-pre-commit-gate-chặn-rò-rỉ-khóa-bí-mật)
9. [Chạy Benchmark so tài với Snyk / Semgrep / SonarQube](#9-chạy-benchmark-so-tài-với-snyk--semgrep--sonarqube)
10. [Nạp tri thức Zero-Day & CVE mới vào Hexora](#10-nạp-tri-thức-zero-day--cve-mới-vào-hexora)
11. [Tích hợp CI/CD trên GitHub Actions](#11-tích-hợp-cicd-trên-github-actions)
12. [Bảng tổng hợp câu lệnh thường dùng (Cheatsheet)](#12-bảng-tổng-hợp-câu-lệnh-thường-dùng-cheatsheet)

---

## 1. Yêu cầu hệ thống
Hexora được thiết kế siêu nhẹ, không phụ thuộc vào Docker hay các cỗ máy JVM cồng kềnh:
- **Node.js**: Phiên bản 18.0.0 trở lên. (Kiểm tra bằng lệnh: `node -v`)
- **Hệ điều hành**: Windows, macOS, Linux (Ubuntu, Debian, Fedora...).

---

## 2. Cách 1: Chạy ngay lập tức không cần cài đặt (Khuyên dùng)
Bạn không cần phải tải hay clone bất kỳ repo nào. Chỉ cần mở Terminal tại thư mục dự án và chạy:

```bash
npx hexora .
```

*Lần đầu tiên chạy, `npx` sẽ tự động tải phiên bản mới nhất của Hexora và thực thi quét toàn bộ mã nguồn chỉ trong 3 giây.*

---

## 3. Cách 2: Cài đặt toàn hệ thống (Global CLI)
Nếu bạn thường xuyên kiểm toán bảo mật nhiều dự án khác nhau và muốn gõ lệnh ngắn gọn (`hexora` hoặc `audit`):

### Tùy chọn A: Cài đặt từ mã nguồn (Dành cho Contributor & Master)
```bash
# 1. Clone repository về máy
git clone https://github.com/khoadev-vn/Hexora.git
cd Hexora

# 2. Cài dependencies và build mã nguồn TypeScript
npm install
npm run build

# 3. Đăng ký liên kết nhị phân toàn cầu (Global Link)
npm link
```

Bây giờ bạn có thể đứng ở bất kỳ thư mục nào trên máy tính và gõ:
```bash
hexora .
# hoặc lệnh rút gọn siêu ngắn:
audit
```

---

## 4. Hướng dẫn quét chi tiết các loại mục tiêu

### A. Quét thư mục dự án hiện tại
```bash
npx hexora .
```

**Màn hình Terminal thực tế (Live Demo):**
```text
PS D:\my-app> npx hexora .

Hexora

Scanning project...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Secrets                  1 finding
Security vulnerabilities 2 findings
Vulnerable dependencies  1 finding
Insecure configuration   0 findings

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
4 findings detected (Adversarial filtered 6 false positives)

Critical: 1
High:     2
Medium:   1
Low:      0

Report:
  📄 Text (Structured): ./hexora-report.txt
  📑 PDF (Executive):   ./hexora-report.pdf
  📝 Markdown:          ./hexora-report.md
  🌐 HTML Dashboard:    ./hexora-report.html
```

* **Giải thích cơ chế:** Hexora tự động kích hoạt 4 tầng phân tích:
  1. Phân tích ngữ cảnh AST và luồng dữ liệu (Data-flow / Taint analysis).
  2. Dò tìm khóa bí mật qua thuật toán độ hỗn loạn Shannon Entropy.
  3. Quét thành phần phụ thuộc bên thứ 3 (SCA) đối chiếu kho CVE toàn cầu.
  4. Bộ lọc đối nghịch Red-Team loại bỏ hoàn toàn các biến giả lập (mock), sanitize hợp lệ để không làm phiền bạn với cảnh báo rác (False Positives).

### B. Quét một thư mục hoặc tệp cụ thể ở đường dẫn khác
```bash
npx hexora ./path/to/my-web-app
npx hexora /var/www/ecommerce/src/auth.ts
```

### C. Quét thẳng một kho mã nguồn GitHub từ xa (Remote Repo Sandbox)
Hexora hỗ trợ cơ chế Sandbox tự động: Tải nông repo về môi trường cô lập, quét và xuất báo cáo mà không làm ảnh hưởng máy tính của bạn:
```bash
npx hexora facebook/react
npx hexora expressjs/express
```

### D. Xem nhật ký kiểm toán chuyên sâu 4 giai đoạn
Nếu bạn là Chuyên gia bảo mật muốn xem từng bước phân tích AST, entropy secrets, dependency vulnerabilities và Red-Team adversarial reasoning:
```bash
npx hexora . --verbose
```

### E. Chạy không dừng tiến trình (Không exit code 1)
Mặc định nếu phát hiện lỗi `CRITICAL` hoặc `HIGH`, Hexora sẽ trả về `exit code 1` để chặn pipeline. Nếu bạn muốn kiểm tra thăm dò mà không ngắt luồng lệnh:
```bash
npx hexora . --no-fail
```

---

## 5. Đọc và sử dụng các file Báo cáo (PDF, TXT, HTML, SARIF)

Sau khi quét xong, Hexora sẽ tự động khởi tạo các bản báo cáo tiêu chuẩn chuyên nghiệp ngay tại thư mục làm việc của bạn:

| Tên tập tin | Mục đích & Đối tượng sử dụng |
| :--- | :--- |
| **`hexora-report.pdf`** | **Báo cáo hành pháp (Executive Report)**: Định dạng đồ họa chuyên nghiệp, có bảng tóm tắt rủi ro, phân loại mức độ nghiêm trọng (Critical/High/Medium/Low), PoC tái hiện và mã vá lỗi (Patch diff) – Thích hợp nhất để gửi khách hàng, đối tác hoặc sếp duyệt. |
| **`hexora-report.txt`** | **Báo cáo cấu trúc văn bản thuần (UNIX/Dev Friendly)**: Cực kỳ trực quan, dễ mở trên Notepad/Vim, hỗ trợ lệnh `grep`, `cat`, chuyển hướng pipe hoặc xem lướt ngay trong Terminal. |
| **`hexora-report.html`** | **Báo cáo đồ họa tương tác (Interactive Dashboard)**: Mở bằng bất kỳ trình duyệt nào (Chrome, Edge, Safari), hiển thị giao diện Dark Mode cyberpunk hiện đại, lọc động theo mức độ lỗi. |
| **`hexora-report.md`** | **Báo cáo Markdown**: Chuẩn GitHub Flavored Markdown, có thể dán trực tiếp vào GitHub Issues, Pull Request Summary hoặc Notion. |
| **`.hexora-results/audit-report.sarif`** | **Chuẩn SARIF quốc tế (OASIS)**: Dùng để tích hợp trực tiếp vào tab **Security > Code Scanning** của GitHub. |

---

## 6. Tích hợp 1-Click vào Google Antigravity, Cursor, Claude & AI Agents

Bạn đang dùng **Google Antigravity**, **Cursor IDE**, **Claude Code / Desktop**, **Windsurf**, hay các AI Agent tự hành? Thay vì phải cấu hình thủ công từng file JSON hay viết prompt dài dòng:

### Cách 1: Xuất Skill & MCP trực tiếp cho Google Antigravity
Chỉ cần chạy lệnh:
```bash
npx hexora skill antigravity
```

**Màn hình Terminal thực tế:**
```text
PS D:\my-app> npx hexora skill antigravity

======================================================
📦 HEXORA AI AGENT SKILL & MCP INSTALLER
   Target: ANTIGRAVITY
   Workspace: D:\my-app
======================================================

✅ Installed Google Antigravity Skill & MCP server:
   - C:\Users\user\.gemini\config\mcp_config.json
   - D:\my-app\.agents\skills\hexora\SKILL.md
   - C:\Users\user\.gemini\config\skills\hexora\SKILL.md
   - D:\my-app\.agents\rules\hexora-security.md
   - D:\my-app\GEMINI.md

✨ Installation complete! Your AI agents are ready to audit code.
```

### Cách 2: Trình cài đặt đa nền tảng (Universal Setup)
Chạy lệnh:
```bash
npx hexora init
```

**Màn hình Terminal tương tác (Interactive Demo):**
```text
PS D:\my-app> npx hexora init

======================================================
🚀 HEXORA UNIVERSAL AI AGENT & SECURITY SETUP
======================================================

Where do you want to integrate Hexora?

  [1] Google Antigravity (IDE & CLI - MCP & Skills)
  [2] Cursor (MCP Server & .cursor/rules)
  [3] Claude Code (CLI ~/.claude.json)
  [4] Claude Desktop (claude_desktop_config.json)
  [5] VS Code (Workspace Tasks & Extension)
  [6] Windsurf (.windsurf & .windsurfrules)
  [7] Terminal Global Shortcuts & Git Pre-commit Hook
  [8] All Integrations (Recommended for Full AI Stack)

Select an option (1-8): 8

======================================================
⚡ INTEGRATING HEXORA SECURITY PROTOCOL
   Workspace: D:\my-app
======================================================

✅ Configured Google Antigravity Skill & MCP server
✅ Configured Cursor MCP (.cursor/mcp.json) & Rules (.cursor/rules/hexora.mdc)
✅ Configured Claude Code (~/.claude.json)
✅ Configured Claude Desktop (claude_desktop_config.json)
✅ Added VS Code tasks (.vscode/tasks.json)
✅ Created Terminal shortcuts 'hexora' and 'audit'
✅ Installed pre-commit security hook (.git/hooks/pre-commit)

🎉 Hexora configured successfully across all environments!
```

---

### 🤖 Danh mục 14 Công cụ MCP Hexora Cung Cấp Cho AI Agent:

Khi tích hợp vào Antigravity, Cursor hay Claude, AI Agent sẽ sở hữu một "kho vũ khí" an ninh chuyên nghiệp:

| MCP Tool | Chức Năng Cốt Lõi | Ví Dụ Prompt Thực Tế |
| :--- | :--- | :--- |
| `scan_project` | Quét toàn bộ repository & đối kháng lọc bỏ false positive | *"Hãy scan toàn bộ repo này bằng Hexora"* |
| `audit_scan_file` | Quét tức thì 1 file hoặc buffer code đang mở trên RAM | *"Kiểm tra an toàn file authController.ts vừa sửa"* |
| `get_findings` | Lấy danh sách lỗ hổng đã xác minh (phân loại theo mức độ) | *"Liệt kê tất cả lỗi CRITICAL trong project"* |
| `apply_fix` | Tự động vá code bằng unified diff an toàn 100% | *"Áp dụng bản vá Hexora đề xuất cho lỗi SQLi"* |
| `audit_explain_vulnerability` | Phân tích kiến trúc, CVSS và nguyên nhân gốc rễ (Root Cause) | *"Giải thích tại sao hàm này bị Reentrancy"* |
| `audit_generate_poc` | Tự động sinh kịch bản PoC test an toàn để chứng minh lỗ hổng | *"Tạo script PoC chứng minh lỗi bypass quyền"* |
| `audit_get_workspace_posture` | Chấm điểm an ninh workspace (A+ đến F) và thống kê rủi ro | *"Đánh giá điểm an ninh tổng thể của repo"* |
| `validate_finding` | Thử thách nghi vấn để loại bỏ cảnh báo giả lập | *"Xác thực xem cảnh báo này có phải false positive không"* |
| `audit_check_snippet` | Quét nhanh một đoạn code / function trực tiếp | *"Đoạn code regex này có bị ReDoS không?"* |
| `audit_learn_report` | Nạp CVE mới hoặc writeup bug bounty vào bộ nhớ tri thức | *"Học báo cáo CVE vừa công bố này vào database"* |
| `audit_search_knowledge` | Tra cứu cơ chế tấn công và cách phòng thủ từ threat database | *"Tìm các biến thể tấn công Solana CPI hijack"* |
| `audit_get_threat_intel_stats` | Xem thống kê số lượng CVE và attack variants đã học | *"Thống kê tri thức zero-day trong hệ thống"* |
| `audit_export_skill` | Xuất skill và cấu hình MCP tức thì cho agent khác | *"Xuất skill Hexora sang Cursor workspace"* |
| `audit_scan_directory` | Quét một thư mục cụ thể và xuất report chi tiết | *"Quét riêng thư mục src/controllers"* |

* **Ví dụ Prompt ra lệnh cho Antigravity / Cursor:**
  > *"Em ơi, hãy dùng công cụ Hexora MCP kiểm tra toàn bộ workspace, phân tích các lỗ hổng CRITICAL và tự động sinh bản vá chuẩn unified diff giúp anh nhé!"*

---

## 7. Chế độ Vệ sĩ canh gác tự động khi Save (Watch Mode)

Bạn muốn vừa gõ code vừa được bảo vệ theo thời gian thực mà không cần gõ lệnh quét thủ công liên tục?

Chạy lệnh:
```bash
npx hexora watch
```

**Màn hình Terminal thực tế (Live Demo):**
```text
PS D:\my-app> npx hexora watch

======================================================
👁️  HEXORA REAL-TIME WATCH ENGINE
   Monitoring: D:\my-app
   Auto-scans and verifies code on every save (Ctrl+S)
======================================================

⚡ Watcher active! Listening for file changes... (Press Ctrl+C to stop)

[20:15:10] 🟢 CLEAN: src/services/user.service.ts (0 issues, 13.5ms)
[20:15:42] 🟢 CLEAN: src/utils/format.ts (0 issues, 10.2ms)

------------------------------------------------------
[20:16:05] 🚨 SECURITY ALERT: src/routes/auth.ts (18.1ms)
Found 1 genuine vulnerability(ies):

  🔴 CRITICAL | Hardcoded Cloud Access Key (Line 14) [CWE-798]
  Target: src/routes/auth.ts:14
  💡 Suggested Fix: Extract credentials to environment variables (.env) and access via process.env.
------------------------------------------------------
```

* **Giải thích cơ chế:**
  - Bộ lắng nghe nền (Background Daemon) theo dõi các sự kiện lưu file với bộ trễ chống rung 250ms (Debouncing).
  - Chỉ quét phân tích vi sai (Micro-delta AST) đúng tệp vừa sửa trong dưới **20 mili-giây**, không làm lag máy hay đứng IDE.
  - Khi phát hiện mã độc hại hay lộ key, terminal sẽ phát tiếng chuông cảnh báo (`beep`) kèm dòng vị trí chính xác và gợi ý sửa code tức thì.
* **Cách thử nghiệm:** Mở tệp bất kỳ trong VS Code, thử dán một chuỗi giả lập khóa bí mật rồi bấm `Ctrl + S`, bạn sẽ thấy Hexora báo động ngay lập tức!

---

## 8. Cài đặt Git Pre-commit Gate (Chặn rò rỉ khóa bí mật)

Để đảm bảo các thành viên trong nhóm không bao giờ vô tình `git commit` nhầm file `.env`, khóa API OpenAI/AWS hay code dính SQL Injection lên GitHub:

Chạy lệnh:
```bash
npx hexora hook
```

**1. Màn hình Cài đặt Hook:**
```text
PS D:\my-app> npx hexora hook
✅ Installed pre-commit hook at D:\my-app\.git\hooks\pre-commit
```

**2. Màn hình Chặn đứng Commit Lỗi (Enforcement Demo):**
```text
PS D:\my-app> git add src/routes/payment.ts
PS D:\my-app> git commit -m "feat: integrate stripe payment"

🛡️ Hexora Pre-Commit Gate: Verifying staged files...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Secrets                  1 finding
Security vulnerabilities 0 findings
Vulnerable dependencies  0 findings
Insecure configuration   0 findings
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

❌ [Hexora Pre-Commit Hook] Hardcoded Secret Detected!
   File: src/routes/payment.ts:18 -> Unencrypted Stripe API Secret Key
   
Commit rejected to protect repository history.
To inspect or fix, run: npx hexora .
```

* **Giải thích cơ chế:** Hexora ghi đè hook `.git/hooks/pre-commit` chuẩn của Git. Trước khi Git tạo commit, Hexora lập tức kiểm tra toàn bộ thay đổi. Nếu có lỗi **CRITICAL** hoặc lộ khóa API bí mật, lệnh commit sẽ bị hủy bỏ ngay tại máy lập trình viên, bảo vệ an toàn 100% cho lịch sử Git!

---

## 9. Chạy Benchmark so tài với Snyk / Semgrep / SonarQube

Muốn kiểm chứng sức mạnh thực tế của Hexora so với các cỗ máy bảo mật hàng đầu thế giới?

Chạy lệnh:
```bash
npx hexora bench
```

**Màn hình Terminal thực tế (Arena Benchmark Demo):**
```text
PS D:\my-app> npx hexora bench

======================================================
🥊 HEXORA GLOBAL VULNERABILITY BENCHMARK ARENA
======================================================
Running 11 high-fidelity test suites across Web2, Web3, and AI Agents...

[Suite 1/11] SQL Injection in ORM Bypass ............. ✅ DETECTED (Confirmed)
[Suite 2/11] False Positive: Mock Test DB Client ..... 🛡️ DISPROVED (Adversarial)
[Suite 3/11] Solana Arbitrary CPI Missing Signer ..... ✅ DETECTED (Confirmed)
[Suite 4/11] False Positive: Constant In-Memory Key .. 🛡️ DISPROVED (Adversarial)
[Suite 5/11] Prompt Injection & Tool Exfiltration ... ✅ DETECTED (Confirmed)
...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BENCHMARK RESULTS SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
True Positive Detection Rate:     100.0% (11/11)
False Positive Elimination Rate:  100.0% (0 false positives)
Execution Time:                   412ms
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 10. Nạp tri thức Zero-Day & CVE mới vào Hexora

Khi bạn đọc được một bài viết phân tích lỗ hổng mới (Security Writeup) hoặc thông báo CVE trên mạng dưới dạng file Markdown/Text:

Chạy lệnh:
```bash
npx hexora learn ./exploits/solana-cpi-writeup.md
```

**Màn hình Terminal thực tế:**
```text
PS D:\my-app> npx hexora learn ./exploits/solana-cpi-writeup.md

📚 [Hexora Threat Ingestion] Processing: ./exploits/solana-cpi-writeup.md...
✨ Successfully ingested report: [CVE-2024-SOL-01] "Arbitrary CPI Execution in Solana Anchor"
   - Attack Variants learned: cpi_spoofing, missing_program_id_check
   - Mitigation: Verify program_id matches expected Pubkey before invoking invoke_signed

PS D:\my-app> npx hexora intel

======================================================
🧠 HEXORA THREAT INTELLIGENCE KNOWLEDGE VAULT
======================================================
Total Reports Learned: 14
Total Attack Variants: 48

📌 [CVE-Database] CVE-2024-SOL-01: Arbitrary CPI Execution (CRITICAL)
   - Ecosystem: Solana | Class: CPI_HIJACK
   - Attack Variants: cpi_spoofing; missing_program_id_check
```

---

## 11. Tích hợp CI/CD trên GitHub Actions

Để tự động quét bảo mật mỗi khi có Pull Request hoặc Push code lên nhánh chính:

Tạo tập tin `.github/workflows/security.yml` trong dự án của bạn:
```yaml
name: Hexora Security Gate

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Run Hexora Security Audit
        run: npx --yes hexora .

      - name: Upload SARIF Report to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: .hexora-results/audit-report.sarif
```

---

## 12. Bảng tổng hợp câu lệnh thường dùng (Cheatsheet)

| Nhu cầu sử dụng | Câu lệnh thực thi |
| :--- | :--- |
| **Quét nhanh dự án** | `npx hexora .` |
| **Quét chi tiết 4 giai đoạn** | `npx hexora . --verbose` |
| **Quét repo GitHub từ xa** | `npx hexora <owner>/<repo>` |
| **Bật chế độ tự quét khi bấm Save** | `npx hexora watch` |
| **Cài đặt cho Cursor & Claude** | `npx hexora init` |
| **Cài Git Hook chặn lỗi** | `npx hexora hook` |
| **Chạy Benchmark so tài** | `npx hexora bench` |
| **Dạy bài viết CVE mới** | `npx hexora learn <file.md>` |
| **Xem tri thức đã học** | `npx hexora intel` |
| **Xem trợ giúp nhanh** | `npx hexora --help` |

---
*Tài liệu được biên soạn và bảo chứng bởi Hexora Core Development Team.*
