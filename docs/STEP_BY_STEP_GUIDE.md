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

### B. Quét một thư mục hoặc tệp cụ thể ở đường dẫn khác
```bash
npx hexora ./path/to/my-web-app
npx hexora /var/www/ecommerce/src/auth.ts
```

### C. Quét thẳng một kho mã nguồn GitHub từ xa (Remote Repo)
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
Dành cho các kịch bản kiểm tra thăm dò mà không muốn ngắt luồng lệnh:
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

## 6. Tích hợp 1-Click vào Cursor, Claude Desktop & AI Agents

Bạn đang dùng **Cursor IDE**, **Claude Desktop**, **Windsurf**, hay các AI Agent thông minh? Thay vì phải cấu hình file JSON phức tạp:

Chỉ cần chạy lệnh duy nhất:
```bash
npx hexora init
```

Hexora sẽ tự động tìm kiếm và chèn cấu hình Model Context Protocol (MCP) vào:
- `.cursor/mcp.json` (Dành cho Cursor)
- `claude_desktop_config.json` (Dành cho Claude Desktop)
- Bộ quy tắc AI Agent Task & Git Hook

Sau đó, trong Cursor hoặc Claude, bạn chỉ cần chat:
> *"Hãy dùng Hexora quét dự án này và tự động sửa các lỗi bảo mật tìm thấy."*

---

## 7. Chế độ Vệ sĩ canh gác tự động khi Save (Watch Mode)

Bạn muốn vừa gõ code vừa được bảo vệ theo thời gian thực mà không cần gõ lệnh quét liên tục?

Chạy lệnh:
```bash
npx hexora watch
```

Mỗi khi bạn nhấn `Ctrl + S` trên VS Code/Editor, Hexora sẽ tự động quét vi sai (Micro-delta scan) trong tích tắc (vài mili-giây) và báo động ngay nếu dòng code vừa gõ chứa lỗ hổng hoặc lộ mật khẩu!

---

## 8. Cài đặt Git Pre-commit Gate (Chặn rò rỉ khóa bí mật)

Để đảm bảo các thành viên trong nhóm không bao giờ vô tình `git commit` nhầm file `.env`, khóa API OpenAI/AWS hay code dính SQL Injection lên GitHub:

Chạy lệnh:
```bash
npx hexora hook
```

Hexora sẽ thiết lập script `.git/hooks/pre-commit`. Từ giờ trở đi, mỗi khi gõ `git commit`, Hexora sẽ quét tự động:
- Nếu phát hiện lỗi **CRITICAL** hoặc **HIGH** -> Lệnh commit sẽ bị chặn đứng ngay lập tức!
- Chỉ cho phép commit khi mã nguồn an toàn.

---

## 9. Chạy Benchmark so tài với Snyk / Semgrep / SonarQube

Muốn kiểm chứng sức mạnh thực tế của Hexora so với các cỗ máy bảo mật hàng đầu thế giới?

Chạy lệnh:
```bash
npx hexora bench
```

Hexora sẽ khởi chạy bộ đấu trường kiểm thử tự động gồm 11 kịch bản tấn công thực tế (Web2, Web3 Smart Contracts, AI Prompt Injection, SSTI, Reentrancy, False Positive traps) và in bảng đối sánh định lượng chi tiết.

---

## 10. Nạp tri thức Zero-Day & CVE mới vào Hexora

Khi bạn đọc được một bài viết phân tích lỗ hổng mới (Security Writeup) hoặc thông báo CVE trên mạng dưới dạng file Markdown/Text:

Chạy lệnh:
```bash
npx hexora learn ./path/to/cve-writeup.md
```

Hexora sẽ phân tích cấu trúc, học các vector tấn công mới và tự động cập nhật vào cơ sở tri thức (Threat Intelligence Memory) để từ nay về sau phát hiện được biến thể tấn công đó!

Xem toàn bộ kho tri thức đã học:
```bash
npx hexora intel
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
