/**
 * Pure Zero-Dependency PDF 1.4 Generator for Hexora Security Engine.
 * Generates standards-compliant, professional A4 executive security reports.
 */
export class PdfGenerator {
    static generate(report) {
        const pageWidth = 595.28;
        const pageHeight = 841.89;
        const margin = 40;
        const contentWidth = pageWidth - margin * 2;
        const pages = [];
        let currentStream = [];
        let currentY = pageHeight - margin;
        const escapePdfText = (str) => {
            // Sanitize unicode and map common symbols to clean ASCII equivalents for standard Type1 PDF fonts
            const sanitized = str
                .replace(/[\u0080-\uFFFF]/g, (ch) => {
                // Normalize Vietnamese diacritics
                const norm = ch.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
                if (norm.length > 0 && norm.charCodeAt(0) < 128)
                    return norm;
                return ' ';
            })
                .replace(/\\/g, '\\\\')
                .replace(/\(/g, '\\(')
                .replace(/\)/g, '\\)');
            return sanitized;
        };
        const flushPage = () => {
            pages.push(currentStream.join('\n'));
            currentStream = [];
            currentY = pageHeight - margin;
        };
        const checkPageBreak = (neededHeight) => {
            if (currentY - neededHeight < margin + 30) {
                flushPage();
            }
        };
        const drawRect = (x, y, w, h, fillColor, strokeColor, lineWidth = 1) => {
            let ops = 'q ';
            ops += `${lineWidth} w `;
            if (strokeColor) {
                ops += `${strokeColor[0]} ${strokeColor[1]} ${strokeColor[2]} RG `;
            }
            if (fillColor) {
                ops += `${fillColor[0]} ${fillColor[1]} ${fillColor[2]} rg `;
            }
            ops += `${x.toFixed(2)} ${y.toFixed(2)} ${w.toFixed(2)} ${h.toFixed(2)} re `;
            if (fillColor && strokeColor)
                ops += 'B Q';
            else if (fillColor)
                ops += 'f Q';
            else if (strokeColor)
                ops += 'S Q';
            else
                ops += 'Q';
            currentStream.push(ops);
        };
        const drawLine = (x1, y1, x2, y2, color, width = 1) => {
            currentStream.push(`q ${width} w ${color[0]} ${color[1]} ${color[2]} RG ${x1.toFixed(2)} ${y1.toFixed(2)} m ${x2.toFixed(2)} ${y2.toFixed(2)} l S Q`);
        };
        const drawText = (text, x, y, options = {}) => {
            const font = options.font || 'F1';
            const size = options.size || 10;
            const color = options.color || [0.1, 0.1, 0.1];
            const safe = escapePdfText(text);
            currentStream.push(`BT /${font} ${size} Tf ${color[0]} ${color[1]} ${color[2]} rg ${x.toFixed(2)} ${y.toFixed(2)} Td (${safe}) Tj ET`);
        };
        const drawWrappedText = (text, x, startY, maxWidth, lineHeight, options = {}) => {
            const words = text.split(/\s+/);
            const font = options.font || 'F1';
            const size = options.size || 10;
            // Approximate character width for Helvetica
            const approxCharWidth = (font === 'F3' || font === 'F4') ? size * 0.6 : size * 0.52;
            const maxCharsPerLine = Math.floor(maxWidth / approxCharWidth);
            let line = '';
            let y = startY;
            for (const word of words) {
                if ((line + ' ' + word).trim().length > maxCharsPerLine) {
                    checkPageBreak(lineHeight);
                    drawText(line.trim(), x, y, options);
                    y -= lineHeight;
                    line = word;
                }
                else {
                    line = line ? line + ' ' + word : word;
                }
            }
            if (line.trim()) {
                checkPageBreak(lineHeight);
                drawText(line.trim(), x, y, options);
                y -= lineHeight;
            }
            return y;
        };
        // =========================================================================
        // PAGE 1: EXECUTIVE AUDIT REPORT
        // =========================================================================
        // Top Header Dark Banner
        drawRect(margin, currentY - 60, contentWidth, 60, [0.06, 0.09, 0.14], [0.15, 0.2, 0.3], 1.5);
        drawText('HEXORA UNIVERSAL SECURITY AUDIT', margin + 18, currentY - 26, {
            font: 'F2',
            size: 16,
            color: [1, 1, 1]
        });
        drawText('Executive Security Report & Adversarial Verification', margin + 18, currentY - 44, {
            font: 'F1',
            size: 9.5,
            color: [0.65, 0.72, 0.82]
        });
        const isSecure = report.stats.confirmed === 0;
        const statusBg = isSecure ? [0.06, 0.5, 0.28] : [0.85, 0.2, 0.2];
        const statusText = isSecure ? 'STATUS: SECURE (PASSED)' : `ACTION: ${report.stats.confirmed} ISSUES`;
        drawRect(margin + contentWidth - 165, currentY - 45, 150, 28, statusBg);
        drawText(statusText, margin + contentWidth - 155, currentY - 33, {
            font: 'F2',
            size: 9,
            color: [1, 1, 1]
        });
        currentY -= 75;
        // Metadata Bar
        drawRect(margin, currentY - 34, contentWidth, 34, [0.96, 0.97, 0.98], [0.88, 0.9, 0.92], 1);
        drawText(`Target: ${report.targetRoot}`, margin + 12, currentY - 15, {
            font: 'F2',
            size: 8.5,
            color: [0.2, 0.25, 0.3]
        });
        drawText(`Generated: ${report.createdAt}  |  Engine: ${report.generatedBy}`, margin + 12, currentY - 26, { font: 'F1', size: 8, color: [0.45, 0.5, 0.55] });
        currentY -= 48;
        // Executive Metrics Cards (4 columns)
        const cardGap = 10;
        const cardWidth = (contentWidth - cardGap * 3) / 4;
        const cardHeight = 52;
        const metrics = [
            { label: 'FILES ANALYZED', val: `${report.coverage.analyzedFiles.length}`, color: [0.1, 0.5, 0.9] },
            { label: 'ATTACK SURFACES', val: `${report.coverage.attackSurfaces.length}`, color: [0.55, 0.2, 0.8] },
            {
                label: 'CONFIRMED VULNS',
                val: `${report.stats.confirmed}`,
                color: (report.stats.confirmed > 0 ? [0.85, 0.15, 0.15] : [0.08, 0.6, 0.35])
            },
            { label: 'FALSE POSITIVES FILTERED', val: `${report.stats.disproved}`, color: [0.1, 0.65, 0.75] }
        ];
        metrics.forEach((m, idx) => {
            const cx = margin + idx * (cardWidth + cardGap);
            drawRect(cx, currentY - cardHeight, cardWidth, cardHeight, [0.98, 0.99, 1], [0.85, 0.88, 0.92], 1);
            drawText(m.val, cx + 12, currentY - 24, { font: 'F2', size: 16, color: m.color });
            drawText(m.label, cx + 12, currentY - 40, { font: 'F2', size: 6.8, color: [0.5, 0.55, 0.6] });
        });
        currentY -= cardHeight + 20;
        // Section 1: Severity Matrix Table
        drawText('1. SEVERITY BREAKDOWN', margin, currentY, { font: 'F2', size: 11, color: [0.1, 0.15, 0.25] });
        currentY -= 8;
        drawLine(margin, currentY, margin + contentWidth, currentY, [0.8, 0.85, 0.9], 1);
        currentY -= 14;
        const sevCols = [
            { label: 'CRITICAL', count: report.stats.bySeverity.CRITICAL, color: [0.85, 0.15, 0.15] },
            { label: 'HIGH', count: report.stats.bySeverity.HIGH, color: [0.95, 0.45, 0.05] },
            { label: 'MEDIUM', count: report.stats.bySeverity.MEDIUM, color: [0.85, 0.65, 0.05] },
            { label: 'LOW / INFO', count: report.stats.bySeverity.LOW + report.stats.bySeverity.INFO, color: [0.2, 0.5, 0.85] }
        ];
        const sevBoxWidth = (contentWidth - 10 * 3) / 4;
        sevCols.forEach((sc, idx) => {
            const sx = margin + idx * (sevBoxWidth + 10);
            drawRect(sx, currentY - 32, sevBoxWidth, 32, [1, 1, 1], sc.color, 1.2);
            drawText(`${sc.label}:`, sx + 8, currentY - 20, { font: 'F2', size: 8, color: sc.color });
            drawText(`${sc.count} findings`, sx + 68, currentY - 20, { font: 'F1', size: 8.5, color: [0.2, 0.2, 0.2] });
        });
        currentY -= 48;
        // Section 2: Categorical Security Assessment
        drawText('2. CATEGORICAL SECURITY ASSESSMENT', margin, currentY, {
            font: 'F2',
            size: 11,
            color: [0.1, 0.15, 0.25]
        });
        currentY -= 8;
        drawLine(margin, currentY, margin + contentWidth, currentY, [0.8, 0.85, 0.9], 1);
        currentY -= 16;
        const confirmed = report.findings.filter((f) => f.status === 'CONFIRMED');
        const categories = [
            { name: 'Hardcoded Secrets & API Keys', count: confirmed.filter((f) => f.category === 'SECRET').length },
            {
                name: 'Injection & Deserialization Vulnerabilities',
                count: confirmed.filter((f) => ['INJECTION', 'DESERIALIZATION'].includes(f.category)).length
            },
            { name: 'Web3, Smart Contract & Flash Loan Attacks', count: confirmed.filter((f) => f.category === 'WEB3').length },
            { name: 'AI Agent Prompt Injection & Tool Hijacking', count: confirmed.filter((f) => f.category === 'AI_AGENT').length },
            {
                name: 'Business Logic Flaws, IDOR & Broken Access Control',
                count: confirmed.filter((f) => ['AUTH', 'BUSINESS_LOGIC'].includes(f.category)).length
            },
            { name: 'Vulnerable Dependencies & Supply Chain (SCA)', count: confirmed.filter((f) => ['DEPENDENCY', 'SCA'].includes(f.category)).length },
            {
                name: 'Insecure Configurations & Crypto Weaknesses',
                count: confirmed.filter((f) => ['CRYPTO', 'MISCONFIG', 'CLOUD'].includes(f.category)).length
            }
        ];
        categories.forEach((cat, idx) => {
            const rowY = currentY - idx * 18;
            const isClean = cat.count === 0;
            const rowBg = idx % 2 === 0 ? [0.97, 0.98, 0.99] : [1, 1, 1];
            drawRect(margin, rowY - 14, contentWidth, 16, rowBg);
            drawText(cat.name, margin + 8, rowY - 10, { font: 'F1', size: 8.5, color: [0.2, 0.25, 0.3] });
            const statusTag = isClean ? '[PASS] 0 Issues' : `[FAIL] ${cat.count} Issues`;
            const tagColor = isClean ? [0.08, 0.55, 0.25] : [0.85, 0.15, 0.15];
            drawText(statusTag, margin + contentWidth - 95, rowY - 10, { font: 'F2', size: 8.5, color: tagColor });
        });
        currentY -= categories.length * 18 + 20;
        // Section 3: Threat Intelligence Cross-Correlation
        if (report.threatIntel) {
            drawText('3. ZERO-DAY & THREAT INTELLIGENCE CROSS-CORRELATION', margin, currentY, {
                font: 'F2',
                size: 11,
                color: [0.1, 0.15, 0.25]
            });
            currentY -= 8;
            drawLine(margin, currentY, margin + contentWidth, currentY, [0.8, 0.85, 0.9], 1);
            currentY -= 16;
            drawRect(margin, currentY - 38, contentWidth, 38, [0.95, 0.97, 1], [0.75, 0.82, 0.95], 1);
            drawText(`Learned Intelligence Vault: ${report.threatIntel.totalLearnedReports} Incident Reports (${report.threatIntel.totalAttackVariants} Attack Variants)`, margin + 10, currentY - 14, { font: 'F2', size: 8.5, color: [0.15, 0.3, 0.6] });
            drawText(`Source Code Correlation: Scanned AST & semantic data against historical exploit signatures. Correlated: ${report.threatIntel.matchedReportsCount} matches.`, margin + 10, currentY - 28, { font: 'F1', size: 8, color: [0.35, 0.45, 0.6] });
            currentY -= 50;
        }
        // =========================================================================
        // PAGE 2+: FINDINGS & ADVERSARIAL AUDIT LEDGER
        // =========================================================================
        if (confirmed.length === 0) {
            // Clean Bill of Health Banner
            drawRect(margin, currentY - 60, contentWidth, 60, [0.92, 0.98, 0.94], [0.3, 0.7, 0.45], 1.5);
            drawText('CLEAN BILL OF HEALTH: ZERO VULNERABILITIES DETECTED', margin + 15, currentY - 26, {
                font: 'F2',
                size: 12,
                color: [0.1, 0.55, 0.25]
            });
            drawText('All attack surfaces verified. Candidate pattern alerts disproved by Dual-Agent Adversarial Verifier.', margin + 15, currentY - 44, { font: 'F1', size: 8.5, color: [0.2, 0.4, 0.25] });
            currentY -= 75;
        }
        else {
            flushPage();
            drawText('4. CONFIRMED VULNERABILITIES & ACTIONABLE REMEDIATION', margin, currentY, {
                font: 'F2',
                size: 13,
                color: [0.1, 0.15, 0.25]
            });
            currentY -= 10;
            drawLine(margin, currentY, margin + contentWidth, currentY, [0.8, 0.85, 0.9], 1.5);
            currentY -= 18;
            for (let i = 0; i < confirmed.length; i++) {
                const f = confirmed[i];
                checkPageBreak(130);
                // Finding card header
                const sevColor = f.severity === 'CRITICAL'
                    ? [0.85, 0.15, 0.15]
                    : f.severity === 'HIGH'
                        ? [0.95, 0.45, 0.05]
                        : [0.85, 0.65, 0.05];
                drawRect(margin, currentY - 22, contentWidth, 22, [0.96, 0.97, 0.99], sevColor, 1);
                drawText(`[${f.severity}] #${i + 1}: ${f.title}`, margin + 8, currentY - 14, {
                    font: 'F2',
                    size: 9.5,
                    color: sevColor
                });
                drawText(`Rule: ${f.ruleId} | CWE: ${f.cwe || 'N/A'}`, margin + contentWidth - 170, currentY - 14, {
                    font: 'F1',
                    size: 8,
                    color: [0.4, 0.45, 0.5]
                });
                currentY -= 32;
                // Metadata
                drawText(`Location: ${f.location.filePath}:${f.location.lineStart}`, margin + 8, currentY, {
                    font: 'F3',
                    size: 8,
                    color: [0.2, 0.2, 0.2]
                });
                currentY -= 12;
                // Description
                currentY = drawWrappedText(`Description: ${f.description}`, margin + 8, currentY, contentWidth - 16, 12, {
                    font: 'F1',
                    size: 8.5,
                    color: [0.25, 0.3, 0.35]
                });
                currentY -= 6;
                // Code snippet
                if (f.location.snippet) {
                    checkPageBreak(40);
                    drawRect(margin + 8, currentY - 32, contentWidth - 16, 32, [0.94, 0.95, 0.96], [0.85, 0.88, 0.9], 1);
                    const snippetFirstLine = f.location.snippet.split('\n')[0] || '';
                    drawText(snippetFirstLine.slice(0, 90), margin + 14, currentY - 18, {
                        font: 'F3',
                        size: 7.5,
                        color: [0.1, 0.1, 0.1]
                    });
                    currentY -= 40;
                }
                // Remediation
                if (f.remediation?.explanation) {
                    currentY = drawWrappedText(`Remediation: ${f.remediation.explanation}`, margin + 8, currentY, contentWidth - 16, 11, { font: 'F2', size: 8, color: [0.1, 0.45, 0.2] });
                    currentY -= 14;
                }
                currentY -= 10;
            }
        }
        // Adversarial Ledger Section
        checkPageBreak(120);
        drawText('5. ADVERSARIAL VERIFICATION LEDGER (FALSE-POSITIVE SHIELD)', margin, currentY, {
            font: 'F2',
            size: 11,
            color: [0.1, 0.15, 0.25]
        });
        currentY -= 8;
        drawLine(margin, currentY, margin + contentWidth, currentY, [0.8, 0.85, 0.9], 1);
        currentY -= 16;
        const disproved = report.findings.filter((f) => f.status === 'DISPROVED');
        if (disproved.length === 0) {
            drawText('No candidate false positives evaluated.', margin + 8, currentY, {
                font: 'F1',
                size: 8.5,
                color: [0.5, 0.55, 0.6]
            });
            currentY -= 16;
        }
        else {
            drawText(`Dual-Agent Adversarial Verifier cross-examined candidate SAST detections and filtered ${disproved.length} false positives:`, margin + 8, currentY, { font: 'F1', size: 8.5, color: [0.35, 0.4, 0.45] });
            currentY -= 16;
            const sampleDisproved = disproved.slice(0, 8);
            for (const d of sampleDisproved) {
                checkPageBreak(24);
                drawText(`- [FILTERED] ${d.title} (${d.location.filePath}:${d.location.lineStart})`, margin + 12, currentY, { font: 'F2', size: 8, color: [0.2, 0.45, 0.7] });
                currentY -= 10;
                const reason = d.adversarialVerification?.argument || 'Sanitized or contextual safety verified.';
                currentY = drawWrappedText(`  Reason: ${reason}`, margin + 18, currentY, contentWidth - 28, 10, {
                    font: 'F1',
                    size: 7.5,
                    color: [0.45, 0.5, 0.55]
                });
                currentY -= 4;
            }
            if (disproved.length > 8) {
                drawText(`... and ${disproved.length - 8} more candidates successfully disproved.`, margin + 18, currentY, {
                    font: 'F1',
                    size: 7.5,
                    color: [0.55, 0.6, 0.65]
                });
                currentY -= 14;
            }
        }
        // Flush final page
        flushPage();
        // Add page numbers and footers to all pages
        const totalPages = pages.length;
        for (let p = 0; p < totalPages; p++) {
            const footerOps = [
                pages[p],
                `q 0.8 w 0.8 0.85 0.9 RG ${margin} 36 m ${margin + contentWidth} 36 l S Q`,
                `BT /F1 7.5 Tf 0.5 0.55 0.6 rg ${margin} 24 Td (Hexora Universal Security Engine  |  Confidential Audit Report) Tj ET`,
                `BT /F2 7.5 Tf 0.5 0.55 0.6 rg ${margin + contentWidth - 65} 24 Td (Page ${p + 1} of ${totalPages}) Tj ET`
            ];
            pages[p] = footerOps.join('\n');
        }
        // Build standard PDF binary structure
        return this.assemblePdf(pages, pageWidth, pageHeight);
    }
    static assemblePdf(pageStreams, width, height) {
        const objects = [];
        // Object 1: Catalog
        // Object 2: Pages
        // Object 3: Font Helvetica
        // Object 4: Font Helvetica-Bold
        // Object 5: Font Courier
        // Object 6: Font Courier-Bold
        // Followed by Page objects and Content stream objects
        const fontStart = 3;
        const pageStartObj = 7;
        const totalPages = pageStreams.length;
        // 1: Catalog
        objects.push('1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj');
        // 2: Pages
        const pageRefs = Array.from({ length: totalPages }, (_, i) => `${pageStartObj + i * 2} 0 R`).join(' ');
        objects.push(`2 0 obj\n<< /Type /Pages /Kids [${pageRefs}] /Count ${totalPages} >>\nendobj`);
        // Standard Type 1 Fonts
        objects.push('3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj');
        objects.push('4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj');
        objects.push('5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj');
        objects.push('6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold >>\nendobj');
        // Generate Page and Content Stream objects
        for (let i = 0; i < totalPages; i++) {
            const pageObjNum = pageStartObj + i * 2;
            const contentObjNum = pageObjNum + 1;
            const streamContent = pageStreams[i];
            const streamLen = Buffer.byteLength(streamContent, 'utf-8');
            // Page Object
            objects.push(`${pageObjNum} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${width.toFixed(2)} ${height.toFixed(2)}] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R /F4 6 0 R >> >> /Contents ${contentObjNum} 0 R >>\nendobj`);
            // Content Stream Object
            objects.push(`${contentObjNum} 0 obj\n<< /Length ${streamLen} >>\nstream\n${streamContent}\nendstream\nendobj`);
        }
        // Assemble PDF file with xref table
        let body = '%PDF-1.4\n%\xE2\xE3\xCF\xD3\n';
        const offsets = [0];
        for (let i = 0; i < objects.length; i++) {
            offsets.push(Buffer.byteLength(body, 'utf-8'));
            body += objects[i] + '\n';
        }
        const startXref = Buffer.byteLength(body, 'utf-8');
        body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
        for (let i = 1; i <= objects.length; i++) {
            const offsetStr = String(offsets[i]).padStart(10, '0');
            body += `${offsetStr} 00000 n \n`;
        }
        body += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${startXref}\n%%EOF\n`;
        return Buffer.from(body, 'utf-8');
    }
}
//# sourceMappingURL=pdfGenerator.js.map