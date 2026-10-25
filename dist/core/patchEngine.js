import fs from 'node:fs';
import path from 'node:path';
import { SastScanner } from '../analyzers/sastScanner.js';
import { AdversarialVerifier } from './adversarialVerifier.js';
export class PatchEngine {
    static apply(options) {
        const root = options.rootPath || process.cwd();
        const absPath = path.isAbsolute(options.filePath)
            ? options.filePath
            : path.resolve(root, options.filePath);
        if (!fs.existsSync(absPath)) {
            return {
                success: false,
                message: `Target file not found: ${absPath}`,
                filePath: absPath,
                remainingFindings: 0,
            };
        }
        const originalContent = fs.readFileSync(absPath, 'utf-8');
        let backupPath;
        if (options.createBackup !== false) {
            backupPath = `${absPath}.bak`;
            fs.writeFileSync(backupPath, originalContent, 'utf-8');
        }
        let modifiedContent = originalContent;
        // Strategy 1: Direct target string replacement
        if (options.target !== undefined && options.replacement !== undefined) {
            if (!originalContent.includes(options.target)) {
                return {
                    success: false,
                    message: `Target snippet not found in ${absPath}. Content might have shifted.`,
                    filePath: absPath,
                    backupPath,
                    remainingFindings: -1,
                };
            }
            modifiedContent = originalContent.split(options.target).join(options.replacement);
        }
        // Strategy 2: Simple Unified Diff patch parsing
        else if (options.unifiedDiff) {
            const patched = this.applyUnifiedDiff(originalContent, options.unifiedDiff);
            if (!patched.success) {
                return {
                    success: false,
                    message: `Failed to apply unified diff: ${patched.error}`,
                    filePath: absPath,
                    backupPath,
                    remainingFindings: -1,
                };
            }
            modifiedContent = patched.content;
        }
        else {
            return {
                success: false,
                message: `Neither (target + replacement) nor unifiedDiff was provided.`,
                filePath: absPath,
                backupPath,
                remainingFindings: -1,
            };
        }
        fs.writeFileSync(absPath, modifiedContent, 'utf-8');
        // Run verification on modified file
        const scanner = new SastScanner();
        const verifier = new AdversarialVerifier();
        const findings = scanner.scanSingleFile(absPath, root, modifiedContent);
        const verified = findings.map((f) => verifier.verifyFinding(f, modifiedContent));
        const confirmed = verified.filter((f) => f.status === 'CONFIRMED');
        return {
            success: true,
            message: `Patch successfully applied to ${path.basename(absPath)}.`,
            filePath: absPath,
            backupPath,
            remainingFindings: confirmed.length,
            diffSummary: `Original: ${originalContent.length} bytes -> Modified: ${modifiedContent.length} bytes`,
        };
    }
    static applyUnifiedDiff(content, diffText) {
        try {
            const lines = content.split('\n');
            const diffLines = diffText.split('\n');
            // Extract hunk removals and additions
            const toRemove = [];
            const toAdd = [];
            for (const line of diffLines) {
                if (line.startsWith('---') || line.startsWith('+++') || line.startsWith('@@'))
                    continue;
                if (line.startsWith('-')) {
                    toRemove.push(line.slice(1));
                }
                else if (line.startsWith('+')) {
                    toAdd.push(line.slice(1));
                }
            }
            if (toRemove.length === 0 && toAdd.length === 0) {
                return { success: false, error: 'No hunk additions or removals found in diff.' };
            }
            const targetBlock = toRemove.join('\n');
            const replacementBlock = toAdd.join('\n');
            if (content.includes(targetBlock)) {
                return { success: true, content: content.replace(targetBlock, replacementBlock) };
            }
            // Fallback: line-by-line fuzzy trim match
            const targetTrimmed = toRemove.map((l) => l.trim()).join('\n');
            const linesTrimmed = lines.map((l) => l.trim());
            const idx = linesTrimmed.indexOf(toRemove[0]?.trim());
            if (idx !== -1 && toRemove.length <= lines.length - idx) {
                const slice = lines.slice(idx, idx + toRemove.length).map((l) => l.trim()).join('\n');
                if (slice === targetTrimmed) {
                    lines.splice(idx, toRemove.length, ...toAdd);
                    return { success: true, content: lines.join('\n') };
                }
            }
            return { success: false, error: 'Target hunk lines could not be aligned in target file.' };
        }
        catch (err) {
            return { success: false, error: err.message };
        }
    }
}
//# sourceMappingURL=patchEngine.js.map