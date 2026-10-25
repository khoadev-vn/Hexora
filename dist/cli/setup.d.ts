export interface SetupOptions {
    workspaceDir?: string;
    target?: string;
}
export declare function runUniversalSetup(options?: SetupOptions): Promise<void>;
export declare function installGitHook(targetDir?: string): void;
export declare function runSkillCommand(platform?: string, targetDir?: string): Promise<void>;
//# sourceMappingURL=setup.d.ts.map