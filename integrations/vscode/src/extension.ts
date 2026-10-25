/**
 * Hexora VS Code Extension
 * Connects VS Code Diagnostics & Editor directly to the Hexora Engine.
 */

export function activate(context: any) {
  console.log('🛡️ Hexora Security Engine Extension is active.');

  // Diagnostics collection for inline problem highlighting
  // const diagnosticCollection = vscode.languages.createDiagnosticCollection('hexora');
  // context.subscriptions.push(diagnosticCollection);

  // Command: hexora.scanWorkspace
  // Triggers the Hexora engine to analyze the workspace and display problems.
}

export function deactivate() {}
