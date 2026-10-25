# Hexora - Universal Security Engine Installer for Windows
# https://github.com/khoadev-vn/Hexora

$Host.UI.RawUI.ForegroundColor = "Cyan"
Write-Host @"
    __  __                          
   / / / /__  _  ______  _________ _
  / /_/ / _ \| |/_/ __ \/ ___/ __ `/
 / __  /  __/>  </ /_/ / /  / /_/ / 
/_/ /_/\___/_/|_|\____/_/   \__,_/  
"@
$Host.UI.RawUI.ForegroundColor = "White"
Write-Host "Next-Generation Universal Security Engine" -ForegroundColor White
Write-Host "------------------------------------------------------" -ForegroundColor DarkGray

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Error: Node.js (v18+) is required to run Hexora." -ForegroundColor Red
    Write-Host "👉 Please install Node.js from https://nodejs.org/" -ForegroundColor Yellow
    Exit 1
}

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Error: npm is required to install Hexora." -ForegroundColor Red
    Exit 1
}

Write-Host "⚡ Installing Hexora globally from GitHub (khoadev-vn/Hexora)..." -ForegroundColor Cyan
npm install -g khoadev-vn/Hexora

Write-Host ""
Write-Host "✅ Hexora has been successfully installed globally!" -ForegroundColor Green
Write-Host "------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "🚀 Run in any project directory:" -ForegroundColor White
Write-Host "   hexora .         # Full security & secret audit" -ForegroundColor Cyan
Write-Host "   hexora watch     # Instant scan on every Ctrl+S" -ForegroundColor Cyan
Write-Host "   hexora init      # 1-Click setup for Cursor, Claude & VS Code" -ForegroundColor Cyan
Write-Host "   hexora bench     # Run adversarial verification benchmark" -ForegroundColor Cyan
Write-Host ""
Write-Host "🌟 GitHub: https://github.com/khoadev-vn/Hexora" -ForegroundColor Yellow
Write-Host ""
