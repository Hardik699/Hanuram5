param()

# Start script for PowerShell: ensures `dist/server/node-build.mjs` exists and runs it.
# Create a local `.env` (copy from `.env.example`) and set your real `MONGODB_URI` there.

if (-not (Test-Path -Path ".env")) {
  Write-Host "Missing .env file. Copy .env.example -> .env and add your MONGODB_URI"
  exit 1
}

if (-not (Test-Path -Path "dist/server/node-build.mjs")) {
  if (Get-Command pnpm -ErrorAction SilentlyContinue) {
    Write-Host "Building project (pnpm build)..."
    pnpm build
  } else {
    Write-Host "Build output not found. Install pnpm and run: pnpm build";
    exit 1
  }
}

Write-Host "Starting server..."
node dist/server/node-build.mjs
