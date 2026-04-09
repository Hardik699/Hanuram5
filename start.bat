@echo off
REM Start script for CMD: ensures build exists and runs node server
if not exist .env (
  echo Missing .env file. Copy .env.example to .env and set MONGODB_URI
  exit /b 1
)

if not exist dist\server\node-build.mjs (
  where pnpm >nul 2>nul
  if %ERRORLEVEL%==0 (
    echo Building project (pnpm build)...
    pnpm build
  ) else (
    echo Build output not found. Install pnpm and run: pnpm build
    exit /b 1
  )
)

echo Starting server...
node dist\server\node-build.mjs
