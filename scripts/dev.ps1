[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet(
        "help",
        "setup",
        "lint",
        "validate",
        "test",
        "test-e2e",
        "test-e2e-local",
        "up",
        "down",
        "dev",
        "verify",
        "local-up",
        "local-down",
        "local-verify",
        "eval",
        "eval-dry",
        "freeze"
    )]
    [string]$Task = "help"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ComposeFile = Join-Path $RepoRoot "deploy\docker-compose.yml"
$EnvFile = Join-Path $RepoRoot ".env"
$LocalConfigFile = Join-Path $RepoRoot "deploy\litellm_config.local.yaml"
$RunDir = Join-Path $RepoRoot ".run"
$MockPidFile = Join-Path $RunDir "mock-model.json"
$ProxyPidFile = Join-Path $RunDir "litellm.json"
$DecisionLog = Join-Path $RunDir "decisions.jsonl"
$MockStdoutLog = Join-Path $RunDir "mock-model.stdout.log"
$MockStderrLog = Join-Path $RunDir "mock-model.stderr.log"
$ProxyStdoutLog = Join-Path $RunDir "litellm.stdout.log"
$ProxyStderrLog = Join-Path $RunDir "litellm.stderr.log"

function Assert-Command {
    param([Parameter(Mandatory = $true)][string]$Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found on PATH. See the Windows prerequisites in README.md."
    }
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string[]]$ToolArgs
    )

    & $Name @ToolArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Name $($ToolArgs -join ' ')"
    }
}

function New-LocalEnvironment {
    if (Test-Path -LiteralPath $EnvFile) {
        Write-Host ".env already exists; leaving it unchanged."
        return
    }

    $template = Get-Content -LiteralPath (Join-Path $RepoRoot ".env.example") -Raw
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    $secret = "sk-" + [BitConverter]::ToString($bytes).Replace("-", "").ToLowerInvariant()
    $contents = $template.Replace("replace-with-a-long-random-local-secret", $secret)
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($EnvFile, $contents, $utf8NoBom)
    Write-Host "Created .env with a random local master key. Do not commit this file."
}

function Import-LocalEnvironment {
    if (-not (Test-Path -LiteralPath $EnvFile)) {
        throw ".env is missing. Run '.\scripts\dev.ps1 setup' first."
    }

    foreach ($line in Get-Content -LiteralPath $EnvFile) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#") -or -not $trimmed.Contains("=")) {
            continue
        }

        $separator = $trimmed.IndexOf("=")
        $key = $trimmed.Substring(0, $separator).Trim()
        $value = $trimmed.Substring($separator + 1).Trim()
        if ($value.Length -ge 2 -and (
            ($value.StartsWith('"') -and $value.EndsWith('"')) -or
            ($value.StartsWith("'") -and $value.EndsWith("'"))
        )) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        [Environment]::SetEnvironmentVariable($key, $value, "Process")
    }
}

function Invoke-Compose {
    param([Parameter(Mandatory = $true)][string[]]$ComposeArgs)

    Assert-Command "docker"
    Import-LocalEnvironment
    $dockerArgs = @("compose", "--env-file", $EnvFile, "-f", $ComposeFile) + $ComposeArgs
    Invoke-External "docker" $dockerArgs
}

function Save-ProcessRecord {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExecutablePath,
        [Parameter(Mandatory = $true)][string]$PidFile
    )

    [pscustomobject]@{
        Id = $Process.Id
        StartTimeUtc = $Process.StartTime.ToUniversalTime().ToString("o")
        ExecutablePath = [IO.Path]::GetFullPath($ExecutablePath)
    } | ConvertTo-Json | Set-Content -LiteralPath $PidFile -Encoding utf8
}

function Stop-TrackedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$PidFile,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (-not (Test-Path -LiteralPath $PidFile)) {
        Write-Host "$Name is not tracked as running."
        return
    }

    $record = Get-Content -LiteralPath $PidFile -Raw | ConvertFrom-Json
    $process = Get-Process -Id $record.Id -ErrorAction SilentlyContinue
    if ($process) {
        $sameStart = [Math]::Abs(
            ($process.StartTime.ToUniversalTime() - [datetime]::Parse($record.StartTimeUtc)).TotalSeconds
        ) -lt 2
        $sameExecutable = $process.Path -and (
            [IO.Path]::GetFullPath($process.Path) -eq
            [IO.Path]::GetFullPath([string]$record.ExecutablePath)
        )
        if (-not ($sameStart -and $sameExecutable)) {
            throw "Refusing to stop PID $($record.Id): it no longer matches the tracked $Name process."
        }
        Stop-Process -Id $record.Id
        try {
            Wait-Process -Id $record.Id -Timeout 10 -ErrorAction Stop
        }
        catch {
            Stop-Process -Id $record.Id -Force -ErrorAction SilentlyContinue
        }
        Write-Host "Stopped $Name (PID $($record.Id))."
    }
    Remove-Item -LiteralPath $PidFile -Force
}

function Wait-LocalEndpoint {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$PidFile,
        [Parameter(Mandatory = $true)][string]$ErrorLog,
        [int]$TimeoutSeconds = 60
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Uri -TimeoutSec 2 -UseBasicParsing
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
                Write-Host "$Name is ready at $Uri"
                return
            }
        }
        catch {
            # The service may still be starting. Check again below.
        }

        if (Test-Path -LiteralPath $PidFile) {
            $record = Get-Content -LiteralPath $PidFile -Raw | ConvertFrom-Json
            if (-not (Get-Process -Id $record.Id -ErrorAction SilentlyContinue)) {
                $details = if (Test-Path -LiteralPath $ErrorLog) {
                    (Get-Content -LiteralPath $ErrorLog -Tail 30) -join [Environment]::NewLine
                } else {
                    "No stderr log was created."
                }
                throw "$Name exited before it became ready.`n$details"
            }
        }
        Start-Sleep -Milliseconds 500
    }

    $details = if (Test-Path -LiteralPath $ErrorLog) {
        (Get-Content -LiteralPath $ErrorLog -Tail 30) -join [Environment]::NewLine
    } else {
        "No stderr log was created."
    }
    throw "$Name did not become ready within $TimeoutSeconds seconds.`n$details"
}

function Start-LocalStack {
    Import-LocalEnvironment

    foreach ($pidFile in @($MockPidFile, $ProxyPidFile)) {
        if (-not (Test-Path -LiteralPath $pidFile)) {
            continue
        }
        $record = Get-Content -LiteralPath $pidFile -Raw | ConvertFrom-Json
        if (Get-Process -Id $record.Id -ErrorAction SilentlyContinue) {
            throw "The native Windows stack is already running. Run '.\scripts\dev.ps1 local-down' before restarting it."
        }
        Remove-Item -LiteralPath $pidFile -Force
    }

    $uvicorn = Join-Path $RepoRoot ".venv\Scripts\uvicorn.exe"
    $litellm = Join-Path $RepoRoot ".venv\Scripts\litellm.exe"
    foreach ($executable in @($uvicorn, $litellm)) {
        if (-not (Test-Path -LiteralPath $executable)) {
            throw "Missing $executable. Run '.\scripts\dev.ps1 setup' first."
        }
    }

    New-Item -ItemType Directory -Path $RunDir -Force | Out-Null
    foreach ($path in @(
        $DecisionLog,
        $MockStdoutLog,
        $MockStderrLog,
        $ProxyStdoutLog,
        $ProxyStderrLog
    )) {
        if (Test-Path -LiteralPath $path) {
            Clear-Content -LiteralPath $path
        }
    }

    $env:PYTHONPATH = $RepoRoot
    # Hidden Windows processes otherwise inherit a legacy console encoding, and
    # LiteLLM's Unicode startup banner can fail with UnicodeEncodeError.
    $env:PYTHONUTF8 = "1"
    $env:PYTHONIOENCODING = "utf-8"
    $env:ROUTER_MODE = if ($env:ROUTER_MODE) { $env:ROUTER_MODE } else { "session" }
    $env:ROUTER_LEVEL = if ($env:ROUTER_LEVEL) { $env:ROUTER_LEVEL } else { "L3" }
    $env:ROUTER_LOG_PATH = $DecisionLog
    $env:CLASSIFIER_BACKEND = if ($env:CLASSIFIER_BACKEND) { $env:CLASSIFIER_BACKEND } else { "none" }
    $env:PROMPTGUARD_THRESHOLD = if ($env:PROMPTGUARD_THRESHOLD) { $env:PROMPTGUARD_THRESHOLD } else { "0.5" }
    $env:ROUTER_ENFORCE = if ($env:ROUTER_ENFORCE) { $env:ROUTER_ENFORCE } else { "true" }
    $env:ROUTER_HARDENED_MODEL = if ($env:ROUTER_HARDENED_MODEL) { $env:ROUTER_HARDENED_MODEL } else { "mock" }
    $env:POLICY_PATH = Join-Path $RepoRoot "deploy\policy.yaml"

    $mock = Start-Process `
        -FilePath $uvicorn `
        -ArgumentList @("main:app", "--host", "127.0.0.1", "--port", "8001") `
        -WorkingDirectory (Join-Path $RepoRoot "deploy\mock_model") `
        -WindowStyle Hidden `
        -RedirectStandardOutput $MockStdoutLog `
        -RedirectStandardError $MockStderrLog `
        -PassThru
    Save-ProcessRecord -Process $mock -ExecutablePath $uvicorn -PidFile $MockPidFile

    try {
        Wait-LocalEndpoint `
            -Uri "http://127.0.0.1:8001/health" `
            -Name "Mock model" `
            -PidFile $MockPidFile `
            -ErrorLog $MockStderrLog

        $proxy = Start-Process `
            -FilePath $litellm `
            -ArgumentList @("--config", "`"$LocalConfigFile`"", "--host", "127.0.0.1", "--port", "4000") `
            -WorkingDirectory $RepoRoot `
            -WindowStyle Hidden `
            -RedirectStandardOutput $ProxyStdoutLog `
            -RedirectStandardError $ProxyStderrLog `
            -PassThru
        Save-ProcessRecord -Process $proxy -ExecutablePath $litellm -PidFile $ProxyPidFile
        Wait-LocalEndpoint `
            -Uri "http://127.0.0.1:4000/health/liveliness" `
            -Name "LiteLLM proxy" `
            -PidFile $ProxyPidFile `
            -ErrorLog $ProxyStderrLog `
            -TimeoutSeconds 90
    }
    catch {
        Stop-TrackedProcess -PidFile $ProxyPidFile -Name "LiteLLM proxy"
        Stop-TrackedProcess -PidFile $MockPidFile -Name "mock model"
        throw
    }

    Write-Host "Native Windows stack is running. Logs and PID records are in $RunDir"
}

function Test-Stack {
    param([switch]$SkipModelHealth)

    Import-LocalEnvironment
    $headers = @{ Authorization = "Bearer $env:LITELLM_MASTER_KEY" }

    $mock = Invoke-RestMethod -Uri "http://localhost:8001/health" -TimeoutSec 10
    $liveness = Invoke-RestMethod -Uri "http://localhost:4000/health/liveliness" -TimeoutSec 10
    $healthyModels = "not checked"
    if (-not $SkipModelHealth) {
        $modelHealth = Invoke-RestMethod -Uri "http://localhost:4000/health" -Headers $headers -TimeoutSec 60
        $healthyModels = $modelHealth.healthy_count
    }
    $body = @{
        model = "mock"
        messages = @(@{ role = "user"; content = "hello" })
    } | ConvertTo-Json -Depth 5
    $completion = Invoke-RestMethod `
        -Uri "http://localhost:4000/chat/completions" `
        -Method Post `
        -Headers $headers `
        -ContentType "application/json" `
        -Body $body `
        -TimeoutSec 30

    $content = $completion.choices[0].message.content
    if ($mock.status -ne "ok" -or $content -ne "[mock] hello") {
        throw "Stack verification returned an unexpected response."
    }

    [pscustomobject]@{
        MockModel = $mock.status
        Proxy = $liveness
        HealthyModels = $healthyModels
        Completion = $content
    } | Format-List
}

Push-Location $RepoRoot
try {
    switch ($Task) {
        "help" {
            Write-Host "Usage: .\scripts\dev.ps1 <task>"
            Write-Host "Tasks: setup, lint, validate, test, test-e2e, test-e2e-local, up, down, dev, verify, local-up, local-down, local-verify, eval, eval-dry, freeze"
        }
        "setup" {
            Assert-Command "uv"
            Invoke-External "uv" @("sync", "--locked", "--all-groups")
            New-LocalEnvironment
        }
        "lint" {
            Assert-Command "uv"
            Invoke-External "uv" @("run", "ruff", "check", ".")
            Invoke-External "uv" @("run", "ruff", "format", "--check", ".")
        }
        "validate" {
            Assert-Command "uv"
            Invoke-External "uv" @("run", "python", "corpus/validate.py")
        }
        "test" {
            Assert-Command "uv"
            Invoke-External "uv" @("run", "pytest", "tests/", "-v", "--ignore=tests/test_e2e.py")
        }
        "test-e2e" {
            Assert-Command "uv"
            Import-LocalEnvironment
            if (-not $env:E2E_MASTER_KEY) {
                $env:E2E_MASTER_KEY = $env:LITELLM_MASTER_KEY
            }
            Invoke-External "uv" @("run", "pytest", "tests/test_e2e.py", "-v", "-m", "e2e")
        }
        "test-e2e-local" {
            Import-LocalEnvironment
            if (-not $env:E2E_MASTER_KEY) {
                $env:E2E_MASTER_KEY = $env:LITELLM_MASTER_KEY
            }
            $env:E2E_DECISION_LOG = $DecisionLog
            $python = Join-Path $RepoRoot ".venv\Scripts\python.exe"
            if (-not (Test-Path -LiteralPath $python)) {
                throw "Missing $python. Run '.\scripts\dev.ps1 setup' first."
            }
            Invoke-External $python @("-m", "pytest", "tests/test_e2e.py", "-v", "-m", "e2e")
        }
        "up" { Invoke-Compose @("up", "-d", "--build") }
        "down" { Invoke-Compose @("down") }
        "dev" { Invoke-Compose @("up", "--build") }
        "verify" { Test-Stack }
        "local-up" { Start-LocalStack }
        "local-down" {
            try {
                Stop-TrackedProcess -PidFile $ProxyPidFile -Name "LiteLLM proxy"
            }
            finally {
                Stop-TrackedProcess -PidFile $MockPidFile -Name "mock model"
            }
        }
        "local-verify" { Test-Stack -SkipModelHealth }
        "eval" {
            Assert-Command "uv"
            Import-LocalEnvironment
            Invoke-External "uv" @("run", "python", "harness/matrix.py", "--seeds", "3")
            Invoke-External "uv" @("run", "python", "eval/metrics.py", "--table", "--figures")
        }
        "eval-dry" {
            Assert-Command "uv"
            Invoke-External "uv" @("run", "python", "harness/matrix.py", "--dry-run")
        }
        "freeze" {
            Assert-Command "uv"
            Invoke-External "uv" @("run", "python", "harness/freeze.py", "--tag")
        }
    }
}
finally {
    Pop-Location
}
