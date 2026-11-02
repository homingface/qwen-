$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$sdk = 'C:\Android\Sdk'
$log = 'C:\AndroidSetup\phase2.log'
function Log($m) { $l = ('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $m); Add-Content -LiteralPath $log -Value $l -Encoding utf8; Write-Output $l }

New-Item -ItemType Directory -Force -Path C:\AndroidSetup | Out-Null
try {
    Log 'extract cmdline-tools'
    Expand-Archive -LiteralPath 'C:\AndroidSetup\cmdline-tools.zip' -DestinationPath 'C:\AndroidSetup\ct' -Force
    $dst = Join-Path $sdk 'cmdline-tools'
    New-Item -ItemType Directory -Force -Path $dst | Out-Null
    if (-not (Test-Path (Join-Path $dst 'latest\bin\sdkmanager.bat'))) {
        Copy-Item -LiteralPath 'C:\AndroidSetup\ct\cmdline-tools' -Destination (Join-Path $dst 'latest') -Recurse -Force
    }
    Log 'cmdline-tools in place'

    $env:ANDROID_HOME = $sdk
    $env:ANDROID_SDK_ROOT = $sdk
    $sdkmgr = Join-Path $dst 'latest\bin\sdkmanager.bat'

    $yes = Join-Path C:\AndroidSetup 'yes.txt'
    1..50 | ForEach-Object { 'y' } | Set-Content -LiteralPath $yes -Encoding ascii

    Log 'accept licenses'
    cmd.exe /c "`"$sdkmgr`" --licenses < `"$yes`" > C:\AndroidSetup\lic2.out 2>&1"
    Log ("licenses exit=" + $LASTEXITCODE)

    Log 'install platform-tools platform-34 build-tools-34'
    cmd.exe /c "`"$sdkmgr`" `"platform-tools`" `"platforms;android-34`" `"build-tools;34.0.0`" < `"$yes`" > C:\AndroidSetup\sdk2.out 2>&1"
    Log ("packages exit=" + $LASTEXITCODE)

    $okBuild = Test-Path 'C:\Android\Sdk\build-tools\34.0.0\aapt2.exe'
    $okPlat = Test-Path 'C:\Android\Sdk\platforms\android-34\android.jar'
    Log ("build-tools=" + $okBuild + " platform=" + $okPlat)
    if (-not ($okBuild -and $okPlat)) { throw 'sdk packages missing' }
    Set-Content -LiteralPath 'C:\AndroidSetup\PHASE2_DONE' -Value 'ok' -Encoding ascii
    Log 'PHASE2 ALL DONE'
} catch {
    Set-Content -LiteralPath 'C:\AndroidSetup\PHASE2_FAIL' -Value ($_.Exception.Message) -Encoding utf8
    Log ('FAILED: ' + $_.Exception.Message)
    exit 1
}
