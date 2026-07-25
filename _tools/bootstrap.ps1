# Downloads resvg.exe and the TTF fonts needed to render OG images.
# Run once. Idempotent: skips files that already exist.

$ErrorActionPreference = 'Stop'

$tools = $PSScriptRoot
$fonts = Join-Path $tools 'fonts'
$temp  = Join-Path $env:TEMP ("og-boot-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $fonts, $temp | Out-Null

$hdr = @{ 'User-Agent' = 'PowerShell' }

function Fetch-Release($repo) {
    Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers $hdr
}

function Pick-Asset($release, $regex) {
    $a = $release.assets | Where-Object { $_.name -match $regex } | Select-Object -First 1
    if (-not $a) { throw "No asset matching $regex in $($release.html_url)" }
    return $a
}

$targets = @(
    @{ path = "$tools\resvg.exe"         ; source = 'resvg'   ; inZip = 'resvg.exe'          }
    @{ path = "$fonts\CascadiaCode.ttf"  ; source = 'cascadia'; inZip = 'CascadiaCode.ttf'   }
    @{ path = "$fonts\Inter-Regular.ttf" ; source = 'inter'   ; inZip = 'Inter-Regular.ttf'  }
    @{ path = "$fonts\Inter-SemiBold.ttf"; source = 'inter'   ; inZip = 'Inter-SemiBold.ttf' }
    @{ path = "$fonts\Inter-Bold.ttf"    ; source = 'inter'   ; inZip = 'Inter-Bold.ttf'     }
)

$missing = $targets | Where-Object { -not (Test-Path $_.path) }

if (-not $missing) {
    Write-Host "All dependencies already present. Nothing to do."
    Remove-Item $temp -Recurse -Force
    exit 0
}

Write-Host "Missing:"

$missing | ForEach-Object { Write-Host ("  " + $_.path) }
$needed = $missing.source | Select-Object -Unique
$archives = @{}

if ($needed -contains 'resvg') {
    Write-Host "Querying resvg release..."
    $rel = Fetch-Release 'linebender/resvg'
    $asset = Pick-Asset $rel 'x86_64.*windows.*\.zip$|win.*x86_64.*\.zip$|windows.*x86_64.*\.zip$|win64.*\.zip$'
    Write-Host "  -> $($asset.name)"
    $zip = Join-Path $temp $asset.name
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -Headers $hdr
    $out = Join-Path $temp 'resvg-extract'
    Expand-Archive $zip $out -Force
    $archives['resvg'] = $out
}

if ($needed -contains 'cascadia') {
    Write-Host "Querying Cascadia Code release..."
    $rel = Fetch-Release 'microsoft/cascadia-code'
    $asset = Pick-Asset $rel '^CascadiaCode-.*\.zip$'
    Write-Host "  -> $($asset.name)"
    $zip = Join-Path $temp $asset.name
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -Headers $hdr
    $out = Join-Path $temp 'casc-extract'
    Expand-Archive $zip $out -Force
    $archives['cascadia'] = $out
}

if ($needed -contains 'inter') {
    Write-Host "Querying Inter release..."
    $rel = Fetch-Release 'rsms/inter'
    $asset = Pick-Asset $rel '^Inter-\d.*\.zip$'
    Write-Host "  -> $($asset.name)"
    $zip = Join-Path $temp $asset.name
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -Headers $hdr
    $out = Join-Path $temp 'inter-extract'
    Expand-Archive $zip $out -Force
    $archives['inter'] = $out
}

foreach ($t in $missing) {
    $extractRoot = $archives[$t.source]
    $found = Get-ChildItem $extractRoot -Recurse -Filter $t.inZip -ErrorAction SilentlyContinue | Select-Object -First 1

    if (-not $found -and $t.source -eq 'cascadia' -and $t.inZip -eq 'CascadiaCode.ttf') {
        $found = Get-ChildItem $extractRoot -Recurse -Filter 'CascadiaCode-Regular.ttf' -ErrorAction SilentlyContinue | Select-Object -First 1
    }

    if (-not $found) {
        throw "Could not find $($t.inZip) inside $extractRoot"
    }

    Copy-Item $found.FullName $t.path -Force
    Write-Host ("  wrote " + $t.path)
}

Remove-Item $temp -Recurse -Force
Write-Host "Bootstrap complete."
