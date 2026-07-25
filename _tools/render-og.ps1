# Rasterizes every SVG under _tools/og/ into a PNG in assets/og/.
# Requires:
#   _tools/resvg.exe   - github.com/linebender/resvg/releases (resvg-win64.zip)
#   _tools/fonts/*.ttf - Inter-Regular, Inter-Bold, CascadiaCode-Regular

$ErrorActionPreference = 'Stop'

$tools  = $PSScriptRoot
$root   = Split-Path -Parent $tools
$resvg  = Join-Path $tools 'resvg.exe'
$fonts  = Join-Path $tools 'fonts'
$srcDir = Join-Path $tools 'og'
$outDir = Join-Path $root 'assets\og'

if (-not (Test-Path $resvg)) {
    throw "resvg.exe not found at $resvg. Download from https://github.com/linebender/resvg/releases and place it there."
}

if (-not (Test-Path $fonts)) {
    throw "Fonts directory not found at $fonts. Drop the TTFs there first."
}

if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}

$sources = Get-ChildItem $srcDir -Filter '*.svg' -ErrorAction SilentlyContinue

if (-not $sources) {
    Write-Warning "No SVGs found in $srcDir"
    exit 0
}

foreach ($svg in $sources) {
    $png = Join-Path $outDir ($svg.BaseName + '.png')
    & $resvg --use-fonts-dir $fonts $svg.FullName $png

    if ($LASTEXITCODE -eq 0) {
        Write-Host ("OK   " + $svg.BaseName + ".png")
    }
    else {
        Write-Warning ("FAIL " + $svg.Name + " (exit " + $LASTEXITCODE + ")")
    }
}
