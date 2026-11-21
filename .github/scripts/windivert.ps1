# Download WinDivert and verify its SHA-256 (version/hash from the workflow env).
$ErrorActionPreference = "Stop"
$zip = "WinDivert.zip"
$url = "https://github.com/basil00/WinDivert/releases/download/v$env:WINDIVERT_VERSION/WinDivert-$env:WINDIVERT_VERSION-A.zip"
Invoke-WebRequest -Uri $url -OutFile $zip
$hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
if ($hash -ne $env:WINDIVERT_SHA256) { throw "WinDivert checksum mismatch: $hash" }
Expand-Archive $zip -DestinationPath windivert -Force
