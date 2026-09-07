$exe = Join-Path $PSScriptRoot "x64\Release\kmu.exe"
if (-not (Test-Path $exe))
{
   exit 0
}
$sha = [System.Security.Cryptography.SHA256]::Create()
$fs = [System.IO.File]::OpenRead($exe)
try
{
   $hash = [BitConverter]::ToString($sha.ComputeHash($fs)).Replace("-", "")
}
finally
{
   $fs.Dispose()
   $sha.Dispose()
}
Set-Content -Path ($exe + ".sha256") -Value $hash
exit 0
