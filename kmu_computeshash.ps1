Get-FileHash .\x64\Release\kmu.exe | Select-Object -ExpandProperty Hash | Out-File .\x64\Release\kmu.exe.sha256
exit