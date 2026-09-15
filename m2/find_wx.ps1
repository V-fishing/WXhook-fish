Get-Process Weixin -ErrorAction SilentlyContinue |
  Sort-Object WorkingSet64 -Descending |
  Select-Object -First 3 Id, @{n='MB';e={[math]::Round($_.WorkingSet64/1MB)}} |
  Format-Table -AutoSize
