$listeners = Get-NetTCPConnection -State Listen |
    Select-Object LocalAddress, LocalPort, OwningProcess

$listeners | ConvertTo-Json -Depth 3
