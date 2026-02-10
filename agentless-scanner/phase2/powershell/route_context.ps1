$routes = Get-NetRoute |
    Where-Object { $_.NextHop -ne "0.0.0.0" } |
    Select-Object InterfaceAlias, DestinationPrefix, NextHop

$routes | ConvertTo-Json -Depth 3
