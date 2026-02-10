$neighbors = Get-NetNeighbor | Select-Object `
    InterfaceAlias,
    IPAddress,
    LinkLayerAddress,
    State

$neighbors | ConvertTo-Json -Depth 3
