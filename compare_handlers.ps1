# Count handler registrations in plugin_main.cpp
$plugin_main = Get-Content 'plugin\src\plugin_main.cpp' -Raw
$handler_declarations = [regex]::Matches($plugin_main, 'void register_(\w+)_routes')
Write-Host "Plugin handlers registered: $($handler_declarations.Count)"
$handlers = @()
foreach ($match in $handler_declarations) {
    $handlers += $match.Groups[1].Value
}
$handlers | Sort-Object | ForEach-Object { Write-Host "  $_" }

Write-Host ""

# Count tool registrations in server index.ts
$index = Get-Content 'server\src\tools\index.ts' -Raw
$tool_registrations = [regex]::Matches($index, 'register([A-Za-z]+)Tools\(server\)')
Write-Host "Server tools registered: $($tool_registrations.Count)"
$tools = @()
foreach ($match in $tool_registrations) {
    $tools += $match.Groups[1].Value
}
$tools | Sort-Object | ForEach-Object { Write-Host "  $_" }
