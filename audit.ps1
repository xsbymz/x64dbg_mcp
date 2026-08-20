# Extract all routes from C++ handlers
$routes = @()
Get-ChildItem -Path 'plugin\src\handlers\*.cpp' -ErrorAction SilentlyContinue | ForEach-Object {
    $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
    if ($content) {
        $matches = [regex]::Matches($content, 'router\.(get|post|put|patch|delete)\s*\("([^"]+)"')
        foreach ($match in $matches) {
            $routes += $match.Groups[2].Value
        }
    }
}

# Extract all HTTP calls from TypeScript tools
$calls = @()
Get-ChildItem -Path 'server\src\tools\*.ts' -ErrorAction SilentlyContinue | ForEach-Object {
    $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
    if ($content) {
        $getMatches = [regex]::Matches($content, "httpClient\.get\('([^']+)'")
        $postMatches = [regex]::Matches($content, "httpClient\.post\('([^']+)'")
        
        foreach ($match in $getMatches) {
            $calls += $match.Groups[1].Value
        }
        foreach ($match in $postMatches) {
            $calls += $match.Groups[1].Value
        }
    }
}

$routes_unique = $routes | Sort-Object -Unique
$calls_unique = $calls | Sort-Object -Unique

Write-Host "Total unique routes: $($routes_unique.Count)"
Write-Host "Total unique tool calls: $($calls_unique.Count)"
Write-Host ""

# Find routes not called by tools
$missing_in_tools = @()
foreach ($route in $routes_unique) {
    if ($calls_unique -notcontains $route) {
        $missing_in_tools += $route
    }
}

if ($missing_in_tools.Count -gt 0) {
    Write-Host "Routes NOT called by tools ($($missing_in_tools.Count)):"
    $missing_in_tools | Sort-Object | ForEach-Object { Write-Host "  $_" }
} else {
    Write-Host "All routes are called by tools!"
}
