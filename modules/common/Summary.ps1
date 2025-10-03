# Summary counters helper
function Add-Summary {
    param([string]$Key)
    if (-not $script:Summary) { $script:Summary = @{} }
    $current = $script:Summary[$Key]
    if ($null -ne $current) { $script:Summary[$Key] = [int]$current + 1 }
    else { $script:Summary[$Key] = 1 }
}


