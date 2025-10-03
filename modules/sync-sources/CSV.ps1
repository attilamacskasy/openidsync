# CSV source provider

function Get-UsersFromCsv {
    param([Parameter(Mandatory=$true)][string]$CsvPath)
    if (-not (Test-Path -LiteralPath $CsvPath)) { throw "CSV file not found: $CsvPath" }
    return Import-Csv -LiteralPath $CsvPath
}


