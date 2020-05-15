#https://www.leeholmes.com/blog/2015/01/05/extracting-tables-from-powershells-invoke-webrequest/
function Get-HTMLTable {
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.HtmlWebResponseObject] $WebRequest,
       
        [Parameter(Mandatory = $true)]
        [int] $TableNumber
    )
    ## Extract the tables out of the web request
    $tables = @($WebRequest.ParsedHtml.getElementsByTagName("TABLE"))
    $table = $tables[$TableNumber]
    $titles = @()
    $rows = @($table.Rows)
    ## Go through all of the rows in the table
    foreach($row in $rows)
    {
        $cells = @($row.Cells)
       
        ## If we've found a table header, remember its titles
        if($cells[0].tagName -eq "TH")
        {
            $titles = @($cells | % { ("" + $_.InnerText).Trim() })
            continue
        }
        ## If we haven't found any table headers, make up names "P1", "P2", etc.
        if(-not $titles)
        {
            $titles = @(1..($cells.Count + 2) | % { "P$_" })
        }
        ## Now go through the cells in the the row. For each, try to find the
        ## title that represents that column and create a hashtable mapping those
        ## titles to content
        $resultObject = [Ordered] @{}
        for($counter = 0; $counter -lt $cells.Count; $counter++)
        {
            $title = $titles[$counter]
            if(-not $title) { continue }
           
            $resultObject[$title] = ("" + $cells[$counter].InnerText).Trim()
        }
        ## And finally cast that hashtable to a PSCustomObject
        [PSCustomObject] $resultObject
    }
}

#IANA-OpenSSL matched table
$IanaOpenSSLCiphers = Get-HTMLTable -WebRequest $(Invoke-WebRequest https://testssl.sh/openssl-iana.mapping.html) -TableNumber 0 `
    | Select-Object `
        @{ Name = "CSHexCode"; Expression = { $_."Cipher Suite".Replace("[",$null).Replace("]",$null) }},
        @{ Name = "CSDecimal"; Expression = { [int64]"$($_."Cipher Suite".Replace("[",$null).Replace("]",$null))" }},
        @{ Name = "KeyExchange"; Expression = { $_."KeyExch." }},
        @{ Name = "Encryption"; Expression = { $_.Encryption }},
        @{ Name = "Bits"; Expression = { $_.Bits }},
        @{ Name = "CSNameIana"; Expression = { $_."Cipher Suite Name (IANA)" }},
        @{ Name = "CSNameOpenSSL"; Expression = { $_."Name (OpenSSL)" }}

$FileName = "$((Get-Date).ToString('yyyyMMdd'))-IanaOpenSSLRawData.json"
$IanaOpenSSLCiphers | ConvertTo-Json | Out-File -FilePath $FileName
$IanaOpenSSLCiphers | ConvertTo-Json | Out-File -FilePath "Export_IanaOpenSSLRawData.json" -Force
Write-Host "Object Saved - Export_IanaOpenSSLRawData.json & $FileName`r`n"
