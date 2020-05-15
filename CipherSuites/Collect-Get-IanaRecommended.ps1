$IanaRecommended = Invoke-RestMethod -Uri https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv `
    | ConvertFrom-Csv -Delimiter "," `
    | Where-Object {-Not [String]::IsNullOrEmpty($($_.Recommended)) -Or -Not [String]::IsNullOrEmpty($($_.'DTLS-OK'))} `
    | Select-Object `
	    @{ Name = "CSDecimal"; Expression = { [Int32]$_.Value.Replace(",0x",$null) }},
		@{ Name = "DTLSOKIana"; Expression = { $_."DTLS-OK" }},
		@{ Name = "RecommendedIana"; Expression = { $_.Recommended }},
		@{ Name = "Reference"; Expression = { $_.Reference }}

$FileName = "$((Get-Date).ToString('yyyyMMdd'))-IanaRecommended.json"
$IanaRecommended | ConvertTo-Json | Out-File -FilePath $FileName
$IanaRecommended | ConvertTo-Json | Out-File -FilePath "Export_IanaRecommended.json" -Force
Write-Host "Object Saved - Export_IanaRecommended.json & $FileName`r`n"
