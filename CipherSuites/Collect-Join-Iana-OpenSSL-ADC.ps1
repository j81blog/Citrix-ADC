
try {
    $IanaRecommended = Get-Content -Path ".\Export_IanaRecommended.json"  -Raw -ErrorAction Stop | ConvertFrom-Json
} catch {
    "`r`nCould not locate/read `"Export_IanaRecommended.json`"`r`n"
}
try {
    $IanaOpenSSLCiphers = Get-Content -Path ".\Export_IanaOpenSSLRawData.json"  -Raw  -ErrorAction Stop | ConvertFrom-Json
} catch {
    "`r`nCould not locate/read `"Export_IanaOpenSSLRawData.json`"`r`n"
}
try {
    $ADCCiphers = Get-Content -Path ".\Export_ADC-Ciphers.json"  -Raw -ErrorAction Stop | ConvertFrom-Json
} catch {
    "`r`nCould not locate/read `"Export_ADC-Ciphers.json`"`r`n"
}

try {
    $ADCCipherSupportVPX = Get-Content -Path ".\CipherSupport-Citrix-VPX.json"  -Raw -ErrorAction Stop | ConvertFrom-Json
} catch {
    "`r`nCould not locate/read `"CipherSupport-Citrix-VPX.json`"`r`n"
	$ADCCipherSupportVPX = $null
}
try {
    $ADCCipherSupportMPX_SDX_N2 = Get-Content -Path ".\CipherSupport-Citrix-MPX-SDX-(N2).json"  -Raw -ErrorAction Stop | ConvertFrom-Json
} catch {
    "`r`nCould not locate/read `"CipherSupport-Citrix-MPX-SDX-(N2).json`"`r`n"
	$ADCCipherSupportMPX_SDX_N2 = $null
}
try {
    $ADCCipherSupportMPX_SDX_N3 = Get-Content -Path ".\CipherSupport-Citrix-MPX-SDX-(N3).json"  -Raw -ErrorAction Stop | ConvertFrom-Json
} catch {
    "`r`nCould not locate/read `"CipherSupport-Citrix-MPX-SDX-(N3).json`"`r`n"
	$ADCCipherSupportMPX_SDX_N3 = $null
}
try {
    $ADCCipherSupportMPX_SDX_Intel = Get-Content -Path ".\CipherSupport-Citrix-MPX-SDX-IntelColetoSSLchip.json"  -Raw -ErrorAction Stop | ConvertFrom-Json
} catch {
    "`r`nCould not locate/read `"CipherSupport-Citrix-MPX-SDX-IntelColetoSSLchip.json`"`r`n"
	$ADCCipherSupportMPX_SDX_Intel = $null
}


if (Get-InstalledScript -Name Join) {
    try {
        Update-Script -Name Join -Force -ErrorAction Stop
    } catch {
        "`r`nCould not check/update Script `"Join`" it's installed but maybe outdated.`r`nWhen running this script as Administrator Script will be updated!`r`n"
    }
} else {
    try {
        Install-Script -Name Join -Force -ErrorAction Stop
    } catch {
        "`r`nCould not install the Script `"Join`" required to join the objects.`r`nWhen running this script as Administrator Join Script will be installed!`r`n"
		Throw "Could not install `"Join`""
    }
}

#Load Join Modules
. "$((Get-InstalledScript -Name Join | select *).InstalledLocation)\Join.ps1"

$Joined = $IanaOpenSSLCiphers | Merge-Object -RightObject $ADCCiphers -On CSDecimal

$Joined = $Joined | LeftJoin-Object -RightObject $IanaRecommended -On CSDecimal

if($null -ne $ADCCipherSupportVPX) {
    $ADCCipherSupportVPX = $ADCCipherSupportVPX | Select-Object CSDecimal,
	@{ Name = "VPX_FE_Supported"; Expression = { $_.FrontendBuildsSupported }},
	@{ Name = "VPX_BE_Supported"; Expression = { $_.BackendBuildsSupported }}
	$Joined = $Joined | LeftJoin-Object -RightObject $ADCCipherSupportVPX -On CSDecimal
}
if($null -ne $ADCCipherSupportMPX_SDX_N2) {
    $ADCCipherSupportMPX_SDX_N2 = $ADCCipherSupportMPX_SDX_N2 | Select-Object CSDecimal,
	@{ Name = "MPX_SDX_N2_FE_Supported"; Expression = { $_.FrontendBuildsSupported }},
	@{ Name = "MPX_SDX_N2_BE_Supported"; Expression = { $_.BackendBuildsSupported }}
	$Joined = $Joined | LeftJoin-Object -RightObject $ADCCipherSupportMPX_SDX_N2 -On CSDecimal
}
if($null -ne $ADCCipherSupportMPX_SDX_N3) {
    $ADCCipherSupportMPX_SDX_N3 = $ADCCipherSupportMPX_SDX_N3 | Select-Object CSDecimal,
	@{ Name = "MPX_SDX_N3_FE_Supported"; Expression = { $_.FrontendBuildsSupported }},
	@{ Name = "MPX_SDX_N3_BE_Supported"; Expression = { $_.BackendBuildsSupported }}
	$Joined = $Joined | LeftJoin-Object -RightObject $ADCCipherSupportMPX_SDX_N3 -On CSDecimal
}
if($null -ne $ADCCipherSupportMPX_SDX_Intel) {
    $ADCCipherSupportMPX_SDX_Intel = $ADCCipherSupportMPX_SDX_Intel | Select-Object CSDecimal,
	@{ Name = "MPX_SDX_Intel_FE_Supported"; Expression = { $_.FrontendBuildsSupported }},
	@{ Name = "MPX_SDX_Intel_BE_Supported"; Expression = { $_.BackendBuildsSupported }}
	$Joined = $Joined | LeftJoin-Object -RightObject $ADCCipherSupportMPX_SDX_Intel -On CSDecimal
}

$Joined = $Joined `
    | Sort-Object -Property CSDecimal `
    | Select CSHexCode,
        CSHexCodeADC,
        CSDecimal,
        CSNameIana,
        CSNameADC,
        CSNameOpenSSL,
        DTLSOKIana,
        RecommendedIana,
        ProtocolADC,
        Bits,
        BitsADC,
        Encryption,
        EncryptionADC,
        KeyExchange,
        KeyExchangeADC,
        AuthenticationADC,
        MessageAuthenticationCodeADC,
        VPX_FE_Supported,
        VPX_BE_Supported,
        MPX_SDX_N2_FE_Supported,
        MPX_SDX_N2_BE_Supported,
        MPX_SDX_N3_FE_Supported,
        MPX_SDX_N3_BE_Supported,
        MPX_SDX_Intel_FE_Supported,
        MPX_SDX_Intel_BE_Supported,
        Reference


$FileName = "$((Get-Date).ToString('yyyyMMdd'))-CipherList-Iana-ADC-OpenSSL.json"
$Joined | ConvertTo-Json | Out-File -FilePath $FileName
$Joined | ConvertTo-Json | Out-File -FilePath "CipherList-Iana-ADC-OpenSSL.json" -Force
$Joined | ConvertTo-Csv -Delimiter ";" -NoTypeInformation | Out-File -FilePath "CipherList-Iana-ADC-OpenSSL.csv" -Force
Write-Host "Object Saved - CipherList-Iana-ADC-OpenSSL.json/csv & $FileName`r`n"
