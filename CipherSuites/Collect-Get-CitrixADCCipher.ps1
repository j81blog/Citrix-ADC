[cmdletbinding()]
param(
    [ValidateNotNullOrEmpty()]
	[System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
	$Credential = [System.Management.Automation.PSCredential]::Empty,
	
	[ValidateNotNullOrEmpty()]
	[String]
	$ManagementURL
)


function Invoke-ADCRestApi {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSObject]$Session,

        [Parameter(Mandatory = $true)]
        [ValidateSet('DELETE', 'GET', 'POST', 'PUT')]
        [String]$Method,

        [Parameter(Mandatory = $true)]
        [String]$Type,

        [String]$Resource,

        [String]$Action,

        [hashtable]$Arguments = @{ },

        [Switch]$Stat = $false,

        [ValidateScript( { $Method -eq 'GET' })]
        [hashtable]$Filters = @{ },

        [ValidateScript( { $Method -ne 'GET' })]
        [hashtable]$Payload = @{ },

        [Switch]$GetWarning = $false,

        [ValidateSet('EXIT', 'CONTINUE', 'ROLLBACK')]
        [String]$OnErrorAction = 'EXIT'
    )
    # https://github.com/devblackops/NetScaler
    if ([String]::IsNullOrEmpty($($Session.ManagementURL))) {
        Write-Verbose "Probably not logged into the Citrix ADC!"
        throw "ERROR. Probably not logged into the ADC"
    }
    if ($Stat) {
        $uri = "$($Session.ManagementURL)/nitro/v1/stat/$Type"
    } else {
        $uri = "$($Session.ManagementURL)/nitro/v1/config/$Type"
    }
    if (-not ([String]::IsNullOrEmpty($Resource))) {
        $uri += "/$Resource"
    }
    if ($Method -ne 'GET') {
        if (-not ([String]::IsNullOrEmpty($Action))) {
            $uri += "?action=$Action"
        }

        if ($Arguments.Count -gt 0) {
            $queryPresent = $true
            if ($uri -like '*?action*') {
                $uri += '&args='
            } else {
                $uri += '?args='
            }
            $argsList = @()
            foreach ($arg in $Arguments.GetEnumerator()) {
                $argsList += "$($arg.Name):$([System.Uri]::EscapeDataString($arg.Value))"
            }
            $uri += $argsList -join ','
        }
    } else {
        $queryPresent = $false
        if ($Arguments.Count -gt 0) {
            $queryPresent = $true
            $uri += '?args='
            $argsList = @()
            foreach ($arg in $Arguments.GetEnumerator()) {
                $argsList += "$($arg.Name):$([System.Uri]::EscapeDataString($arg.Value))"
            }
            $uri += $argsList -join ','
        }
        if ($Filters.Count -gt 0) {
            $uri += if ($queryPresent) { '&filter=' } else { '?filter=' }
            $filterList = @()
            foreach ($filter in $Filters.GetEnumerator()) {
                $filterList += "$($filter.Name):$([System.Uri]::EscapeDataString($filter.Value))"
            }
            $uri += $filterList -join ','
        }
    }
    Write-Verbose "URI: $uri"

    $jsonPayload = $null
    if ($Method -ne 'GET') {
        $warning = if ($GetWarning) { 'YES' } else { 'NO' }
        $hashtablePayload = @{ }
        $hashtablePayload.'params' = @{'warning' = $warning; 'onerror' = $OnErrorAction; <#"action"=$Action#> }
        $hashtablePayload.$Type = $Payload
        $jsonPayload = ConvertTo-Json -InputObject $hashtablePayload -Depth 100 -Compress
        Write-Verbose "JSON Payload: $($jsonPayload | ConvertTo-Json -Compress)"
    }

    $response = $null
    $restError = $null
    try {
        $restError = @()
        $restParams = @{
            Uri           = $uri
            ContentType   = 'application/json'
            Method        = $Method
            WebSession    = $Session.WebSession
            ErrorVariable = 'restError'
            Verbose       = $false
        }

        if ($Method -ne 'GET') {
            $restParams.Add('Body', $jsonPayload)
        }

        $response = Invoke-RestMethod @restParams

        if ($response) {
            if ($response.severity -eq 'ERROR') {
                Write-Verbose "Got an ERROR response: $($response| ConvertTo-Json -Compress)"
                throw "Error. See log"
            } else {
                Write-Verbose "Response: $($response | ConvertTo-Json -Compress)"
                if ($Method -eq "GET") { 
                    return $response 
                }
            }
        }
    } catch [Exception] {
        if ($Type -eq 'reboot' -and $restError[0].Message -eq 'The underlying connection was closed: The connection was closed unexpectedly.') {
            Write-Verbose "Connection closed due to reboot."
        } else {
            Write-Verbose "Caught an error. Exception Message: $($_.Exception.Message)"
            throw $_
        }
    }
}

function Connect-ADC {
    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        [String]$ManagementURL,

        [parameter(Mandatory)]
        [PSCredential]$Credential,

        [int]$Timeout = 3600,

        [Switch]$PassThru
    )
    # https://github.com/devblackops/NetScaler


    if ($ManagementURL -like "https://*") {
        Write-Verbose "SSL Connection, Trusting all certificates."
        $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
        $Provider.CreateCompiler() | Out-Null
        $Params = New-Object System.CodeDom.Compiler.CompilerParameters
        $Params.GenerateExecutable = $false
        $Params.GenerateInMemory = $true
        $Params.IncludeDebugInformation = $false
        $Params.ReferencedAssemblies.Add("System.DLL") > $null
        $TASource = @'
            namespace Local.ToolkitExtensions.Net.CertificatePolicy
            {
                public class TrustAll : System.Net.ICertificatePolicy
                {
                    public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                    {
                        return true;
                    }
                }
            }
'@ 
        $TAResults = $Provider.CompileAssemblyFromSource($Params, $TASource)
        $TAAssembly = $TAResults.CompiledAssembly
        $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
        [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
    }
    Write-Verbose "Connecting to $ManagementURL..."
    try {
        $login = @{
            login = @{
                Username = $Credential.Username;
                password = $Credential.GetNetworkCredential().Password
                timeout  = $Timeout
            }
        }
        $loginJson = ConvertTo-Json -InputObject $login -Compress
        $saveSession = @{ }
        $params = @{
            Uri             = "$ManagementURL/nitro/v1/config/login"
            Method          = 'POST'
            Body            = $loginJson
            SessionVariable = 'saveSession'
            ContentType     = 'application/json'
            ErrorVariable   = 'restError'
            Verbose         = $false
        }
        $response = Invoke-RestMethod @params

        if ($response.severity -eq 'ERROR') {
            Write-Verbose "Caught an error. Response: $($response | Select-Object message,severity,errorcode | ConvertTo-Json -Compress)"
            Write-Error "Error. See log"
            TerminateScript 1 "Error. See log"
        } else {
            Write-Verbose "Response: $($response | Select-Object message,severity,errorcode | ConvertTo-Json -Compress)"
        }
    } catch [Exception] {
        throw $_
    }
    $session = [PSObject]@{
        ManagementURL = [String]$ManagementURL;
        WebSession    = [Microsoft.PowerShell.Commands.WebRequestSession]$saveSession;
        Username      = $Credential.Username;
        Version       = "UNKNOWN";
    }
    try {
        Write-Verbose "Trying to retrieve the ADC version"
        $params = @{
            Uri           = "$ManagementURL/nitro/v1/config/nsversion"
            Method        = 'GET'
            WebSession    = $Session.WebSession
            ContentType   = 'application/json'
            ErrorVariable = 'restError'
            Verbose       = $false
        }
        $response = Invoke-RestMethod @params
        Write-Verbose "Response: $($response | ConvertTo-Json -Compress)"
        $version = $response.nsversion.version.Split(",")[0]
        if (-not ([String]::IsNullOrWhiteSpace($version))) {
            $session.version = $version
        }
        Write-Verbose "Connected"
        Write-Verbose "Connected to Citrix ADC $ManagementURL, as user $($Credential.Username), ADC Version $($session.Version)"
    } catch {
        Write-Verbose "Caught an error. Exception Message: $($_.Exception.Message)"
        Write-Verbose "Response: $($response | ConvertTo-Json -Compress)"
    }
    if ($PassThru) {
        return $session
    }
}

$ADCSession = Connect-ADC -ManagementURL $ManagementURL -Credential $Credential -PassThru
$ADCCiphers = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslciphersuite `
    | Select-Object -ExpandProperty sslciphersuite `
	| ForEach-Object {"cipher=$($_.ciphername),proto=$(($_.description -replace ('\s{2,5}', ',')).Replace(', ',',').Replace(' ',',').Replace('Export,',"misc=Export,"))"} `
	| ForEach {
        $Object = $_.Split(",") | ConvertFrom-StringData
	    if ($null -ne $Object.Misc) {
	        $Bits = "$(try { $Object.Enc.Split("(")[1].Replace(")",$null) } catch {$null}), $($Object.Misc)"
	    } else {
	        $Bits = "$(try { $Object.Enc.Split("(")[1].Replace(")",$null) } catch {$null})"
	    }
	    [PSCustomObject]@{
	        CSNameADC = $Object.cipher
	        CSHexCodeADC = $Object.HexCode
	    	CSDecimal = [int64]"$($Object.HexCode)"
	        ProtocolADC = $Object.proto
	        BitsADC = $Bits
	        KeyExchangeADC = $Object.Kx
	        AuthenticationADC = $Object.Au
	        EncryptionADC = $Object.Enc.Split("(")[0]
	        MessageAuthenticationCodeADC = $Object.Mac
	    }
        $Bits = $null
    }

$FileName = "$((Get-Date).ToString('yyyyMMdd'))-ADC-Ciphers.json"
$ADCCiphers | ConvertTo-Json | Out-File -FilePath $FileName
$ADCCiphers | ConvertTo-Json | Out-File -FilePath "Export_ADC-Ciphers.json" -Force
Write-Host "Object Saved - Export_ADC-Ciphers.json & $FileName`r`n"
