# Citrix-ADC - CipherSuites

## Gathering
".\Get-CitrixADCCipher.ps1 -Credential $(get-credential) -ManagementURL https://adc.domain.local"
- Script to collect the ciphers from the ADC
- Output: "Export_ADC-Ciphers.json"

".\Collect-Get-IanaOpenSSLRawData.ps1"
- Script to gather the list of Iana-OpenSSL CipherSuite names
- Output: "Export_IanaOpenSSLRawData.json"

".\Collect-Get-IanaRecommended.ps1"
- Script to gather the list of Iana recommended CipherSuites
- Output: "Export_IanaRecommended.json"

CipherSupport-Citrix-VPX.json
- Data from: https://docs.citrix.com/en-us/citrix-adc/media/cipher-support-on-a-citrix-vpx-appliance.pdf

CipherSupport-Citrix-MPX-SDX-(N2).json
- Data from: https://docs.citrix.com/en-us/citrix-adc/media/cipher-support-on-a-citrix-mpx-sdx-n2-appliance.pdf

CipherSupport-Citrix-MPX-SDX-(N3).json
- Data from: https://docs.citrix.com/en-us/citrix-adc/media/cipher-support-on-a-citrix-mpx-sdx-n3-appliance.pdf

CipherSupport-Citrix-MPX-SDX-IntelColetoSSLchip.json
- Data from: https://docs.citrix.com/en-us/citrix-adc/media/cipher-support-on-a-citrix-mpx-sdx-intel-coleto-ssl-chip-based-appliance.pdf

## Joining

".\Collect-Join-Iana-OpenSSL-ADC.ps1"
- Join all the json objects and create one file
- Output: "CipherList-Iana-ADC-OpenSSL.json"
