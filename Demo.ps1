# Graph Explorer link
https://developer.microsoft.com/en-us/graph/graph-explorer 

# Get enrolled devices
https://graph.microsoft.com/beta/deviceManagement/managedDevices

# Filter enrolled devices
https://graph.microsoft.com/beta/deviceManagement/managedDevices?$select=deviceName,id

# Get proactive remediation scripts
https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts 
https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?$select=displayname

# Creation of the azure app
# Azure portal link
https://portal.azure.com/#home

# Azure app part
$tenant = ""
$clientId = ""
$clientSecret = ""

# Microsoft.Graph.Intune: Authenticate with secret
$authority = "https://login.windows.net/$tenant"
Update-MSGraphEnvironment -AppId $clientId -Quiet
Update-MSGraphEnvironment -AuthUrl $authority -Quiet
Connect-MSGraph -ClientSecret $ClientSecret -Quiet

# Microsoft.Graph.Intune: List devices with 
Get-IntuneManagedDevice

# MSAL.PS: Authenticate  and secret
$secret = $clientSecret | ConvertTo-SecureString -AsPlainText -Force
$myToken = Get-MsalToken -ClientId $clientID -TenantId $tenant -ClientSecret $secret 

# MSAL.PS: List devices
$Devices_URL = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"
(Invoke-RestMethod -Headers @{Authorization="Bearer $($myToken.AccessToken)" } -Uri $Devices_URL -Method Get).value 

# MSAL.PS: Interactively authenticate to the basic PowerShell Intune Azure app
$App_ID = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
$myToken = Get-MsalToken -ClientId $App_ID -RedirectUri "urn:ietf:wg:oauth:2.0:oob" –Interactive

# Generate a certificate
$Cert_Name = "Intune_Certificate_SD"
$Cert_Location = "Cert:\currentuser\My"
$Cert_Export_Path = "C:\$Cert_Name.cer"
$Cert_Thb = "$Cert_Location\$MyCert_Thumbprint" 
New-SelfSignedCertificate -DnsName $Cert_Name -CertStoreLocation $Cert_Location -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"
$MyCert_Thumbprint = (Get-ChildItem -Path $Cert_Location | Where-Object {$_.Subject -match $Cert_Name}).Thumbprint
Export-Certificate –Cert $Cert_Thb -FilePath $Cert_Export_Path 

# Microsoft.Graph.Intune: Authenticate and cerificate
$tenant = "Your tenant ID"
$clientId = "Application client ID"
$Thumbprint = "Certificate Thumbprint"
$authority = "https://login.windows.net/$tenant"
Update-MSGraphEnvironment -AppId $clientId -Quiet
Update-MSGraphEnvironment -AuthUrl $authority -Quiet
Connect-MSGraph -CertificateThumbprint $Thumbprint

# MSAL.PS: Authenticate with cerificate
$Thumbprint = "Certificate Thumbprint"
$Cert = Get-Item "Cert:\LocalMachine\My\$($thumbPrint)"
$myToken = Get-MsalToken -ClientId $clientID -TenantId $tenantID -ClientCertificate $Cert


# Export content from proactive remediation script
$tenant = ""
$authority = "https://login.windows.net/$tenant"
$clientId = ""
$clientSecret = ''
$Script_name = ""

Update-MSGraphEnvironment -AppId $clientId -Quiet
Update-MSGraphEnvironment -AuthUrl $authority -Quiet
Connect-MSGraph -ClientSecret $ClientSecret -Quiet

# Get main details
$Main_Path = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts"
$Get_script_info = (Invoke-MSGraphRequest -Url $Main_Path -HttpMethod Get).value | Where{$_.DisplayName -like "*$Script_name*"}
$Get_Script_ID = $Get_script_info.id

# Get script execution info
$Main_Details_Path = "$Main_Path/$Get_Script_ID/deviceRunStates/" + '?$expand=*'
$Get_script_details = (Invoke-MSGraphRequest -Url $Main_Details_Path -HttpMethod Get).value      

$Remediation_details = @()
ForEach($Detail in $Get_script_details)
	{
		$Remediation_Values = New-Object PSObject
		$userPrincipalName = $Detail.managedDevice.userPrincipalName      
		$deviceName = $Detail.managedDevice.deviceName
		$osVersion = $Detail.managedDevice.osVersion		
		$Script_lastStateUpdateDateTime = $Detail.lastStateUpdateDateTime                                        
		$Script_lastSyncDateTime = $Detail.lastSyncDateTime                                 
		$Script_DetectionScriptOutput   = $Detail.preRemediationDetectionScriptOutput  

		$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Device name" $deviceName -passthru -force
		$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "User name" $userPrincipalName -passthru -force
		$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "OS version" $osVersion -passthru -force
		$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Last update" $Script_lastStateUpdateDateTime -passthru -force
		$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Last sync" $Script_lastSyncDateTime -passthru -force
		$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Local admin" $Script_DetectionScriptOutput -passthru -force
		$Remediation_details += $Remediation_Values
	} 
	



