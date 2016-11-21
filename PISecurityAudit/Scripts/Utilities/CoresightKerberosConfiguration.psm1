﻿
<# PI Dog - function designed to check Coresight configuration to ensure Kerberos authentication is possible.
PI Dog must be run locally. Import PISYSAUDIT module to make the function available.
#>

Function Test-PI_KerberosConfiguration {

$title = "PI DOG - Please run it locally on the PI Coresight server machine."
$message = "PI Dog always fetches information about Coresight IIS settings and SPNs. Would you like to check Kerberos Delegation configuration as well?"

$NoKerberos = New-Object System.Management.Automation.Host.ChoiceDescription "&No Kerberos delegation check", `
    "Doesn't check Kerberos Delegation Configuration."

$ClassicKerberos = New-Object System.Management.Automation.Host.ChoiceDescription "&Classic Kerberos delegation check", `
    "Checks Classic Kerberos Configuration."

$RBKerberos = New-Object System.Management.Automation.Host.ChoiceDescription "&Resource-Based Kerberos delegation check", `
    "Checks Resource-Based Kerberos Configuration."

$options = [System.Management.Automation.Host.ChoiceDescription[]]($NoKerberos,$ClassicKerberos,$RBKerberos)

$result = $host.ui.PromptForChoice($title, $message, $options, 0) 

switch ($result)
    {
		# Basic IIS Configuration checks only
        0 {"Kerberos Delegation configuration will not be checked."
        $blnDelegationCheckConfirmed = $false
        $rbkcd = $false
        $ADMtemp = $false
        }

		# Basic IIS checks + classic Kerberos delegation check (unconstrained delegation not supported!)
        1 {"Classic Kerberos Delegation configuration will be checked."
        $ADM = Get-Module -Name ActiveDirectory
        $blnDelegationCheckConfirmed = $true
        $rbkcd = $false
        If ($ADM) { $ADMtemp = $false } Else { $ADMtemp = $true }
        }

		# Basic IIS checks + resource based Kerberos constrained delegation check
        2 {"Resource-Based Kerberos Delegation configuration will be checked."
        $ADM = Get-Module -Name ActiveDirectory
        $blnDelegationCheckConfirmed = $true
        $rbkcd = $true
        If ($ADM) { $ADMtemp = $false } Else { $ADMtemp = $true }
        }
    }

# If needed, install 'Remote Active Directory Administration' PS Module.
If ($ADMtemp) {

$titleRSAT = "RSAT-AD-PowerShell required"
$messageRSAT = "'Remote Active Directory Administration' Module is required to proceed."

$yesRSAT = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes, install the module."
$noRSAT = New-Object System.Management.Automation.Host.ChoiceDescription "&No, don't install the module and abort."
$optionsRSAT = [System.Management.Automation.Host.ChoiceDescription[]]($yesRSAT,$noRSAT)
$resultRSAT = $host.ui.PromptForChoice($titleRSAT, $messageRSAT, $optionsRSAT, 0) 

    If ($resultRSAT -eq 0) {
    Write-Output "Installation of 'Remote Active Directory Administration' module is about to start.."
    Add-WindowsFeature RSAT-AD-PowerShell
    }
    Else { Write-Output "'Remote Active Directory Administration' is required to check Kerberos Delegation settings. Aborting." 
    break
    }

}

# To be sure, reset sonme of the variables
$strSPNs = $null
$global:strIssues = $null
$global:issueCount = 0
$global:strRecommendations = $null
$global:strClassicDelegation = $null
$global:RBKCDstring = $null

# Get CoreSight Web Site Name
$RegKeyPath = "HKLM:\Software\PISystem\Coresight"
$attribute = "WebSite"
$CSwebSite = Get-PISysAudit_RegistryKeyValue -lc $true -rcn $RemoteComputerName -rkp $RegKeyPath -a $attribute -DBGLevel $DBGLevel	

# Get CoreSight Installation Directory
$RegKeyPath = "HKLM:\Software\PISystem\Coresight"
$attribute = "InstallationDirectory"
$CSInstallDir = Get-PISysAudit_RegistryKeyValue -lc $true -rcn $RemoteComputerName -rkp $RegKeyPath -a $attribute -DBGLevel $DBGLevel	

# Get CoreSight Web Site name
$csWebAppQueryTemplate = "Get-WebApplication -Site `"{0}`""
$csWebAppQuery = [string]::Format($csWebAppQueryTemplate, $CSwebSite)
$csWebApp = Get-PISysAudit_IISproperties -lc $true -rcn $RemoteComputerName -qry $csWebAppQuery -DBGLevel $DBGLevel
$csWebApp = $csWebApp | ? {$_.physicalPath -eq $CSInstallDir.TrimEnd("\")}

#Generate root path that's used to grab Web Configuration properties
$csAppPSPath = $csWebApp.pspath + "/" + $CSwebSite + $csWebApp.path

# Get CoreSight Service AppPool Identity Type
$QuerySvcAppPool = "Get-ItemProperty iis:\apppools\coresightserviceapppool -Name processmodel.identitytype"
$CSAppPoolSvc = Get-PISysAudit_IISproperties -lc $true -rcn $RemoteComputerName -qry $QuerySvcAppPool -DBGLevel $DBGLevel

# Get CoreSight Admin AppPool Identity Type
$QueryAdmAppPool = "Get-ItemProperty iis:\apppools\coresightadminapppool -Name processmodel.identitytype"
$CSAppPoolAdm = Get-PISysAudit_IISproperties -lc $true -rcn $RemoteComputerName -qry $QueryAdmAppPool -DBGLevel $DBGLevel

# Get CoreSight Admin AppPool Username
$QueryAdmUser = "Get-ItemProperty iis:\apppools\coresightadminapppool -Name processmodel.username.value"
$CSUserAdm = Get-PISysAudit_IISproperties -lc $true -rcn $RemoteComputerName -qry $QueryAdmUser -DBGLevel $DBGLevel

# Get CoreSight Service AppPool Username
$QuerySvcUser = "Get-ItemProperty iis:\apppools\coresightserviceapppool -Name processmodel.username.value"
$CSUserSvc = Get-PISysAudit_IISproperties -lc $true -rcn $RemoteComputerName -qry $QuerySvcUser -DBGLevel $DBGLevel
# Output to string for gMSA check
$CSUserGMSA = $CSUserSvc | Out-String

    # Check whether a custom account is used to run the Coresight Service AppPool
	# This doesn't take into account edge cases like LocalSystem as it's handled in the main Coresight module
    if ($CSAppPoolSvc -ne "NetworkService" -and $CSAppPoolSvc -ne "ApplicationPoolIdentity")
    {   # Custom account is used
        $blnCustomAccount = $true 

        # Custom account, but is it a gMSA?
        If ($CSUserSvc.contains('$')) { $blngMSA = $True } Else 
        {   $blngMSA = $false 
            $global:strRecommendations += "`n Use a (group) Managed Service Account. For more information, please read - LINK."
        }
        }
        else # Custom account is not used (so it cannot be a gMSA)
        {
            $blnCustomAccount = $false
            $blngMSA = $false
            $global:strRecommendations += "`n Use a (group) Managed Service Account. For more information, please read - LINK."
         }


    # Get Windows Authentication Property
    $blnWindowsAuthQueryTemplate = "Get-WebConfigurationProperty -PSPath `"{0}`" -Filter '/system.webServer/security/authentication/windowsAuthentication' -name enabled | select -expand Value"
    $blnWindowsAuthQuery = [string]::Format($blnWindowsAuthQueryTemplate, $csAppPSPath)
    $blnWindowsAuth = Get-PISysAudit_IISproperties -lc $true -rcn $RemoteComputerName -qry $blnWindowsAuthQuery -DBGLevel $DBGLevel
    # Windows Authentication must be enabled - if it isn't, exit.
    if (!$blnWindowsAuth) { 
    Write-Output "Windows Authentication must be enabled!"
    break }

    # Get Windows Authentication Providers
    $authProviders = $(Get-WebConfigurationProperty -PSPath $csAppPSPath -Filter '/system.webServer/security/authentication/windowsAuthentication/providers' -Name *).Collection
    $strProviders = ""
    foreach($provider in $authProviders){$strProviders+="`r`n`t`t`t"+$provider.Value}
  
    # Get Kernel-mode authentication status
    $blnKernelModeQueryTemplate = "Get-WebConfigurationProperty -PSPath `"{0}`" -Filter '/system.webServer/security/authentication/windowsAuthentication' -name useKernelMode | select -expand Value"
    $blnKernelModeQuery = [string]::Format($blnKernelModeQueryTemplate, $csAppPSPath)
    $blnKernelMode = Get-PISysAudit_IISproperties -lc $true -rcn $RemoteComputerName -qry $blnKernelModeQuery -DBGLevel $DBGLevel

    # Get UseAppPoolCredentials property
    $blnUseAppPoolCredentialsQueryTemplate = "Get-WebConfigurationProperty -PSPath `"{0}`" -Filter '/system.webServer/security/authentication/windowsAuthentication' -name useAppPoolCredentials | select -expand Value"
    $blnUseAppPoolCredentialsQuery = [string]::Format($blnUseAppPoolCredentialsQueryTemplate, $csAppPSPath)
    $blnUseAppPoolCredentials = Get-PISysAudit_IISproperties -lc $true -rcn $RemoteComputerName -qry $blnUseAppPoolCredentialsQuery -DBGLevel $DBGLevel

	# Get Coresight Web Site bindings
	$WebBindingsQueryTemplate = "Get-WebBinding -Name `"{0}`""
	$WebBindingsQuery = [string]::Format($WebBindingsQueryTemplate, $CSwebSite)
	$CSWebBindings = Get-PISysAudit_IISproperties -lc $true -rcn $RemoteComputerName -qry $WebBindingsQuery -DBGLevel $DBGLevel

    # Get the CoreSight web server hostname, domain name, and build the FQDN
    # $CSWebServerName = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName).ComputerName
    $CSWebServerName = Get-PISysAudit_RegistryKeyValue "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" "ComputerName" -lc $true -rcn $RemoteComputerName -dbgl $DBGLevel
    $CSWebServerDomain = Get-PISysAudit_RegistryKeyValue "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" "Domain" -lc $true -rcn $RemoteComputerName -dbgl $DBGLevel
    $CSWebServerFQDN = $CSWebServerName + "." + $CSWebServerDomain 

	# By default, assume custom header is not used.
	$blnCustomHeader = $false

	# Convert WebBindings to string and look for custom headers.
	$BindingsToString = $($CSWebBindings) | Out-String
	$matches = [regex]::Matches($BindingsToString, ':{1}\d+:{1}(\S+)\s') 
		foreach ($match in $matches) { 
			$CSheader = $match.Groups[1].Captures[0].Value 
				If ($CSheader) { 
				# A custom host header is used! The first result is taken.
				$CScustomHeader = $CSheader
				$blnCustomHeader = $true
				break 
				}
		}

          
              
		# Custom Host Header is used.
		If ($blnCustomHeader) {

				# Check whether the custom host header is a CNAME Alias or Host (A) DNS entry
				$AliasTypeCheck = Resolve-DnsName $CScustomHeader | Select -ExpandProperty Type

				# Custom Host header used for the Coresight Web Site is a CNAME
				If ($AliasTypeCheck -match "CNAME") { 
				$CNAME = $true 
				# Host (A) DNS entry is preferred
				$global:strRecommendations += "`n Do NOT use CNAME aliases as Custom Host Headers. Use custom HOST (A) DNS entry instead."
				} 

				# Custom Host header used for the Coresight Web Sire is a Host (A) DNS record
				Else { 
				$CNAME = $false 
				}

				# Find out whether the custom host header is using short or fully qualified domain name.
				If ($CScustomHeader -match "\.") 
				{
				# The specified custom host header is an FQDN
				$csCHeaderLong = $CScustomHeader
				$pos = $CScustomHeader.IndexOf(".")
				$csCHeaderShort = $CScustomHeader.Substring(0, $pos)
				} 
		
				Else { 
				# The specified custom host header is a short domain name.
				$csCHeaderShort = $CScustomHeader
				$csCHeaderLong = $CScustomHeader + "." + $CSWebServerDomain
				}

			   # Custom Account is running Coresight AppPools.
			   If ($blnCustomAccount) {
       
				   # Kernel-mode Authentication is enabled, but UseAppPoolCredentials property is FALSE.
				   If ($blnKernelMode -eq $True -and $blnUseAppPoolCredentials -eq $false) {
				   $global:strIssues += "`n Kernel-mode Authentication is enabled AND Custom Account is running Coresight, BUT UseAppPoolCredentials property is FALSE! Change it to TRUE."
				   $global:issueCount += 1
				   }
                
				   # Kernel-mdoe Authentication is disabled.
				   ElseIf ($blnKernelMode -eq $false) {
				   $global:strRecommendations += "`n ENABLE Kernel-mode Authentication and set UseAppPoolCredentials property to TRUE."
				   }

				   # Kernel-mode Authentication is enabled, and UseAppPoolCredentials property is TRUE. Great!
				   Else { }

						# SPN check
						$spnCheck = $(setspn -l $CSUserSvc).ToLower()
						$spnCounter = 0

							# CNAME is used.
							If ($CNAME) {
							$hostnameSPN = $("http/" + $CSWebServerName.ToLower())
							$fqdnSPN = $("http/" + $CSWebServerFQDN.ToLower())
			
								foreach($line in $spnCheck)
								{
									switch($line.ToLower().Trim())
									{
										$hostnameSPN {$spnCounter++; break}
										$fqdnSPN {$spnCounter++; break}
										default {break}
									}
								}

									If ($spnCounter -eq 2) { 
									$strSPNs = "Service Principal Names are configured correctly: $hostnameSPN and $fqdnSPN"                            
									}
									Else {
									$strSPNs = "Unable to find all required HTTP SPNs."
									$global:strIssues += "`n Unable to find all required HTTP SPNs. Please make sure $hostnameSPN and $fqdnSPN SPNs are created. See this link for more information."
									$global:issueCount += 1
									}

							}
                    
							# Host (A)
							Else {


							$csCHeaderSPN = $("http/" + $csCHeaderShort.ToLower())
							$csCHeaderLongSPN = $("http/" + $csCHeaderLong.ToLower())
								foreach($line in $spnCheck)
								{
									switch($line.ToLower().Trim())
									{
										$csCHeaderSPN {$spnCounter++; break}
										$csCHeaderLongSPN {$spnCounter++; break}
										default {break}
									}
								}

									If ($spnCounter -eq 2) { 
									$strSPNs = "Service Principal Names are configured correctly: $csCHeaderSPN and $csCHeaderLongSPN"                            
									}
									Else {
									$strSPNs = "Unable to find all required HTTP SPNs."
									$global:strIssues += "`n Unable to find all required HTTP SPNs. Please make sure $csCHeaderSPN and $csCHeaderLongSPN SPNs are created. See this link for more information."
									$global:issueCount += 1
									}

							}


                
					}

					# Machine Account is running Coresight AppPools.
					Else {
					If ($blnKernelMode -ne $True) {
					$global:strRecommendations += "`n ENABLE Kernel-mode Authentication."
					}
            
						# SPN check
						$spnCheck = $(setspn -l $CSWebServerName).ToLower()
						$spnCounter = 0

							# CNAME is used.
							If ($CNAME) {
							$hostnameSPN = $("host/" + $CSWebServerName.ToLower())
							$fqdnSPN = $("host/" + $CSWebServerFQDN.ToLower())
			
								foreach($line in $spnCheck)
								{
									switch($line.ToLower().Trim())
									{
										$hostnameSPN {$spnCounter++; break}
										$fqdnSPN {$spnCounter++; break}
										default {break}
									}
								}

									If ($spnCounter -eq 2) { 
									$strSPNs = "Service Principal Names are configured correctly: $hostnameSPN and $fqdnSPN"                            
									}
									Else {
									$strSPNs = "Unable to find all required HTTP SPNs."
									$global:strIssues += "`n Unable to find all required HTTP SPNs. 
									Please make sure $hostnameSPN and $fqdnSPN SPNs are created. See this link for more information."
									$global:issueCount += 1
									}

							}
                    
							# Host (A)
							Else {


							$csCHeaderSPN = $("http/" + $csCHeaderShort.ToLower())
							$csCHeaderLongSPN = $("http/" + $csCHeaderLong.ToLower())
								foreach($line in $spnCheck)
								{
									switch($line.ToLower().Trim())
									{
										$csCHeaderSPN {$spnCounter++; break}
										$csCHeaderLongSPN {$spnCounter++; break}
										default {break}
									}
								}

									If ($spnCounter -eq 2) { 
									$strSPNs = "Service Principal Names are configured correctly: $csCHeaderSPN and $csCHeaderLongSPN"                            
									}
									Else {
									$strSPNs = "Unable to find all required HTTP SPNs."
									$global:strIssues += "`n Unable to find all required HTTP SPNs. 
									Please make sure $csCHeaderSPN and $csCHeaderLongSPN SPNs are created. See this link for more information."
									$global:issueCount += 1
									}

							}

					}

			   }
		# Custom Host Header is NOT used.
		Else {
			   $global:strRecommendations += "`n Use Custom Host Header (Name) in $CSWebSiteName web site bindings."


				   If ($blnCustomAccount) {
						# Kernel-mode Authentication is enabled, but UseAppPoolCredentials property is FALSE.
						If ($blnKernelMode -eq $True -and $blnUseAppPoolCredentials -eq $false) {
						$global:strIssues += "`n Kernel-mode Authentication is enabled AND Custom Account is running Coresight, BUT UseAppPoolCredentials property is FALSE! Change it to TRUE."
						$global:issueCount += 1
						}
						# Kernel-mdoe Authentication is disabled.
						ElseIf ($blnKernelMode -eq $false) {
						$global:strRecommendations += "`n ENABLE Kernel-mode Authentication and set UseAppPoolCredentials property to TRUE."
						}
						# Kernel-mode Authentication is enabled, and UseAppPoolCredentials property is TRUE. Great!
						Else {
						# All good.
						}

						#SPN check
						$spnCheck = $(setspn -l $CSUserSvc).ToLower()
						$spnCounter = 0
                    
							$hostnameSPN = $("http/" + $CSWebServerName.ToLower())
							$fqdnSPN = $("http/" + $CSWebServerFQDN.ToLower())
			
								foreach($line in $spnCheck)
								{
									switch($line.ToLower().Trim())
									{
										$hostnameSPN {$spnCounter++; break}
										$fqdnSPN {$spnCounter++; break}
										default {break}
									}
								}

									If ($spnCounter -eq 2) { 
									$strSPNs = "Service Principal Names are configured correctly: $hostnameSPN and $fqdnSPN"                            
									}
									Else {
									$strSPNs = "Unable to find all required HTTP SPNs."
									$global:strIssues += "`n Unable to find all required HTTP SPNs. 
									Please make sure $hostnameSPN and $fqdnSPN SPNs are created. See this link for more information."
									$global:issueCount += 1
									}




				   }


				   Else {
						#$global:strRecommendations += "`n Use Custom Domain Account to run Coresight AppPools. Ideally, use a (Group) Managed Service Account."
						If (!$blnKernelMode) {
						$global:strRecommendations += "`n ENABLE Kernel-mode Authentication."
						}

						$spnCheck = $(setspn -l $CSWebServerName).ToLower()
						$spnCounter = 0
                    
							$hostnameSPN = $("host/" + $CSWebServerName.ToLower())
							$fqdnSPN = $("host/" + $CSWebServerFQDN.ToLower())
			
								foreach($line in $spnCheck)
								{
									switch($line.ToLower().Trim())
									{
										$hostnameSPN {$spnCounter++; break}
										$fqdnSPN {$spnCounter++; break}
										default {break}
									}
								}

									If ($spnCounter -eq 2) { 
									$strSPNs = "Service Principal Names are configured correctly: $hostnameSPN and $fqdnSPN"                            
									}
									Else {
									$strSPNs = "Unable to find all required HTTP SPNs."
									$global:strIssues += "`n Unable to find all required HTTP SPNs. 
									Please make sure $hostnameSPN and $fqdnSPN SPNs are created. See this link for more information."
									$global:issueCount += 1
									}

				   }



			   }

		# KERBEROS DELEGATION CHECK IS CONFIRMED
		If ($blnDelegationCheckConfirmed) {
				   # RESOURCE BASED KERBEROS DELEGATION
				   If ($rbkcd) {

						If (!$blnCustomAccount) { $RBKCDAppPoolIdentity = $CSWebServerName }
						Else {
						$RBKCDAppPoolIdentityPos = $CSUserSvc.IndexOf("\")
						$RBKCDAppPoolIdentity = $CSUserSvc.Substring($RBKCDAppPoolIdentityPos+1)
						$RBKCDAppPoolIdentity = $RBKCDAppPoolIdentity.TrimEnd('$')
						}
						$AFSDK = Get-Content "$env:ProgramData\OSIsoft\AF\AFSDK.config" | Out-String
						$AFServers = [regex]::Matches($AFSDK, 'host=\"([^\"]*)') 

								foreach ($AFServerTemp in $AFServers) { 
									$AFServer = $AFServerTemp.Groups[1].Captures[0].Value
									$value = Get-PISysAudit_ServiceLogOnAccount "afservice" -lc $false -rcn $AFServer -ErrorAction SilentlyContinue
									#Write-Host "DEBUG $value"
									If ($value -ne $null ) { 
									If ($value -eq "LocalSystem" -or $value -eq "NetworkService") { $value = $AFServer }
									$RBKCDpos = $value.IndexOf("\")
									$value = $value.Substring($RBKCDpos+1)
									$value = $value.TrimEnd('$')

									$DomainObjectType = Get-ADObject -Filter { Name -like $value } -Properties ObjectCategory | Select -ExpandProperty objectclass
									If ($DomainObjectType -eq "user") { $AccType = 1 } ElseIf ($DomainObjectType -eq "computer") { $AccType = 2 } ElseIf ($DomainObjectType -eq "msDS-GroupManagedServiceAccount") {  $AccType = 3 } Else { "Unable to locate ADObject $DomainObjectType." }

									If ($AccType -eq 1) { 
									$RBKCDPrincipal = Get-ADUser $value -Properties PrincipalsAllowedToDelegateToAccount | Select -ExpandProperty PrincipalsAllowedToDelegateToAccount
										If ($RBKCDPrincipal -match $RBKCDAppPoolIdentity) { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity can delegate to AF Server $AFServer running under $value"
										} 
										Else { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity CAN'T delegate to AF Server $AFServer running under $value"
										}
									}


									If ($AccType -eq 2) { 
									$RBKCDPrincipal = Get-ADComputer $value -Properties PrincipalsAllowedToDelegateToAccount | Select -ExpandProperty PrincipalsAllowedToDelegateToAccount
										If ($RBKCDPrincipal -match $RBKCDAppPoolIdentity) { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity can delegate to AF Server $AFServer running under $value"
										} 
										Else { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity CAN'T delegate to AF Server $AFServer running under $value"
										}
									}


									If ($AccType -eq 3) { 
									$RBKCDPrincipal = Get-ADServiceAccount $value -Properties PrincipalsAllowedToDelegateToAccount | Select -ExpandProperty PrincipalsAllowedToDelegateToAccount
										If ($RBKCDPrincipal -match $RBKCDAppPoolIdentity) { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity can delegate to AF Server $AFServer running under $value"
										} 
										Else { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity CAN'T delegate to AF Server $AFServer running under $value"
										}
									}

									}
									Else { 
									$global:RBKCDstring += "`n Could not get the service account running AF Server. Please make sure AF Server $AFServer is configured for PSRemoting.
									https://github.com/osisoft/PI-Security-Audit-Tools/wiki/Tutorial2:-Running-the-scripts-remotely-(USERS) `n "
									}

								}

						$regpath = 'HKLM:\SOFTWARE\PISystem\PI-SDK\1.0\ServerHandles'
						$PIServers = Get-ChildItem $regpath | ForEach-Object {Get-ItemProperty $_.pspath} | where-object {$_.path} | Foreach-Object {$_.path}
								foreach ($PIServer in $PIServers) { 
									$value = Get-PISysAudit_ServiceLogOnAccount "pinetmgr" -lc $false -rcn $PIServer -ErrorAction SilentlyContinue
									If ($value -ne $null ) { 
									If ($value -eq "LocalSystem" -or $value -eq "NetworkService") { $value = $PIServer }
									$RBKCDpos = $value.IndexOf("\")
									$value = $value.Substring($RBKCDpos+1)
									$value = $value.TrimEnd('$')

									$DomainObjectType = Get-ADObject -Filter { Name -like $value } -Properties ObjectCategory | Select -ExpandProperty objectclass
									If ($DomainObjectType -eq "user") { $AccType = 1 } ElseIf ($DomainObjectType -eq "computer") { $AccType = 2 } 
									ElseIf ($DomainObjectType -eq "msDS-GroupManagedServiceAccount") {  $AccType = 3 } Else { "I DUNNO" }

									If ($AccType -eq 1) { 
									$RBKCDPrincipal = Get-ADUser $value -Properties PrincipalsAllowedToDelegateToAccount | Select -ExpandProperty PrincipalsAllowedToDelegateToAccount
										If ($RBKCDPrincipal -match $RBKCDAppPoolIdentity) { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity can delegate to PI Server $PIServer running under $value"
										} 
										Else { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity CAN'T delegate to PI Server $PIServer running under $value"
										}
									}


									If ($AccType -eq 2) { 
									$RBKCDPrincipal = Get-ADComputer $value -Properties PrincipalsAllowedToDelegateToAccount | Select -ExpandProperty PrincipalsAllowedToDelegateToAccount
									If ($RBKCDPrincipal -match $RBKCDAppPoolIdentity) { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity can delegate to PI Server $PIServer running under $value"
										} 
										Else { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity CAN'T delegate to PI Server $PIServer running under $value"
										}
									}


									If ($AccType -eq 3) { 
									$RBKCDPrincipal = Get-ADServiceAccount $value -Properties PrincipalsAllowedToDelegateToAccount | Select -ExpandProperty PrincipalsAllowedToDelegateToAccount
									If ($RBKCDPrincipal -match $RBKCDAppPoolIdentity) { 
									$global:RBKCDstring += "`n $RBKCDAppPoolIdentity can delegate to PI Server $PIServer running under $value" }
									}

									}
									Else { 
									$global:RBKCDstring += "`n Could not get the service account running AF Server. Please make sure PI Server $PIServer is configured for PSRemoting.
									https://github.com/osisoft/PI-Security-Audit-Tools/wiki/Tutorial2:-Running-the-scripts-remotely-(USERS) `n "
									}


								}


						}

				   # CLASSIC KERBEROS DELEGATION
				   Else {


					# Get PI Servers
					$regpath = 'HKLM:\SOFTWARE\PISystem\PI-SDK\1.0\ServerHandles'
					$PIServers = Get-ChildItem $regpath | ForEach-Object {Get-ItemProperty $_.pspath} | where-object {$_.path} | Foreach-Object {$_.path}
            
					# Get AF Servers
					$AFSDK = Get-Content "$env:ProgramData\OSIsoft\AF\AFSDK.config" | Out-String
					$AFServers = [regex]::Matches($AFSDK, 'host=\"([^\"]*)') 
            
					$global:strRecommendations += "`n ENABLE Kerberos Resource Based Constrained Delegation. 
					For more information, please check OSIsoft KB01222 - Types of Kerberos Delegation
					`n http://techsupport.osisoft.com/Troubleshooting/KB/KB01222 "

					If ($CSAppPoolSvc -eq "NetworkService") { $CSUserSvc = $CSWebServerName  }
						If ($blnCustomAccount) { 
							If ($blngMSA) { 
							$posAppPool = $CSUserSvc.IndexOf("\")
							$CSUserSvc = $CSUserSvc.Substring($posAppPool+1)
							$CSUserSvc = $CSUserSvc.TrimEnd('$')
							}
							Else { 
							$posAppPool = $CSUserSvc.IndexOf("\")
							$CSUserSvc = $CSUserSvc.Substring($posAppPool+1)
							}
						}
            
								$AppAccType = Get-ADObject -Filter { Name -like $CSUserSvc } -Properties ObjectCategory | Select -ExpandProperty objectclass
								If ($AppAccType -eq "user") { $AccType = 1 } ElseIf ($AppAccType -eq "computer") { $AccType = 2 } ElseIf ($AppAccType -eq "msDS-GroupManagedServiceAccount") {  $AccType = 3 } 
								Else { "Unable to locate ADObject $DomainObjectType." 
								break
								}
            
								If ($AccType -eq 1) {
								$AppPoolDelegation = Get-ADUser $CSUserSvc -Properties msDS-AllowedToDelegateTo | Select -ExpandProperty msDS-AllowedToDelegateTo
								$ProtocolTransition = Get-ADUser $CSUserSvc -Properties TrustedToAuthForDelegation | Select -ExpandProperty TrustedToAuthForDelegation
								$UnconstrainedKerberos = Get-ADUser $CSUserSvc -Properties TrustedForDelegation | Select -ExpandProperty TrustedForDelegation
								}


								If ($AccType -eq 2) { 
								$AppPoolDelegation = Get-ADComputer $CSUserSvc -Properties msDS-AllowedToDelegateTo | Select -ExpandProperty msDS-AllowedToDelegateTo
								$ProtocolTransition = Get-ADComputer $CSUserSvc -Properties TrustedToAuthForDelegation | Select -ExpandProperty TrustedToAuthForDelegation
								$UnconstrainedKerberos = Get-ADComputer $CSUserSvc -Properties TrustedForDelegation | Select -ExpandProperty TrustedForDelegation
								}


								If ($AccType -eq 3) { 
								$AppPoolDelegation = Get-ADServiceAccount $CSUserSvc -Properties msDS-AllowedToDelegateTo | Select -ExpandProperty msDS-AllowedToDelegateTo
								$ProtocolTransition = Get-ADServiceAccount $CSUserSvc -Properties TrustedToAuthForDelegation | Select -ExpandProperty TrustedToAuthForDelegation
								$UnconstrainedKerberos = Get-ADServiceAccount $CSUserSvc -Properties TrustedForDelegation | Select -ExpandProperty TrustedForDelegation
								}


							   If ($UnconstrainedKerberos -eq $true) { 
							   $global:strIssues += "`n Unconstrained Kerberos Delegation is enabled on $CSUserSvc. This is neither secure nor supported. 
							   `n Enable Constrained Kerberos Delegation instead. Please check OSIsoft KB01222 - Types of Kerberos Delegation
							   `n http://techsupport.osisoft.com/Troubleshooting/KB/KB01222           
							   `n Aborting."
							   $global:issueCount += 1
							   $global:strIssues
							   break
							   }


								# Get Domain info.
								$CSWebServerDomain = Get-PISysAudit_RegistryKeyValue "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" "Domain" -lc $true -dbgl $DBGLevel


								# Delegation
								If ($AppPoolDelegation -ne $null) { 
								$DelegationSPNList = $AppPoolDelegation.ToLower().Trim() 
								$dot = '.'
								$PISPNClass = "piserver/"
								$AFSPNClass = "afserver/"
									# DELEGATION TO PI
									foreach ($PIServer in $PIServers) {

        
										If ($PIServer -match [regex]::Escape($dot)) { 
										# FQDN
										$fqdnPI = $PIServer.ToLower() 
										$pos = $fqdnPI.IndexOf(".")
										$shortPI = $fqdnPI.Substring(0, $pos)
										}
         
										Else { 
										#SHORT
										$shortPI = $PIServer.ToLower() 
										$fqdnPI = ($PIServer.ToLower() + "." + $CSWebServerDomain.ToLower()).ToString()
										}

									   # Check if delegation is enabled.
									   $shortPISPN = ($PISPNClass + $shortPI).ToString()
									   $longPISPN = ($PISPNClass + $fqdnPI).ToString()
									   If ($DelegationSPNList -match $shortPISPN -and $DelegationSPNList -match $longPISPN ) { 
									   $global:strClassicDelegation += "`n Coresight can delegate to PI Server: $PIServer" 
									   }
									   Else { 
									   $global:strClassicDelegation += "`n Coresight can't delegate to PI Server: $PIServer" 
									   }


									}

										# DELEGATION TO AF
										foreach ($AFServerTemp in $AFServers) {
										$AFServer = $AFServerTemp.Groups[1].Captures[0].Value
										If ($AFServer -match [regex]::Escape($dot)) { 
										# FQDN
										$fqdnAF = $AFServer.ToLower() 
										$pos = $fqdnAF.IndexOf(".")
										$shortAF = $fqdnAF.Substring(0, $pos)
										}
         
										Else { 
										#SHORT
										$shortAF = $AFServer.ToLower() 
										$fqdnAF = ($AFServer.ToLower() + "." + $CSWebServerDomain.ToLower()).ToString()
										}

									   # Check if delegation is enabled.
									   $shortAFSPN = ($AFSPNClass + $shortAF).ToString()
									   $longAFSPN = ($AFSPNClass + $fqdnAF).ToString()
									   If ($DelegationSPNList -match $shortAFSPN -and $DelegationSPNList -match $longAFSPN ) { 
									   $global:strClassicDelegation += "`n Coresight can delegate to AF Server: $AFServer" 
									   }
									   Else { 
									   $global:strClassicDelegation += "`n Coresight can't delegate to AF Server: $AFServer" 
									   }


									}


												} 
								Else { Write-Output "Kerberos Deleagation is not configured.
													`n Enable Constrained Kerberos Delegation instead. Please check OSIsoft KB01222 - Types of Kerberos Delegation
													`n http://techsupport.osisoft.com/Troubleshooting/KB/KB01222   " }
								}


				## BACK-END SERVICES SERVICE PRINCIPAL NAME CHECK
				foreach ($AFServerBEC in $AFServers) {
				$AFServer = $AFServerBEC.Groups[1].Captures[0].Value
				$serviceType = "afserver"
				$serviceName = "afservice"
				$LocalComputer = $false
				$result = Invoke-PISysAudit_SPN -svctype $serviceType -svcname $serviceName -lc $LocalComputer -rcn $AFServer -dbgl $DBGLevel
				If ($result) { $strBackEndSPNS += "`n Service Principal Names for AF Server $AFServer are set up correctly." }
				Else { $strBackEndSPNS += "`n Service Principal Names for AF Server $AFServer are NOT set up correctly." }
				}

				foreach ($PIServerBEC in $PIServers) {
				$serviceType = "piserver"
				$serviceName = "pinetmgr"
				$LocalComputer = $false
				$result = Invoke-PISysAudit_SPN -svctype $serviceType -svcname $serviceName -lc $LocalComputer -rcn $PIServerBEC -dbgl $DBGLevel
				If ($result) { $strBackEndSPNS += "`n Service Principal Names for PI Server $PIServerBEC are set up correctly." }
				Else { $strBackEndSPNS += "`n Service Principal Names for PI Server $PIServerBEC are NOT set up correctly." }
				}
			}


Write-Output "`nIIS AUTHENTICATION SETTINGS SUMMARY:"
Write-Output "Windows Authentication Providers: $strProviders"
Write-Output "Kernel-mode Auth?: $blnKernelMode"
Write-Output "UseAppPool Credentials?: $blnUseAppPoolCredentials"
Write-Output "`n"
Write-Output "CORESIGHT SERVICE ACCOUNT SUMMARY:"

If (!$blngMSA) {                
If ($blnCustomAccount) { Write-Output "CS AppPool identity type is: $AppAccType and its name is: $CSUserSvc" }
Else { Write-Output "CS AppPool identity is: $CSAppPoolSvc" }
}

If ($blngMSA) { Write-Output "CS AppPool identity type is group Managed Service Account and its name is: $CSUserSvc" }

Write-Output "`n"
Write-Output "CORESIGHT WEB SITE BINDINGS SUMMARY"
Write-Output "Is Custom Header used?: $blnCustomHeader"

If ($blnCustomHeader) {
Write-Output "Custom Header Name: $CScustomHeader"
If ($CNAME) {
Write-Output "Custom Header Type: CNAME" }
Else {
Write-Output "Custom Header Type: HOST (A)" }
}

Write-Output "`n"

Write-Output "KERBEROS AUTHENTICATION and DELEGATION SUMMARY"
Write-Output "SPNs: $strSPNs"
If ($blnDelegationCheckConfirmed) {
If (!$rbkcd) {
Write-Output "The Coresight Service account can delegate to: $AppPoolDelegation"
Write-Output "`n"
Write-Output "Comparing that to the list of PI and AF Servers currently allowed on this machine (assuming the default service accounts are used): $global:strClassicDelegation"
Write-Output "Kerberos Delegation Protocol Transition: $ProtocolTransition" }

If ($rbkcd) { Write-Output "Coresight Application Pool: $global:RBKCDstring" }

Write-Output "PI SERVER AND AF SERVER SERVICE PRINCIPALS CHECK: $strBackEndSPNS"
}
Write-Output "`n"
Write-Output "RECOMMENDATIONS: " $global:strRecommendations
Write-Output "`n"
Write-Output "ISSUES: " 
Write-Output "Number of issues found: " $global:issueCount
Write-Output "`n"
Write-Output $global:strIssues             
}


Export-ModuleMember -Function Test-PI_KerberosConfiguration
Set-Alias -Name Unleash-PI_Dog -Value Test-PI_KerberosConfiguration -Description “Sniff out Kerberos issues.”
Export-ModuleMember -Alias Unleash-PI_Dog