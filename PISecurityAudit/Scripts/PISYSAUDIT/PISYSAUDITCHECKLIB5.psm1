# ***********************************************************************
# Validation library
# ***********************************************************************
# * Modulename:   PISYSAUDIT
# * Filename:     PISYSAUDITCHECKLIB5.psm1
# * Description:  Validation rules for PI Coresight.
# *
# * Copyright 2016 OSIsoft, LLC
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# * 
# *   <http://www.apache.org/licenses/LICENSE-2.0>
# * 
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# *
# * Modifications copyright (C) 2016 Harry Paul, OSIsoft, LLC
# * Created validation rule module based off of template used for the
# * previous modules.
# *
# ************************************************************************
# Version History:
# ------------------------------------------------------------------------
#
# ************************************************************************

# ........................................................................
# Internal Functions
# ........................................................................
function GetFunctionName
{ return (Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name }

# ........................................................................
# Public Functions
# ........................................................................
function Get-PISysAudit_FunctionsFromLibrary5
{
<#  
.SYNOPSIS
Get functions from machine library.
#>
	# Form a list of all functions that need to be called to test
	# the machine compliance.
	[System.Collections.HashTable]$listOfFunctions = @{}	
	$listOfFunctions.Add("Get-PISysAudit_CheckCoresightVersion", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckCoresightAppPools", 1)
	$listOfFunctions.Add("Get-PISysAudit_CoresightSSLcheck", 1)
	$listOfFunctions.Add("Get-PISysAudit_CoresightSPNcheck", 1)
	# Return the list.
	return $listOfFunctions
}

function Get-PISysAudit_CheckCoresightVersion
{
<#  
.SYNOPSIS
AU50001 - Check for latest version of Coresight
.DESCRIPTION
VALIDATION: verifies PI Coresight version.<br/>
COMPLIANCE: upgrade to the latest version of PI Coresight.  For more information, 
see "Upgrade a PI Coresight installation" in the PI Live Library.<br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v7/GUID-5CF8A863-E056-4B34-BB6B-8D4F039D8DA6">https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v7/GUID-5CF8A863-E056-4B34-BB6B-8D4F039D8DA6</a>
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		
BEGIN {}
PROCESS
{		
	# Get and store the function Name.
	$fn = GetFunctionName
	$msg = ""
	
	try
	{		
		$RegKeyPath = "HKLM:\Software\PISystem\Coresight"
		$attribute = "CurrentVersion"
		$installVersion = Get-PISysAudit_RegistryKeyValue -lc $LocalComputer -rcn $RemoteComputerName -rkp $RegKeyPath -a $attribute -DBGLevel $DBGLevel		
		
		$installVersionTokens = $installVersion.Split(".")
		# Form an integer value with all the version tokens.
		[string]$temp = $InstallVersionTokens[0] + $installVersionTokens[1] + $installVersionTokens[2] + $installVersionTokens[3]
		$installVersionInt64 = [Convert]::ToInt64($temp)
		if($installVersionInt64 -ge 3004)
		{
			$result = $true
			$msg = "Version is compliant."
		}	
		else 
		{
			$result = $false
			$msg = "Version is not compliant."
		}
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}	
	
	# Define the results in the audit table.
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
									-at $AuditTable "AU50001" `
									-aif $fn -msg $msg `
									-ain "PI Coresight Version" -aiv $result `
									-Group1 "PI System" -Group2 "PI Coresight" `
									-Severity "Moderate"																																																

}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckCoresightAppPools
{
<#  
.SYNOPSIS
AU50002 - Check Coresight AppPools identity
.DESCRIPTION
VALIDATION: checks PI Coresight AppPool identity.<br/>
COMPLIANCE: Use a custom domain account. Network Service is acceptable, but not ideal. 
For more information, see "Create a service account for PI Coresight" in the PI Live Library. <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v7/GUID-A790D013-BAC8-405B-A017-33E55595B411">https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v7/GUID-A790D013-BAC8-405B-A017-33E55595B411</a>
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		
BEGIN {}
PROCESS
{		
	# Get and store the function Name.
	$fn = GetFunctionName
	
	try
	{	
		# Get the Identity Type of Coresight Service AppPool.
		$QuerySvcAppPool = "Get-ItemProperty iis:\apppools\coresightserviceapppool -Name processmodel.identitytype"
		$global:CSAppPoolSvc = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $QuerySvcAppPool -DBGLevel $DBGLevel

		# Get the Identity Type of Coresight Admin AppPool.
		$QueryAdmAppPool = "Get-ItemProperty iis:\apppools\coresightadminapppool -Name processmodel.identitytype"
		$CSAppPoolAdm = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $QueryAdmAppPool -DBGLevel $DBGLevel

		# Get the User running Coresight Service AppPool.
		$QuerySvcUser = "Get-ItemProperty iis:\apppools\coresightserviceapppool -Name processmodel.username.value"
		$global:CSUserSvc = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $QuerySvcUser -DBGLevel $DBGLevel

		# Get the User running Coresight Admin AppPool.
		$QueryAdmUser = "Get-ItemProperty iis:\apppools\coresightadminapppool -Name processmodel.username.value"
		$CSUserAdm = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $QueryAdmUser -DBGLevel $DBGLevel

		# Both Coresight AppPools must run under the same identity.
		If ( $global:CSAppPoolSvc -eq $CSAppPoolAdm -and $global:CSUserSvc -eq $CSUserAdm ) 
		{ 

			# If a custom account is used, we need to distinguish between a local and domain account.
			If ( $global:CSAppPoolSvc -eq "SpecificUser") 
			{
				# Local user would use ".\user" format.
				If ($global:CSUserSvc -contains ".\" ) 
				{ 
					$result = $false
					$msg =  "Local User is running Coresight AppPools. Please use a custom domain account."
				}

				# At this point, it's either a domain account or local account using "HOSTNAME\user" format.
				Else 
				{

					# Get the hostname from registry.
					$hostname = Get-PISysAudit_RegistryKeyValue "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" "ComputerName" -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel
					
					# Get position of \ within the AppPool identity string.
					$position = $global:CSUserSvc.IndexOf("\")
					
					# Remove the \username part from the AppPool identity string.
					$LsplitName = $global:CSUserSvc.Substring(0, $position)

					# Detect local user.
					If ($hostname -eq $LsplitName )
					{
						$result = $false
						$msg =  "Local User is running Coresight AppPools. Please use a custom domain account."
					}

					# A custom domain account is used.
					Else 
					{
						$result = $true
						$msg =  "A custom domain account is running both Coresight AppPools"
					}
				}

			}
			# LocalSystem is running the Coresight AppPools. That's a bad idea.
			ElseIf ($global:CSAppPoolSvc -eq "LocalSystem" ) 
			{ 
				$result = $false
				$msg =  "Local System is running both Coresight AppPools. Use a custom domain account instead."
			}
			# The only other options are: LocalService, NetworkService and AppPoolIdentity.
			# Let's keep it at Pass for now, but recommend using a custom domain account.
			Else 
			{
				$result = $true
				$msg =  $global:CSAppPoolSvc + " is running the Coresight AppPools. Use a custom domain account instead."

			}
		}

		# For technical reasons, both Coresight AppPools must run under the same identity.
		Else
		{
			$result = $false
			$msg = "Both Coresight AppPools must run under the same identity."
		}


	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}	
	
	# Define the results in the audit table	
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
									-at $AuditTable "AU50002" `
									-aif $fn -msg $msg `
									-ain "PI Coresight AppPool Check" -aiv $result `
									-Group1 "PI System" -Group2 "PI Coresight" `
									-Severity "Moderate"																																																
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CoresightSSLcheck
{
<#  
.SYNOPSIS
AU50003 - Coresight SSL check
.DESCRIPTION
VALIDATION: Checks whether SSL is enabled and enforced on the Coresight Web Site.<br/>
COMPLIANCE: A valid HTTPS binding is configured and only connections with SSL are allowed. The SSL certificate is issued by a Certificate Authority.
For more information, see "Configure Secure Sockets Layer (SSL) access" in the PI Live Library. <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v7/GUID-CB46B733-264B-48D3-9033-73D16B4DBD3B">https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v7/GUID-CB46B733-264B-48D3-9033-73D16B4DBD3B</a>
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		
BEGIN {}
PROCESS
{		
	# Get and store the function Name.
	$fn = GetFunctionName
	
	try
	{	
		# Get the name of PI Coresight Web Site.
		$RegKeyPath = "HKLM:\Software\PISystem\Coresight"
		$attribute = "WebSite"
		$CSwebSite = Get-PISysAudit_RegistryKeyValue -lc $LocalComputer -rcn $RemoteComputerName -rkp $RegKeyPath -a $attribute -DBGLevel $DBGLevel	

		# Get Coresight Web Site bindings.
		$WebBindingsQueryTemplate = "Get-WebBinding -Name `"{0}`""
		$WebBindingsQuery = [string]::Format($WebBindingsQueryTemplate, $CSwebSite)
		$WebBindings = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $WebBindingsQuery -DBGLevel $DBGLevel

		# Check if HTTPS binding is enabled.
		$httpsBindingConfigured = $false

 		# Handle PS Version 2.0 where the web bindings need to be treated as a collection and looped through.
 		if($PSVersionTable.PSVersion.Major -eq 2)
 		{
 			foreach($WebBinding in $WebBindings)
 			{
 				if($WebBinding.protocol -contains "https"){
 					$httpsBindingConfigured = $true
 				}
 			}
 		}
		# Modern PowerShell is used.
 		else 
 		{
 			$httpsBindingConfigured = $WebBindings.protocol -contains "https"
 		}

		# HTTPS binding is disabled, so there's no point in checking anything else.
		If ($httpsBindingConfigured = $false) 
		{ 
			# Test fails.
			$result = $false

			# But how epic is the fail?

			# Get full path to Coresight application.
			$CSwebSiteAndName = $CSwebSite.ToString() + "/Coresight"

			# Check if Basic Authentication is enabled.
			$basicAuthQueryTemplate = "Get-WebConfigurationProperty -Filter /system.webServer/security/authentication/BasicAuthentication -Name Enabled -location `"{0}`" | select-object Value"
			$basicAuthQuery = [string]::Format($basicAuthQueryTemplate, $CSwebSiteAndName)
			$basicAuth = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $basicAuthQuery -DBGLevel $DBGLevel

			# Basic Authentication is disabled.
			If ($basicAuth.Value -eq $False) 
			{ 
				$severity = "Moderate" 
				$msg = "HTTPS binding is not enabled."
			} 

			# Basic Authentication is enabled and yet, SSL is not enabled. Epic fail.
			Else 
			{ 
				$severity = "Severe"
				$msg = "Basic Authentication is enabled, but HTTPS binding is not enabled. User credentials sent over the wire are not encrypted!"
			}
		} 

		# HTTPS binding is enabled.
		Else 
		{ 
			# Web Site level:
			# Check SSL configuration.
			$enforceSSLQueryTemplate_WebSite = "Get-WebConfigurationProperty -Location `"{0}`" -Filter `"system.webServer/security/access`" -Name `"sslFlags`""
			$enforceSSLQuery_WebSite = [string]::Format($enforceSSLQueryTemplate_WebSite, $CSwebSite)
			$SSLCheck_WebSite = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $enforceSSLQuery_WebSite -DBGLevel $DBGLevel


			# Web App level:
			# Get full path to Coresight application.
			$CSwebSiteAndName = $CSwebSite.ToString() + "/Coresight"

			# Check SSL configuration.	
			$enforceSSLQueryTemplate_WebApp = "Get-WebConfigurationProperty -Location `"{0}`" -Filter `"system.webServer/security/access`" -Name `"sslFlags`""
			$enforceSSLQuery_WebApp = [string]::Format($enforceSSLQueryTemplate_WebApp, $CSwebSiteAndName)
			$SSLCheck_WebApp = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $enforceSSLQuery_WebApp -DBGLevel $DBGLevel

			# If either the Web Site OR Web App allows only connections with SSL, it's OK.
			If ($SSLCheck_WebSite.ToString() -eq "Ssl" -or $SSLCheck_WebApp.ToString() -eq "Ssl") 
			{ 
				# SSL is correctly configured. Let's check whether the SSL certificate is issued by a CA.

				# Get Domain info.
				$MachineDomain = Get-PISysAudit_RegistryKeyValue "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" "Domain" -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel

				# Get Hostname.
				$hostname = Get-PISysAudit_RegistryKeyValue "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" "ComputerName" -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel

				# Build FQDN using hostname and domain strings.
				$fqdn = $hostname + "." + $machineDomain

				# Get the issuer of the SSL certificate used on the Coresight Web Site.
				$matches = [regex]::Matches($WebBindings, 'https \*:([0-9]+):') 
				
				# Go through all bindings.
				foreach ($match in $matches) {

					# Find SSL certificate for each binding of the PI Coresight Web Site.
					$portCertTemplateQuery = "netsh http show sslcert ipport=0.0.0.0:`"{0}`""
					$portCertQuery = [string]::Format($portCertTemplateQuery, $($match.Groups[1].Captures[0].Value))
					$portCert = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $portCertQuery -DBGLevel $DBGLevel
					
					# Get the Thumbprint from all SSL certificates that have been found.
					$Thumbprint = $portCert[5].Split(":")[1].Trim()
					
					# Using the Thumbrpint, find the Issuer of the SSL certificate.
					$sslissuerTemplateQuery = "(Get-ChildItem -Path Cert:\LocalMachine\My\`"{0}`" | Format-List -Property issuer| Out-String)"
					$sslissuerQuery = [string]::Format($sslissuerTemplateQuery, $thumbprint)
					$sslissuer = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $sslissuerQuery -DBGLevel $DBGLevel
					
					# Trim and only get the actual SSL issuer in a single string.
					$pos = $sslissuer.IndexOf("=")
					$sslissuerTrim = $sslissuer.Substring($pos+1).Trim()
					
					 # Certificate is self-signed (barring false positive).
					 
					# The Issuer is compared with the FQDN of the machine. This can lead to false positives (e.g. a leftover certificate from before the machine was renamed etc.)
					 If ($sslissuerTrim.ToLower() -eq $fqdn.ToLower()) 
					 { 
						 $result = $false 
						 $severity = "Low"
						 $msg = "The SSL certificate is self-signed."
					 
					 } 
					 
					 # Certificate is issued by a CA (barring false positive).
					 Else 
					 
					 { 
						 $result = $true 
						 $severity = "N/A"
						 $msg = "SSL is configured properly."
					 }

					If ( $result ) # If at least one certificate is issued by a CA, pass.
					 { 
						 break 
					 }
					}
			} 	

			# HTTPS binding is enabled, but connections without SSL are allowed.
			Else 		
			{ 
				# Test fails.
				$result = $false

				# But how epic is the fail?

				# Get full path to Coresight application.
				$CSwebSiteAndName = $CSwebSite.ToString() + "/Coresight"

				# Check if Basic Authentication is enabled.
				$basicAuthQueryTemplate = "Get-WebConfigurationProperty -Filter /system.webServer/security/authentication/BasicAuthentication -Name Enabled -location `"{0}`" | select-object Value"
				$basicAuthQuery = [string]::Format($basicAuthQueryTemplate, $CSwebSiteAndName)
				$basicAuth = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $basicAuthQuery -DBGLevel $DBGLevel

				# Basic Authentication is disabled. Not too bad.
				If ($basicAuth.Value -eq $False) 
				{ 
					$severity = "Moderate" 
					$msg = "Connections without SSL are allowed."
				} 

				# Basic Authentication is enabled and yet, SSL is not enabled. Epic fail.
				Else 
				{ 
					$severity = "Severe" 
					$msg = "Basic Authentication is enabled, but connections without SSL are allowed. User credentials sent over the wire may not be encrypted!"
				}
			}
		}
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}	
	
	# Define the results in the audit table	
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
									-at $AuditTable "AU50003" `
									-aif $fn -msg $msg `
									-ain "PI Coresight SSL Check" -aiv $result `
									-Group1 "PI System" -Group2 "PI Coresight" `
									-Severity $severity																																															
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CoresightSPNcheck
{
<#  
.SYNOPSIS
AU50004 - Coresight SPN check
.DESCRIPTION
VALIDATION: Checks PI Coresight SPN assignment. <br/>
COMPLIANCE: HTTP or HOST SPNs exist and are assigned to the Coresight AppPool account. This makes Kerberos Authentication possible.
For more information, see the PI Live Library link below. <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v7/GUID-68329569-D75C-406D-AE2D-9ED512E74D46">https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v7/GUID-68329569-D75C-406D-AE2D-9ED512E74D46</a>
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		
BEGIN {}
PROCESS
{		
	# Get and store the function Name.
	$fn = GetFunctionName
	
	try
	{		

		# Get the name of PI Coresight Web Site.
		$RegKeyPath = "HKLM:\Software\PISystem\Coresight"
		$attribute = "WebSite"
		$CSwebSite = Get-PISysAudit_RegistryKeyValue -lc $LocalComputer -rcn $RemoteComputerName -rkp $RegKeyPath -a $attribute -DBGLevel $DBGLevel	

		# Get Coresight Web Site bindings.
		$WebBindingsQueryTemplate = "Get-WebBinding -Name `"{0}`""
		$WebBindingsQuery = [string]::Format($WebBindingsQueryTemplate, $CSwebSite)
		$WebBindings = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $WebBindingsQuery -DBGLevel $DBGLevel

		# Coresight is using the http service class.
		$serviceType = "http"

		# Special 'service name' for Coresight.
		# This is needed to distinguish between SPN check for IIS Apps such as Coresight, and Windows Services such as PI or AF.
		$serviceName = "coresight"

		# Converting the binding info to a string. Otherwise $matches based on RegExps are not returned correctly.
		$BindingsToString = $($WebBindings) | Out-String

		# Leverage WebBindings global variable and look for custom headers.
		$matches = [regex]::Matches($BindingsToString, ':{1}\d+:{1}(\S+)\s') 
				
		# Go through all bindings.
		foreach ($match in $matches) 
		{
			$CSheader = $match.Groups[1].Captures[0].Value 				
			If ($CSheader) # A custom host header is used!
			{ 
				$serviceName = "coresight_custom"
				break 
			}
		}

		# Coresight is running under a custom domain account.
		# Using the global variables $global:CSAppPoolSvc and $global:CSUserSvc to reduce the overhead.
		If ( $global:CSAppPoolSvc -eq "SpecificUser") 
		{ 
			$csappPool = $global:CSUserSvc 
		} 

		# Coresight is running under a machine account.
		Else 
		{ 
			$csappPool = $global:CSAppPoolSvc

			# Machine accounts don't need HTTP service class - it's already included in the HOST service class.
			$serviceType = "host"
		}
		
		$result = Invoke-PISysAudit_SPN -svctype $serviceType -svcname $serviceName -lc $LocalComputer -rcn $RemoteComputerName -appPool $csappPool -CustomHeader $CSheader -dbgl $DBGLevel

		if($null -eq $result)
		{
			$msg = "Processing failed to parse setspn utility output."
			$result = "N/A"
		}
		Else
		{
			If ($result) 
			{ 
				$msg = "The Service Principal Name exists and it is assigned to the correct Service Account."
			} 
			Else 
			{ 			
				$msg = "The Service Principal Name does NOT exist or is NOT assigned to the correct Service Account."
			}	
		}			
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}	
	
	# Define the results in the audit table	
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
									-at $AuditTable "AU50004" `
									-aif $fn -msg $msg `
									-ain "PI Coresight SPN Check" -aiv $result `
									-Group1 "PI System" -Group2 "PI Coresight" `
									-Severity "Moderate"																																																
}

END {}

#***************************
#End of exported function
#***************************
}


# ........................................................................
# Add your cmdlet after this section. Don't forget to add an intruction
# to export them at the bottom of this script.
# ........................................................................
function Get-PISysAudit_TemplateAU1xxxx
{
<#  
.SYNOPSIS
AU5xxxx - <Name>
.DESCRIPTION
VALIDATION: <Enter what the verification checks>
COMPLIANCE: <Enter what it needs to be compliant>
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		
BEGIN {}
PROCESS
{		
	# Get and store the function Name.
	$fn = GetFunctionName
	
	try
	{		
		# Enter routine.			
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}	
	
	# Define the results in the audit table	
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
									-at $AuditTable "AU1xxxx" `
									-ain "<Name>" -aiv $result `
									-aif $fn -msg $msg `
									-Group1 "<Category 1>" -Group2 "<Category 2>" `
									-Group3 "<Category 3>" -Group4 "<Category 4>" `
									-Severity "<Severity>"																																																
}

END {}

#***************************
#End of exported function
#***************************
}

# ........................................................................
# Export Module Member
# ........................................................................
# <Do not remove>
Export-ModuleMember Get-PISysAudit_FunctionsFromLibrary5
Export-ModuleMember Get-PISysAudit_CheckCoresightVersion
Export-ModuleMember Get-PISysAudit_CheckCoresightAppPools
Export-ModuleMember Get-PISysAudit_CoresightSSLcheck
Export-ModuleMember Get-PISysAudit_CoresightSPNcheck
# </Do not remove>

# ........................................................................
# Add your new Export-ModuleMember instruction after this section.
# Replace the Get-PISysAudit_TemplateAU1xxxx with the name of your
# function.
# ........................................................................
# Export-ModuleMember Get-PISysAudit_TemplateAU1xxxx