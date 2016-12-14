# ***********************************************************************
# Validation library
# ***********************************************************************
# * Modulename:   PISYSAUDIT
# * Filename:     PISYSAUDITCHECKLIB1.psm1
# * Description:  Validation rules for machines.
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
# * Modifications copyright (C) <YYYY> <Name>, <Org>
# * <Description of modification>
# *
# ************************************************************************
# Version History:
# ------------------------------------------------------------------------
# Version 1.0.0.8 Initial release on OSIsoft Users Community.
# Authors:  Jim Davidson, Bryan Owen and Mathieu Hamel from OSIsoft.
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
function Get-PISysAudit_FunctionsFromLibrary1
{
<#  
.SYNOPSIS
Get functions from machine library.
#>
	# Form a list of all functions that need to be called to test
	# the machine compliance.
	[System.Collections.HashTable]$listOfFunctions = @{}	
	$listOfFunctions.Add("Get-PISysAudit_CheckDomainMemberShip", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckOSInstallationType", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckFirewallEnabled", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckAppLockerEnabled", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckUACEnabled", 1)
			
	# Return the list.
	return $listOfFunctions
}

function Get-PISysAudit_CheckDomainMemberShip
{
<#  
.SYNOPSIS
AU10001 - Domain Membership Check
.DESCRIPTION
VALIDATION: verifies that the machine is a member of an Active Directory Domain.<br/>  
COMPLIANCE: join the machine to an Active Directory Domain.  Use of a domain is 
encouraged as AD provides Kerberos authentication and is our best available technology 
for securing a PI System.  Furthermore, the implementation of transport security in the 
PI System relies on Windows Integrated Security and AD to automatically enable higher 
strength ciphers.
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
		# Read the registry key.
		$value = Get-PISysAudit_RegistryKeyValue "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" "Domain" `
									-lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel
		
		# Compliance is to have computer belonging to a domain.
		# If the value is null or empty, it means it is not defined and the result of
		# the test is False (fail), otherwise it is true (pass).		
		if(($null -eq $value) -or ($value -eq "")) 
		{ 
			$result =  $false 
			$msg = "Machine is not a member of an AD Domain."
		} 
		else 
		{ 
			$result = $true 
			$msg = "Machine is a member of an AD Domain."
		}
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check."					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
	
	# Define the results in the audit table	
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU10001" `
										-ain "Domain Membership Check" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "Machine" -Group2 "Domain" `
										-Severity "Severe"																				 
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckOSInstallationType
{
<#  
.SYNOPSIS
AU10002 - Operating System Installation Type
.DESCRIPTION   
VALIDATION: verifies that the OS installation type is server core for the 
reduced surface area.<br/>
COMPLIANCE: Installation Type should be Server Core. Different SKUs are
available at the link below:<br/>
<a href="http://msdn.microsoft.com/en-us/library/ms724358.aspx">http://msdn.microsoft.com/en-us/library/ms724358.aspx</a><br/>  
For more on the advantages of Windows Server Core, please see:<br/>
<a href="https://msdn.microsoft.com/en-us/library/hh846314(v=vs.85).aspx">https://msdn.microsoft.com/en-us/library/hh846314(v=vs.85).aspx </a>
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
		$InstallationType = Get-PISysAudit_RegistryKeyValue "HKLM:\Software\Microsoft\Windows NT\CurrentVersion" "InstallationType" -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel

		# Check if the value is from one in the list			
		if($InstallationType -eq "Server Core") { $result =  $true } else { $result = $false }

		# Set a message to return with the audit object.
		$msgTemplate = "The following installation type is used: {0}"
		$msg = [string]::Format($msgTemplate, $InstallationType)

	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check."					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
	
	# Define the results in the audit table													
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU10002" `
										-ain "Operating System Installation Type" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "Machine" -Group2 "Operating System" `
										-Severity "Severe"													
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckFirewallEnabled
{
<#  
.SYNOPSIS
AU10003 - Firewall Enabled
.DESCRIPTION
VALIDATION: verifies that the Windows host based firewall is enabled.<br/> 
COMPLIANCE: enable the Windows firewall for Domain, Private and Public Scope.  
A firewall's effectiveness is heavily dependent on the configuration.  
For PI specific port requirements, please see:<br/> 
<a href="https://techsupport.osisoft.com/Troubleshooting/KB/KB01162"> https://techsupport.osisoft.com/Troubleshooting/KB/KB01162 </a> <br/>
For more general information on the Windows firewall, see "Windows Firewall with 
Advanced Security Overview" on TechNet: <br/>
<a href="https://technet.microsoft.com/en-us/library/hh831365(v=ws.11).aspx">https://technet.microsoft.com/en-us/library/hh831365(v=ws.11).aspx </a>
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
		# Read the registry key.
		$outputFileContent = Get-PISysAudit_FirewallState -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel
		
		# Read each line to find the state of each profile.	
		$result = $false		
		$validationCounter = 0
		
		foreach($line in $OutputFileContent)
		{														
			if($line.ToLower().Contains("state"))
			{								
				if($line.ToLower().Contains("on")) { $validationCounter++ }				
			}					
		}
		
		# Check if the counter is 3 = compliant, 2 or less it is not compliant
		if($validationCounter -eq 3) 
		{ 
			$result = $true 
			$msg = "Firewall enabled."
		} 
		else 
		{ 
			$result = $false 
			$msg = "Firewall not enabled."
		}							
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check."					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
	
	# Define the results in the audit table	
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU10003" `
										-ain "Firewall Enabled" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "Machine" -Group2 "Policy" `
										-Severity "Moderate"																				 
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckAppLockerEnabled
{
<#  
.SYNOPSIS
AU10004 - AppLocker Enabled
.DESCRIPTION
VALIDATION: verifies that AppLocker is enabled. <br/>  
COMPLIANCE: set AppLocker to Enforce mode after establishing a policy.  For a 
primer on running AppLocker on a PI Data Archive, see: <br/>
<a href="https://techsupport.osisoft.com/Troubleshooting/KB/KB00994">https://techsupport.osisoft.com/Troubleshooting/KB/KB00994</a>
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
		$result = $false
		# Read the AppLocker policy.
		[xml] $appLockerPolicy = Get-PISysAudit_AppLockerState -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel
		if($null -ne $appLockerPolicy)
		{
			if($(Select-Xml -xml $appLockerPolicy -XPath "//RuleCollection[@Type='Exe']").Node.EnforcementMode -eq "Enabled" -and `
				$(Select-Xml -xml $appLockerPolicy -XPath "//RuleCollection[@Type='Msi']").Node.EnforcementMode -eq "Enabled")
			{
				$result = $true
				$msg = "AppLocker is configured to enforce."
			}
			else
			{
				$msg = "AppLocker is not configured to enforce."
			}
		}
		else
		{
			$msg = "No AppLocker policy returned."
		}
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check."					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
	
	# Define the results in the audit table	
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU10004" `
										-ain "AppLocker Enabled" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "Machine" -Group2 "Policy" `
										-Severity "Moderate"																				 
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckUACEnabled
{
<#  
.SYNOPSIS
AU10005 - UAC Enabled
.DESCRIPTION
VALIDATION: verifies that UAC is enabled.  More precisely, it verifies the 
following default features: EnableLUA, ConsentPromptBehaviorAdmin, 
EnableInstallerDetection, PromptOnSecureDesktop and EnableSecureUIAPaths.
Additionally, a check is performed for the feature ValidateAdminCodeSignatures.  
Lower severity is assigned if this is the only feature disabled.<br/>
COMPLIANCE: enable the flagged UAC features through Local Security Policy.  
For more information on specific UAC features, see: <br/>
<a href="https://technet.microsoft.com/en-us/library/dd835564(v=ws.10).aspx">https://technet.microsoft.com/en-us/library/dd835564(v=ws.10).aspx </a>
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
	$severity = "Unknown"

	try
	{				
		$result = $true
		$uacKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system"
		$defaultEnabledUACFeatures = "EnableLUA", "ConsentPromptBehaviorAdmin", "EnableInstallerDetection", "PromptOnSecureDesktop", "EnableSecureUIAPaths"
		
		# Loop through key default enabled UAC features
		$tmpmsg = "Some default UAC features are disabled: "
		foreach ($uacFeature in $defaultEnabledUACFeatures) 
		{
			if ($(Get-PISysAudit_RegistryKeyValue -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel -RegKeyPath $uacKeyPath -Attribute $uacFeature) -eq 0)
			{
				$result = $false
				$severity = "Moderate"
				$tmpmsg += $uacFeature + "; "
			}
		}
		
		# If the default features are enabled, check for additional feature for added security.
		if($result) 
		{
			# Assigning lower severity since the default features are in place.
			$severity = "Low"
			$additionalUACFeature = "ValidateAdminCodeSignatures"
			if ($(Get-PISysAudit_RegistryKeyValue -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel -RegKeyPath $uacKeyPath -Attribute $additionalUACFeature) -eq 0)
			{
				$result = $false
				$msg = "Recommended UAC feature {0} disabled."
				$msg = [string]::Format($msg, $additionalUACFeature)
			}	
			else {$msg = "UAC features enabled."}
		}
		else
		{$msg = $tmpmsg}	
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check."					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}	
	
	# Define the results in the audit table	
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU10005" `
										-ain "UAC Enabled" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "Machine" -Group2 "Policy" `
										-Severity $severity																				 
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
AU1xxxx - <Name>
.DESCRIPTION
VERIFICATION: <Enter what the verification checks>
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
	$msg = ""
	try
	{		
		# Enter routine.			
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check."					
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
Export-ModuleMember Get-PISysAudit_FunctionsFromLibrary1
Export-ModuleMember Get-PISysAudit_CheckDomainMemberShip
Export-ModuleMember Get-PISysAudit_CheckOSInstallationType
Export-ModuleMember Get-PISysAudit_CheckFirewallEnabled
Export-ModuleMember Get-PISysAudit_CheckAppLockerEnabled
Export-ModuleMember Get-PISysAudit_CheckUACEnabled
# </Do not remove>

# ........................................................................
# Add your new Export-ModuleMember instruction after this section.
# Replace the Get-PISysAudit_TemplateAU1xxxx with the name of your
# function.
# ........................................................................
# Export-ModuleMember Get-PISysAudit_TemplateAU1xxxx