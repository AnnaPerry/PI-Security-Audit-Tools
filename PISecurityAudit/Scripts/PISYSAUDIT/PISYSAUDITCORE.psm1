# ***********************************************************************
# Core library
# ***********************************************************************
# * Modulename:   PISYSAUDIT
# * Filename:     PISYSAUDITCORE.psm1
# * Description:  Script block to create the PISYSAUDIT module.
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
# Global Variables
#
#	PISysAuditShowUI
#	PISysAuditPIConfigExec
#	PIConfigScriptPath
#	ScriptsPath
#	PasswordPath
#	PISysAuditInitialized
#	PISysAuditCachedSecurePWD
#   PISysAuditIsElevated
# ........................................................................

# ........................................................................
# Internal Functions
# ........................................................................
function GetFunctionName
{ return (Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name }

function SetFolders
{
	# Retrieve the folder from which this script is called ..\Scripts and split the path
	# to remove the Scripts part.	
	$modulePath = $PSScriptRoot
	
	# ..\
	# ..\Scripts
	# ..\Scripts\PISYSAUDIT
	# ..\Scripts\Temp
	# ..\Export
	# ..\Scripts\piconfig
	# ..\pwd	
	$scriptsPath = Split-Path $modulePath
	$rootPath = Split-Path $scriptsPath				
	
	$exportPath = PathConcat -ParentPath $rootPath -ChildPath "Export"
	if (!(Test-Path $exportPath)){
	New-Item $exportPath -type directory
	}
	$scriptsPathTemp = PathConcat -ParentPath $scriptsPath -ChildPath "Temp"
	if (!(Test-Path $scriptsPathTemp)){
	New-Item $scriptsPathTemp -type directory
	}

	$picnfgPath = PathConcat -ParentPath $scriptsPath -ChildPath "piconfig"
	$pwdPath = PathConcat -ParentPath $rootPath -ChildPath "pwd"		
	$logFile = PathConcat -ParentPath $exportPath -ChildPath "PISystemAudit.log"		

	# Store them at within the global scope range.	
	New-Variable -Name "ScriptsPath" -Option "Constant" -Scope "Global" -Visibility "Public" -Value $scriptsPath
	New-Variable -Name "ScriptsPathTemp" -Option "Constant" -Scope "Global" -Visibility "Public" -Value $scriptsPathTemp			
	New-Variable -Name "PasswordPath" -Option "Constant" -Scope "Global" -Visibility "Public" -Value $pwdPath
	if($null -eq (Get-Variable "ExportPath" -Scope "Global" -ErrorAction "SilentlyContinue").Value)
	{
		New-Variable -Name "ExportPath" -Option "Constant" -Scope "Global" -Visibility "Public" -Value $exportPath
	}
	New-Variable -Name "PIConfigScriptPath" -Option "Constant" -Scope "Global" -Visibility "Public" -Value $picnfgPath
	if($null -eq (Get-Variable "PISystemAuditLogFile" -Scope "Global" -ErrorAction "SilentlyContinue").Value)
	{
		New-Variable -Name "PISystemAuditLogFile" -Option "Constant" -Scope "Global" -Visibility "Public" -Value $logFile	
	}
}

function NewObfuscateValue
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(	
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("v")]
		[string]
		$Value)
		
	$fn = GetFunctionName
	
	try
	{
		# Create a Rijndael symmetric key encryption object.
		$r = New-Object System.Security.Cryptography.RijndaelManaged  
		# Set the key and initialisation vector to 128-bytes each of (1..16).
		$c = $r.CreateEncryptor((1..16), (1..16))    
		# Create so objectes needed for manipulation.
		$ms = New-Object IO.MemoryStream
		# Target data stream, transformation, and mode.
		$cs = New-Object Security.Cryptography.CryptoStream $ms, $c, "Write"
		$sw = New-Object IO.StreamWriter $cs
		
		# Write the string through the crypto stream into the memory stream
		$sw.Write($Value)
		
		# Clean up	
		$sw.Close()
		$cs.Close()
		$ms.Close()
		$r.Clear()
		
		# Convert to byte array from the encrypted memory stream.
		[byte[]]$result = $ms.ToArray()
		# Convert to base64 for transport.
		$encryptedValue = [Convert]::ToBase64String($result)

		# return the encryptedvalue
		return $encryptedValue
	}
	catch
	{
		# Return the error message.
		$msg = "The obfuscation of the value has failed"						
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}	
}

function WriteHostPartialResult
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(	
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]		
		[object]
		$AuditItem)
	
	$fn = GetFunctionName
	
	# Read from the global constant bag.
	$ShowUI = (Get-Variable "PISysAuditShowUI" -Scope "Global" -ErrorAction "SilentlyContinue").Value							
	
	# Initialize.
	$msg1 = ""
	$msg2 = ""
	$msg3 = ""
	$msg4 = ""
	
	# Template
	$msgTemplate1 = "A severe issue was found"
	$msgTemplate2 = "A moderate issue was found"
	$msgTemplate3 = "A low issue was found"
	$msgTemplate4 = " on {0} server regarding {1} check (ID: {2}). See details on the generated report"
	$defaultForegroundColor = "White"
	$defaultBackgroundColor = "Black"
			
	# Process only if this item is not compliant.
	if($AuditItem.AuditItemValue -eq $false)
	{	
		# Set the message.			
		$msg2 = [string]::Format($msgTemplate4, $AuditItem.ServerName, $AuditItem.AuditItemName, $AuditItem.ID)
		$msg3 = $msg2 + "."		
			
		if($AuditItem.Severity -eq "Severe")
		{
			# Set color and message.
			$alertForegroundColor = "Red"
			$alertBackgroundColor = "Gray"												
			$msg1 = $msgTemplate1
			
			# Write to console with colors. This needs to be performed in 2 steps.
			if($ShowUI -eq $true)
			{											
				Write-Host $msg1 -Foregroundcolor $alertForegroundColor -Backgroundcolor $alertBackgroundColor -nonewline
				Write-Host $msg3 -Foregroundcolor $defaultForegroundColor -Backgroundcolor $defaultBackgroundColor
			}
		}
		elseif($AuditItem.Severity -eq "Moderate")
		{
			# Set color and message.
			$alertForegroundColor = "Magenta"
			$alertBackgroundColor = "Gray"									
			$msg1 = $msgTemplate2
			
			# Write to console with colors. This needs to be performed in 2 steps.
			if($ShowUI -eq $true)
			{				
				Write-Host $msg1 -Foregroundcolor $alertForegroundColor -Backgroundcolor $alertBackgroundColor -nonewline
				Write-Host $msg3 -Foregroundcolor $defaultForegroundColor -Backgroundcolor $defaultBackgroundColor
			}
		}	
		elseif($AuditItem.Severity -eq "Low")
		{
			# Set color and message.
			$alertForegroundColor = "DarkYellow"
			$alertBackgroundColor = "Gray"									
			$msg1 = $msgTemplate3
			
			# Write to console with colors. This needs to be performed in 2 steps.
			if($ShowUI -eq $true)
			{				
				Write-Host $msg1 -Foregroundcolor $alertForegroundColor -Backgroundcolor $alertBackgroundColor -nonewline
				Write-Host $msg3 -Foregroundcolor $defaultForegroundColor -Backgroundcolor $defaultBackgroundColor
			}
		}					
						
		# Write to the log file either.
		$msg4 = $msg1 + $msg2
		Write-PISysAudit_LogMessage $msg4 "Info" $fn
	}
}

function GetPIConfigExecPath
{				
param(
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
		
	$fn = GetFunctionName		
	
	try
	{
		#......................................................................................
		# Set Paths
		#......................................................................................						
			$cluFound = $false
			# Get the PIHOME folder.
			$PIHome64_path = Get-PISysAudit_EnvVariable "PIHOME64"
			$PIHome_path = Get-PISysAudit_EnvVariable "PIHOME"
			
			# Get the PI folder.
			$PIServer_path = Get-PISysAudit_EnvVariable "PISERVER"			
			
			# Validate where the piconfig CLU is installed.
			# The piconfig.exe is installed with PI SDK since version 1.4.0.416 on PINS									
			
			# Test for the PISERVER variable.
			if($null -ne $PIServer_path)
			{							
				if($cluFound -eq $false)
				{
					$PIConfigExec = PathConcat -ParentPath $PIServer_path -ChildPath "adm\piconfig.exe"										
					if(Test-Path $PIConfigExec) { $cluFound = $true }
				}
				
				# ............................................................................................................
				# Verbose at Debug Level 1+
				# Show some extra messages.
				# ............................................................................................................			
				$msgTemplate = "Test the PISERVER variable, piconfigExec = {0}, CLU found = {1}"
				$msg = [string]::Format($msgTemplate, $PIConfigExec, $cluFound)
				Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 1
			}									
			
			if($cluFound -eq $false)
			{
				$PIConfigExec = PathConcat -ParentPath $PIHome64_path -ChildPath "adm\piconfig.exe"
				if(Test-Path $PIConfigExec) { $cluFound = $true }
				
				# ............................................................................................................
				# Verbose at Debug Level 1+
				# Show some extra messages.
				# ............................................................................................................			
				$msgTemplate = "Test the PIHOME64 variable, piconfigExec = {0}, CLU found = {1}"
				$msg = [string]::Format($msgTemplate, $PIConfigExec, $cluFound)
				Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 1
			}
			
			if($cluFound -eq $false)
			{
				$PIConfigExec = PathConcat -ParentPath $PIHome_path -ChildPath "adm\piconfig.exe"
				if(Test-Path $PIConfigExec) { $cluFound = $true }
					
				# ............................................................................................................
				# Verbose at Debug Level 1+
				# Show some extra messages.
				# ............................................................................................................			
				$msgTemplate = "Test the PIHOME variable, piconfigExec = {0}, CLU found = {1}"
				$msg = [string]::Format($msgTemplate, $PIConfigExec, $cluFound)
				Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 1
			}
			
			# If found, set the path as a global variable to not redo this test continously.
			if($cluFound)
			{
				# Set the PIConfig.exe path
				New-Variable -Name "PISysAuditPIConfigExec" -Scope "Global" -Visibility "Public" -Value $PIConfigExec				
				return $true
			}
			else
			{
				$msg = "The PI System Audit module cannot find a piconfig.exe command-line utility on this machine"				
				Write-PISysAudit_LogMessage $msg "Error" $fn -sc $true
				return $false
			}            
	}
	catch
	{
		# Return the error message.
		$msg = "The validation of piconfig.exe CLU presence has not been completed"						
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $false
	}	
}

function CheckIfRunningElevated
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
		
	$fn = GetFunctionName		
	
	try
	{
		$windowsPrinciple = new-object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
		return $windowsPrinciple.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)         
	}
	catch
	{
		# Return the error message.
		$msg = "Error encountered when checking if running elevated."						
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $false
	}
}

function ValidateFileContent
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(	
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("fc")]		
		$FileContent,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("v")]
		[string]
		$Validation)
					
	$fn = GetFunctionName
	
	try
	{
		Foreach($line in $FileContent)
		{						
			if(($line.ToLower() ).Contains($Validation.ToLower() ))
			{ return $true }
		}
		
		# The content was not found.
		return $false						
	}
	catch
	{
		# Return the error message.
		$msg = "The content validation has failed"						
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}	
}

function ResolveComputerName
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(									
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]		
		[AllowEmptyString()]
		[alias("rcn")]
		[string]
		$RemoteComputerName)
		
	# Get and store the function Name.
	$fn = GetFunctionName

	try
	{								
		# Return the right server name to use.
		if($LocalComputer)
		{
			# Obtain the machine name from the environment variable.			
			return (get-content env:computername)
		}
		else
		{ 
			if($RemoteComputerName -eq "")
			{
				$msg = "The remote computer name is empty."
				Write-PISysAudit_LogMessage $msg "Error" $fn
				return $null
			}
			else
			{ return $RemoteComputerName }
		}
	}
	catch
	{ return $null }
}
		
function ReturnSQLServerName
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(									
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]		
		[string]
		$ServerName,
		[parameter(Mandatory=$true, Position=2, ParameterSetName = "Default")]		
		[AllowEmptyString()]
		[string]
		$InstanceName)
		
	# Get and store the function Name.
	$fn = GetFunctionName

	try
	{						
		# Build the connection string.
		if(($InstanceName.ToLower() -eq "default") `
			-or ($InstanceName.ToLower() -eq "mssqlserver") `
			-or ($SQLServerInstanceName -eq ""))
		{
			# Use the Server name only as the identity of the server.
			return $ServerName						
		}
		else
		{
			# Use the Server\Named Instance as the identity of the server.
			return ($ServerName + "\" + $InstanceName)
		}								
	}
	catch
	{ return $null }
}

function SetSQLAccountPasswordInCache
{	
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(											
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]		
		[string]
		$ServerName,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]				
		[string]
		$InstanceName,
		[parameter(Mandatory=$true, Position=2, ParameterSetName = "Default")]		
		[string]
		$UserName)
		
	# Get and store the function Name.
	$fn = GetFunctionName

	try
	{
		# Define the password message template
		$msgPasswordTemplate = "Please enter the password for the user {0} for the SQL Server: {1}"	

		# Get the SQL Server name.
		$sqlServerName = ReturnSQLServerName $ServerName $InstanceName
		
		# Get the password via a protected prompt.
		$msgPassword = [string]::Format($msgPasswordTemplate, $UserName, $sqlServerName)
		$securePWD = Read-Host -assecurestring $msgPassword
		
		# Verbose only if Debug Level is 2+
		$msg = "The user was prompted to enter the password for SQL connection"					
		Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2
		
		# Cache the secure password for next usage.
		New-Variable -Name "PISysAuditCachedSecurePWD" -Scope "Global" -Visibility "Public" -Value $securePWD		
	}
	catch
	{
		# Return the error message.
		$msg = "Set the SQL Account passwor into cache failed"						
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}
}				

function SetConnectionString
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(									
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]		
		[alias("rcn")]
		[string]
		$RemoteComputerName,								
		[parameter(Mandatory=$false, ParameterSetName = "Default")]				
		[string]
		$InstanceName = "Default",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]				
		[boolean]
		$IntegratedSecurity = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]	
		[alias("pf")]
		[string]
		$PasswordFile = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)			
		
	# Get and store the function Name.
	$fn = GetFunctionName

	try
	{				
		# Define the requested server name.
		$computerName = ResolveComputerName $LocalComputer $RemoteComputerName		
		
		# Define the complete SQL Server name (Server + instance name).
		$sqlServerName = ReturnSQLServerName $computerName $InstanceName			
										
		# SQL Server uses named instance.
		# If you use the integrated security to connect to your PI AF Storage Server use this connection string template.
		$connectionStringTemplate1="Server={0};Database=master;Integrated Security=SSPI;"				
		# If you use the sa account to connect to your PI AF Storage Server use this connection string template.		
		$connectionStringTemplate2="Server={0};Database=master;User ID={1};Password={2};"
				
		# Define the connection string.
		if($IntegratedSecurity)
		{ $connectionString = [string]::format($connectionStringTemplate1, $sqlServerName) }
		else
		{			
			if($PasswordFile -eq "")
			{								
				# Read from the global constant bag.
				# Read the secure password from the cache								 
				$securePWDFromCache = (Get-Variable "PISysAuditCachedSecurePWD" -Scope "Global" -ErrorAction "SilentlyContinue").Value					
				if(($null -eq $securePWDFromCache) -or ($securePWDFromCache -eq ""))
				{ 
					# Return the error message.
					$msg = "The password is not stored in cache"					
					Write-PISysAudit_LogMessage $msg "Error" $fn
					return $null
				}
				else
				{ 																				
					# Verbose only if Debug Level is 2+
					$msg = "The password stored in cached will be used for SQL connection"					
					Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2										
					
					# The CLU does not understand secure string and needs to get the raw password
					# Use the pointer method to reach the value in memory.
					$pwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePWDFromCache))
				}												
			}
			else
			{ $pwd = GetPasswordOnDisk $PasswordFile }							
			$connectionString = [string]::format($connectionStringTemplate2, $SQLServerName, $UserName, $pwd)
		}						
	
		# Return the connection string.
		return $connectionString
				
	}
	catch
	{ 
		# Return the error message.
		$msg = "Setting the connection string has failed"		
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}
}

function ExecuteCommandLineUtility
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(									
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]		
		[alias("rcn")]
		[string]
		$RemoteComputerName,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("exec")]
		[string]
		$UtilityExec,		
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("output")]
		[string]
		$OutputFilePath,	
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("args")]
		[string]
		$ArgList,	
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[ValidateSet("Read","Write","Delete","Default")]
		[alias("oper")]
		[string]
		$Operation = "Default",	
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)			
		
	# Get and store the function Name.
	$fn = GetFunctionName

	try
	{	
			
			if($LocalComputer)
			{
				if($Operation -eq "Default" -or $Operation -eq "Write")
				{
					#......................................................................................
					# Delete any residual output file.
					#......................................................................................
					if(Test-Path $OutputFilePath) { Remove-Item $OutputFilePath }
			
					#......................................................................................
					# Execute the command locally by calling another process.
					#......................................................................................
					Start-Process -FilePath $UtilityExec `
									-ArgumentList $ArgList `
									-RedirectStandardOutput $OutputFilePath `
									-Wait -NoNewWindow				
				}

				if($Operation -eq "Default" -or $Operation -eq "Read")
				{
					#......................................................................................
					# Read the content.			
					#......................................................................................
					$outputFileContent = Get-Content -Path $OutputFilePath
				}

				if($Operation -eq "Default" -or $Operation -eq "Delete")
				{
					#......................................................................................
					# Delete output file.
					#......................................................................................
					if(Test-Path $OutputFilePath) { Remove-Item $OutputFilePath }
				}
			}
			else
			{
				if($Operation -eq "Default" -or $Operation -eq "Write")
				{
					#......................................................................................			
					# Delete (remotely) any residual output file.
					# Write the script block template with '[' and ']' delimiter because the
					# [string]::Format function will fail and then replace with the '{' and '}'
					#......................................................................................
					$scriptBlockCmdTemplate = "if(Test-Path `"{0}`") [ Remove-Item `"{0}`" ]"
					$scriptBlockCmd = [string]::Format($scriptBlockCmdTemplate, $OutputFilePath)
					$scriptBlockCmd = ($scriptBlockCmd.Replace("[", "{")).Replace("]", "}")			
			
					# Verbose only if Debug Level is 2+
					$msgTemplate = "Remote command to send to {0} is: {1}"
					$msg = [string]::Format($msgTemplate, $RemoteComputerName, $scriptBlockCmd)
					Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2
			
					$scriptBlock = [scriptblock]::create( $scriptBlockCmd )										
					# The script block returns the result but we are not interested, so send it
					# to null.
					Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock | Out-Null
			
					#......................................................................................
					# Execute the command remotely.
					#......................................................................................
					$scriptBlockCmdTemplate = "Start-Process -FilePath `"{0}`" -ArgumentList {1} -RedirectStandardOutput `"{2}`" -Wait -NoNewWindow"
					$scriptBlockCmd = [string]::Format($scriptBlockCmdTemplate, $UtilityExec, $ArgList, $OutputFilePath)											
			
					# Verbose only if Debug Level is 2+
					$msgTemplate = "Remote command to send to {0} is: {1}"
					$msg = [string]::Format($msgTemplate, $RemoteComputerName, $scriptBlockCmd)
					Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2
			
					$scriptBlock = [scriptblock]::create( $scriptBlockCmd )
					Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock
				}

				if($Operation -eq "Default" -or $Operation -eq "Read")
				{
					#......................................................................................
					# Read the content remotely.
					#......................................................................................
					$scriptBlockCmdTemplate = "Get-Content -Path ""{0}"""
					$scriptBlockCmd = [string]::Format($scriptBlockCmdTemplate, $outputFilePath)									
			
					# Verbose only if Debug Level is 2+
					$msgTemplate = "Remote command to send to {0} is: {1}"
					$msg = [string]::Format($msgTemplate, $RemoteComputerName, $scriptBlockCmd)
					Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2
			
					$scriptBlock = [scriptblock]::create( $scriptBlockCmd )
					$outputFileContent = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock	
				}

				if($Operation -eq "Default" -or $Operation -eq "Delete")
				{
					# Delete (remotely) output file.
					# Write the script block template with '[' and ']' delimiter because the
					# [string]::Format function will fail and then replace with the '{' and '}'
					#......................................................................................
					$scriptBlockCmdTemplate = "if(Test-Path `"{0}`") [ Remove-Item `"{0}`" ]"
					$scriptBlockCmd = [string]::Format($scriptBlockCmdTemplate, $OutputFilePath)
					$scriptBlockCmd = ($scriptBlockCmd.Replace("[", "{")).Replace("]", "}")			
			
					# Verbose only if Debug Level is 2+
					$msgTemplate = "Remote command to send to {0} is: {1}"
					$msg = [string]::Format($msgTemplate, $RemoteComputerName, $scriptBlockCmd)
					Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2
			
					$scriptBlock = [scriptblock]::create( $scriptBlockCmd )				
					# The script block returns the result but we are not interested, so send it
					# to null.
					Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock | Out-Null
				}
			}

			if($Operation -eq "Default" -or $Operation -eq "Read"){return $outputFileContent}
	}
	catch
	{
		# Return the error message.
		$msgTemplate1 = "A problem occurred with {0} on local computer"
		$msgTemplate2 = "A problem occurred with {0} on {1} computer"
		if($LocalComputer)
		{ $msg = [string]::Format($msgTemplate1, $UtilityExec) }
		else
		{ $msg = [string]::Format($msgTemplate2, $UtilityExec, $RemoteComputerName) }		
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}
}

function GetPasswordOnDisk
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(	
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]		
		[string]
		$File)
		
	$fn = GetFunctionName
	
	try
	{
		# Read from the global constant bag.
		$pwdPath = (Get-Variable "PasswordPath" -Scope "Global").Value			
		# Set the path.
		$pwdFile = PathConcat -ParentPath $pwdPath -ChildPath $File
		
		# Decrypt.
		
		# If you want to use Windows Data Protection API (DPAPI) to encrypt the standard string representation
		# leave the key undefined. Visit this URL: http://msdn.microsoft.com/en-us/library/ms995355.aspx to know more.
		# This salt key had been generated with the Set-PISysAudit_SaltKey cmdlet.
		# $mySaltKey = "Fnzg+mrVxXEEmfEMzFwiag=="
		# $keyInBytes = [System.Convert]::FromBase64String($mySaltKey)
		# $securePWD = Get-Content -Path $pwdFile | ConvertTo-SecureString -key $keyInBytes				
		$securePWD = Get-Content -Path $pwdFile | ConvertTo-SecureString -key (1..16)			
		
		# Return the password.
		return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePWD))					
	}
	catch
	{
		# Return the error message.
		$msg = "Decrypting the password has failed"
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}
}

function ValidateIfHasPIDataArchiveRole
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(		
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

	$fn = GetFunctionName
	
	try
	{
		# Get the PISERVER variable.
		if($LocalComputer)
		{ $PIServer_path = Get-PISysAudit_EnvVariable "PISERVER" }
		else
		{ $PIServer_path = Get-PISysAudit_EnvVariable "PISERVER" -lc $false -rcn $RemoteComputerName }
		
		# Validate...
		if($null -eq $PIServer_path) { return $false }
		return $true
	}
	catch
	{ return $false }
}

function ValidateIfHasPIAFServerRole
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(		
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

	$fn = GetFunctionName
	
	try
	{
		$className = "Win32_Service"
		$namespace = "root\CIMV2"
		$filterExpression = [string]::Format("name='{0}'", "AFService")
		$WMIObject = ExecuteWMIQuery $className -n $namespace -lc $LocalComputer -rcn $RemoteComputerName -FilterExpression $filterExpression -DBGLevel $DBGLevel								
		if($null -eq $WMIObject) { return $false}
		return $true
	}
	catch
	{ return $false }
}

function ValidateIfHasSQLServerRole
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[string]
		$InstanceName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		

	$fn = GetFunctionName
	
	try
	{
		$className = "Win32_Service"
		$namespace = "root\CIMV2"
		if(($InstanceName -eq "") -or ($InstanceName.ToLower() -eq "default") -or ($InstanceName.ToLower() -eq "mssqlserver"))
		{ $filterExpression = [string]::Format("name='{0}'", "MSSQLSERVER") }
		else
		{
			# Don't forget the escape character (2 times) in the name of the WMI query won't
			# return anything.
			$value = ("MSSQL``$" + $InstanceName).ToUpper()
			$filterExpression = [string]::Format("name='{0}'", $value)			
		}
		$WMIObject = ExecuteWMIQuery $className -n $namespace -lc $LocalComputer -rcn $RemoteComputerName -FilterExpression $filterExpression -DBGLevel $DBGLevel								
		if($null -eq $WMIObject) { return $false}
		return $true
	}
	catch
	{ return $false }
}

function ValidateIfHasPICoresightRole
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(		
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

	$fn = GetFunctionName
	
	try
	{
		$result = $false
		$RegKeyPath = "HKLM:\Software\PISystem\Coresight"
		$result = Get-PISysAudit_TestRegistryKey -lc $LocalComputer -rcn $RemoteComputerName -rkp $RegKeyPath -DBGLevel $DBGLevel						
		return $result
	}
	catch
	{ return $false }
}

function ExecuteWMIQuery
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("wcn")]
		[string]
		$WMIClassName,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("n")]
		[string]
		$Namespace = "root\CIMV2",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("f")]
		[string]
		$FilterExpression = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
		
	$fn = GetFunctionName
	
	try
	{
		if($LocalComputer)
		{		
			# Perform the WMI Query via an Invoke-Command to be able
			# to pass the Class under a variable.
			if($FilterExpression -eq "")
			{				
				$scriptBlockCmdTemplate = "Get-WMIObject -Namespace {0} -Class {1}"
				$scriptBlockCmd = [string]::Format($scriptBlockCmdTemplate, $Namespace, $WMIClassName)			
			}
			else
			{
				$scriptBlockCmdTemplate = "Get-WMIObject -Namespace {0} -Class {1} -filter `"{2}`""
				$scriptBlockCmd = [string]::Format($scriptBlockCmdTemplate, $Namespace, $WMIClassName, $FilterExpression)			
			}			
						
			# Verbose only if Debug Level is 2+
			$msgTemplate = "Local command to send is: {0}"
			$msg = [string]::Format($msgTemplate, $scriptBlockCmd)
			Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2
			
			# Create the script block to send via PS Remoting.
			$scriptBlock = [scriptblock]::create( $scriptBlockCmd )
			$WMIObject = Invoke-Command -ScriptBlock $scriptBlock												
			return $WMIObject			
		}
		else
		{												
			# To avoid DCOM to be used with WMI queries, use PS Remoting technique to wrap
			# the WMI call.			
			# Call to perform remotely is...
			# $serviceObject  = Get-WMIObject "Win32_Service" -filter $filterExpression
			$scriptBlockCmdTemplate = "Get-WMIObject -Namespace {0} -Class {1} -filter `"{2}`""
			$scriptBlockCmd = [string]::Format($scriptBlockCmdTemplate, $Namespace, $WMIClassName, $FilterExpression)
			
			# Verbose only if Debug Level is 2+
			$msgTemplate = "Remote command to send to {0} is: {1}"
			$msg = [string]::Format($msgTemplate, $RemoteComputerName, $scriptBlockCmd)
			Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2
			
			# Create the script block to send via PS Remoting.
			$scriptBlock = [scriptblock]::create( $scriptBlockCmd )
			$WMIObject = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock									
			return $WMIObject
		}
	}
	catch
	{
		# Return the error message.
		$msgTemplate1 = "Query the WMI classes from local computer has failed"
		$msgTemplate2 = "Query the WMI classes from {0} has failed"
		if($LocalComputer)
		{ $msg = $msgTemplate1 }
		else
		{ $msg = [string]::Format($msgTemplate2, $RemoteComputerName) }		
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}
}

function GetFilteredListOfComputerParams
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(	
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("cpt")]
		[System.Collections.HashTable]
		$ComputerParamsTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
					
	$fn = GetFunctionName
	
	try
	{				
		# Create a Hash table containing the unique computers to visit.
		[System.Collections.HashTable]$validatedComputers = @{}
		
		# Process.
		foreach($item in $ComputerParamsTable.GetEnumerator())
		{			
			# Get the current parameter
			$computerParams = $item.Value
			$addComputer = $false
		
			if($validatedComputers.Count -eq 0) { $addComputer = $true }
			if($addComputer -eq $false)
			{							
				# Test if the computer is already part of the list,
				# if not set the flag to true.
				$item = $null
				$item = $validatedComputers[$computerParams.ComputerName]
				if($null -eq $item) { $addComputer = $true }				
			}
				
			if($addComputer)
			{				
				# Maintain the list of already validated computer.			
				$validatedComputers.Add($computerParams.ComputerName, $computerParams)
			}					
		}
		
		# Return the filtered list of computers.
		return $validatedComputers
	}
	catch
	{
		# Return the error message.
		$msg = "A problem has occurred during the generation of the filtered list of computers"						
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		# Validation has failed.
		return $null
	}	
}

function ValidateWSMan
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(	
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("vlc")]
		[System.Collections.HashTable]
		$ValidatedListOfComputers,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
					
	$fn = GetFunctionName
	
	try
	{								
		$problemCounter = 0
		
		# Process with the unique list.
		foreach($item in $ValidatedListOfComputers.GetEnumerator())
		{
			# Get the current parameter
			# Read the object within the System.Collections.DictionaryEntry
			$computerParams = $item.Value
			
			# Test non-local computer to validate if WSMan is working.
			if($computerParams.IsLocal)
			{							
				$msgTemplate = "The server: {0} does not need WinRM communication because it will use a local connection"
				$msg = [string]::Format($msgTemplate, $computerParams.ComputerName)
				Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 1					
			}
			else
			{								
				$result = $null
				$result = Test-WSMan -authentication default -ComputerName $computerParams.ComputerName
				if($null -eq $result)
				{
					$problemCounter++
					$msgTemplate = "The server: {0} has a problem with WinRM communication"
					$msg = [string]::Format($msgTemplate, $computerParams.ComputerName)
					Write-PISysAudit_LogMessage $msg "Error" $fn
				}					
			}
		}						
		
		# At least a problem was found.
		if($problemCounter -gt 0) { return $false }
		
		# Validation is a success.
		return $true
	}
	catch
	{
		# Return the error message.
		$msg = "A problem has occurred during the validation with WSMan"						
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		# Validation has failed.
		return $false
	}	
}

function Test-WebAdministrationModuleAvailable
{
<#
.SYNOPSIS
(Core functionality) Checks for the WebAdministration module.
.DESCRIPTION
Validate that IIS module can be loaded and configuration data can be accessed.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
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
	$fn = GetFunctionName
	$value = $false
	try
	{
		$query = 'Test-Path IIS:\'
		$scriptBlock = [scriptblock]::create( $query )
		# Execute the Get-ItemProperty cmdlet method locally or remotely via the Invoke-Command cmdlet
		if($LocalComputer)		
		{						
			
			# Import the WebAdministration module
			Import-Module -Name "WebAdministration"		
			
			# Execute the command locally	
			$value = Invoke-Command -ScriptBlock $scriptBlock			
		}
		else
		{	
					
			# Establishing a new PS session on a remote computer		
			$PSSession = New-PSSession -ComputerName $RemoteComputerName

			# Importing WebAdministration module within the PS session
			Invoke-Command -Session $PSSession -ScriptBlock {Import-Module WebAdministration}
			
			# Execute the command within a remote PS session
			$value = Invoke-Command -Session $PSSession -ScriptBlock $scriptBlock
			Remove-PSSession -ComputerName $RemoteComputerName
		}
	
		# Return the value found.
		return $value		
	}
	catch
	{
		# Return the error message.
		$msgTemplate1 = "A problem occurred checking for IIS scripting tools: {0} from local machine."
		$msgTemplate2 = "A problem occurred checking for IIS scripting tools: {0} from {1} machine."
		if($LocalComputer)
		{ $msg = [string]::Format($msgTemplate1, $_.Exception.Message) }
		else
		{ $msg = [string]::Format($msgTemplate2, $_.Exception.Message) }
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Test-PowerShellToolsForPISystemAvailable
{
    # Check for availability of PowerShell Tools for the PI System
    if( -not(Test-Path variable:global:ArePowerShellToolsAvailable) -and $PSVersionTable.PSVersion.Major -ge 3)
	{
		if(Get-Module -ListAvailable -Name OSIsoft.PowerShell)
		{
			Import-Module -Name OSIsoft.PowerShell
			$global:ArePowerShellToolsAvailable = $true
		}
		else
		{
			$global:ArePowerShellToolsAvailable = $false
		}
	}
}

function StartComputerAudit
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,		
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("cpt")]
		[System.Collections.HashTable]
		$ComputerParamsTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)	
					
	# Get and store the function Name.
	$fn = GetFunctionName
	
	try
	{		
		# Read from the global constant bag.
		$ShowUI = (Get-Variable "PISysAuditShowUI" -Scope "Global" -ErrorAction "SilentlyContinue").Value					
		
		# Get the list of functions to execute.
		$listOfFunctions = Get-PISysAudit_FunctionsFromLibrary1				
		# There is nothing to execute.
		if($listOfFunctions.Count -eq 0)		
		{
			# Return the error message.
			$msg = "No machine checks have been found."
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}																						
				
		# Set message templates.
		$activityMsgTemplate1 = "Check computer '{0}'..."				
		$statusMsgProgressTemplate1 = "Perform check {0}/{1}"	
		$statusMsgCompleted = "Completed"
		$complianceCheckFunctionTemplate = "Compliance Check function: {0}, arguments: {1}, {2}, {3}, {4}"
				
		# Process.
		foreach($item in $ComputerParamsTable.GetEnumerator())
		{	
			$i = 0	
			# Read the object within the System.Collections.DictionaryEntry
			$computerParams = $item.Value
			
			# Set activity message.			
			$activityMsg1 = [string]::Format($activityMsgTemplate1, $ComputerParams.ComputerName)								
																										
			# Proceed with all the compliance checks.
			foreach($function in $listOfFunctions.GetEnumerator())
			{																									
				# Set the progress.
				if($ShowUI)
				{
					# Increment the counter.
					$i++				
					$ActivityMsg1 = [string]::Format($activityMsgTemplate1, $computerParams.ComputerName)                     
					$StatusMsg = [string]::Format($statusMsgProgressTemplate1, $i, $listOfFunctions.Count.ToString())
					Write-Progress -activity $ActivityMsg1 -Status $StatusMsg	
				}
				
				# ............................................................................................................
				# Verbose at Debug Level 2+
				# Show some extra messages.
				# ............................................................................................................						
				$msg = [string]::Format($complianceCheckFunctionTemplate, $function.Name, $AuditTable, `
											$computerParams.IsLocal, $computerParams.ComputerName, $DBGLevel)
				Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 2
				
				# Call the function.
				& $function.Name $AuditTable -lc $computerParams.IsLocal -rcn $computerParams.ComputerName -dbgl $DBGLevel						
			}			
		}
		# Set the progress.
		if($ShowUI)
		{ Write-Progress -activity $activityMsg1 -Status $statusMsgCompleted -completed }
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of computer checks"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return
	}			
}	

function StartPIDataArchiveAudit
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,		
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("cp")]		
		$ComputerParams,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)	
					
	# Get and store the function Name.
	$fn = GetFunctionName
	$global:PIDataArchiveConnection = $null

	try
	{
		# Read from the global constant bag.
		$ShowUI = (Get-Variable "PISysAuditShowUI" -Scope "Global" -ErrorAction "SilentlyContinue").Value						

		# Validate the presence of a PI Data Archive
		if((ValidateIfHasPIDataArchiveRole -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName -dbgl $DBGLevel) -eq $false)
		{
			# Return the error message.
			$msgTemplate = "The computer {0} does not have a PI Data Archive role or the validation failed"
			$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}

		# Verify that the PI Data Archive is accessible over port 5450, if not, checks will not complete
		try
		{
			$testConnection = New-Object net.sockets.tcpclient
			$testConnection.Connect($ComputerParams.ComputerName, 5450)
		}
		catch
		{
			# Return the error message.
			$msgTemplate = "The PI Data Archive {0} is not accessible over port 5450"
			$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
			Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
			return
		}

		# Check for availability of PowerShell Tools for the PI System
		Test-PowerShellToolsForPISystemAvailable

		if($global:ArePowerShellToolsAvailable)
		{
			try
			{
				$global:PIDataArchiveConnection = Connect-PIDataArchive -PIDataArchiveMachineName $ComputerParams.ComputerName
				if($global:PIDataArchiveConnection.Connected){
					$msgTemplate = "Successfully connected to the PI Data Archive {0} with PowerShell."
					$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
					Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 2
				}
				else
				{
					$msgTemplate = "Unable to access the PI Data Archive {0} with PowerShell.  Check if there is a valid mapping for your user."
					$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
					Write-PISysAudit_LogMessage $msg "Warning" $fn
					return
				}
			}
			catch
			{
				# Return the error message.
				$msgTemplate = "An error occurred connecting to the PI Data Archive {0} with PowerShell."
				$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
				Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
				return
			}
		}
		else
		{
			$msgTemplate = "Unable to locate the PowerShell Tools for the PI System on the computer running this script.  The piconfig utility will be used instead."
			Write-PISysAudit_LogMessage $msg "Info" $fn

			# Get the piconfig CLU location on the machine where the script runs.		
			if( -not(Test-Path variable:global:PISysAuditPIConfigExec) )
			{
				if((GetPIConfigExecPath -dbgl $DBGLevel) -eq $false) { return }
			}

			# After we've validated connections over 5450, make sure PI Utilities will be able to connect.
			if($testConnection.Connected)
			{
				$outputFileContent = Invoke-PISysAudit_PIConfigScript -f "CheckPIServerAvailability.dif" `
																	-lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName -dbgl $DBGLevel
				if($null -eq $outputFileContent)
				{
					$msgTemplate = "Unable to access the PI Data Archive {0} with piconfig.  Check if there is a valid mapping for your user."
					$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
					Write-PISysAudit_LogMessage $msg "Warning" $fn
					return
				}
			}

		}
		
		# Get the list of functions to execute.
		$listOfFunctions = Get-PISysAudit_FunctionsFromLibrary2
		# There is nothing to execute.
		if($listOfFunctions.Count -eq 0)		
		{
			# Return the error message.
			$msg = "No PI Data Archive checks have been found."
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}			
									
		# Set message templates.		
		$activityMsgTemplate1 = "Check PI Data Archive component on '{0}' computer"
		$activityMsg1 = [string]::Format($activityMsgTemplate1, $ComputerParams.ComputerName)					
		$statusMsgProgressTemplate1 = "Perform check {0}/{1}"	
		$statusMsgCompleted = "Completed"
		$complianceCheckFunctionTemplate = "Compliance Check function: {0}, arguments: {1}, {2}, {3}, {4}"
															
		# Proceed with all the compliance checks.
		$i = 0
		foreach($function in $listOfFunctions.GetEnumerator())
		{		
			# Set the progress.
			if($ShowUI)
			{
				# Increment the counter.
				$i++				
				$statusMsg = [string]::Format($statusMsgProgressTemplate1, $i, $listOfFunctions.Count.ToString())
				Write-Progress -activity $activityMsg1 -Status $statusMsg
			}
			
			# ............................................................................................................
			# Verbose at Debug Level 2+
			# Show some extra messages.
			# ............................................................................................................				
			$msg = [string]::Format($complianceCheckFunctionTemplate, $function.Name, $AuditTable, `
										$ComputerParams.IsLocal, $ComputerParams.ComputerName, $DBGLevel)
			Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 2
			
			# Call the function.
			& $function.Name $AuditTable -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName -dbgl $DBGLevel																																							
		}

		# Disconnect if PowerShell Tools are used.
		if($global:PIDataArchiveConnection.Connected){$global:PIDataArchiveConnection.Disconnect()}

		# Set the progress.
		if($ShowUI)
		{ Write-Progress -activity $activityMsg1 -Status $statusMsgCompleted -completed }
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of PI Data Archive checks"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return
	}			
}

function PathConcat {
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("pp")]
		[string]
		$ParentPath,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("cp")]
		[string]
		$ChildPath,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
		
	# Get and store the function Name.
	$fn = GetFunctionName

		try {
		$FullPath = ($ParentPath.TrimEnd('\', '/') + '\' + $ChildPath.TrimStart('\', '/'))
		return $FullPath
		}
		catch {
		# Return the error message.
		$msgTemplate = "An error occurred building file path {0} with PowerShell."
		$msg = [string]::Format($msgTemplate, $FullPath)
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return
		}
}

function StartPIAFServerAudit
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,		
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("cp")]		
		$ComputerParams,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)	
					
	# Get and store the function Name.
	$fn = GetFunctionName

	try
	{
		# Read from the global constant bag.
		$ShowUI = (Get-Variable "PISysAuditShowUI" -Scope "Global" -ErrorAction "SilentlyContinue").Value
		$IsElevated = (Get-Variable "PISysAuditIsElevated" -Scope "Global" -ErrorAction "SilentlyContinue").Value				
		
		# Validate the presence of a PI AF Server
		if((ValidateIfHasPIAFServerRole -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName -dbgl $DBGLevel) -eq $false)
		{
			# Return the error message.
			$msgTemplate = "The computer {0} does not have a PI AF Server role or the validation failed"
			$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}
		
		# Get the list of functions to execute.
		$listOfFunctions = Get-PISysAudit_FunctionsFromLibrary3
		# There is nothing to execute.
		if($listOfFunctions.Count -eq 0)		
		{
			# Return the error message.
			$msg = "No PI AF Server checks have been found."
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}						
		
		# Check for availability of PowerShell Tools for the PI System
		Test-PowerShellToolsForPISystemAvailable

		if($global:ArePowerShellToolsAvailable)
		{
			try
			{
				$global:AFServerConnection = Connect-AFServer -AFServer $(Get-AFServer -Name $ComputerParams.ComputerName)
				if($global:AFServerConnection.ConnectionInfo.IsConnected)
				{
					$msgTemplate = "Successfully connected to the PI AF Server {0} with PowerShell."
					$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
					Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 2
				}
				else
				{
					$msgTemplate = "Unable to access the PI AF Server {0} with PowerShell.  Check if there is a valid mapping for your user."
					$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
					Write-PISysAudit_LogMessage $msg "Warning" $fn
					return
				}
			}
			catch
			{
				# Return the error message.
				$msgTemplate = "An error occurred connecting to the PI Data Archive {0} with PowerShell."
				$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
				Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
				return
			}
		}

		# Set message templates.		
		$activityMsgTemplate1 = "Check PI AF Server component on '{0}' computer"
		$activityMsg1 = [string]::Format($activityMsgTemplate1, $ComputerParams.ComputerName)					
		$statusMsgProgressTemplate1 = "Perform check {0}/{1}"	
		$statusMsgCompleted = "Completed"
		$complianceCheckFunctionTemplate = "Compliance Check function: {0}, arguments: {1}, {2}, {3}, {4}"						
				
		# Prepare data required for multiple compliance checks

		Invoke-PISysAudit_AFDiagCommand -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName -dbgl $DBGLevel -oper "Write"
										
		# Proceed with all the compliance checks.
		$i = 0
		foreach($function in $listOfFunctions.GetEnumerator())
		{									
			# Set the progress.
			if($ShowUI)
			{
				# Increment the counter.
				$i++				
				$statusMsg = [string]::Format($statusMsgProgressTemplate1, $i, $listOfFunctions.Count.ToString())
				Write-Progress -activity $activityMsg1 -Status $statusMsg							
			}
			
			# ............................................................................................................
			# Verbose at Debug Level 2+
			# Show some extra messages.
			# ............................................................................................................				
			$msg = [string]::Format($complianceCheckFunctionTemplate, $function.Name, $AuditTable, `
										$ComputerParams.IsLocal, $ComputerParams.ComputerName, $DBGLevel)
			Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 2
			
			# Call the function.
			& $function.Name $AuditTable -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName -dbgl $DBGLevel
		}

		# Clean up data required for multiple compliance checks

		Invoke-PISysAudit_AFDiagCommand -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName -dbgl $DBGLevel -oper "Delete"

		# Set the progress.
		if($ShowUI)
		{ Write-Progress -activity $activityMsg1 -Status $statusMsgCompleted -completed }
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of PI AF Server checks"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return
	}
}

function StartSQLServerAudit
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(										
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,		
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("cp")]		
		$ComputerParams,				
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
					
	# Get and store the function Name.
	$fn = GetFunctionName
	
	try
	{
		# Read from the global constant bag.
		$ShowUI = (Get-Variable "PISysAuditShowUI" -Scope "Global" -ErrorAction "SilentlyContinue").Value					
				
		# Validate the presence of a SQL Server
		$global:UseSQLCmdlets = $PSVersionTable.PSVersion.Major -gt 2 -and $ComputerParams.PasswordFile -eq ""
		if($global:UseSQLCmdlets)
		{
			try
			{
				# Push and Pop are to prevent a context switch to the SQL shell from persisting after invocation of SQL commands.
				Push-Location
				Import-Module SQLPS -DisableNameChecking
				Pop-Location
				# Simplest query to return a response to ensure we can query the SQL server
				Invoke-Sqlcmd_ScalarValue -Query 'SELECT 1 as TEST' -RemoteComputerName $ComputerParams.ComputerName -InstanceName $ComputerParams.InstanceName -ScalarValue 'TEST' | Out-Null
			}
			catch
			{
				# Return the error message.
				$msgTemplate = "The computer {0} does not have a SQL Server role or the validation failed"
				$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
				Write-PISysAudit_LogMessage $msg "Warning" $fn
				return
			}
		}
		else
		{
			if((ValidateIfHasSQLServerRole -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName `
											-InstanceName $ComputerParams.InstanceName -dbgl $DBGLevel) -eq $false)
										
			{
				# Return the error message.
				$msgTemplate = "The computer {0} does not have a SQL Server role or the validation failed"
				$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
				Write-PISysAudit_LogMessage $msg "Warning" $fn
				return
			}
		}
		
		# Get the list of functions to execute.
		$listOfFunctions = Get-PISysAudit_FunctionsFromLibrary4
		# There is nothing to execute.
		if($listOfFunctions.Count -eq 0)		
		{
			# Return the error message.
			$msg = "No SQL Server checks have been found."
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}			
		
		# Set message templates.
		$activityMsgTemplate1 = "Check SQL Server component on '{0}' computer"
		$activityMsg1 = [string]::Format($activityMsgTemplate1, $ComputerParams.ComputerName)					
		$statusMsgProgressTemplate1 = "Perform check {0}/{1}"	
		$statusMsgCompleted = "Completed"
		$complianceCheckFunctionTemplate = "Compliance Check function: {0} and arguments are:" `
												+ " Audit Table = {1}, Server Name = {2}, SQL Server Instance Name = {3}," `
												+ " Use Integrated Security  = {4}, User name = {5}, Password file = {6}, Debug Level = {7}"								

		# If no password has been given and SQL Server security is in use,
		# prompt for a password and store in the cache.
		# This will avoid to ask many times to the user when a
		# SQL query is performed.
		if(($ComputerParams.IntegratedSecurity -eq $false) -and ($ComputerParams.PasswordFile -eq ""))
		{ SetSQLAccountPasswordInCache $ComputerParams.ComputerName $ComputerParams.InstanceName $ComputerParams.SQLServerUserID}		
				
		# Proceed with all the compliance checks.
		$i = 0
		foreach($function in $listOfFunctions.GetEnumerator())
		{									
			# Set the progress.
			if($ShowUI)
			{
				# Increment the counter.
				$i++				
				$statusMsg = [string]::Format($statusMsgProgressTemplate1, $i, $listOfFunctions.Count.ToString())
				Write-Progress -activity $activityMsg1 -Status $statusMsg				
			}

			# ............................................................................................................
			# Verbose at Debug Level 2+
			# Show some extra messages.
			# ............................................................................................................							
			$msg = [string]::Format($complianceCheckFunctionTemplate, $function.Name, $AuditTable, $ComputerParams.ComputerName, `
									$ComputerParams.InstanceName, $ComputerParams.IntegratedSecurity, `
									$ComputerParams.SQLServerUserID, $ComputerParams.PasswordFile, $DBGLevel)
			Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 2
			
			# Call the function.
			& $function.Name $AuditTable -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName `
												-InstanceName $ComputerParams.InstanceName `
												-IntegratedSecurity $ComputerParams.IntegratedSecurity `
												-user $ComputerParams.SQLServerUserID `
												-pf $ComputerParams.PasswordFile `
												-dbgl $DBGLevel														
		}
		# Set the progress.
		if($ShowUI)
		{ Write-Progress -activity $activityMsg1 -Status $statusMsgCompleted -completed }
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of SQL Server checks"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return
	}		
}

function StartPICoresightServerAudit
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(										
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,		
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("cp")]		
		$ComputerParams,				
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
					
	# Get and store the function Name.
	$fn = GetFunctionName
	
	try
	{
		# Read from the global constant bag.
		$ShowUI = (Get-Variable "PISysAuditShowUI" -Scope "Global" -ErrorAction "SilentlyContinue").Value					
		$IsElevated = (Get-Variable "PISysAuditIsElevated" -Scope "Global" -ErrorAction "SilentlyContinue").Value	
			
		# Validate the presence of IIS
		if((ValidateIfHasPICoresightRole -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName -dbgl $DBGLevel) -eq $false)
		{
			# Return the error message.
			$msgTemplate = "The computer {0} does not have the PI Coresight role or the validation failed"
			$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}

		if($ComputerParams.IsLocal -and -not($IsElevated))
		{
			$msg = "Elevation required to run Audit checks using IIS Cmdlet.  Run PowerShell as Administrator to complete these checks."
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}

		if((Get-PISysAudit_InstalledWin32Feature -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName -wfn "IIS-ManagementScriptingTools" -DBGLevel $DBGLevel) -ne 1)
		{
			# Return the error message.
			$msgTemplate = "The computer {0} does not have the IIS Management Scripting Tools Feature (IIS cmdlets) or the validation failed; some audit checks may not be available."
			$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}
		
		# Get the list of functions to execute.
		$listOfFunctions = Get-PISysAudit_FunctionsFromLibrary5
		# There is nothing to execute.
		if($listOfFunctions.Count -eq 0)		
		{
			# Return the error message.
			$msg = "No PI Coresight checks have been found."
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}			
		
		# Set message templates.
		$activityMsgTemplate1 = "Check PI Coresight component on '{0}' computer"
		$activityMsg1 = [string]::Format($activityMsgTemplate1, $ComputerParams.ComputerName)					
		$statusMsgProgressTemplate1 = "Perform check {0}/{1}"	
		$statusMsgCompleted = "Completed"
		$complianceCheckFunctionTemplate = "Compliance Check function: {0} and arguments are:" `
												+ " Audit Table = {1}, Server Name = {2}," `
												+ " Debug Level = {3}"									
				
		# Proceed with all the compliance checks.
		$i = 0
		foreach($function in $listOfFunctions.GetEnumerator())
		{									
			# Set the progress.
			if($ShowUI)
			{
				# Increment the counter.
				$i++				
				$statusMsg = [string]::Format($statusMsgProgressTemplate1, $i, $listOfFunctions.Count.ToString())
				Write-Progress -activity $activityMsg1 -Status $statusMsg				
			}

			# ............................................................................................................
			# Verbose at Debug Level 2+
			# Show some extra messages.
			# ............................................................................................................							
			$msg = [string]::Format($complianceCheckFunctionTemplate, $function.Name, $AuditTable, $ComputerParams.ComputerName, $DBGLevel)
			Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 2
			
			# Call the function.
			& $function.Name $AuditTable -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName -dbgl $DBGLevel														
		}
		# Set the progress.
		if($ShowUI)
		{ Write-Progress -activity $activityMsg1 -Status $statusMsgCompleted -completed }
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of PI Coresight checks"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return
	}		
}

# ........................................................................
# Public Functions
# ........................................................................
function Initialize-PISysAudit
{
<#  
.SYNOPSIS
(Core functionality) Initialize the module.
.DESCRIPTION
Initialize the module.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(	
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$ShowUI = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS
{		
	# Read from the global constant bag.
	$isPISysAuditInitialized = (Get-Variable "PISysAuditInitialized" -Scope "Global" -ErrorAction "SilentlyContinue").Value		
			
	# Set folders.
	# Set the initialization flag..
	if(($null -eq $isPISysAuditInitialized) -or ($isPISysAuditInitialized -eq $false))
	{			
		# Set folder names required by the script.
		SetFolders
		
		# Set global variable checking for elevated status.
		$IsElevated = CheckIfRunningElevated
		New-Variable -Name "PISysAuditIsElevated" -Scope "Global" -Visibility "Public" -Value $IsElevated

		# Validate if used with PowerShell version 2.x and more	
		$majorVersionPS = $Host.Version.Major	
		if($majorVersionPS -lt 2)
		{						
			$msg = "This script won't execute under less than version 2.0 of PowerShell"
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}
		 
		# Set the Host/Window settings.
		$appHost = Get-Host		
		$appHost.UI.RawUI.BackgroundColor = "black"
		$appHost.UI.RawUI.ForegroundColor = "white"
		$appHost.UI.RawUI.WindowTitle = "PI System Audit"
		$size = $appHost.UI.RawUI.WindowSize
		$bufferSize = $appHost.UI.RawUI.BufferSize
		$bufferSize.Width = 120
		$size.Width = 120
		$size.Height = 25
		# It does not work all the time.
		try
		{
			$appHost.UI.RawUI.WindowSize = $size
			$appHost.UI.RawUI.BufferSize = $bufferSize
		}
		catch
		{
			# Do nothing and skip the resizing...
		}
		# Clear the screen. For some reasons, the Clear-Host cmdlet does not work.
		cls
		
		# Set the ShowUI flag
		if($null -eq (Get-Variable "PISysAuditShowUI" -Scope "Global" -ErrorAction "SilentlyContinue").Value)
		{ New-Variable -Name "PISysAuditShowUI" -Scope "Global" -Visibility "Public" -Value $true }		
									
		# Set an PISysAuditInitialized flag
		New-Variable -Name "PISysAuditInitialized" -Scope "Global" -Visibility "Public" -Value $true				
	}			
}

END {}

#***************************
#End of exported function
#***************************
}
				
function Set-PISysAudit_SaltKey
{
<#  
.SYNOPSIS
(Core functionality) Create a crypto salt key (16 digits).
.DESCRIPTION
Create a crypto salt key (16 digits).
#>
BEGIN {}
PROCESS
{
	$fn = GetFunctionName
	
	try
	{
		# Initialize the module if needed	
		Initialize-PISysAudit
			
		# Read from the global constant bag.
		$isPISysAuditInitialized = (Get-Variable "PISysAuditInitialized" -Scope "Global" -ErrorAction "SilentlyContinue").Value					
		# If initialization failed, leave the function.
		if(($null -eq $isPISysAuditInitialized) -or ($isPISysAuditInitialized -eq $false))
		{
			$msg = "This script won't execute because initialization has not completed"
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}
		
		$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()		
		$myKey = New-Object System.Byte[] 16
		$rng.GetBytes($myKey)
		return [System.Convert]::ToBase64String($myKey)		
	}
	catch
	{
		# Return the error message.
		$msg = "The creation of a cryptokey has failed."								
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
	}
}

END {}

#***************************
#End of exported function
#***************************
}
  
function New-PISysAudit_PasswordOnDisk
{
<#  
.SYNOPSIS
(Core functionality) Encrypt password on disk.
.DESCRIPTION
Encrypt password on disk.
#>
BEGIN {}
PROCESS
{			
	$fn = GetFunctionName
	
	try
	{				
		# Initialize the module if needed	
		Initialize-PISysAudit
		
		# Read from the global constant bag.
		$isPISysAuditInitialized = (Get-Variable "PISysAuditInitialized" -Scope "Global" -ErrorAction "SilentlyContinue").Value					
		# If initialization failed, leave the function.
		if(($null -eq $isPISysAuditInitialized) -or ($isPISysAuditInitialized -eq $false))
		{
			$msg = "This script won't execute because initialization has not completed"
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}
	
		# Read from the global constant bag.
		$pwdPath = (Get-Variable "PasswordPath" -Scope "Global").Value			
			
		# Get the password.	
		$pwd = Read-Host -assecurestring "Please enter the password to save on disk for further usage"
		
		# Define the file to save it.	
		$file = Read-Host "Please enter the file name to store it"
		# Validate.
		if([string]::IsNullOrEmpty($file))
		{
			Write-PISysAudit_LogMessage "No file name has been entered. Please retry!" "Error" $fn -sc $true
			return
		}
			
		# Set the path.
		$pwdFile = PathConcat -ParentPath $pwdPath -ChildPath $file
		
		# Encrypt.	
		
		# If you want to use Windows Data Protection API (DPAPI) to encrypt the standard string representation
		# leave the key undefined. Visit this URL: http://msdn.microsoft.com/en-us/library/ms995355.aspx to know more.
		# This salt key had been generated with the Set-PISysAudit_SaltKey cmdlet.
		# $mySaltKey = "Fnzg+mrVxXEEmfEMzFwiag=="
		# $keyInBytes = [System.Convert]::FromBase64String($mySaltKey)			
		# $securePWD = ConvertFrom-SecureString $pwd -key $keyInBytes
		$securepwd = ConvertFrom-SecureString $pwd -key (1..16)
				
		# Save.
		Out-File -FilePath $pwdFile -InputObject $securePWD
	}
	catch
	{
		# Return the error message.
		$msgTemplate = "The creation of {0} file containing your password has failed."						
		$msg = [string]::Format($msgTemplate, $pwdFile)
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
	}	
}

END {}

#***************************
#End of exported function
#***************************
}

function Write-PISysAudit_LogMessage
{
<#  
.SYNOPSIS
(Core functionality) Write to console and/or log file (PISystemAudit.log) in the same folder where the script is found.
.DESCRIPTION
Write to console and/or log file (PISystemAudit.log) in the same folder where the script is found.
.NOTES
The non-use of Write-Error, Write-Verbose, Write-Warning have been deliberately taken for design purposes.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(	
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("msg,M")]
		[string]
		$Message,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("mt")]
		[ValidateSet("Error", "Warning", "Info", "Debug")]
		[string]
		$MessageType,						
		[parameter(Mandatory=$true, Position=2, ParameterSetName = "Default")]
		[alias("fn")]			
		[string]
		$FunctionName,						
		[parameter(ParameterSetName = "Default")]
		[alias("dbgl")]			
		[int]
		$CurrentDBGLevel = 0,
		[parameter(ParameterSetName = "Default")]
		[alias("rdbgl")]			
		[int]
		$RequiredDBGLevel = 0,
		[parameter(ParameterSetName = "Default")]
		[alias("sc")]			
		[boolean]
		$ShowToConsole = $false,		
		[parameter(ParameterSetName = "Default")]
		[alias("eo")]			
		[object]
		$ErrorObject = $null)
BEGIN {}
PROCESS
{		
		# Skip if this the proper level is not reached.
		if($CurrentDBGLevel -lt $RequiredDBGLevel) { return }
		
		# Get the defined PISystemAudit log file.
		$logPath = (Get-Variable "PISystemAuditLogFile" -Scope "Global" -ErrorAction "SilentlyContinue").Value								
		
		# Read from the global constant bag.
		$ShowUI = (Get-Variable "PISysAuditShowUI" -Scope "Global" -ErrorAction "SilentlyContinue").Value							
	
		# Get current date
		$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
				
		# Templates
		$msgTemplate1 = "{0}, Function: {1}, Error: {2}."
		$msgTemplate2 = "{0}, Function: {1}, Error: {2}, Details: {3}."
		$msgTemplate3 = "{0}, Function: {1}, Line: {2}, Error: {3}, Details: {4}."
		$msgTemplate4 = "{0}, Warning, {1}."
		$msgTemplate5 = "{0}, Information, {1}."
		$msgTemplate6 = "{0}, Function: {1}, Debug: {2}."				
		
		# Message.
		$extMessageFile = ""
		$extMessageConsole = ""
		
		# Default Color
		$defaultForegroundColor = "Gray"
		$defaultBackgroundColor = "Black"
				
		if($MessageType.ToLower() -eq "error")
		{
			# This type of message is always shown whatever the debug level.
			# Form the message.
			if($null -eq $ErrorObject)
			{ $extMessageFile = [string]::Format($msgTemplate1, $ts, $FunctionName, $Message) }
			else
			{				
				# Remove the trailing period of the error message, template already contains
				# a period to end the message.
				if($ErrorObject.Exception.Message.EndsWith("."))
				{ $modifiedErrorMessage = $ErrorObject.Exception.Message.SubString(0, $ErrorObject.Exception.Message.Length - 1) }
				else
				{ $modifiedErrorMessage = $ErrorObject.Exception.Message }
				
				$extMessageFile = [string]::Format($msgTemplate3, $ts, $FunctionName, `
												$ErrorObject.InvocationInfo.ScriptLineNumber, `
												$Message, $modifiedErrorMessage)
			}
			$extMessageConsole = $extMessageFile
			
			# Write the content.
			Add-Content -Path $logPath -Value $extMessageFile -Encoding ASCII
			
			# Force to show on console.
			$ShowToConsole = $true			
			
			# Set color.
			$defaultForegroundColor = "Red"
			
		}
		elseif($MessageType.ToLower() -eq "warning")
		{						
			# Form the message.
			$extMessageFile = [string]::Format($msgTemplate4, $ts, $Message)
			$extMessageConsole = $extMessageFile
			
			# Write the content.
			Add-Content -Path $logPath -Value $extMessageFile -Encoding ASCII
			
			# Force to show on console.
			$ShowToConsole = $true			
			
			# Set color.
			$defaultForegroundColor = "Yellow"
		}
		elseif($MessageType.ToLower() -eq "info")
		{
			if($Message -ne "")			
			{
				# Form the message.
				$extMessageFile = [string]::Format($msgTemplate5, $ts, $Message)
				$extMessageConsole = $Message
			
				# Write the content.
				Add-Content -Path $logPath -Value $extMessageFile -Encoding ASCII						
			}
		}
		elseif($MessageType.ToLower() -eq "debug")
		{
			# Do nothing if the debug level is not >= required debug level
			if($CurrentDBGLevel -ge $RequiredDBGLevel)
			{			
				# Form the message.
				$extMessageFile = [string]::Format($msgTemplate6, $ts, $FunctionName, $Message)
				$extMessageConsole = $extMessageFile
				
				# Write the content.
				Add-Content -Path $logPath -Value $extMessageFile -Encoding ASCII								
			}
		}
		else
		{			
			$extMessageFile = [string]::Format($msgTemplate1, $ts, $FunctionName, "An invalid level of message has been picked.")
			$extMessageConsole = $extMessageFile			
				
			# Write the content.
			Add-Content -Path $logPath -Value $extMessageFile -Encoding ASCII								
			
			# Set color.
			$defaultForegroundColor = "Red"						
		}
		
		# Show at the console?.
		if($ShowToConsole -and $ShowUI) { Write-Host $extMessageConsole -ForeGroundColor $defaultForegroundColor -BackgroundColor $defaultBackgroundColor }
	}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_EnvVariable
{
<#
.SYNOPSIS
(Core functionality) Get a machine related environment variable.
.DESCRIPTION
Get a machine related environment variable.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("vn")]
		[string]
		$VariableName,		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("t")]
		[ValidateSet("Machine", "User", "Process")]
		[string]
		$Target = "Machine",				
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
	$fn = GetFunctionName
	
	try
	{
		# Execute the GetEnvironmentVariable method locally or remotely via the Invoke-Command cmdlet.
		# Always use the Machine context to write the variable.
		if($LocalComputer)
		{
			$value = [Environment]::GetEnvironmentVariable($VariableName, $Target)
		}
		else
		{			
			$scriptBlockCmd = [string]::Format("[Environment]::GetEnvironmentVariable(`"{0}`", `"{1}`")", $VariableName, $Target)
			
			# Verbose if debug level is 2+
			$msgTemplate = "Script block to execute against {0} machine is {1}"
			$msg = [string]::Format($msgTemplate, $RemoteComputerName, $scriptBlockCmd)
			Write-PISysAudit_LogMessage $msg "Debug" $fn -rdbgl 2 -dbgl $DBGLevel	
			
			$scriptBlock = [scriptblock]::create( $scriptBlockCmd )
			$value = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock			
			
			# Verbose if debug level is 2+
			$msgTemplate = "Value returned is {0}"
			$msg = [string]::Format($msgTemplate, $value)
			Write-PISysAudit_LogMessage $msg "Debug" $fn -rdbgl 2 -dbgl $DBGLevel				
		}
		
		# Return the value found.
		return $value
	}	
	catch
	{
		# Return the error message.
		$msgTemplate1 = "A problem occurred during the reading of the environment variable: {0} from local machine."
		$msgTemplate2 = "A problem occurred during the reading of the environment variable: {0} from {1} machine."
		if($LocalComputer)
		{ $msg = [string]::Format($msgTemplate1, $_.Exception.Message) }
		else
		{ $msg = [string]::Format($msgTemplate2, $_.Exception.Message, $RemoteComputerName) }
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return $null
	}		
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_RegistryKeyValue
{
<#
.SYNOPSIS
(Core functionality) Read a value from the Windows Registry Hive.
.DESCRIPTION
Read a value from the Windows Registry Hive.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("rkp")]
		[string]
		$RegKeyPath,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("a")]
		[string]
		$Attribute,
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
	$fn = GetFunctionName
	
	try
	{
		$scriptBlockCmdTemplate = "(Get-ItemProperty -Path `"{0}`" -Name `"{1}`").{1}"
		$scriptBlockCmd = [string]::Format($scriptBlockCmdTemplate, $RegKeyPath, $Attribute)
		$scriptBlock = [scriptblock]::create( $scriptBlockCmd )
		# Execute the Get-ItemProperty cmdlet method locally or remotely via the Invoke-Command cmdlet.
		if($LocalComputer)
		{						
			# To only obtain the property of the registry key, it is easier to use a dynamic script.			
			$value = Invoke-Command -ScriptBlock $scriptBlock			
		}
		else
		{			
			$value = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock
		}
	
		# Return the value found.
		return $value		
	}
	catch
	{
		# Return the error message.
		$msgTemplate1 = "A problem occurred during the reading of the registry key: {0} from local machine."
		$msgTemplate2 = "A problem occurred during the reading of the registry key: {0} from {1} machine."
		if($LocalComputer)
		{ $msg = [string]::Format($msgTemplate1, $_.Exception.Message) }
		else
		{ $msg = [string]::Format($msgTemplate2, $_.Exception.Message, $RemoteComputerName) }
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_IISproperties
{
<#
.SYNOPSIS
(Core functionality) Enables use of the WebAdministration module.
.DESCRIPTION
Get IIS: properties.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("qry")]
		[string]
		$query,
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
	$fn = GetFunctionName
	
	try
	{
		# This approach works, but can be optimized


		# Get the query string and create a scriptblock
		$scriptBlock = [scriptblock]::create( $query )

		# Execute the Get-ItemProperty cmdlet method locally or remotely via the Invoke-Command cmdlet
		if($LocalComputer)		
		{						
			
			# Import the WebAdministration module
			Import-Module -Name "WebAdministration"		
			
			# Execute the command locally	
			$value = Invoke-Command -ScriptBlock $scriptBlock			
		}
		else
		{	
					
			# Establishing a new PS session on a remote computer		
			$PSSession = New-PSSession -ComputerName $RemoteComputerName

			# Importing WebAdministration module within the PS session
			Invoke-Command -Session $PSSession -ScriptBlock {Import-Module WebAdministration}
			
			# Execute the command within a remote PS session
			$value = Invoke-Command -Session $PSSession -ScriptBlock $scriptBlock
			Remove-PSSession -ComputerName $RemoteComputerName
		}
	
		# Return the value found.
		return $value		
	}
	catch
	{
		# Return the error message.
		$msgTemplate1 = "A problem occurred during the reading of IIS Property: {0} from local machine."
		$msgTemplate2 = "A problem occurred during the reading of IIS Property: {0} from {1} machine."
		if($LocalComputer)
		{ $msg = [string]::Format($msgTemplate1, $_.Exception.Message) }
		else
		{ $msg = [string]::Format($msgTemplate2, $_.Exception.Message) }
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_TestRegistryKey
{
<#
.SYNOPSIS
(Core functionality) Test for the existence of a key in the Windows Registry Hive.
.DESCRIPTION
Test for the existence of a key in the Windows Registry Hive.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("rkp")]
		[string]
		$RegKeyPath,
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
	$fn = GetFunctionName
	
	try
	{
		# To only obtain the property of the registry key, it is easier to use a dynamic script.			
		$scriptBlockCmdTemplate = "`$(Test-Path `"{0}`")"
		$scriptBlockCmd = [string]::Format($scriptBlockCmdTemplate, $RegKeyPath)
		$scriptBlock = [scriptblock]::create( $scriptBlockCmd )

		# Execute the Test-Path cmdlet method locally or remotely via the Invoke-Command cmdlet.
		if($LocalComputer)
		{						
			$value = Invoke-Command -ScriptBlock $scriptBlock			
		}
		else
		{			
			$value = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock
		}
	
		# Return the value found.
		return $value		
	}
	catch
	{
		# Return the error message.
		$msgTemplate1 = "A problem occurred during the reading of the registry key: {0} from local machine."
		$msgTemplate2 = "A problem occurred during the reading of the registry key: {0} from {1} machine."
		if($LocalComputer)
		{ $msg = [string]::Format($msgTemplate1, $_.Exception.Message) }
		else
		{ $msg = [string]::Format($msgTemplate2, $_.Exception.Message) }
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_ServiceLogOnAccount
{
<#
.SYNOPSIS
(Core functionality) Get the logon account of a service on a given computer.
.DESCRIPTION
Get the logon account of a service on a given computer.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("sn")]
		[string]
		$ServiceName,
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
	$fn = GetFunctionName
	
	try
	{
		$className = "Win32_Service"
		$namespace = "root\CIMV2"
		$filterExpression = [string]::Format("name='{0}'", $ServiceName)				
		$WMIObject = ExecuteWMIQuery $className -n $namespace -lc $LocalComputer -rcn $RemoteComputerName -FilterExpression $filterExpression -DBGLevel $DBGLevel								
		return $WMIObject.StartName				
	}
	catch
	{
		# Return the error message.				
		Write-PISysAudit_LogMessage "Execution of WMI Query has failed!" "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_ParseDomainAndUserFromString
{
<#
.SYNOPSIS
(Core functionality) Parse the domain portion out of an account string.
.DESCRIPTION
Parse the domain portion out of an account string.  Supports UPN or Down-Level format
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("us")]
		[string]
		$UserString,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS
{
	$fn = GetFunctionName
	try
	{
		If ($UserString -eq "LocalSystem" -or $UserString -eq "NetworkService" `
			-or $UserString -eq "NT AUTHORITY\LocalSystem" -or $UserString -eq "NT AUTHORITY\NetworkService" `
			-or $UserString -eq "ApplicationPoolIdentity" `
			-or $UserString -eq "NT SERVICE\AFService") 
		{ 
			$ServiceAccountDomain = 'MACHINEACCOUNT'
			$parsingPosDL = $UserString.IndexOf('\')
			If($parsingPosDL -ne -1 ) 
			{
				$ServiceAccount = $UserString.Substring($parsingPosDL+1)
			}
			Else 
			{
				$ServiceAccount = $UserString
			}
		}
		Else{
			# Parse as UPN or Down-Level Logon format
			$parsingPosDL = $UserString.IndexOf('\') # DL
			$parsingPosUPN = $UserString.IndexOf('@') # UPN
			If($parsingPosDL -ne -1 ) 
			{
				$ServiceAccountDomain = $UserString.Substring(0,$parsingPosDL)
				$ServiceAccount = $UserString.Substring($parsingPosDL+1)
			}
			ElseIf($parsingPosUPN -ne -1)
			{
				$ServiceAccountDomain = $UserString.Substring($parsingPosUPN+1)
				$ServiceAccount = $UserString.Substring(0,$parsingPosUPN)
			}
			Else
			{
				$ServiceAccountDomain = $null
				$ServiceAccount = $UserString
			}
		}

		$AccountObject = New-Object PSCustomObject					
		Add-Member -InputObject $AccountObject -MemberType NoteProperty -Name "UserName" -Value $ServiceAccount
		Add-Member -InputObject $AccountObject -MemberType NoteProperty -Name "Domain" -Value $ServiceAccountDomain	

		return $AccountObject			
	}
	catch
	{
		# Return the error message.				
		Write-PISysAudit_LogMessage "Unable to determine account domain." "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_ServiceState
{
<#
.SYNOPSIS
(Core functionality) Get the state of a service on a given computer.
.DESCRIPTION
Get the state of a service on a given computer.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("sn")]
		[string]
		$ServiceName,
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
	$fn = GetFunctionName
	
	try
	{
		$className = "Win32_Service"
		$namespace = "root\CIMV2"
		$filterExpression = [string]::Format("name='{0}'", $ServiceName)
		$WMIObject = ExecuteWMIQuery $className -n $namespace -lc $LocalComputer -rcn $RemoteComputerName -FilterExpression $filterExpression -DBGLevel $DBGLevel								
		return $WMIObject.State
	}
	catch
	{
		
		# Return the error message.
		Write-PISysAudit_LogMessage "Execution of WMI Query has failed!" "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_InstalledComponents
{
<#
.SYNOPSIS
(Core functionality) Get installed software on a given computer.
.DESCRIPTION
Get installed software on a given computer.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(		
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
	$fn = GetFunctionName
	
	try
	{				
		if($LocalComputer)
		{
			$unsortedAndUnfilteredResult = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall | ForEach-Object { Get-ItemProperty $_.PsPath } | Where-Object { $_.Displayname -and ($_.Displayname -match ".*") }
			$result = $unsortedAndUnfilteredResult | Sort-Object Displayname | Select-Object DisplayName, Publisher, DisplayVersion, InstallDate			
			return $result
		}
		else
		{	
			$scriptBlockCmd = "Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall | ForEach-Object { Get-ItemProperty `$_.PsPath } | Where-Object { `$_.Displayname -and (`$_.Displayname -match `".*`") }"
			# Create the script block to send via PS Remoting.
			$scriptBlock = [scriptblock]::create( $scriptBlockCmd )
			$unsortedAndUnfilteredResult = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock									
			$result = $unsortedAndUnfilteredResult | Sort-Object Displayname | Select-Object DisplayName, Publisher, DisplayVersion, InstallDate
			return $result			
		}	
	}
	catch
	{
		
		# Return the error message.
		Write-PISysAudit_LogMessage "Reading the registry for installed components failed!" "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_InstalledKBs
{
<#
.SYNOPSIS
(Core functionality) Get installed Microsoft KBs (patches) on a given computer.
.DESCRIPTION
Get installed Microsoft KBs (patches) on a given computer.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(		
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
	$fn = GetFunctionName
	
	try
	{									
		$className = "Win32_quickfixengineering"
		$namespace = "root\CIMV2"
		$filterExpression = ""
		$WMIObject = ExecuteWMIQuery $className -n $namespace -lc $LocalComputer -rcn $RemoteComputerName -FilterExpression $filterExpression -DBGLevel $DBGLevel								
		return $WMIObject | Sort-Object HotFixID | Select-Object HotFixID, InstalledOn						
	}
	catch
	{
		
		# Return the error message.
		Write-PISysAudit_LogMessage "Execution of WMI Query has failed!" "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_InstalledWin32Feature
{
<#
.SYNOPSIS
(Core functionality) Get install status of Windows Feature on a given computer.
.DESCRIPTION
Get install status of Windows Feature on a given computer.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("wfn")]
		[string]
		$WindowsFeatureName,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{		
	$fn = GetFunctionName
	
	try
	{									
		$className = "Win32_OptionalFeature"
		$namespace = "root\CIMV2"		
		$filterExpressionTemplate = "Name='{0}'"
		$filterExpression = [string]::Format($filterExpressionTemplate, $WindowsFeatureName)
		$WMIObject = ExecuteWMIQuery $className -n $namespace -lc $LocalComputer -rcn $RemoteComputerName -FilterExpression $filterExpression -DBGLevel $DBGLevel										
		return $WMIObject.InstallState
	}
	catch
	{
		
		# Return the error message.
		Write-PISysAudit_LogMessage "Reading the registry for installed components failed!" "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_FirewallState
{
<#
.SYNOPSIS
(Core functionality) Validate the state of a firewall.
.DESCRIPTION
Validate the state of a firewall.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(		
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
	$fn = GetFunctionName
	
	try
	{									
		
		# Set the path to netsh CLU.
		$windowsFolder = Get-PISysAudit_EnvVariable "WINDIR" -lc $LocalComputer -rcn $RemoteComputerName
		$netshExec = PathConcat -ParentPath $windowsFolder -ChildPath "System32\netsh.exe"

		if($LocalComputer)
		{			
			# Get the Scripts path.
			$scriptTempFileLocation = (Get-Variable "ScriptsPathTemp" -Scope "Global").Value																			                                                             						
			# Set the arguments of netsh.exe
			$argList = "advfirewall show allprofiles state"						
		}
		else
		{
			# Get the PIHome folder.
			$PIHome_path = Get-PISysAudit_EnvVariable "PIHOME" -lc $false -rcn $RemoteComputerName											           
			# Set the log folder.
			$scriptTempFileLocation = PathConcat -ParentPath $PIHome_path -ChildPath "dat"                          			                                						
			# Set the arguments of netsh.exe
			$argList = "'advfirewall show allprofiles state'"
		}
		# Set the output for the CLU.
		$outputFilePath = PathConcat -ParentPath $scriptTempFileLocation -ChildPath "netsh_output.txt"
		$outputFileContent = ExecuteCommandLineUtility -lc $LocalComputer -rcn $RemoteComputerName -UtilityExec $netshExec `
																			-ArgList $argList -OutputFilePath $outputFilePath -dbgl $DBGLevel
		
		# Return the content.
		return $outputFileContent
	}
	catch
	{
		# Return the error message.
		Write-PISysAudit_LogMessage "A problem occurred when calling the netsh command." "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_AppLockerState
{
<#
.SYNOPSIS
(Core functionality) Get the state of AppLocker.
.DESCRIPTION
Get the state of AppLocker.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(		
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
	$fn = GetFunctionName
	
	try
	{									
		$scriptBlockCmd = " if(`$PSVersionTable.PSVersion.Major -ge 3) [Get-AppLockerPolicy -Effective -XML] else [`$null] "
		$scriptBlockCmd = ($scriptBlockCmd.Replace("[", "{")).Replace("]", "}")	
		$scriptBlock = [scriptblock]::create( $scriptBlockCmd )
		if($LocalComputer)
		{			                    			
			$appLockerPolicy = Invoke-Command -ScriptBlock $scriptBlock
		}
		else
		{                            				
			$appLockerPolicy = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock
		}
		
		# Return the content.
		return $appLockerPolicy
	}
	catch
	{
		
		# Return the error message.
		Write-PISysAudit_LogMessage "A problem occurred while retrieving the AppLocker configuration." "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

Function Get-PISysAudit_KnownServers
{
<#
.SYNOPSIS
(Core functionality) Get the servers in the PI Data Archive or PI AF Server KST.
.DESCRIPTION
Get the servers in the PI Data Archive or PI AF Server KST.
#>
	param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]		
		[alias("rcn")]
		[string]
		$RemoteComputerName,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("st")]
		[ValidateSet('PIServer','AFServer')]
		[string] 
		$ServerType,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	
	)	

	$fn = GetFunctionName

	If($ServerType -eq 'PIServer')
	{
		# Get PI Servers
		$regpathKST = 'HKLM:\SOFTWARE\PISystem\PI-SDK\1.0\ServerHandles'
		if($LocalComputer)
		{
			$KnownServers = Get-ChildItem $regpathKST | ForEach-Object {Get-ItemProperty $_.pspath} | where-object {$_.path} | Foreach-Object {$_.path}
		}
		Else
		{
			$scriptBlockCmdTemplate = "Get-ChildItem `"{0}`" | ForEach-Object [ Get-ItemProperty `$_.pspath ] | where-object [ `$_.path ] | Foreach-Object [ `$_.path ]"
			$scriptBlockCmd = [string]::Format($scriptBlockCmdTemplate, $regpathKST)
			$scriptBlockCmd = ($scriptBlockCmd.Replace("[", "{")).Replace("]", "}")			
			$scriptBlock = [scriptblock]::create( $scriptBlockCmd )													
			$KnownServers = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock 
		}
	}
	Else
	{
		# Get AF Servers
		$programDataWebServer = Get-PISysAudit_EnvVariable "ProgramData" -lc $LocalComputer -rcn $RemoteComputerName  -Target Process
		$afsdkConfigPathWebServer = "$programDataWebServer\OSIsoft\AF\AFSDK.config"
		if($LocalComputer)
		{
			$AFSDK = Get-Content -Path $afsdkConfigPathWebServer | Out-String
		}
		Else
		{
			$scriptBlockCmdTemplate = "Get-Content -Path ""{0}"" | Out-String"
			$scriptBlockCmd = [string]::Format($scriptBlockCmdTemplate, $afsdkConfigPathWebServer)									
			
			# Verbose only if Debug Level is 2+
			$msgTemplate = "Remote command to send to {0} is: {1}"
			$msg = [string]::Format($msgTemplate, $RemoteComputerName, $scriptBlockCmd)
			Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2
			
			$scriptBlock = [scriptblock]::create( $scriptBlockCmd )
			$AFSDK = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock
		}
		$KnownServers = [regex]::Matches($AFSDK, 'host=\"([^\"]*)')
	}

	$msgTemplate = "Known servers found: {0}"
	$msg = [string]::Format($msgTemplate, $KnownServers)
	Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2

	return $KnownServers
}

function Get-PISysAudit_CheckPrivilege
{
<#
.SYNOPSIS
(Core functionality) Return the access token (security) of a process or service.
.DESCRIPTION
Return the access token (security) of a process or service.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("priv")]		
		[ValidateSet(
			"All","SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", 
			"SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege", 
			"SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege", 
			"SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", 
			"SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", 
			"SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege", 
			"SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", 
			"SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", 
			"SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege", 
			"SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege", 
			"SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
		[string]
		$Privilege,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("sn")]
		[string]
		$ServiceName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("pn")]
		[string]
		$ProcessName = "",		
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
	$fn = GetFunctionName
	
	try
	{						
		# Must validate against a service or a process.
		if(($null -eq $ServiceName) -and ($null -eq $ProcessName))
		{
			# Return the error message.
			$msg = "Reading privileges from the process failed. The syntax is: CheckProcessPrivilege.ps1 <Privilege Name> [<Service Name>] [<Process Name>]."
					 + " Cannot process two items at a time!"		
			Write-PISysAudit_LogMessage $msg "Error" $fn			
			return $null
		}		

		# Set the path to the inner script.
		$scriptsPath = (Get-Variable "scriptsPath" -Scope "Global").Value														
		$checkProcessPrivilegePSScript = PathConcat -ParentPath $scriptsPath -ChildPath "CheckProcessPrivilege.ps1"																											
		#......................................................................................
		# Verbose only if Debug Level is 2+
		#......................................................................................
		$msgTemplate1 = "Command to execute is: {0}"
		$msgTemplate2 = "Remote command to send to {0} is: {1}"		
		$PS1ScriptFileExecTemplate1 = "CheckProcessPrivilege.ps1 `"{0}`" `"{1}`" `"`" {2}"
		$PS1ScriptFileExecTemplate2 = "CheckProcessPrivilege.ps1 `"{0}`" `"`" `"{1}`" {2}"				
		if($ProcessName -eq "")
		{ $PS1ScriptFileExec = [string]::Format($PS1ScriptFileExecTemplate1, $Privilege, $ServiceName, $DBGLevel) }
		if($ServiceName -eq "")
		{ $PS1ScriptFileExec = [string]::Format($PS1ScriptFileExecTemplate2, $Privilege, $ProcessName, $DBGLevel) }		
		
		if($LocalComputer)
		{ $msg = [string]::Format($msgTemplate1, $PS1ScriptFileExec) }
		else
		{ $msg = [string]::Format($msgTemplate2, $RemoteComputerName, $PS1ScriptFileExec) }				
		Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2
		
		#......................................................................................
		# Launch the execution of the inner script
		#......................................................................................
		if($LocalComputer)
		{ $result = & $checkProcessPrivilegePSScript $Privilege $ServiceName $ProcessName $DBGLevel }
		else
		{ 
			# Define the list of arguments (Remote execution only).
			if(!($LocalComputer))
			{
				$argList = @()
				$argList += $Privilege
				$argList += $ServiceName
				$argList += $ProcessName
				$argList += $DBGLevel
			}
			$result = Invoke-Command -ComputerName $RemoteComputerName -FilePath $checkProcessPrivilegePSScript -ArgumentList $argList
		}
	}
	catch
	{
		# Return the error message.
		$msg = "Reading privileges from the process failed"
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}
	
	# Return the result.
	return $result
}

END {}

#***************************
#End of exported function
#***************************
}

function Invoke-PISysAudit_AFDiagCommand
{
<#
.SYNOPSIS
(Core functionality) Perform a diagnostic check with the AFDiag.exe command.
.DESCRIPTION
Perform a diagnostic check with the AFDiag.exe command.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
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
		$DBGLevel = 0,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[ValidateSet("Write","Read","Delete")]
		[alias("oper")]
		[string]
		$Operation)
BEGIN {}
PROCESS		
{						
	$fn = GetFunctionName
	
	try
	{
		#......................................................................................
		# Set Paths
		#......................................................................................
		# Set the PIPC folder (64 bit).		
		$PIHome64_path = Get-PISysAudit_EnvVariable "PIHOME64" -lc $LocalComputer -rcn $RemoteComputerName
		# Set the PIPC\AF folder (64 bit).		
		$PIHome_AF_path = PathConcat -ParentPath $PIHome64_path -ChildPath "AF"
		# Set the path to reach out the afdiag.exe CLU.
		$AFDiagExec = PathConcat -ParentPath $PIHome_AF_path -ChildPath "afdiag.exe"
		# Set the path to reach out the AFService executable.
		$pathToService = PathConcat -ParentPath $PIHome_AF_path -ChildPath "AFService.exe"

		if($LocalComputer)
		{						
			$IsElevated = (Get-Variable "PISysAuditIsElevated" -Scope "Global" -ErrorAction "SilentlyContinue").Value
			
			if(-not($IsElevated))
			{
				$msg = "Elevation required to run Audit checks using AFDiag.  Run PowerShell as Administrator to complete these checks."
				Write-PISysAudit_LogMessage $msg "Warning" $fn
				return $null
			}

			# Set the output folder.
			$scriptTempFilesPath = (Get-Variable "scriptsPathTemp" -Scope "Global").Value 
			# Define the arguments required by the afdiag.exe command						
			$argListTemplate = "/ExeFile:`"{0}`""	                          			                                
		}
		else
		{																		
			$PIHome_path = Get-PISysAudit_EnvVariable "PIHOME" -lc $false -rcn $RemoteComputerName
			# Set the PIPC\dat folder (64 bit).
			$scriptTempFilesPath = PathConcat -ParentPath $PIHome_path -ChildPath "dat"		                                       						                                   					                                      
			# Define the arguments required by the afdiag.exe command						
			$argListTemplate = "'/ExeFile:`"{0}`"'"	
		}
		$argList = [string]::Format($ArgListTemplate, $pathToService)
		
		# Set the output for the CLU.
        $outputFilePath = PathConcat -ParentPath $scriptTempFilesPath -ChildPath "afdiag_output.txt"
		$outputFileContent = ExecuteCommandLineUtility -lc $LocalComputer -rcn $RemoteComputerName -UtilityExec $AFDiagExec `
														-ArgList $argList -OutputFilePath $outputFilePath -Operation $Operation -DBGLevel $DBGLevel	
		
		if($Operation -eq "Read"){ return $outputFileContent }			
	}
	catch
	{
		# Return the error message.
		$msgTemplate1 = "A problem occurred with afdiag.exe on local computer"
		$msgTemplate2 = "A problem occurred with afdiag.exe on {0} computer"
		if($LocalComputer)
		{ $msg = $msgTemplate1 }
		else
		{ $msg = [string]::Format($msgTemplate2, $RemoteComputerName) }		
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Invoke-PISysAudit_PIConfigScript
{
<#
.SYNOPSIS
(Core functionality) Perform a given piconfig script locally or remotely.
.DESCRIPTION
Perform a given piconfig script locally or remotely.
#>
[CmdletBinding(DefaultParameterSetName="File", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$false, ParameterSetName = "File")]
		[parameter(Mandatory=$false, ParameterSetName = "Script")]
		[alias("f")]
		[string]
		$File = "",
		[parameter(Mandatory=$false, ParameterSetName = "File")]
		[parameter(Mandatory=$false, ParameterSetName = "Script")]
		[alias("pcs")]
		[string]
		$PIConfigScript = "",
		[parameter(Mandatory=$false, ParameterSetName = "File")]
		[parameter(Mandatory=$false, ParameterSetName = "Script")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "File")]
		[parameter(Mandatory=$false, ParameterSetName = "Script")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "File")]
		[parameter(Mandatory=$false, ParameterSetName = "Script")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{											
	$fn = GetFunctionName
	
	try
	{
		#......................................................................................
		# Validate the arguments passed
		#......................................................................................
		# Set the adhoc flag.
		$UseAdhocScript = $false				
		
		if([string]::IsNullOrEmpty($File) -and [string]::IsNullOrEmpty($PIConfigScript))
		{
			# Return the error message.		
			$msg = "No script file or piconfig script was passed to the function. The syntax is" `
						+ " Invoke-PISysAudit_PIConfigScript [-f <file name> | -psc <script content>] [-lc <true or false> [-rcn <remote computer name>]]"
			Write-PISysAudit_LogMessage $msg "Error" $fn
			return $null
		}
		elseif(!([string]::IsNullOrEmpty($File)) -and !([string]::IsNullOrEmpty($PIConfigScript)))
		{
			# if both parameters were passed, use the file.
			$UseAdhocScript = $false					
		}	
		elseif(([string]::IsNullOrEmpty($File)) -and !([string]::IsNullOrEmpty($PIConfigScript)))
		{ $UseAdhocScript = $true }
				
		# If the the script file is used and the name contains the trace of folder.
		if(($UseAdhocScript -eq $false) -and ($File.Contains("\")))
		{					
			# Return the error message.		
			$msgTemplate = "A path was specified with your script file and this feature is not supported. You need to specify the file name only containing" `
								+ " your script under the {0} folder"
			$msg = [string]::Format($msgTemplate, $picnfgPath)
			Write-PISysAudit_LogMessage $msg "Error" $fn
			return $null
		}				
		
		# Get the script path.
		$picnfgPath = (Get-Variable "PIConfigScriptPath" -Scope "Global").Value								
		
		if($LocalComputer)
		{										
			#......................................................................................
			# Set Paths
			#......................................................................................			
            # Get the Scripts Temp path.
			$scriptsPathTemp = (Get-Variable "scriptsPathTemp" -Scope "Global").Value
			# Get the Scripts path.
			$scriptsPath = (Get-Variable "scriptsPath" -Scope "Global").Value
			# Set the path to reach out the piconfig.exe CLU.												
			$piconfigExec = (Get-Variable "PISysAuditPIConfigExec" -Scope "Global").Value			
			
			# ............................................................................................................
			# Verbose at Debug Level 1+
			# Show some extra messages.
			# ............................................................................................................			
			$msgTemplate = "scriptsPath = {0}, piconfigExec = {1}"
			$msg = [string]::Format($msgTemplate, $scriptsPath, $piconfigExec)
			Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 1
		
			# Set the input for the CLU.			
			if($UseAdhocScript)
			{
				# Set the path for the .dif file containing the script for piconfig.exe
				$PIConfigInputFilePath = PathConcat -ParentPath $scriptsPathTemp -ChildPath "input.dif"         								
				# Create the input file.
				Out-File -FilePath $PIConfigInputFilePath -InputObject $PIConfigScript -Encoding ASCII
			}
			else
			{
				# Set the path for the .dif file containing the script for piconfig.exe				
				$PIConfigInputFilePath = PathConcat -ParentPath $picnfgPath -ChildPath $File								
				
				# Validate that the .dif file specified exists.
				if((Test-Path $PIConfigInputFilePath) -eq $false)
				{
					# Return the error message.		
					$msgTemplate = "The specified piconfig script file ({0}) was not found."
					$msg = [string]::Format($msgTemplate, $PIConfigInputFilePath)
					Write-PISysAudit_LogMessage $msg "Error" $fn
					return $null
				}

				

			}
			
			# Construct new input file for the CLU
			# Set the PIconfig output
			$outputFilePath = PathConcat -ParentPath $scriptsPathTemp -ChildPath "piconfig_output.txt"
			$inputFilePath = PathConcat -ParentPath $scriptsPathTemp -ChildPath "piconfig_input.dif"
			

			if(Test-Path $outputFilePath){Clear-Content $outputFilePath}
			if(Test-Path $inputFilePath){Clear-Content $inputFilePath}
			

			Out-File -FilePath $inputFilePath -InputObject ("@outp " + $outputFilePath) -Encoding ASCII	
			Add-Content -Path $inputFilePath -Value ("@echo none")
			Add-Content -Path $inputFilePath -Value (Get-Content $PIConfigInputFilePath)			

			# Start a piconfig as a local session.
			# As the command is local to the PI Data Archive it will make use of Named Pipe.
			Start-Process -FilePath $PIConfigExec `
				-RedirectStandardInput $inputFilePath `
				-Wait -NoNewWindow			
				
			#	$msg = Get-Content -Path $outputDebugFilePath | Out-String
			Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 2

			# Read the content.
			$outputFileContent = Get-Content -Path $outputFilePath

			if(Test-Path $outputFilePath){Remove-Item $outputFilePath}
			if(Test-Path $inputFilePath){Remove-Item $inputFilePath}
		}
		else
		{					
			# PS Remoting impersonates the command (piconfig) under a network user on the remote computer, this will
			# create and use a PISDK object after the impersonation process. As the token does not contain any local
			# logon privilege, this will fail the connection.
			# This is due to the reduced permissions of the impersonated PISDK on the local machine that is
			# prevented from using local resources (PINS subsystems) because pinetmgr (PINS component)
			# pinetmgr) started using tighter security with released version 3.4.375.79 and later.
			
			#......................................................................................
			# Set Paths
			#......................................................................................
			# Get the Scripts path.
			$scriptsPath = (Get-Variable "ScriptsPath" -Scope "Global").Value
			# Get the Scripts Temp path.
			$scriptsPathTemp = (Get-Variable "ScriptsPathTemp" -Scope "Global").Value
			# Set the path to reach out the piconfig.exe CLU.												
			$piconfigExec = (Get-Variable "PISysAuditPIConfigExec" -Scope "Global").Value			
									
			# ............................................................................................................
			# Verbose at Debug Level 1+
			# Show some extra messages.
			# ............................................................................................................			
			$msgTemplate = "scriptsPath = {0}, piconfigExec = {1}"
			$msg = [string]::Format($msgTemplate, $scriptsPath, $piconfigExec)
			Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 1
			
			# Set the input for the CLU.
			if($UseAdhocScript)
			{
				# Set the path for the .dif file containing the script for piconfig.exe
				$PIConfigInputFilePath = PathConcat -ParentPath $scriptsPathTemp -ChildPath "input.dif"         
				# Create the input file.
				Out-File -FilePath $PIConfigInputFilePath -InputObject $PIConfigScript -Encoding ASCII
			}
			else
			{
				# Set the path for the .dif file containing the script for piconfig.exe				
				$PIConfigInputFilePath = PathConcat -ParentPath $picnfgPath -ChildPath $File				
				

				# Validate that the .dif file specified exists.
				if((Test-Path $PIConfigInputFilePath) -eq $false)
				{
					# Return the error message.		
					$msgTemplate = "The specified piconfig script file ({0}) was not found."
					$msg = [string]::Format($msgTemplate, $PIConfigInputFilePath)
					Write-PISysAudit_LogMessage $msg "Error" $fn
					return $null
				}
			}
						
			# Use the Windows IS authentication mechanism first and the Trust one if
			# if fails.
			$argList1 = [string]::Format(" -Node `"{0}`" -Windows", $RemoteComputerName)					
			$argList2 = [string]::Format(" -Node `"{0}`" -Trust", $RemoteComputerName)																		
			
			# Construct new input file for the CLU
			# Set the PIconfig output
			$outputFilePath = PathConcat -ParentPath $scriptsPathTemp -ChildPath "piconfig_output.txt"
			$inputFilePath = PathConcat -ParentPath $scriptsPathTemp -ChildPath "piconfig_input.dif"
			$errFilePath = PathConcat -ParentPath $scriptsPathTemp -ChildPath "piconfig_err_output.txt"

			if(Test-Path $outputFilePath){Clear-Content $outputFilePath}
			if(Test-Path $inputFilePath){Clear-Content $inputFilePath}
			if(Test-Path $errFilePath){Clear-Content $errFilePath}

			Out-File -FilePath $inputFilePath -InputObject ("@outp " + $outputFilePath) -Encoding ASCII	
			Add-Content -Path $inputFilePath -Value ("@echo none")
			Add-Content -Path $inputFilePath -Value (Get-Content $PIConfigInputFilePath)

			#......................................................................................
			# Start a piconfig remote session.
			#......................................................................................
			Start-Process -FilePath $PIConfigExec `
				-ArgumentList $argList1 `
				-RedirectStandardInput $inputFilePath `
				-RedirectStandardOutput $errFilePath `
				-Wait -NoNewWindow																					
			
			#......................................................................................
			# Read the content remotely.
			#......................................................................................			
			$outputFileContent = Get-Content -Path $outputFilePath												
			
			if($null -eq $outputFileContent)
			{
				$outputFileContent = ""
				$errFileContent = Get-Content -Path $errFilePath
				if($null -ne $errFileContent)
				{ 
					if(ValidateFileContent $errFileContent "no read access")
					{
						# Return the error message.		
						$msgTemplate = "An authentication or authorization issue occurred with piconfig while running {0}"
						$msg = [string]::Format($msgTemplate, $inputFilePath)
						Write-PISysAudit_LogMessage $msg "Error" $fn
						return $null
					}
				}
			}

			#......................................................................................			
			# Validate that the command succeeded
			#......................................................................................									
			if(ValidateFileContent $outputFileContent "no access")
			{
				#......................................................................................
				# Start a piconfig remote session.
				#......................................................................................
				Start-Process -FilePath $PIConfigExec `
					-ArgumentList $argList2 `
					-RedirectStandardInput $inputFilePath `
					-Wait -NoNewWindow
					
				#......................................................................................
				# Read the content remotely.
				#......................................................................................			
				$outputFileContent = Get-Content -Path $outputFilePath 												
				
				#......................................................................................			
				# Validate that the command succeeded (2nd time)
				#......................................................................................			
				if(ValidateFileContent $outputFileContent "no access")
				{
					# Return the error message.		
					$msg = "An authentication problem occurred with piconfig.exe"
					Write-PISysAudit_LogMessage $msg "Error" $fn
					return $null		
				}
			}

			if(Test-Path $outputFilePath){Remove-Item $outputFilePath}
			if(Test-Path $inputFilePath){Remove-Item $inputFilePath}
			if(Test-Path $errFilePath){Remove-Item $errFilePath}
		}
							
		# Return the output file path.
		return $outputFileContent
	}
	catch
	{
		# Return the error message.		
		$msg = "A problem occurred using piconfig.exe"
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Invoke-PISysAudit_PIVersionCommand
{
<#
.SYNOPSIS
(Core functionality) Perform a version check with the piversion.exe command.
.DESCRIPTION
Perform a version check with the piversion.exe command.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
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
	$fn = GetFunctionName
	
	try
	{
		
		#......................................................................................
		# Set Paths
		#......................................................................................
		# Get the PI folder.
		$PIServer_path = Get-PISysAudit_EnvVariable "PISERVER" -lc $LocalComputer -rcn $RemoteComputerName
		# Set the ADM folder.
		$PIServer_adm_path = PathConcat -ParentPath $PIServer_path -ChildPath "adm"
		# Set the path to reach out the piversion.exe CLU.
		$PIVersionExec = PathConcat -ParentPath $PIServer_adm_path -ChildPath "piversion.exe"

		if($LocalComputer)
		{			                                       			
			# Define the arguments required by the piversion.exe command
			# piversion.exe -v
			$argList = "`"-v`""
			# Get the Scripts Temp path.
			$scriptsPathTemp = (Get-Variable "scriptsPathTemp" -Scope "Global").Value		                                       						
			# Set the output for the CLU.
			$outputFilePath = PathConcat -ParentPath $scriptsPathTemp -ChildPath "piversion_output.txt"
		}
		else
		{						                                       						
			# Define the arguments required by the piversion.exe command
			# piversion.exe -v
			# argument is enclosed between single quotes to pass correctly the parameter for
			# PS Remoting.
			$argList = "'-v'"
			# Get the PIHome folder.
			$PIHome_path = Get-PISysAudit_EnvVariable "PIHOME" -lc $false -rcn $RemoteComputerName
			# Set the ADM folder.
			$PIHome_log_path = PathConcat -ParentPath $PIHome_path -ChildPath "dat"
			# Set the output for the CLU.
			$outputFilePath = PathConcat -ParentPath $PIHome_log_path -ChildPath "piversion_output.txt"								
		}
		$outputFileContent = ExecuteCommandLineUtility -lc $LocalComputer -rcn $RemoteComputerName -UtilityExec $PIVersionExec -ArgList $argList -OutputFilePath $outputFilePath -DBGLevel $DBGLevel
		
		# Return the output path + file to read the extract of the command.
		return $outputFileContent
	}
	catch
	{
		# Return the error message.
		$msgTemplate1 = "A problem occurred using piversion.exe on local computer"
		$msgTemplate2 = "A problem occurred using piversion.exe on {0} computer"
		if($LocalComputer)
		{ $msg = $msgTemplate1 }
		else
		{ $msg = [string]::Format($msgTemplate2, $RemoteComputerName) }		
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Invoke-PISysAudit_SPN
{
<#
.SYNOPSIS
(Core functionality) Perform an SPN check with the setspn.exe command.
.DESCRIPTION
Perform an SPN check with the setspn.exe command.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("svcname")]
		[string]
		$ServiceName,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("svctype")]
		[string]
		$ServiceType,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("appPool")]
		[string]
		$csappPool,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("CustomHeader")]
		[string]
		$CoresightHeader,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{
	$fn = GetFunctionName
	
	try
	{
		# Get Domain info.
		$MachineDomain = Get-PISysAudit_RegistryKeyValue "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" "Domain" -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel

		# Get Hostname.
		$hostname = Get-PISysAudit_RegistryKeyValue "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" "ComputerName" -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel

		# Build FQDN using hostname and domain strings.
		$fqdn = $hostname + "." + $MachineDomain

		# SPN check is done for PI Coresight using a custom host header.
		If ( $ServiceName -eq "coresight_custom" ) 
		{ 
			# Pass the Coresight AppPool identity as the service account.
			$svcacc = $csappPool
			$svcaccParsed = Get-PISysAudit_ParseDomainAndUserFromString -UserString $svcacc -DBGLevel $DBGLevel
				
			# Take Custom header information and create its short and long version.
			If ($CoresightHeader -match "\.") 
			{
				$csCustomHeaderLong = $CoresightHeader
				$pos = $CoresightHeader.IndexOf(".")
				$csCustomHeaderShort = $CoresightHeader.Substring(0, $pos)
			} 
			Else 
			{ 
				$csCustomHeaderShort = $CoresightHeader
				$csCustomHeaderLong = $CoresightHeader + "." + $MachineDomain
			}

			# Deal with the custom header - run nslookup and capture the result.
			$AliasTypeCheck = nslookup $CoresightHeader

			# Check if the custom header is a Alias (CNAME) or Host (A) entry.
			If ($AliasTypeCheck -match "Aliases:") 
			{ 
			# Dealing with Alias (CNAME). 

			# Verify hostnane AND FQDN SPNs are assigned to the service account.
			#
			# In case of Alias (CNAME), SPNs should exist for both short and fully qualified name of oth the Alias (CNAME)
			# ..and for the machine the Alias (CNAME) is pointing to. Overall, there should be 4 SPNs.
			#
			# With Host (A) entries, SPNs are needed only for the short and fully qualified names.
			
			$hostnameSPN = $($serviceType.ToLower() + "/" + $hostname.ToLower())
			$fqdnSPN = $($serviceType.ToLower() + "/" + $fqdn.ToLower())
			$csCustomHeaderSPN = $($serviceType.ToLower() + "/" + $csCustomHeaderShort.ToLower())
			$csCustomHeaderLongSPN = $($serviceType.ToLower() + "/" + $csCustomHeaderLong.ToLower())
			
			$result = Test-PISysAudit_ServicePrincipalName -HostName $hostname -MachineDomain $MachineDomain `
															-SPNShort $hostnameSPN -SPNLong $fqdnSPN `
															-SPNShortAlias $csCustomHeaderSPN -SPNLongAlias $csCustomHeaderLongSPN `
															-TargetAccountName $svcaccParsed.UserName -ServiceAccountDomain $svcaccParsed.Domain -DBGLevel $DBGLevel
						
			return $result			
			} 			
			Else 
			{ 
			# Host (A) 
			
			$csCustomHeaderSPN = $($serviceType.ToLower() + "/" + $csCustomHeaderShort.ToLower())
			$csCustomHeaderLongSPN = $($serviceType.ToLower() + "/" + $csCustomHeaderLong.ToLower())

			$result = Test-PISysAudit_ServicePrincipalName -HostName $hostname -MachineDomain $MachineDomain `
															-SPNShort $csCustomHeaderSPN -SPNLong $csCustomHeaderLongSPN `
															-TargetAccountName $svcaccParsed.UserName -TargetDomain $svcaccParsed.Domain -DBGLevel $DBGLevel

			return $result
			}
		}	
		# SPN Check is done for PI Coresight or other service
		Else
		{
			# SPN check is done for PI Coresight without custom headers.
			If ( $ServiceName -eq "coresight" )
			{
				# In case of PI Coresight, the AppPool account is used in the SPN check.
				$svcacc = $csappPool
			}
			# SPN check is not done for PI Coresight.
			Else
			{
				# Get the Service account
				$svcacc = Get-PISysAudit_ServiceLogOnAccount $ServiceName -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel
			}
			$svcaccParsed = Get-PISysAudit_ParseDomainAndUserFromString -UserString $svcacc -DBGLevel $DBGLevel

			# Proceed with checking SPN for Coresight or non-IIS app (PI/AF).
			# Distinguish between Domain/Virtual account and Machine Accounts.
			$hostnameSPN = $($serviceType.ToLower() + "/" + $hostname.ToLower())
			$fqdnSPN = $($serviceType.ToLower() + "/" + $fqdn.ToLower())

			$result = Test-PISysAudit_ServicePrincipalName -HostName $hostname -MachineDomain $MachineDomain `
															-SPNShort $hostnameSPN -SPNLong $fqdnSPN `
															-TargetAccountName $svcaccParsed.UserName -TargetDomain $svcaccParsed.Domain -DBGLevel $DBGLevel

			return $result
		}
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred using setspn.exe"	
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Test-PISysAudit_ServicePrincipalName
{
<#
.SYNOPSIS
(Core functionality) Perform a SQL query against a local/remote computer using an ADO.NET connection.
.DESCRIPTION
Perform a SQL query against a local/remote computer using an ADO.NET connection.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("host")]
		[string]
		$HostName,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[string]
		$MachineDomain,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("SPNS")]
		[string]
		$SPNShort,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("SPNL")]
		[string]
		$SPNLong,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("SPNSA")]
		[string]
		$SPNShortAlias="",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("SPNLA")]
		[string]
		$SPNLongAlias="",
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("TargetAccountName")]
		[string]
		$strSPNtargetAccount,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("TargetDomain")]
		[string]
		$strSPNtargetDomain=".",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	)
BEGIN {}
PROCESS		
{		
	$fn = GetFunctionName
	$blnAlias = $false
	try
	{
		$blnAlias = $SPNShortAlias -ne "" -and $SPNLongAlias -ne ""
		
		# Define user syntax for SPN command
		If($strSPNtargetDomain -eq 'MACHINEACCOUNT') # Use the hostname when a machine account is identified
		{
			$accountNane = $MachineDomain + '\' + $HostName + '$'
		}
		ElseIf($strSPNtargetDomain -eq '.') # Local account detected means SPN call will fail
		{ return $false }
		Else # Use parsed name
		{
			$accountNane = $strSPNtargetDomain + '\' + $strSPNtargetAccount
		}
		
		# Run setspn
		$spnCheck = $(setspn -l $accountNane)
		
		# Loop through SPNs, trimming and ensure all lower for comparison
		$spnCounter = 0
		foreach($line in $spnCheck)
		{		
			If($blnAlias){
				switch($line.ToLower().Trim())
				{
					$SPNShort {$spnCounter++; break}
					$SPNLong {$spnCounter++; break}
					$SPNShortAlias {$spnCounter++; break}
					$SPNLongAlias {$spnCounter++; break}
					default {break}
				}
			}
			Else
			{
				switch($line.ToLower().Trim())
				{
					$SPNShort {$spnCounter++; break}
					$SPNLong {$spnCounter++; break}
					default {break}
				}
			}	
		}

		# Return details to improve messaging in case of failure.
		If ($blnAlias -and $spnCounter -eq 4) { $result = $true } 
		ElseIf ($spnCounter -eq 2) { $result = $true }
		Else 
		{ 
			$result =  $false 
		}
		return $result
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred using setspn.exe"	
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $false
	}
}
END {}

#***************************
#End of exported function
#***************************
}

function Invoke-PISysAudit_ADONET_ScalarValueFromSQLServerQuery
{
<#
.SYNOPSIS
(Core functionality) Perform a SQL query against a local/remote computer using an ADO.NET connection.
.DESCRIPTION
Perform a SQL query against a local/remote computer using an ADO.NET connection.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]		
		[alias("rcn")]
		[string]
		$RemoteComputerName,				
		[parameter(Mandatory=$true, Position=2, ParameterSetName = "Default")]
		[alias("rspc")]
		[boolean]
		$Require_sp_configure,			
		[parameter(Mandatory=$true, Position=3, ParameterSetName = "Default")]
		[alias("q")]
		[string]
		$Query,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]				
		[string]
		$InstanceName = "",								
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$IntegratedSecurity = $true,				
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("pf")]
		[string]
		$PasswordFile = "",				
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{		
	$fn = GetFunctionName
	
	try
	{							
		# Define the connection string.
		$connectionString = SetConnectionString $LocalComputer $RemoteComputerName -InstanceName $InstanceName `
													-IntegratedSecurity $IntegratedSecurity -user $UserName -pf $PasswordFile -dbgl $DBGLevel
											
		# Create a connection object.
		$conn = New-Object System.Data.SQLClient.SQLConnection 
		$conn.ConnectionString = $connectionString
		
		# Open the connection
		$conn.Open() 			
		
		# Does it require to execute the sp_configure stored procedure?
		if($Require_sp_configure)
		{
			$sp_configure_query = "EXEC sp_configure 'show advanced options', 1;Reconfigure;"
			
			# Create a sql command
			$sp_configure_cmd = new-object System.Data.SqlClient.SqlCommand 
			$sp_configure_cmd.Connection = $conn	
		
			# Execute first command.
			$sp_configure_cmd.CommandText = $sp_configure_query
			$sp_configure_cmd.CommandTimeout = 600
			# The query returns the result but we are not interested, so send it
			# to null.
			$sp_configure_cmd.ExecuteNonQuery() | Out-Null			
		}
						
		# Get the value.
		$query_cmd = new-object System.Data.SqlClient.SqlCommand 
		$query_cmd.Connection = $conn	
		$query_cmd.CommandText = $Query
		$query_cmd.CommandTimeout = 600
		
		# Execute a scalar function.
		$value = $query_cmd.ExecuteScalar()				
	}
	catch
	{
		# Return the error message.
		$msgTemplate = "A problem occurred during the SQL Query: {0}"
		$msg = [string]::Format($msgTemplate, $_.Exception.Message)
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_		
		$value = $null
	}				
	
	# Close the connection.
	if(!($null -eq $conn)) { $conn.Close() }
	return $value
}

END {}

#***************************
#End of exported function
#***************************
}

function Invoke-Sqlcmd_ScalarValue
{
<#
.SYNOPSIS
(Core functionality) Perform a SQL query against a local/remote computer using the Invoke-Sqlcmd Cmdlet.
.DESCRIPTION
Perform a SQL query against a local/remote computer using the Invoke-Sqlcmd Cmdlet.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[AllowEmptyString()]
		[alias("rcn")]
		[string]
		$RemoteComputerName,		
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("q")]
		[string]
		$Query,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]				
		[string]
		$ScalarValue,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]				
		[string]
		$InstanceName = "",									
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$IntegratedSecurity = $true,							
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{		
	$fn = GetFunctionName		
															
	try
	{
		if($null -eq $InstanceName -or $InstanceName -eq "Default"){ $ServerInstance = $RemoteComputerName }
		else{ $ServerInstance = $RemoteComputerName + '\' + $InstanceName }
		$value = Invoke-Sqlcmd -Query $query -ServerInstance $ServerInstance | Select-Object -ExpandProperty $ScalarValue
	}
	catch
	{
		# Return the error message.
		$msgTemplate = "A problem occurred during the SQL Query: {0}"
		$msg = [string]::Format($msgTemplate, $_.Exception.Message)
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_		
		$value = $null
	}
	return $value
}

END {}

#***************************
#End of exported function
#***************************
}

function Invoke-PISysAudit_SQLCMD_ScalarValueFromSQLServerQuery
{
<#
.SYNOPSIS
(Core functionality) Perform a SQL query against a local/remote computer using the sqlcmd.exe CLU.
.DESCRIPTION
Perform a SQL query against a local/remote computer using the sqlcmd.exe CLU.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]		
		[AllowEmptyString()]
		[alias("rcn")]
		[string]
		$RemoteComputerName,				
		[parameter(Mandatory=$true, Position=2, ParameterSetName = "Default")]
		[alias("rspc")]
		[boolean]
		$Require_sp_configure,			
		[parameter(Mandatory=$true, Position=3, ParameterSetName = "Default")]
		[alias("q")]
		[string]
		$Query,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]				
		[string]
		$InstanceName = "",								
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$IntegratedSecurity = $true,				
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("pf")]
		[string]
		$PasswordFile = "",				
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{		
	$fn = GetFunctionName		
	
	try
	{														
		#......................................................................................
		# Validate the arguments passed
		#......................................................................................								
		if($Query -eq "")
		{
			# Return the error message.		
			$msg = "No query has been specified for the execution."
			Write-PISysAudit_LogMessage $msg "Error" $fn
			return $null
		}
				
		#......................................................................................
		# Does it require to execute the sp_configure stored procedure?
		#......................................................................................
		if($Require_sp_configure)
		{
			$queryBuilderTemplate = "EXEC sp_configure 'show advanced options', 1;Reconfigure;{0}"
			$queryBuilder = [string]::Format($queryBuilderTemplate, $Query)
			
			# Check if the query is ending with a ';', if not add it.
			if($Query.EndsWith(";") -eq $false) { $queryBuilder = $queryBuilder + ";" }	
		
			# Set the row to read from the output file.
			# Read the second row because the sp_configure provokes a message like the following:
			# Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
			$rowToRead = 1
		}
		else
		{ 
			$queryBuilder = $Query
			# Set the row to read from the output file.		
			$rowToRead = 0
		}
				
		#......................................................................................		
		# Define the requested server name.
		#......................................................................................		
		$computerName = ResolveComputerName $LocalComputer $RemoteComputerName						
		
		#......................................................................................		
		# Define the complete SQL Server name (Server + instance name)
		#......................................................................................
		$SQLServerName = ReturnSQLServerName $computerName $InstanceName											
		
		#......................................................................................
		# Integrated Security or SQL Security?
		#......................................................................................		
		if($IntegratedSecurity -eq $false)
		{
			if($PasswordFile -eq "")
			{												
				# Read from the global constant bag.
				# Read the secure password from the cache								 
				$securePWDFromCache = (Get-Variable "PISysAuditCachedSecurePWD" -Scope "Global" -ErrorAction "SilentlyContinue").Value					
				if(($null -eq $securePWDFromCache) -or ($securePWDFromCache -eq ""))
				{ 
					# Return the error message.
					$msg = "The password is not stored in cache"					
					Write-PISysAudit_LogMessage $msg "Error" $fn
					return $null
				}
				else
				{ 																				
					# Verbose only if Debug Level is 2+
					$msg = "The password stored in cached will be used for SQL connection"					
					Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2										
					
					# The CLU does not understand secure string and needs to get the raw password
					# Use the pointer method to reach the value in memory.
					$pwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePWDFromCache))
				}
			}
			else
			{				
				$pwd = GetPasswordOnDisk $PasswordFile				
			}
		}				
			
		if($LocalComputer)
		{						
			#......................................................................................
			# Set Paths
			#......................................................................................					    						
			# Get the Scripts Temp path.
			$scriptsPathTemp = (Get-Variable "scriptsPathTemp" -Scope "Global").Value
			# Set the path to reach out the sqlcmd.exe CLU. This CLU is called from any location.
			$sqlcmdExec = "sqlcmd.exe"
			# Set the input for the CLU.
            $inputFilePath = PathConcat -ParentPath $scriptsPathTemp -ChildPath "sqlcmd_input.txt"                						
			# Set the output for the CLU.
            $outputFilePath = PathConcat -ParentPath $scriptsPathTemp -ChildPath "sqlcmd_output.txt"                                 									
			# Define the arguments required by the sqlcmd.exe command						
			# S ... for Server\instance name
			# E ... for integrated security
			# h = -1 ... for no header
			# i ... input files
			# o ... output files
			# U ... User name
			# P ... Password
			if($IntegratedSecurity)
			{
				$argListTemplate = "-S {0} -E -h -1 -i `"{1}`" -o `"{2}`""
				$argList = [string]::Format($ArgListTemplate, $SQLServerName, $inputFilePath, $outputFilePath)
			}
			else
			{
				$argListTemplate = "-S {0} -U `"{1}`" -P `"{2}`" -h -1 -i `"{3}`" -o `"{4}`""
				$argList = [string]::Format($ArgListTemplate, $SQLServerName, $UserName, $pwd, $inputFilePath, $outputFilePath)
				$argListObfuscated = [string]::Format($ArgListTemplate, $SQLServerName, "username", "password", $inputFilePath, $outputFilePath)
			}						
			
			#......................................................................................
			# Delete any residual input/output files.
			#......................................................................................
			if(Test-Path $inputFilePath) { Remove-Item $inputFilePath }
			if(Test-Path $outputFilePath) { Remove-Item $outputFilePath }
				
			#......................................................................................
			# Create the input file.			
			#......................................................................................
			Out-File -FilePath $inputFilePath -InputObject $queryBuilder -Encoding ASCII			
			
			#......................................................................................
			# Execute the sqlcmd command locally by calling another process.			
			#......................................................................................
			Start-Process -FilePath $sqlcmdExec -ArgumentList $argList -Wait -NoNewWindow
			
			#......................................................................................
			# Read the content.
			#......................................................................................
			$outputFileContent = Get-Content -Path $outputFilePath
			
			#......................................................................................
			# Delete input/output files.
			#......................................................................................
			if(Test-Path $inputFilePath) { Remove-Item $inputFilePath }
			if(Test-Path $outputFilePath) { Remove-Item $outputFilePath }
		}			
		else
		{														
			#......................................................................................
			# Set Paths.
			#......................................................................................
			# Get the TEMP folder.
			$workPath = Get-PISysAudit_EnvVariable "TEMP"
			# Set the path to reach out the sqlcmd.exe CLU. This CLU is called from any location.
			$sqlcmdExec = "sqlcmd.exe"
			# Set the input for the CLU.
            $inputFilePath = PathConcat -ParentPath $workPath -ChildPath "sqlcmd_input.txt"                						
			# Set the output for the CLU.
            $outputFilePath = PathConcat -ParentPath $workPath -ChildPath "sqlcmd_output.txt"                                 						
			# Define the arguments required by the sqlcmd.exe command						
			# S ... for Server\instance name
			# E ... for integrated security
			# h = -1 ... for no header
			# i ... input files
			# o ... output files
			# U ... User name
			# P ... Password
			if($IntegratedSecurity)
			{
				# arglist must be enclosed by single quote (') or the query won't work.
				# The parameters are interpreted for the Start-Process cmdlet instead of the sqlcmd.exe CLU.
				$argListTemplate = "'-S {0} -E -h -1 -i `"{1}`" -o `"{2}`"'"
				$argList = [string]::Format($ArgListTemplate, $SQLServerName, $inputFilePath, $outputFilePath)
			}
			else
			{
				# arglist must be enclosed by single quote (') or the query won't work.
				# The parameters are interpreted for the Start-Process cmdlet instead of the sqlcmd.exe CLU.
				$argListTemplate = "'-S {0} -U `"{1}`" -P `"{2}`" -h -1 -i `"{3}`" -o `"{4}`"'"
				$argList = [string]::Format($ArgListTemplate, $SQLServerName, $UserName, $pwd, $inputFilePath, $outputFilePath)
				$argListObfuscated = [string]::Format($ArgListTemplate, $SQLServerName, "username", "password", $inputFilePath, $outputFilePath)
			}						
									
			#......................................................................................
			# Create the input file.			
			#......................................................................................
			$scriptBlockCmdTemplate = "Out-File -FilePath `"{0}`" -InputObject `"{1}`" -Encoding ASCII"
			$scriptBlockCmd = [string]::Format($scriptBlockCmdTemplate, $inputFilePath, $queryBuilder)			
			
			# Verbose only if Debug Level is 2+
			$msgTemplate = "Remote command to send to {0} is: {1}"
			$msg = [string]::Format($msgTemplate, $RemoteComputerName, $scriptBlockCmd)
			Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2
			
			$scriptBlock = [scriptblock]::create( $scriptBlockCmd )
			# The script block returns the result but we are not interested, so send it
			# to null.
			Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock | Out-Null
			
			#......................................................................................
			# Execute the sqlcmd command remotely.
			#......................................................................................
			$scriptBlockCmdTemplate = "Start-Process -FilePath `"{0}`" -ArgumentList {1} -Wait -NoNewWindow"
			$scriptBlockCmd = [string]::Format($scriptBlockCmdTemplate, $sqlcmdExec, $argList)
			if($IntegratedSecurity -eq $false)
			{ $scriptBlockCmdObfuscated = [string]::Format($scriptBlockCmdTemplate, $sqlcmdExec, $argListObfuscated) }
			
			# Verbose only if Debug Level is 2+
			$msgTemplate = "Remote command to send to {0} is: {1}"			
			if($IntegratedSecurity)
			{
				$msg = [string]::Format($msgTemplate, $RemoteComputerName, $scriptBlockCmd)
			}
			else
			{ 
				$scriptBlockCmdObfuscated = [string]::Format($scriptBlockCmdTemplate, $sqlcmdExec, $argListObfuscated)
				$msg = [string]::Format($msgTemplate, $RemoteComputerName, $scriptBlockCmdObfuscated)
			}						
			Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2			
			$scriptBlock = [scriptblock]::create( $scriptBlockCmd )
			Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock
			
			#......................................................................................
			# Read the content remotely.
			#......................................................................................
			$scriptBlockCmdTemplate = "Get-Content -Path ""{0}"""
			$scriptBlockCmd = [string]::Format($scriptBlockCmdTemplate, $outputFilePath)									
			
			# Verbose only if Debug Level is 2+
			$msgTemplate = "Remote command to send to {0} is: {1}"
			$msg = [string]::Format($msgTemplate, $RemoteComputerName, $scriptBlockCmd)
			Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2
			
			$scriptBlock = [scriptblock]::create( $scriptBlockCmd )
			$outputFileContent = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock												
		}
	}
	catch
	{
		# Return the error message.
		$msgTemplate = "A problem occurred during the SQL Query: {0}"
		$msg = [string]::Format($msgTemplate, $_.Exception.Message)
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_		
		$value = $null
	}				
	
	# Validate if no error occurs.
	if($null -ne $outputFileContent)
	{
		foreach($line in $outputFileContent)
		{
			# The message could look like: "Sqlcmd: Error: Microsoft SQL Server Native Client 11.0 : Login failed for user 'sa'.."
			if($line.ToLower().Contains("login failed"))
			{ return $null }		
		}
		# Get the scalar value returned. This value is stored on first row of the file.  Trim any whitespace.
		return $outputFileContent[$rowToRead].Trim()
	}
	else 
	{
		return $null
	}		
}

END {}

#***************************
#End of exported function
#***************************
}

function New-PISysAuditObject
{
<#
.SYNOPSIS
(Core functionality) Create an audit object and place it inside a hash table object.
.DESCRIPTION
Create an audit object and place it inside a hash table object.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(			
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]		
		[AllowEmptyString()]
		[alias("lc")]
		[boolean]
		$LocalComputer,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[AllowEmptyString()]
		[alias("rcn")]
		[string]
		$RemoteComputerName,			
		[parameter(Mandatory=$true, Position=2, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditHashTable,		
		[parameter(Mandatory=$true, Position=3, ParameterSetName = "Default")]
		[alias("id")]
		[String]
		$AuditItemID,				
		[parameter(Mandatory=$true, Position=4, ParameterSetName = "Default")]
		[alias("ain")]
		[String]
		$AuditItemName,
		[parameter(Mandatory=$true, Position=5, ParameterSetName = "Default")]
		[alias("aiv")]
		[object]
		$AuditItemValue,
		[parameter(Mandatory=$true, Position=5, ParameterSetName = "Default")]
		[alias("aif")]
		[String]
		$AuditItemFunction,		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("msg")]
		[String]
		$MessageList = "",		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("g1")]
		[String]
		$Group1 = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("g2")]
		[String]
		$Group2 = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("g3")]
		[String]
		$Group3 = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("g4")]
		[String]
		$Group4 = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("s")]
		[ValidateSet("Unknown", "N/A", "Low", "Moderate", "Severe")]
		[String]
		$Severity = "Low")
BEGIN {}
PROCESS		
{	
	$fn = GetFunctionName	

	# Define the server name to use for reporting.				
	$computerName = ResolveComputerName $LocalComputer $RemoteComputerName									
	
	# Create a custom object.
	$tempObj = New-Object PSCustomObject
	
	# Create an unique ID with the item ID and computer name.
	$myKey = $AuditItemID + "-" + $computerName
	
	# If the validation succeeds, there is no issue; if the validation fails, we can't accurately assess severity.
	if($AuditItemValue){$Severity = "N/A"}
	elseif($AuditItemValue -eq "N/A"){$Severity = "Unknown"}

	# Set the properties.
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "ID" -Value $AuditItemID
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "ServerName" -Value $computerName
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "AuditItemName" -Value $AuditItemName
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "AuditItemValue" -Value $AuditItemValue	
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "AuditItemFunction" -Value $AuditItemFunction
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "MessageList" -Value $MessageList
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "Group1" -Value $Group1
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "Group2" -Value $Group2
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "Group3" -Value $Group3
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "Group4" -Value $Group4
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "Severity" -Value $Severity
	
	# Add this custom object to the hash table.
	$AuditHashTable.Add($myKey, $tempObj)
		
	# Show partial results on screen.
	WriteHostPartialResult $tempObj
	
	# return the table
	return $AuditHashTable
}

END {}

#***************************
#End of exported function
#***************************
}

function New-PISysAuditComputerParams
{
<#
.SYNOPSIS
Generate parameters that define the servers to audit with the New-PISysAuditReport cmdlet.
.DESCRIPTION
Generate parameters that define the servers to audit with the New-PISysAuditReport cmdlet.
The syntax is...
New-PISysAuditComputerParams [[-ComputerParamsTable | -cpt] <hashtable>]
								[[-ComputerName | -cn] <string>]
								[[-PISystemComponentType | -type] <string>]
								[-InstanceName <string>]
								[-IntegratedSecurity <boolean>]
								[[-SQLServerUserID | -user] <string>]
								[[-PasswordFile | -pf] <string>]
								[-ShowUI <boolean>]								
.INPUTS
.OUTPUTS
<hashtable> containing the PISysAuditComputerParams objects.
.PARAMETER cpt
Parameter table defining which computers/servers
to audit and for which PI System components. If a $null
value is passed or the parameter is skipped, the cmdlet
will assume to audit the local machine.
.PARAMETER type
PI System Component to audit.
PI, PIDataArchive, PIServer refer to a PI Data Archive component.
PIAF, PIAFServer, AF refer to a PI AF Server component.
SQL, SQLServer refer to a SQL Server component.
.PARAMETER InstanceName
Parameter to specify the instance name of your SQL Server. If a blank string
or "default" or "mssqlserver" is passed, this will refer to the default
instance.
.PARAMETER IntegratedSecurity
Use or not the Windows integrated security. Default is true.
.PARAMETER user
Specify a SQL user account to use if you are not using the
Windows integrated security.
.PARAMETER pf
Specifiy a file that will contained a ciphered password obtained with the
New-PISysAudit_PasswordOnDisk cmdlet. If not specify and the -user parameter
is configured, the end-user will be prompted to enter the password once. This
password will be kept securely in memory until the end of the execution.
.PARAMETER showui
Output messages on the command prompt or not.
.EXAMPLE
$cpt = New-PISysAuditComputerParams -cpt $cpt -cn "MyPIServer" -type "pi"
The -cpt will use the hashtable of parameters to know how to audit
The -dbgl switch sets the debug level to 2 (full debugging)
.LINK
https://pisquare.osisoft.com
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(											
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[AllowNull()]
		[alias("cpt")]
		[System.Collections.HashTable]
		$ComputerParamsTable,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]				
		[AllowEmptyString()]
		[alias("cn")]
		[string]		
		$ComputerName,
		[parameter(Mandatory=$true, Position=2, ParameterSetName = "Default")]						
		[ValidateSet(
					"PIServer", "PIDataArchive", "PIDA",
					"PIAFServer", "AFServer", "PIAF", "AF",
					"SQLServer", "SQL", "PICoresightServer", 
					"CoresightServer", "PICoresight", 
					"Coresight", "PICS", "CS")]
		[alias("type")]
		[string]		
		$PISystemComponentType,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[string]
		$InstanceName = "",					
		[parameter(Mandatory=$false, ParameterSetName = "Default")]			
		[boolean]
		$IntegratedSecurity = $true,				
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("user")]
		[string]
		$SQLServerUserID = "",					
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("pf")]
		[string]
		$PasswordFile = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]				
		[boolean]
		$ShowUI = $true)
BEGIN {}
PROCESS		
{	
	$fn = GetFunctionName	
			
	# Initialize objects.
	$localComputer = $false		
	$resolvedComputerName = ""	
	if($null -eq $ComputerParamsTable) { $ComputerParamsTable = @{} }
	$skipParam = $false
		
	# ............................................................................................................
	# Initialize the module if needed
	# ............................................................................................................
	Initialize-PISysAudit -ShowUI $ShowUI

	# Read from the global constant bag.
	$isPISysAuditInitialized = (Get-Variable "PISysAuditInitialized" -Scope "Global" -ErrorAction "SilentlyContinue").Value					
		
	# If initialization failed, leave!
	if(($null -eq $isPISysAuditInitialized) -or ($isPISysAuditInitialized -eq $false))
	{
		$msg = "PI System Audit Module initialization failed"
		Write-PISysAudit_LogMessage $msg "Error" $fn
		return
	}		
	
	# ............................................................................................................
	# Validate if computer name refers to a local or remote entity and perform substitution if required.
	# ............................................................................................................
	
	# Obtain the machine name from the environment variable.
	$localComputerName = get-content env:computername
	
	# Validate if the server name refers to the local one	
	if(($ComputerName -eq "") -or ($ComputerName.ToLower() -eq "localhost"))
	{												
		$resolvedComputerName = $localComputerName
		$localComputer = $true
	}
	elseif($localComputerName.ToLower() -eq $ComputerName.ToLower())
	{									
		$resolvedComputerName = $localComputerName			
		$localComputer = $true
	}
	else
	{			
		$localComputer = $false			
		$resolvedComputerName = $ComputerName.ToLower()
	}		
	
	# ............................................................................................................
	# Create an object to manipulate that contains the directives on what to audit.
	# ............................................................................................................	
	# Create a custom object (PISysAuditComputerParams).
	$tempObj = New-Object PSCustomObject					
	
	if(($PISystemComponentType.ToLower() -eq "piserver") -or `
		($PISystemComponentType.ToLower() -eq "pidataarchive") -or `
		($PISystemComponentType.ToLower() -eq "pida") -or `
		($PISystemComponentType.ToLower() -eq "dataarchive"))
	{
		# Set the properties.
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "ComputerName" -Value $resolvedComputerName
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "IsLocal" -Value $localComputer		
		# Use normalized type description as 'PIDataArchive'
		$validatePISystemComponentType = "PIDataArchive"
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "PISystemComponentType" -Value $validatePISystemComponentType
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "InstanceName" -Value $null
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "IntegratedSecurity" -Value $null	
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "SQLServerUserID" -Value $null
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "PasswordFile" -Value $null		
	}
	elseif(($PISystemComponentType.ToLower() -eq "piafserver") -or `
		($PISystemComponentType.ToLower() -eq "afserver") -or `
		($PISystemComponentType.ToLower() -eq "piaf") -or `
		($PISystemComponentType.ToLower() -eq "af"))
	{
		# Set the properties.
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "ComputerName" -Value $resolvedComputerName
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "IsLocal" -Value $localComputer		
		# Use normalized type description as 'PIAFServer'
		$validatePISystemComponentType = "PIAFServer"
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "PISystemComponentType" -Value $validatePISystemComponentType
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "InstanceName" -Value $null
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "IntegratedSecurity" -Value $null	
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "SQLServerUserID" -Value $null
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "PasswordFile" -Value $null		
	}
	elseif(($PISystemComponentType.ToLower() -eq "sqlserver") -or `
		($PISystemComponentType.ToLower() -eq "sql"))
	{		
		# Set the properties.
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "ComputerName" -Value $resolvedComputerName
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "IsLocal" -Value $localComputer		
		# Use normalized type description as 'SQLServer'
		$validatePISystemComponentType = "SQLServer"
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "PISystemComponentType" -Value $validatePISystemComponentType
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "InstanceName" -Value $InstanceName
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "IntegratedSecurity" -Value $IntegratedSecurity	
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "SQLServerUserID" -Value $SQLServerUserID
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "PasswordFile" -Value $PasswordFile				
		
		# Test if a user name has been passed if Window integrated security is not used
		if($IntegratedSecurity -eq $false)
		{
			if($SQLServerUserID -eq "")
			{
				$msg = "No user name has been given. This parameter will be skipped"
				Write-PISysAudit_LogMessage $msg "Error" $fn -sc $true
				$skipParam = $true			
			}						
			elseif($PasswordFile -eq "")
			{
				# Warning message to the end-user that a password will be asked
				# before the first query is executed.
				$msg = "You will be prompted for the SQL user account password before the first query!"
				Write-PISysAudit_LogMessage $msg "Warning" $fn -sc $true
				$skipParam = $false
			}
			# Read from the global constant bag.		
			$pwdPath = (Get-Variable "PasswordPath" -Scope "Global").Value			
			# Set the path.
			$pwdFile = PathConcat -ParentPath $pwdPath -ChildPath $PasswordFile
	
			# Test the password file
			if((Test-Path $pwdFile) -eq $false)
			{									
				$msg = "The password file specified cannot be found. If you haven't defined one" `
							+ " yet, use the New-PISysAudit_PasswordOnDisk cmdlet to create one. This parameter will be skipped"
				Write-PISysAudit_LogMessage $msg "Error" $fn -sc $true
				$skipParam = $true
			}
		}
		
		
	}
	elseif (($PISystemComponentType.ToLower() -eq "picoresightserver") -or `
		($PISystemComponentType.ToLower() -eq "picoresight") -or `
		($PISystemComponentType.ToLower() -eq "coresightserver") -or `
		($PISystemComponentType.ToLower() -eq "coresight") -or `
		($PISystemComponentType.ToLower() -eq "cs") -or `
		($PISystemComponentType.ToLower() -eq "pics"))
	{
		# Set the properties.
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "ComputerName" -Value $resolvedComputerName
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "IsLocal" -Value $localComputer		
		# Use normalized type description as 'PICoresightServer'
		$validatePISystemComponentType = "PICoresightServer"
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "PISystemComponentType" -Value $validatePISystemComponentType
		# Nullify all of the MS SQL specific values
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "InstanceName" -Value $null
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "IntegratedSecurity" -Value $null	
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "SQLServerUserID" -Value $null
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "PasswordFile" -Value $null		
	}

	# Skip the addition of the new parameter or not.
	if($skipParam -eq $false)
	{	
		# Create an unique ID with the item ID and computer name.
		$myKey = $ComputerName + "(" + $validatePISystemComponentType + ")"
					
		# Test if the key is already part of the list	
		$item = $null	
		$item = $ComputerParamsTable[$myKey]
		if($null -eq $item) { $ComputerParamsTable.Add($myKey, $tempObj) }
		else { $ComputerParamsTable[$myKey] = $tempObj }				
	}
		
	# Return the computer parameters table.
	return $ComputerParamsTable	
}

END {}

#***************************
#End of exported function
#***************************
}

function Write-PISysAuditReport
{
<#
.SYNOPSIS
(Core functionality) Writes a report of all checks performed.
.DESCRIPTION
Writes a concise CSV report of all checks performed and optionally a detailed HTML report.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditHashTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("obf")]
		[boolean]
		$ObfuscateSensitiveData = $false,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dtl")]
		[boolean]
		$DetailReport = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS
{		
	$fn = GetFunctionName

	try
	{
		# Get the current timestamp for naming the file uniquely.
		$now = Get-Date
		$reportTimestamp = $now.ToString("dd-MMM-yyyy HH:mm:ss")
		$reportFileTimestamp = $now.ToString("yyyy-MM-dd_HH-mm-ss")		
		

		# Get the Scripts path.
		$exportPath = (Get-Variable "ExportPath" -Scope "Global").Value												
						
		# Create the log file in the same folder as the script. 
		$fileName = "PISecurityAudit_$reportFileTimestamp.csv"
		$fileToExport = PathConcat -ParentPath $exportPath -ChildPath $fileName

		# Build a collection for output.
		$results = @()	
		foreach($item in $AuditHashTable.GetEnumerator())			
		{
			# Protect sensitive data if necessary.
			if($ObfuscateSensitiveData)
			{		
				# Obfuscate the server name.
				$newServerName = NewObfuscateValue $item.Value.ServerName
				$item.Value.ServerName = $newServerName							
			}
			
			# Transform the true/false answer into Pass/Fail one.
			if($item.Value.AuditItemValue -eq $true)
			{ $item.Value.AuditItemValue = "Pass" }
			elseif($item.Value.AuditItemValue -eq $false)
			{ $item.Value.AuditItemValue = "Fail" }
			
			# Add to collection.
			$results += $item.Value	
		}
		
		# Export to .csv but sort the results table first to have Failed items on the top sorted by Severity 
		$results = $results | Sort-Object @{Expression="AuditItemValue";Descending=$false},@{Expression="Severity";Descending=$true},@{Expression="ID";Descending=$false}
		$results | Export-Csv -Path $fileToExport -Encoding ASCII -NoType
	
		
		if($DetailReport){
			
			$fileName = "PISecurityAudit_DetailReport_$reportFileTimestamp.html" 

			$fileToExport = PathConcat -ParentPath $exportPath -ChildPath $fileName


			# Construct HTML table and color code the rows by result and severity.
			$tableRows=""
			foreach($result in $results) 
			{
				$highlight = "`"`""
				switch ($result.Severity.ToLower())
				{
					"severe" {$highlight="`"error`""; break}
					"moderate" {$highlight="`"warning`""; break}
					"low" {$highlight="`"info`""; break}
				}
	
				$anchorTag=""
				if($result.AuditItemValue -ieq "fail"){
					$anchorTag = @"
					<a href="#$($result.ID)">
"@
				}
				$tableRow = @"
				<tr class=$highlight>
					<td>$anchorTag$($result.ID)</a></td>
					<td>$($result.ServerName)</td>
					<td>$($result.AuditItemName)</td>
					<td>$($result.AuditItemValue)</td>
					<td>$($result.Severity)</td>
					<td>$($result.MessageList)</td>
					<td>$($result.Group1)</td>
					<td>$($result.Group2)</td>
				</tr>
"@ 
				$tableRows+= $tableRow
			}



			# Get failed results and construct the recommendation section
			$fails=@()
			$fails = $results | Where-Object {$_.AuditItemValue -ieq "fail"}

			$recommendations=""
			if($null -ne $fails){
				$recommendations = "<div>
										<h2>Recommendations for failed validations:</h2>"
		
				$fails | ForEach-Object{
					$AuditFunctionName = $_.AuditItemFunction
					$recommendationInfo = Get-Help $AuditFunctionName
					if($PSVersionTable.PSVersion.Major -eq 2){$recommendationInfoDescription = $recommendationInfo.Description[0].Text} 
					else {$recommendationInfoDescription = $recommendationInfo.Description.Text}
					$recommendations +=@"
					<b id="$($_.ID)">$($recommendationInfo.Synopsis)</b>
					<br/>
					<p>$recommendationInfoDescription</p>
					<br/>
"@
				}
				$recommendations+="</div>"
			}
			

			# HTML report. 
			$reportHTML = @"
			<html>
				<head><meta name="viewport" content="width=device-width" />
					<style type="text/css">
						body {
							font-size: 100%;
							font-family: 'Segoe UI Light','Segoe UI','Lucida Grande',Verdana,Arial,Helvetica,sans-serif;
						}
						h2{
							font-size: 1.875em;
						}
						p{
							font-size: 0.875em;
							}
						a{
							color: black;
						}
	
						.summarytable {
							width: 100%;
							border-collapse: collapse;
							}

						.summarytable td, .summarytable th {
							border: 1px solid #ddd;
							font-size: 0.875em;
						}
						.summarytable th{
							background-color: #f2f2f2;
						}

			
						.info{
							background-color: #FFF59D;
						}
			
						.warning{
							background-color: #FFCC80;
						}
						.error{
							background-color: #FFAB91;
						}	
					</style>

			
				</head>
				<body>
					<div style="padding-bottom:1em">
						<h2>AUDIT SUMMARY </h2>
						<h4>$reportTimestamp</h4> 
					</div>

					<table class="summarytable table">
						<thead>	
							<tr>
								<th>ID</th>
								<th>Server</th>
								<th>Validation</th>
								<th>Result</th> 
								<th>Severity</th>
								<th>Message</th>
								<th>Category</th> 
								<th>Area</th>
							</tr>
						</thead>
						$tableRows
					</table>
			
					<br/>

					$Recommendations
					
				</body>
			</html>
"@		
			# Print report to file.
			$reportHTML | Out-File $fileToExport
		}
		# Return the report name.
		return $fileName
		
	}
	catch
	{
		# Return the error message.
		$msgTemplate = "A problem occurred during generation of the report"
		$msg = [string]::Format($msgTemplate, $_.Exception.Message)
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_		
		return $null
	}	
}	

END {}

#***************************
#End of exported function
#***************************
}

function New-PISysAuditReport
{
<#  
.SYNOPSIS
Generate a PI System audit report.
.DESCRIPTION
Generate a PI System audit report. The syntax is...				 
New-PISysAuditReport [[-ComputerParamsTable | -cpt] <hashtable>]
 					 [[-ObfuscateSensitiveData | -obf] <boolean>]
					 [-ShowUI <boolean>]
					 [[-DBGLevel | -dbgl] <int>]
.INPUTS
.OUTPUTS
.PARAMETER cpt
Parameter table defining which computers/servers
to audit and for which PI System components. If a $null
value is passed or the parameter is skipped, the cmdlet
will assume to audit the local machine.
.PARAMETER obf
Obfuscate or not the name of computers/servers
exposed in the audit report.
.PARAMETER showui
Output messages on the command prompt or not.
.PARAMETER dbglevel
DebugLevel: 0 for no verbose, 1 for intermediary message
to help debugging, 2 for full level of details
.EXAMPLE
New-PISysAuditReport -cpt $cpt -obf $false
The -cpt will use the hashtable of parameters to know how to audit
The -obf switch deactivate the obfuscation of the server name.
The -dbgl switch sets the debug level to 2 (full debugging)
.EXAMPLE
New-PISysAuditReport -cpt $cpt -dbgl 2
-- See Example 1 for explanations of switch -cpt
-- The -dbgl switch sets the debug level to 2 (full debugging)
.LINK
https://pisquare.osisoft.com
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(											
		[parameter(Mandatory=$false, ParameterSetName = "Default")]										
		[alias("cpt")]
		[System.Collections.HashTable]				
		$ComputerParamsTable = $null,		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("obf")]
		[boolean]
		$ObfuscateSensitiveData = $false,				
		[parameter(Mandatory=$false, ParameterSetName = "Default")]				
		[boolean]
		$ShowUI = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dtl")]
		[boolean]
		$DetailReport = $true,				
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		

BEGIN {}
PROCESS
{							
	# Get and store the function Name.
	$fn = GetFunctionName
	
	# ............................................................................................................
	# Initialize the module if needed
	# ............................................................................................................
	Initialize-PISysAudit -ShowUI $ShowUI -dbgl $DBGLevel
	
	# Read from the global constant bag.
	$isPISysAuditInitialized = (Get-Variable "PISysAuditInitialized" -Scope "Global" -ErrorAction "SilentlyContinue").Value					
		
	# If initialization failed, leave!
	if(($null -eq $isPISysAuditInitialized) -or ($isPISysAuditInitialized -eq $false))
	{
		$msg = "PI System Audit Module initialization failed"
		Write-PISysAudit_LogMessage $msg "Error" $fn
		return
	}		
	
	# Initialize some objects.
	$ActivityMsg = "Launch analysis on PI System"
	$statusMsgCompleted = "Completed"
	
	# Write the first message in the log file.
	$msg = "----- Start the audit -----"
	Write-PISysAudit_LogMessage $msg "Info" $fn		
			
	# Add a 5 lines to avoid hiding text under the progress bar.
	if($ShowUI)
	{ Write-Host "`r`n`r`n`r`n`r`n`r`n"	}
	
	# ............................................................................................................
	# Initialize the table of results
	# ............................................................................................................
	$auditHashTable = @{}	
	
	# ............................................................................................................
	# Validate if a ComputerParams table has been passed, if not create one that use localhost as the default
	# ............................................................................................................
	if($null -eq $ComputerParamsTable)
	{
		# Initialize.
		$ComputerParamsTable = @{}
		
		# This means an audit on the local computer is required only PI Data Archive and PI AF Server are checked by default.
		# SQL Server checks ommitted by default as SQL Server will often require an instancename
		$ComputerParamsTable = New-PISysAuditComputerParams $ComputerParamsTable "localhost" "PIServer"
		$ComputerParamsTable = New-PISysAuditComputerParams $ComputerParamsTable "localhost" "PIAFServer"	
	}
	
	# ............................................................................................................
	# Create a filtered list of computers
	# ............................................................................................................						
	$uniqueComputerParamsTable = GetFilteredListOfComputerParams $ComputerParamsTable
	
	# ............................................................................................................
	# Validate that WSMan or WS-Management (WinRM) service is running
	# ............................................................................................................						
	if((ValidateWSMan $uniqueComputerParamsTable -dbgl $DBGLevel) -eq $false) { return }		
		
	# ....................................................................................
	# Perform Checks on computers
	# ....................................................................................								
	StartComputerAudit $auditHashTable $uniqueComputerParamsTable -dbgl $DBGLevel					
	
	# ....................................................................................
	# Perform Checks on PI Data Archive, PI AF Server, SQL Server, etc.
	# ....................................................................................						
	foreach($item in $ComputerParamsTable.GetEnumerator())
	{
		# Read the object within the System.Collections.DictionaryEntry
		$computerParams = $item.Value
		
		# Proceed based on component type.
		if($computerParams.PISystemComponentType -eq "PIDataArchive")
		{ StartPIDataArchiveAudit $auditHashTable $computerParams -dbgl $DBGLevel }		
		elseif($computerParams.PISystemComponentType -eq "PIAFServer")
		{ StartPIAFServerAudit $auditHashTable $computerParams -dbgl $DBGLevel }
		elseif($computerParams.PISystemComponentType -eq "SQLServer")
		{ StartSQLServerAudit $auditHashTable $computerParams -dbgl $DBGLevel }
		elseif($computerParams.PISystemComponentType -eq "PICoresightServer")
		{ StartPICoresightServerAudit $auditHashTable $computerParams -dbgl $DBGLevel}
	}	

	# ....................................................................................
	# Show results.
	# ....................................................................................		
	$ActivityMsg = "Generate report"
	if($ShowUI) { Write-Progress -activity $ActivityMsg -Status "in progress..." }
	$reportName = Write-PISysAuditReport $auditHashTable -obf $ObfuscateSensitiveData -dtl $DetailReport -dbgl $DBGLevel
	if($ShowUI) { Write-Progress -activity $ActivityMsg -Status $statusMsgCompleted -completed }
	
	# ............................................................................................................
	# Display that the analysis is completed and where the report can be found.
	# ............................................................................................................				
	# Read from the global constant bag.
	$exportPath = (Get-Variable "ExportPath" -Scope "Global" -ErrorAction "SilentlyContinue").Value										
	$msgTemplate = "The audit is completed. See the generated report ({0}) under the folder: {1}"
	$msg = [string]::Format($msgTemplate, $reportName, $exportPath)
	Write-PISysAudit_LogMessage $msg "Info" $fn -sc $true		
}

END {}

#***************************
#End of exported function
#***************************
}

# ........................................................................
# Add your core function by replacing the Verb-PISysAudit_TemplateCore one.
# Implement the functionality you want. Don't forget to modify the parameters
# if necessary.
# ........................................................................
function Verb-PISysAudit_TemplateCore
{
<#
.SYNOPSIS
Add a synopsis.
.DESCRIPTION
Add a description.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditHashTable,		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS
{		
	$fn = GetFunctionName
	
	# ........................................................................
	# Add your code here...
	# ........................................................................
}	

END {}

#***************************
#End of exported function
#***************************
}

# ........................................................................
# Create an alias on the cmdlet
# ........................................................................
# <Do not remove>
Set-Alias piaudit New-PISysAuditReport
Set-Alias piauditparams New-PISysAuditComputerParams
Set-Alias pisysauditparams New-PISysAuditComputerParams
Set-Alias pwdondisk New-PISysAudit_PasswordOnDisk
# </Do not remove>
 
# ........................................................................
# Export Module Member
# ........................................................................
# <Do not remove>
Export-ModuleMember PathConcat
Export-ModuleMember Initialize-PISysAudit
Export-ModuleMember Set-PISysAudit_SaltKey
Export-ModuleMember Get-PISysAudit_EnvVariable
Export-ModuleMember Get-PISysAudit_RegistryKeyValue
Export-ModuleMember Get-PISysAudit_TestRegistryKey
Export-ModuleMember Get-PISysAudit_ServiceLogOnAccount
Export-ModuleMember Get-PISysAudit_ParseDomainAndUserFromString
Export-ModuleMember Get-PISysAudit_ServiceState
Export-ModuleMember Get-PISysAudit_CheckPrivilege
Export-ModuleMember Get-PISysAudit_InstalledComponents
Export-ModuleMember Get-PISysAudit_InstalledKBs
Export-ModuleMember Get-PISysAudit_InstalledWin32Feature
Export-ModuleMember Get-PISysAudit_FirewallState
Export-ModuleMember Get-PISysAudit_AppLockerState
Export-ModuleMember Get-PISysAudit_KnownServers
Export-ModuleMember Test-PISysAudit_ServicePrincipalName
Export-ModuleMember Invoke-PISysAudit_AFDiagCommand
Export-ModuleMember Invoke-PISysAudit_PIConfigScript
Export-ModuleMember Invoke-PISysAudit_PIVersionCommand
Export-ModuleMember Invoke-PISysAudit_ADONET_ScalarValueFromSQLServerQuery
Export-ModuleMember Invoke-PISysAudit_SQLCMD_ScalarValueFromSQLServerQuery
Export-ModuleMember Invoke-Sqlcmd_ScalarValue
Export-ModuleMember Invoke-PISysAudit_SPN
Export-ModuleMember Get-PISysAudit_IISproperties
Export-ModuleMember New-PISysAuditObject
Export-ModuleMember New-PISysAudit_PasswordOnDisk
Export-ModuleMember New-PISysAuditComputerParams
Export-ModuleMember New-PISysAuditReport
Export-ModuleMember Write-PISysAuditReport
Export-ModuleMember Write-PISysAudit_LogMessage
Export-ModuleMember -Alias piauditparams
Export-ModuleMember -Alias pisysauditparams
Export-ModuleMember -Alias piaudit
Export-ModuleMember -Alias pwdondisk
Export-ModuleMember Test-PowerShellToolsForPISystemAvailable
Export-ModuleMember Test-WebAdministrationModuleAvailable
# </Do not remove>

# ........................................................................
# Add your new Export-ModuleMember instruction after this section.
# Replace the Verb-PISysAudit_TemplateCore with the name of your
# function.
# ........................................................................
# Export-ModuleMember Verb-PISysAudit_TemplateCore