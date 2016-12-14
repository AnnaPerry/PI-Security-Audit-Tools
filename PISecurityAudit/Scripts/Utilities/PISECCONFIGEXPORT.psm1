# PISECCONFIGEXPORT.psm1
# ........................................................................
# Internal Functions
# ........................................................................
function GetFunctionName
{ return (Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name }

function SetRootExportFolder
{
	# Establish the root path that configurations will be exported to.
	$scriptsPath = Split-Path $PSScriptRoot
	$rootPath = Split-Path $scriptsPath				
	$exportFolderPathRoot = PathConcat -ParentPath $rootPath -ChildPath "Export"
	# Create the root export folder if it doesn't exist.
	if (!(Test-Path $exportFolderPathRoot)){ New-Item $exportFolderPathRoot -type directory }

	return $exportFolderPathRoot
}

function NewConfigDataItem
{
param(
	[Parameter(Mandatory=$True,Position=1)]
	[string] $outputFileName,
	[Parameter(Mandatory=$True,Position=2)]
	[object] $outputFileContent
)
	$ConfigDataItem = New-Object PSObject
	$ConfigDataItem | Add-Member -MemberType NoteProperty -Name FileName -Value $outputFileName
	$ConfigDataItem | Add-Member -MemberType NoteProperty -Name FileContent -Value $outputFileContent
	return $ConfigDataItem
}

function ConvertSelectionToPSObject
{
<#  
.SYNOPSIS
Convert the table of data into a PSObject so that it can be exported or manipulated more easily by 
native PowerShell Cmdlets.
#>
param(
	[Parameter(Mandatory=$True,Position=1,ValueFromPipeline=$True)]
	[object] $outputFileContentRaw
)
BEGIN { $outputFileContent = @() }
PROCESS
{    
	foreach($row in $outputFileContentRaw)
	{
			$entry = New-Object PSObject
			$rowNoteProperties = $row | Get-Member -MemberType NoteProperty | Select-Object Name
            foreach($rowNoteProperty in $rowNoteProperties)
            {
                $name = $rowNoteProperty.Name
                $value = $row | Select-Object -ExpandProperty $name
                $entry | Add-Member -MemberType NoteProperty -Name $name -Value $value
			}
			$outputFileContent += $entry
	}
}
END { return $outputFileContent }
}	

function Get-PISecConfig_FunctionsFromLibrary
{
<#  
.SYNOPSIS
Get functions from machine library.
#>
	[System.Collections.HashTable]$listOfFunctions = @{}	
	$listOfFunctions.Add("PISecConfig_ExportPIDBSecurity", 1)
	$listOfFunctions.Add("PISecConfig_ExportPIFirewall", 1)
	$listOfFunctions.Add("PISecConfig_ExportPIUsers", 1)
    $listOfFunctions.Add("PISecConfig_ExportPIGroups", 1)
	$listOfFunctions.Add("PISecConfig_ExportPIIdentities", 1)
	$listOfFunctions.Add("PISecConfig_ExportPIMappings", 1)
	$listOfFunctions.Add("PISecConfig_ExportPITrusts", 1)
	$listOfFunctions.Add("PISecConfig_ExportPINetManagerStats", 1)
	$listOfFunctions.Add("PISecConfig_ExportPIMessageLogs", 1)
	return $listOfFunctions		
}

function PISecConfig_ExportPIDBSecurity
{
<#  
.SYNOPSIS
Export Database Security to CSV
#>   
param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("pida")]
		[object] $PIDataArchiveConnection)		
	
	$fn = GetFunctionName
	try
	{		
		$outputFileContent = Get-PIDatabaseSecurity -Connection $PIDataArchiveConnection `
										| Select-Object TableName, Security | Sort-Object -Property Tablename `
										| Foreach-Object { $_.Security = $_.Security.ToString(); Write-Output $_ } `
										| ConvertSelectionToPSObject		 																	
		
		return (NewConfigDataItem "PIDatabaseSecurity" $outputFileContent)	
	}
	catch
	{ 
		Write-Output $("A problem occurred during " + $fn + ": " + $_.Exception.Message)
	}								
}

function PISecConfig_ExportPIFirewall
{
<#  
.SYNOPSIS
Export PI Firewall to CSV
#>
param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("pida")]
		[object] $PIDataArchiveConnection)	
	
	$fn = GetFunctionName
	try
	{		
		$outputFileContent = Get-PIFirewall -Connection $PIDataArchiveConnection `
									| Select-Object Hostmask, Access | ConvertSelectionToPSObject
															
		return (NewConfigDataItem "PIFirewall" $outputFileContent)	
	}
	catch
	{ 
		Write-Output $("A problem occurred during " + $fn + ": " + $_.Exception.Message)
	}												
}

function PISecConfig_ExportPIUsers
{
<#  
.SYNOPSIS
Export PI Users to CSV
#>
param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("pida")]
		[object] $PIDataArchiveConnection)	
		
	$fn = GetFunctionName
	try
	{		
		$outputFileContent = Get-PIUser -Connection $PIDataArchiveConnection `
									| Select-Object Name, Groups | ConvertSelectionToPSObject
																	
		return (NewConfigDataItem "PIUser" $outputFileContent)	
	}
	catch
	{ 
		Write-Output $("A problem occurred during " + $fn + ": " + $_.Exception.Message)
	}													

}

function PISecConfig_ExportPIGroups
{
<#  
.SYNOPSIS
Export PI Groups to CSV
#>
param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("pida")]
		[object] $PIDataArchiveConnection)	
		
	$fn = GetFunctionName
	try
	{		
		$outputFileContent = Get-PIGroup -Connection $PIDataArchiveConnection `
									| Select-Object Name, Users | ConvertSelectionToPSObject
																		
		return (NewConfigDataItem "PIGroups" $outputFileContent)	
	}
	catch
	{ 
		Write-Output $("A problem occurred during " + $fn + ": " + $_.Exception.Message)
	}													

}

function PISecConfig_ExportPIIdentities
{
<#  
.SYNOPSIS
Export PI Identities to CSV
#>
param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("pida")]
		[object] $PIDataArchiveConnection)	
		
	$fn = GetFunctionName
	try
	{		
		$outputFileContent = Get-PIIdentity -Connection $PIDataArchiveConnection  `
                            | Select-Object Name, ReadOnlyFlags `
                            | Foreach-Object { $_.ReadOnlyFlags = $_.ReadOnlyFlags.ToString().Replace(',',';'); Write-Output $_ } `
							| ConvertSelectionToPSObject
																	
		return (NewConfigDataItem "PIIdentities" $outputFileContent)	
	}
	catch
	{ 
		Write-Output $("A problem occurred during " + $fn + ": " + $_.Exception.Message)
	}													

}

function PISecConfig_ExportPIMappings
{
<#  
.SYNOPSIS
Export PI Mappings to CSV
#>
param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("pida")]
		[object] $PIDataArchiveConnection)	
		
	$fn = GetFunctionName
	try
	{		
		$outputFileContent = Get-PIMapping -Connection $PIDataArchiveConnection  `
                            | Select-Object Identity, PrincipalName | ConvertSelectionToPSObject
																	
		return (NewConfigDataItem "PIMappings" $outputFileContent)	
	}
	catch
	{ 
		Write-Output $("A problem occurred during " + $fn + ": " + $_.Exception.Message)
	}												

}

function PISecConfig_ExportPITrusts
{
<#  
.SYNOPSIS
Export PI Trusts to CSV
#>
param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("pida")]
		[object] $PIDataArchiveConnection)	
		
	$fn = GetFunctionName
	try
	{		
		$outputFileContent = Get-PITrust -Connection $PIDataArchiveConnection  `
                            | Select-Object Name, Identity, Domain, OSUser, ApplicationName, NetworkHost, IPAddress, NetMask, IsEnabled `
							| ConvertSelectionToPSObject
		
		return (NewConfigDataItem "PITrusts" $outputFileContent)	
	}
	catch
	{ 
		Write-Output $("A problem occurred during " + $fn + ": " + $_.Exception.Message)
	}													

}

function PISecConfig_ExportPINetManagerStats
{
<#  
.SYNOPSIS
Export PI Network Manager Statistics to CSV
#>
param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("pida")]
		[object] $PIDataArchiveConnection)	
		
	$fn = GetFunctionName
	try
	{		
		$outputFileContentRaw = Get-PIConnectionStatistics -Connection $PIDataArchiveConnection
		# Note: ConvertSelectionToPSObject is not used for NetManStats because attributes are dictionary entries and it is simpler to convert them directly to NoteProperties
		# while transposing to work with native export to CSV
		$outputFileContent = @()
		foreach ($row in $outputFileContentRaw)
		{
			$entry = New-Object PSObject 
			for ($index=0; $index -lt $row.Count; $index++)
			{
				$entry | Add-Member -MemberType NoteProperty -Name $row.Name[$index] -Value $row.Value[$index]
			}
			$outputFileContent += $entry
		}
														
		return (NewConfigDataItem "PINetManagerStats" $outputFileContent)	
	}
	catch
	{ 					
		Write-Output $("A problem occurred during " + $fn + ": " + $_.Exception.Message)
	}													
}

function PISecConfig_ExportPIMessageLogs
{
<#  
.SYNOPSIS
Export PI Message Logs of severity Warning or above for the past month.
#>
param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("pida")]
		[object] $PIDataArchiveConnection)
		
	$fn = GetFunctionName
	try
	{		
		$outputFileContent = Get-PIMessage -Connection $PIDataArchiveConnection -Starttime $(Get-Date).AddMonths(-1) -Endtime $(Get-Date) -SeverityType Warning `
									| Select * | ConvertSelectionToPSObject
														
		return (NewConfigDataItem "PIMessages" $outputFileContent)	
	}
	catch
	{ 					
		Write-Output $("A problem occurred during " + $fn + ": " + $_.Exception.Message)
	}													
}

# ........................................................................
# Public Functions
# ........................................................................
function Export-PISecConfig
{
<#  
.SYNOPSIS
Export security configuration information.

.DESCRIPTION
The following information is exported.
	Security Configuration
		1. Export PI Database Security to a CSV file
		2. Export PI Firewall to a CSV file
		3. Export PI Users to a CSV file
		4. Export PI Groups to a CSV file
		5. Export PI Mappings to a CSV file
		6. Export PI Trusts to a CSV file
		7. Export PI Security Level to a CSV file
	Connection Info
		8. Export Network Manager Statistics to a CSV file
	Logs
		9. Export one month of warning, error and critical 
		messages logs from the PI Data Archive
The syntax is...				 
Export-PISecConfig [[-PIDataArchiveComputerName | -pida] <string>]
.PARAMETER pida
The PI Data Archive to dump the security configuration from.
.EXAMPLE
Export-PISecConfig -PIDataArchiveComputerName PIDataArchive01
.LINK
https://pisquare.osisoft.com
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("pida")]
		[string] $PIDataArchiveComputerName)	
BEGIN {}
PROCESS 
{
		Test-PowerShellToolsForPISystemAvailable
		if(!$global:ArePowerShellToolsAvailable)
		{ 
			Write-Output "PowerShell Tools for the PI System are required for export functionality. Exiting..." 
			break
		}
		# Get the list of functions to execute.
		$listOfFunctions = Get-PISecConfig_FunctionsFromLibrary
		# Connect to PI Data Archive
		$PIDataArchiveConnection = Connect-PIDataArchive -PIDataArchiveMachineName $PIDataArchiveComputerName
		# Set export folder
		$exportFolderPathRoot = SetRootExportFolder
		$exportFolderPath = PathConcat -ParentPath $exportFolderPathRoot -ChildPath $PIDataArchiveComputerName
		if (!(Test-Path $exportFolderPath)){ New-Item $exportFolderPath -type directory }
		
		foreach($function in $listOfFunctions.GetEnumerator())
		{
			$PISecConfigDataItem = $null
			$PISecConfigDataItem = & $function.Name -pida $PIDataArchiveConnection
			$exportFilePath = $exportFolderPath + "\" + $PISecConfigDataItem.FileName + ".csv"
			$PISecConfigDataItem.FileContent | Export-Csv -Path $exportFilePath -Encoding ASCII -NoTypeInformation
		}
}
END{}
}

# ........................................................................
# Export Module Member
# ........................................................................
Export-ModuleMember Export-PISecConfig