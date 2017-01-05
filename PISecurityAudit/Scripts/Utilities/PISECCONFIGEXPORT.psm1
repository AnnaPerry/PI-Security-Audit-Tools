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

function PISecConfig_ExportData
{
<#  
.SYNOPSIS
Get security configuration data
#>
param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[object] $PIDataArchiveConnection,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[string] $DataItem,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[int] $MaxResults = 1000)
		
	$fn = GetFunctionName
	try
	{		
		switch ($DataItem)
		{
			"PIDatabaseSecurity" { 
				$outputFileContent = Get-PIDatabaseSecurity -Connection $PIDataArchiveConnection `
										| Select-Object TableName, Security | Sort-Object -Property Tablename `
										| Foreach-Object { $_.Security = $_.Security.ToString(); Write-Output $_ } `
										| ConvertSelectionToPSObject 
				break
			}
			"PIFirewall" { $outputFileContent = Get-PIFirewall -Connection $PIDataArchiveConnection | Select-Object Hostmask, Access | ConvertSelectionToPSObject; break }
			"PIUsers" { $outputFileContent = Get-PIUser -Connection $PIDataArchiveConnection | Select-Object Name, Groups | ConvertSelectionToPSObject; break }
			"PIGroups" { $outputFileContent = Get-PIGroup -Connection $PIDataArchiveConnection | Select-Object Name, Users | ConvertSelectionToPSObject; break }
			"PIIdentities" { 
				$outputFileContent = Get-PIIdentity -Connection $PIDataArchiveConnection  `
                            | Select-Object Name, ReadOnlyFlags `
                            | Foreach-Object { $_.ReadOnlyFlags = $_.ReadOnlyFlags.ToString().Replace(',',';'); Write-Output $_ } `
							| ConvertSelectionToPSObject 
				break
			}
			"PIMappings" { $outputFileContent = Get-PIMapping -Connection $PIDataArchiveConnection	| Select-Object Identity, PrincipalName | ConvertSelectionToPSObject; break }
			"PIMessages" { $outputFileContent = Get-PIMessage -Connection $PIDataArchiveConnection -Starttime $(Get-Date).AddMonths(-1) -Endtime $(Get-Date) -SeverityType Warning -Count $MaxResults | Select * | ConvertSelectionToPSObject; break }
			"PINetManagerStats" {
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
				break
			}
			"PITrusts" { $outputFileContent = Get-PITrust -Connection $PIDataArchiveConnection | Select-Object Name, Identity, Domain, OSUser, ApplicationName, NetworkHost, IPAddress, NetMask, IsEnabled | ConvertSelectionToPSObject; break }
		}
		if($outputFileContent.Count -ge $MaxResults){
			Write-Warning $("Max result limit of " + $MaxResults.ToString() + " reached for " + $dataItem + ".  " + $fn)
		}
		return (NewConfigDataItem $DataItem $outputFileContent)		
	}
	catch
	{ 					
		Write-Output $("A problem occurred on " + $dataItem + ".  " + $fn + ": " + $_.Exception.Message)
		return $null
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
		[string] $PIDataArchiveComputerName,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[int] $MaxResults = 1000
	)	

		Test-PowerShellToolsForPISystemAvailable
		if(!$global:ArePowerShellToolsAvailable)
		{ 
			Write-Output "PowerShell Tools for the PI System are required for export functionality. Exiting..." 
			break
		}
		# Connect to PI Data Archive
		$PIDataArchiveConnection = Connect-PIDataArchive -PIDataArchiveMachineName $PIDataArchiveComputerName
		# Set export folder
		$exportFolderPathRoot = SetRootExportFolder
		$exportFolderPath = PathConcat -ParentPath $exportFolderPathRoot -ChildPath $PIDataArchiveComputerName
		if (!(Test-Path $exportFolderPath)){ New-Item $exportFolderPath -type directory }
		
		$listOfDataItems = @('PIDatabaseSecurity','PIFirewall','PIUsers','PIGroups','PIIdentities','PIMappings','PITrusts','PINetManagerStats','PIMessages')
		foreach($dataItem in $listOfDataItems)
		{
			$PISecConfigDataItem = $null
			$PISecConfigDataItem = PISecConfig_ExportData -PIDataArchiveConnection $PIDataArchiveConnection -DataItem $dataItem -MaxResults $MaxResults
			if($null -ne $PISecConfigDataItem.FileContent) { $PISecConfigDataItem.FileContent | Export-Csv -Path $($exportFolderPath + "\" + $PISecConfigDataItem.FileName + ".csv") -Encoding ASCII -NoTypeInformation }
			else { Write-Warning ("No result returned for " + $dataItem) }
		}

}

# ........................................................................
# Export Module Member
# ........................................................................
Export-ModuleMember Export-PISecConfig