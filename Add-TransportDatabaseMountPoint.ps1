<#PSScriptInfo

.VERSION 1.0.0

.GUID 1105c80c-41a2-406c-8c7c-e43648ace068

.AUTHOR Mike Hendrickson

#>

<# 
.SYNOPSIS
 Creates a mount point for the Exchange Transport database, and assigns appropriate permissions for the Exchange Transport Service.

.DESCRIPTION 
 Creates a mount point for the Exchange Transport database, and assigns appropriate permissions for the Exchange Transport Service.
 Takes the following actions:
    -Creates a new partition on a specified disk number.
    -Removes permissions that don't need to be on the Mount Point folder, or Mount Point itself.
    -Adds required permissions to the Mount Point folder and Mount Point. Specifically, it gives Full Control permissions to SYSTEM, NETWORK SERVICE, and Local Administrators.
    -Stops the Microsoft Exchange Transport service, and the Microsoft Exchange Health Manager service (to prevent it from starting the Transport service back up).
    -Moves any existing Transport database files to a temporary location.
    -Adds a Mount Point to the new partition.
    -Moves the existing Transport database files to the Mount Point.
    -Starts the Microsoft Exchange Transport service, and the Microsoft Exchange Health Manager service.
    -Pre-creates the ‘System Volume Information’ folder underneath the Mount Point if it doesn’t already exist.
    -Gives SYSTEM, NETWORK SERVICE, and BUILTIN\Administrators permissions to the System Volume Information folder underneath the Mount Point.

.PARAMETER DiskNumberForVolume
 Disk number where to add and check for the Transport Database Partition

.PARAMETER UseMaximumSize
 Indicates whether all available remaininig space on the specified Disk should be used for the new Partition. Takes precedence over -PartitionSize. Defaults to True.

.PARAMETER PartitionSize
 Specifies the size of the Partition to create. The acceptable value for this parameter is a positive number followed by zero or one of the following unit values: Bytes, KB, MB, GB, or TB. If no unit specified, numeric value defaults to Bytes.

.PARAMETER FileSystem
 The file system to use when formatting the new Partition. Defaults to NTFS.

.PARAMETER VolumeLabel
 The label to add to the Transport Database Volume, if not already created.

.PARAMETER MountPointPath
 The Mount Point path which will be given to the new Partition.

.PARAMETER TempFileLocation
 A folder to temporarily move the existing Transport Database files to during Mount Point creation.

.PARAMETER TempDiskLetter
 A temporary drive letter to assign to the Volume while checking and setting permissions.

.PARAMETER UsersToGiveFullControl
 Specifies the accounts to give Full Control permissions to on the Mount Point and Volume. Defaults to "NT AUTHORITY\SYSTEM","NT AUTHORITY\NETWORK SERVICE","BUILTIN\Administrators".

.PARAMETER RemoveNonRequiredPermissions
 Whether to remove permissions from the Volume for anyone not specified in UsersToGiveFullControl. Defaults to True.

.EXAMPLE
 Sets up the Mount Point on disk number 1, utilizing all available disk space, and formatting with NTFS
 PS> .\Add-TransportDatabaseMountPoint.ps1 -DiskNumberForVolume 1

.EXAMPLE
 Sets up the Mount Point on disk number 1, and only uses 1TB for the partition size
 PS> .\Add-TransportDatabaseMountPoint.ps1 -DiskNumberForVolume 1 -UseMaximumSize $false -PartitionSize 1TB

.EXAMPLE
 Sets up the Mount Point on disk number 1, and formats the partition using REFS
 PS> .\Add-TransportDatabaseMountPoint.ps1 -DiskNumberForVolume 1 -FileSystem REFS

#>

[CmdletBinding()]
param
(
    [parameter(Mandatory = $true)]
    [UInt32]
    $DiskNumberForVolume,

    [Bool]
    $UseMaximumSize = $true,

    [UInt64]
    $PartitionSize,

    [ValidateSet("NTFS","REFS")]
    [String]
    $FileSystem = "NTFS",
    

    [ValidateSet("MBR","GPT")]
    [String]
    $PartitionStyle = "GPT",

    [String]
    $VolumeLabel = "Transport Database",

    [String]
    $MountPointPath = "C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\data\Queue",

    [String]
    $TempFileLocation = "C:\TransportTemp",

    [String]
    $TempDiskLetter = "T",

    [String[]]
    $UsersToGiveFullControl = @("NT AUTHORITY\SYSTEM","NT AUTHORITY\NETWORK SERVICE","BUILTIN\Administrators"),

    [Boolean]
    $RemoveNonRequiredPermissions = $true
)

function Test-ParameterInput
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [UInt32]
        $DiskNumberForVolume,

        [Bool]
        $UseMaximumSize,

        [UInt64]
        $PartitionSize,

        [String]
        $VolumeLabel,

        [String]
        $MountPointPath,

        [String]
        $TempFileLocation,

        [String]
        $TempDiskLetter,

        [String[]]
        $UsersToGiveFullControl
    )

    $paramsGood = $true

    if ($null -eq ((Get-Disk).Number | Where-Object {$_ -like $DiskNumberForVolume}))
    {
        Write-Error "The disk number which was specified for DiskNumberForVolume does not exist."
        $paramsGood = $false
    }

    if ($UseMaximumSize -eq $false)
    {
        if ($PartitionSize -lt 1GB)
        {
            Write-Error "PartitionSize must be greater than or equal to 1GB."
            $paramsGood = $false
        }
    }

    if ($true -eq ([String]::IsNullOrEmpty($MountPointPath)))
    {
        Write-Error "No path specified for MountPointPath."
        $paramsGood = $false
    }

    if ($true -eq ([String]::IsNullOrEmpty($TempFileLocation)))
    {
        Write-Error "No path specified for TempFileLocation."
        $paramsGood = $false
    }

    if ($true -eq ([String]::IsNullOrEmpty($TempDiskLetter)) -or $TempDiskLetter.Length -gt 1 -or $TempDiskLetter -lt 'A' -or $TempDiskLetter -gt 'z' -or ($TempDiskLetter -gt 'Z' -and $TempDiskLetter -lt 'a'))
    {
        Write-Error "Invalid drive letter specified for TempDiskLetter."
        $paramsGood = $false
    }

    if ($null -ne (Get-Volume -DriveLetter $TempDiskLetter -ErrorAction SilentlyContinue))
    {
        Write-Error "TempDiskLetter already in use."
        $paramsGood = $false
    }

    return $paramsGood
}

function Add-FullControlToAcl
{
    [CmdletBinding()]
    [OutputType([System.Object])]
    param
    (
        [Object]
        $AclObject,

        [String]
        $UserName
    )

    $rights = [System.Security.AccessControl.FileSystemRights]"FullControl"
    $accessType =[System.Security.AccessControl.AccessControlType]::Allow
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None

    $user = New-Object System.Security.Principal.NTAccount($UserName)
    $ace = New-Object System.Security.AccessControl.FileSystemAccessRule($user, $rights, $InheritanceFlag, $PropagationFlag, $accessType)
    $AclObject.AddAccessRule($ace) | Out-Null

    return $AclObject
}

function Get-VolumeForMountPoint
{
    [CmdletBinding()]
    param
    (
        [String]
        $MountPointPath
    )

	return (Get-Volume | Where-Object {($_ | Get-Partition).AccessPaths -like "$($MountPointPath)*"})
}

function New-VolumeForMountPoint
{
    [CmdletBinding()]
    param
    (
        [UInt32]
        $DiskNumberForVolume,

        [Bool]
        $UseMaximumSize,

        [UInt64]
        $PartitionSize,

        [String]
        $VolumeLabel,

        [String]
        $PartitionStyle,

        [String]
        $FileSystem
    )

    $disk = Get-Disk -Number $DiskNumberForVolume

    if ($disk.OperationalStatus -like "Offline")
    {
        Initialize-Disk -Number $DiskNumberForVolume
    }

    if ($UseMaximumSize)
    {
        $newPart = New-Partition -DiskNumber $DiskNumberForVolume -UseMaximumSize -ErrorAction Stop
    }
    else
    {
        $newPart = New-Partition -DiskNumber $DiskNumberForVolume -Size $PartitionSize -ErrorAction Stop
    }

    Write-Verbose "$([DateTime]::Now): Sleeping 10 seconds after partition creation before formatting volume."
    Start-Sleep -Seconds 10

    $formatOutput = $newPart | Format-Volume -FileSystem $FileSystem -NewFileSystemLabel $VolumeLabel -Confirm:$false -ErrorAction Stop

    return (Get-Volume -ObjectId $formatOutput.ObjectId)
}

function Get-PartitionForVolume
{
    [CmdletBinding()]
    param
    (
        $Volume
    )

	return ($Volume | Get-Partition)
}

function Add-DriveLetterToPartition
{
    [CmdletBinding()]
    param
    (
        $Volume,

        [String]
        $DriveLetter
    )

	$partition = Get-PartitionForVolume -Volume $Volume
	
	if ($partition.DriveLetter -ne $DriveLetter)
	{
		$partition  | Set-Partition -NewDriveLetter $DriveLetter
	}
}

function Remove-DriveLetterFromPartition
{
    [CmdletBinding()]
    param
    (
        $Partition,

        [String]
        $DriveLetter
    )

	$Partition | Remove-PartitionAccessPath -AccessPath "$($DriveLetter):\"
}

function Remove-UsersFromAcl
{
    [CmdletBinding()]
    [OutputType([System.Object])]
    param
    (
        [Object]
        $AclObject,

        [String[]]
        $UsersToKeep
    )

    $modifiedAcl = $false

    foreach ($ace in $AclObject.Access)
    {    
        $user = $ace.IdentityReference.ToString()

        if ($null -eq ($UsersToKeep | Where-Object {$_ -like $user}))
        {
            Write-Verbose "$([DateTime]::Now): User '$($user)' with '$($ace.AccessControlType.ToString())' permissions of type '$($ace.FileSystemRights.ToString())' will be removed from partition permissions"
            
            $AclObject.RemoveAccessRule($ace) | Out-Null

            $modifiedAcl = $true
        }
    }

	return $modifiedAcl
}

function Add-UsersToAclWithFullControl
{
    [CmdletBinding()]
    [OutputType([System.Object])]
    param
    (
        [Object]
        $AclObject,

        [String[]]
        $UsersToAdd
    )

    $modifiedAcl = $false

	foreach ($userName in $UsersToAdd)
	{
		if ($null -eq ($AclObject.Access | Where-Object {$_.IdentityReference.ToString() -like $userName -and $_.FileSystemRights.ToString() -like "FullControl"}))
		{
			Write-Verbose "$([DateTime]::Now): $($userName) will be given Full Control permissions to the partition."

			Add-FullControlToAcl -AclObject $acl -UserName $userName

            $modifiedAcl = $true
		}
	}

	return $modifiedAcl
}

function Add-MountPointToVolume
{
    [CmdletBinding()]
    param
    (
        [String]
        $MountPointPath,

        [String]
        $TempFileLocation
    )

    Write-Verbose "$([DateTime]::Now): Stopping transport and health manager services"

    Stop-Service MSExchangeHM
    Stop-Service MSExchangeTransport

    $existingFiles = Get-ChildItem $MountPointPath

    if ($null -ne $existingFiles)
    {
        Write-Verbose "$([DateTime]::Now): Moving existing files out of queue to temporary folder"

        if ((Test-Path $TempFileLocation) -eq $false)
        {
            mkdir $TempFileLocation | Out-Null
        }

        $existingFiles | Move-Item -Destination $TempFileLocation -Force -Confirm:$false
    }    

    Write-Verbose "$([DateTime]::Now): Adding mount point path to partition"

    $partition | Add-PartitionAccessPath -AccessPath $MountPointPath -PassThru | Set-Partition -NoDefaultDriveLetter $true

    if ($null -ne $existingFiles)
    {
        Write-Verbose "$([DateTime]::Now): Moving existing files back to queue mount point"

        Get-ChildItem $TempFileLocation | Move-Item -Destination $MountPointPath -Force -Confirm:$false
    }
    
    Write-Verbose "$([DateTime]::Now): Starting transport and health manager services"

    Start-Service MSExchangeTransport
    Start-Service MSExchangeHM
}

function Set-PermissionsOnSysVolFolder
{
    [CmdletBinding()]
    param
    (
		[String]
		$Folder,

		[String[]]
		$UsersToGivePermissions
	)

    $acl = Get-Acl -Path $Folder

    #Take ownership for local Administrators if they don't already have it
    if (($acl.Owner -like "BUILTIN\Administrators") -eq $false)
    {
        Write-Verbose "$([DateTime]::Now): Taking ownership of System Volume Information folder for local administrators"
        takeown /F "$($Folder)" /A /R /D Y
    }

    #Add missing permissions
	$modifiedAcl = Add-UsersToAclWithFullControl -AclObject $acl -UsersToAdd $UsersToGivePermissions

    if ($modifiedAcl -eq $true)
    {
	    Write-Verbose "$([DateTime]::Now): Committing permission updates"

        #Set the new perms
	    Set-Acl -Path $Folder -AclObject $acl
    }
}

### SCRIPT EXECUTION BEGINS HERE ###

Write-Output "$([DateTime]::Now): Beginning script execution. Use the -Verbose switch to get full details on what the script is doing."

#First verify script parameters
if ($false -eq (Test-ParameterInput -DiskNumberForVolume $DiskNumberForVolume -UseMaximumSize $UseMaximumSize -PartitionSize $PartitionSize -VolumeLabel $VolumeLabel -MountPointPath $MountPointPath -TempFileLocation $TempFileLocation -TempDiskLetter $TempDiskLetter -UsersToGiveFullControl $UsersToGiveFullControl))
{
    Write-Error "One or more parameters failed validation. Exiting script."
    return
}

#See if the desired volume already exists
$volume = Get-VolumeForMountPoint -MountPointPath $MountPointPath

#Create the new volume if needed
if ($null -eq $volume)
{
    Write-Output "$([DateTime]::Now): Desired partition does not exist. Creating new partition."

    $volume = New-VolumeForMountPoint -DiskNumberForVolume $DiskNumberForVolume -UseMaximumSize $UseMaximumSize -PartitionSize $PartitionSize -VolumeLabel $VolumeLabel -PartitionStyle $PartitionSize -FileSystem $FileSystem
}
else
{
    Write-Output "$([DateTime]::Now): Desired partition already exists."
}

if ($null -eq $volume)
{
    throw "Failed to find or create Transport DB volume"
}

##Do permissions

#Add a temp drive letter, as I couldn't find a way to view/modify permissions on a mount point directly
Write-Verbose "$([DateTime]::Now): Adding a temporary drive letter for checking/setting permissions"

Add-DriveLetterToPartition -Volume $volume -DriveLetter $TempDiskLetter

$acl = Get-Acl "$($TempDiskLetter):\"

#Remove unnecessary permissions from the Volume
if ($RemoveNonRequiredPermissions)
{
	$removedFromAcl = Remove-UsersFromAcl -AclObject $acl -UsersToKeep $UsersToGiveFullControl
}

#Add full control to specified users
$addedToAcl = Add-UsersToAclWithFullControl -AclObject $acl -UsersToAdd $UsersToGiveFullControl

if ($removedFromAcl -eq $true -or $addedToAcl -eq $true)
{
    #Set the new perms (even if they didn't change)
    Write-Output "$([DateTime]::Now): Committing permission updates"

    Set-Acl -Path "$($TempDiskLetter):\" -AclObject $acl
}

#Remove the temp drive letter
Write-Verbose "$([DateTime]::Now): Removing temp drive letter"

Get-PartitionForVolume -Volume $Volume | Remove-PartitionAccessPath -AccessPath "$($TempDiskLetter):\"

#Add the mount point to the partition
$partition = Get-PartitionForVolume -Volume $Volume

if ($null -eq ($partition.AccessPaths | Where-Object {$_ -like "*$($MountPointPath)*"}))
{
    Write-Output "$([DateTime]::Now): Adding mount point to new volume"

	Add-MountPointToVolume -MountPointPath $MountPointPath -TempFileLocation $TempFileLocation
}
else
{
    Write-Output "$([DateTime]::Now): Mount point already added to partition"
}

#Get the full path to where System Volume Information will reside
$sysVolFolder = Join-Path $MountPointPath "System Volume Information"

#Precreate the System Volume Information folder if it doesn't exist
if ((Test-Path $sysVolFolder) -eq $false)
{
    Write-Output "$([DateTime]::Now): Creating System Volume Information folder"

    mkdir $sysVolFolder | Out-Null
    attrib.exe +S +H "$($sysVolFolder)"
}

#Check and set permissions on the System Volume Information folder
if ((Test-Path $sysVolFolder) -eq $true)
{
    Set-PermissionsOnSysVolFolder -Folder $sysVolFolder -UsersToGivePermissions $UsersToGiveFullControl
}

Write-Output "$([DateTime]::Now): Finished script execution."
