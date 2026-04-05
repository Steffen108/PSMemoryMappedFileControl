Function Set-MemoryMappedFile {
    [CmdletBinding()]Param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSReference]$Data,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [System.String]$Name,
        [ValidateSet('Local','Global')]
        [System.String]$Scope                = 'Local',  # Local or Global (Global requires admin privileges)
        [System.Int64]$Size                  = 5120,     # 5120 = 5 KB = max. 2560 Characters (UTF8 without Symbols or Emojis)
        [System.Int32]$TimeoutInSeconds      = 30,
        [System.Int32]$WritingPauseInSeconds = 3,
        [System.Management.Automation.SwitchParameter]$WriteHost,
        [System.Management.Automation.SwitchParameter]$WriteHostResultsOnly
    )

    try {
        # Define variables with initial values
        [System.Object]$mmf        = $null
        [System.Object]$accessor   = $null
        [System.Text.Encoding]$enc = [System.Text.Encoding]::UTF8
        [System.IntPtr]$handle     = [System.IntPtr]::Zero
        [System.String]$MapName    = "$($Scope)\$($Name)"

        # Add type for reading existing MemoryMappedFiles
        if (-not (Get-Variable -Name "MMFHelper" -Scope 'Global' -ErrorAction Ignore)) {
            [System.Object]$Global:MMFHelper = Add-Type -PassThru -TypeDefinition @"
                using System;
                using System.Runtime.InteropServices;
                public class MMFHelper {
                    public const uint FILE_MAP_ALL_ACCESS = 1;
                    public const uint FILE_MAP_EXECUTE    = 2;
                    public const uint FILE_MAP_READ       = 4;
                    public const uint FILE_MAP_WRITE      = 8;
                    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
                    public static extern IntPtr OpenFileMapping(uint dwDesiredAccess, bool bInheritHandle, string lpName);
                    [DllImport("kernel32.dll", SetLastError = true)]
                    public static extern bool CloseHandle(IntPtr hObject);
                }
"@
            if ($WriteHost -and -not $WriteHostResultsOnly) {Write-Host "Global 'MMFHelper' object created."}
        } 
        else {if ($WriteHost -and -not $WriteHostResultsOnly) {Write-Host "Global 'MMFHelper' object exists."}}

        # Checks
            # Admin permissions required
            if ($Scope -eq 'Global') {
                [System.Boolean]$isAdmin = ([Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                if (-not $isAdmin) {throw 'Admin permissions required to start MemoryMappedFile with scope Global!'}
            }

            # Referenced data value
            if ($null -eq $Data) {throw 'Data parameter value can not be null!'}
            if ($Data.Value.GetType().Name -ne 'String') {throw 'Data parameter value type has to be String!'}

            # Name value
            if ([System.String]::IsNullOrWhiteSpace($Name)) {throw 'Name parameter value can not be null or whitespaces only!'}

        # Load MemoryMappedFile if already existing
        if ($WriteHost -and -not $WriteHostResultsOnly) {Write-Host "MMF map name: $MapName"}
        [System.IntPtr]$handle = [MMFHelper]::OpenFileMapping([MMFHelper]::FILE_MAP_READ, $false, $MapName)
        if ($handle -ne [System.IntPtr]::Zero) {
            if ($WriteHost -and -not $WriteHostResultsOnly) {Write-Host "MMF handle: $handle"}
            if ($WriteHost -and -not $WriteHostResultsOnly) {Write-Host "Opening existing MMf..."}
            
            # Open MemoryMappedFile
            try {
                [System.IO.MemoryMappedFiles.MemoryMappedFile]$mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::OpenExisting(
                    $MapName,
                    [System.IO.MemoryMappedFiles.MemoryMappedFileRights]::ReadWrite
                )
            } catch {Write-Host $($_ | Out-String).Trim() -ForegroundColor Gray}
        }

        if (-not $mmf) {
            if ($WriteHost -and -not $WriteHostResultsOnly) {Write-Host "Creating new MMf..."}
            
            # Set security definitions for MemoryMappedFile access
            [System.IO.MemoryMappedFiles.MemoryMappedFileSecurity]$security = [System.IO.MemoryMappedFiles.MemoryMappedFileSecurity]::new()
            $security.SetAccessRuleProtection($true, $false)

                # Everyone (Read)
                [System.Security.Principal.SecurityIdentifier]$everyone = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
                [System.Security.AccessControl.AccessRule[System.IO.MemoryMappedFiles.MemoryMappedFileRights]]$rule = [System.Security.AccessControl.AccessRule[System.IO.MemoryMappedFiles.MemoryMappedFileRights]]::new(
                    $everyone, 
                    [System.IO.MemoryMappedFiles.MemoryMappedFileRights]::Read, 
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
                $security.AddAccessRule($rule)

                # Administrators (FullControl and TakeOwnership)
                [System.Security.Principal.SecurityIdentifier]$admins   = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
                [System.Security.AccessControl.AccessRule[System.IO.MemoryMappedFiles.MemoryMappedFileRights]]$rule = [System.Security.AccessControl.AccessRule[System.IO.MemoryMappedFiles.MemoryMappedFileRights]]::new(
                    $admins, 
                    [System.IO.MemoryMappedFiles.MemoryMappedFileRights]::FullControl, 
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
                $security.AddAccessRule($rule)
                [System.Security.AccessControl.AccessRule[System.IO.MemoryMappedFiles.MemoryMappedFileRights]]$rule = [System.Security.AccessControl.AccessRule[System.IO.MemoryMappedFiles.MemoryMappedFileRights]]::new(
                    $admins, 
                    [System.IO.MemoryMappedFiles.MemoryMappedFileRights]::TakeOwnership, 
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
                $security.AddAccessRule($rule)

                # System user (FullControl and TakeOwnership)
                [System.Security.Principal.SecurityIdentifier]$system   = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
                [System.Security.AccessControl.AccessRule[System.IO.MemoryMappedFiles.MemoryMappedFileRights]]$rule = [System.Security.AccessControl.AccessRule[System.IO.MemoryMappedFiles.MemoryMappedFileRights]]::new(
                    $system, 
                    [System.IO.MemoryMappedFiles.MemoryMappedFileRights]::FullControl, 
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
                $security.AddAccessRule($rule)
                [System.Security.AccessControl.AccessRule[System.IO.MemoryMappedFiles.MemoryMappedFileRights]]$rule = [System.Security.AccessControl.AccessRule[System.IO.MemoryMappedFiles.MemoryMappedFileRights]]::new(
                    $system, 
                    [System.IO.MemoryMappedFiles.MemoryMappedFileRights]::TakeOwnership, 
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
                $security.AddAccessRule($rule)

                # Current user (FullControl and TakeOwnership and SetOwner)
                [System.Security.Principal.SecurityIdentifier]$cuser    = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
                [System.Security.AccessControl.AccessRule[System.IO.MemoryMappedFiles.MemoryMappedFileRights]]$rule = [System.Security.AccessControl.AccessRule[System.IO.MemoryMappedFiles.MemoryMappedFileRights]]::new(
                    $cuser, 
                    [System.IO.MemoryMappedFiles.MemoryMappedFileRights]::FullControl, 
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
                $security.AddAccessRule($rule)
                [System.Security.AccessControl.AccessRule[System.IO.MemoryMappedFiles.MemoryMappedFileRights]]$rule = [System.Security.AccessControl.AccessRule[System.IO.MemoryMappedFiles.MemoryMappedFileRights]]::new(
                    $cuser, 
                    [System.IO.MemoryMappedFiles.MemoryMappedFileRights]::TakeOwnership, 
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
                $security.AddAccessRule($rule)
                $security.SetOwner($cuser)
            
            # Create MemoryMappedFile object
            [System.IO.MemoryMappedFiles.MemoryMappedFile]$mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateOrOpen(
                $MapName, 
                $Size,
                [System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite,
                [System.IO.MemoryMappedFiles.MemoryMappedFileOptions]::None,
                $security,
                [System.IO.HandleInheritability]::None
            )
        }

        # Create MemoryMappedViewAccessor object
        [System.IO.MemoryMappedFiles.MemoryMappedViewAccessor]$accessor = $mmf.CreateViewAccessor()
        if ($WriteHost -and -not $WriteHostResultsOnly) {
            Write-Host (
                "Accessor stats: " + `
                "CanRead=$($accessor.CanRead) | CanWrite=$($accessor.CanWrite) | " + `
                "Capacity=$($accessor.Capacity) | PointerOffset=$($accessor.PointerOffset)"
            )
        }

        # Write to memory
            # Define variables
            [System.String]$fillVal    = [System.Char][System.Byte]0
            [System.Byte[]]$buffer     = [System.Byte[]]::new($Size)
            [System.Int64] $i          = 0
            [System.Int64] $valLength  = 0
            [System.Int64] $bytes      = 0
            [System.String]$val        = [System.String]::Empty
            
            # Overwrite last memory space with null
            $accessor.WriteArray(0, $buffer, 0, $buffer.Length)

            # Run loop for memory space writing
            while ($true) {
                # Check for timeout
                if ($TimeoutInSeconds -gt 0) {if ($i -ge $TimeoutInSeconds) {break}}

                # Check for value
                if ($Data.Value -eq 'StopMmfWriting') {break}

                # Add timestamp to value
                $val = "$(Get-Date -Format 'HH:mm:ss'); $($Data.Value)"

                # Set value to overwrite characters of a longer last value in the memory with null characters
                if ($val.Length -lt $valLength) {$val = "$($val)$($fillVal*($valLength - $val.Length))"}
                $valLength = $val.Length

                # Prepare data
                $bytes = $enc.GetBytes($val, 0, $val.Length, $buffer, 0)
                if ($WriteHost -and -not $WriteHostResultsOnly) {Write-Host "Content size: $($buffer.Count)"}

                # Write data to memory space
                $accessor.WriteArray(0, $buffer, 0, $bytes)

                # Finish loop step
                if ($WriteHost -and -not $WriteHostResultsOnly) {Write-Host "String length: $($valLength)"}
                if ($WriteHost -and -not $WriteHostResultsOnly) {Write-Host "Content: $val"}
                if ($WriteHost -and $WriteHostResultsOnly -and -not ([System.String]::IsNullOrWhiteSpace($val))) {Write-Host $val}
                if ($WriteHost -and -not $WriteHostResultsOnly) {Write-Host "Timeout: $(if ($TimeoutInSeconds -gt 0) {"$($i)/$($TimeoutInSeconds) seconds"} else {"None"})"}
                if ($WriteHost -and -not $WriteHostResultsOnly) {Write-Host "Waiting $($WritingPauseInSeconds) seconds for next content update..."}
                $i = $i + $WritingPauseInSeconds
                Start-Sleep -Seconds $(if ($WritingPauseInSeconds -gt 0) {$WritingPauseInSeconds} else {1})
            }
    }
    catch {
        # Error handling
        Write-Host $($_ | Out-String).Trim() -ForegroundColor Yellow
    }
    finally {
        # Free memory space
        if ($null -ne $accessor) {$accessor.Dispose()}
        if ($null -ne $mmf)      {$mmf.Dispose()}
        if ($handle -ne [IntPtr]::Zero) {[System.Boolean]$cHResult = [MMFHelper]::CloseHandle($handle); $handle = [IntPtr]::Zero}
        [System.GC]::Collect()
    }
}


# ---  Main  ---
$ErrorActionPreference = 'Stop'
Clear-Host

[System.String]$global:installPhase  = [System.String]::Empty
[System.String]$Name                 = "SPKState"
[System.String]$Scope                = 'Local'
[System.Int32]$TimeoutInSeconds      = 10
[System.Int32]$WritingPauseInSeconds = 1

Set-MemoryMappedFile -Data $([ref]$global:installPhase) -Name $Name -Scope $Scope -TimeoutInSeconds 15 -WritingPauseInSeconds 3 -WriteHost

$global:installPhase = "Title=The new TITLE; Subtitle = the new MOText2"
Set-MemoryMappedFile -Data $([ref]$global:installPhase) -Name $Name -Scope $Scope -TimeoutInSeconds 15 -WritingPauseInSeconds 3 -WriteHost

$global:installPhase = "FilePathImage=C:\Temp\Logo.png;FilePathImageUpdated=true"
Set-MemoryMappedFile -Data $([ref]$global:installPhase) -Name $Name -Scope $Scope -TimeoutInSeconds 15 -WritingPauseInSeconds 3 -WriteHost

$global:installPhase = "Title=The newest TITLE; Subtitle = the end MOText"
Set-MemoryMappedFile -Data $([ref]$global:installPhase) -Name $Name -Scope $Scope -TimeoutInSeconds 15 -WritingPauseInSeconds 3 -WriteHost