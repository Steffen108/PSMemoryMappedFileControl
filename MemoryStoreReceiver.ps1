Function Get-MemoryMappedFile {
    [CmdletBinding()]Param(
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [System.String]$Name,
        [ValidateSet('Local','Global')]
        [System.String]$Scope  = 'Local',  # Local or Global (Global requires admin privileges)
        [System.Int64]$Size    = 5120,     # 5120 = 5 KB = max. 2560 Characters (UTF8 without Symbols or Emojis)
        [System.Management.Automation.SwitchParameter]$WriteHost,
        [System.Management.Automation.SwitchParameter]$WriteHostResultsOnly
    )

    try {
        # Define variables with initial values
        [System.Text.Encoding]$enc = [System.Text.Encoding]::UTF8
        [System.IntPtr]$handle     = [System.IntPtr]::Zero
        [System.String]$result     = [System.String]::Empty
        [System.String]$MapName    = "$($Scope)\$($Name)"
        
        # Add type for reading existing MemoryMappedFiles
        if (-not (Get-Variable -Name "MMFHelper" -Scope 'Global' -ValueOnly -ErrorAction Ignore)) {
            $Global:MMFHelper = Add-Type -PassThru -TypeDefinition @"
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
        
        # Check Name value
        if ([System.String]::IsNullOrWhiteSpace($Name)) {throw 'Name parameter value can not be null or whitespaces only!'}

        # Load MemoryMappedFile if already existing
        if ($WriteHost -and -not $WriteHostResultsOnly) {Write-Host "MMF map name: $MapName"}
        [System.IntPtr]$handle = [MMFHelper]::OpenFileMapping([MMFHelper]::FILE_MAP_READ, $false, $MapName)
        if ($handle -ne [System.IntPtr]::Zero) {
            if ($WriteHost -and -not $WriteHostResultsOnly) {Write-Host "MMF handle: $handle"}
            
            # Open MemoryMappedFile
            [System.IO.MemoryMappedFiles.MemoryMappedFile]$mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::OpenExisting(
                $MapName, 
                [System.IO.MemoryMappedFiles.MemoryMappedFileRights]::Read
            )

            # Create MemoryMappedViewAccessor object
            [System.IO.MemoryMappedFiles.MemoryMappedViewAccessor]$accessor = $mmf.CreateViewAccessor(
                0,
                0,
                [System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::Read
            )
            if ($WriteHost -and -not $WriteHostResultsOnly) {
                Write-Host (
                    "Accessor stats: " + `
                    "CanRead = $($accessor.CanRead) | CanWrite = $($accessor.CanWrite) | " + `
                    "Capacity = $($accessor.Capacity) | PointerOffset = $($accessor.PointerOffset)"
                )
            }

            # Read data from memory space
            [System.Byte[]]$buffer = [System.Byte[]]::new($Size)
            [System.Int64]$arr     = $accessor.ReadArray(0, $buffer, 0, $buffer.Length)
            if ($WriteHost -and -not $WriteHostResultsOnly) {Write-Host "Content size: $arr"}

            # Free memory space
            if ($null -ne $accessor) {$accessor.Dispose()}
            if ($null -ne $mmf)      {$mmf.Dispose()}
            if ($handle -ne [IntPtr]::Zero) {[System.Boolean]$cHResult = [MMFHelper]::CloseHandle($handle); $handle = [IntPtr]::Zero}
            if ($WriteHost -and -not $WriteHostResultsOnly) {Write-Host "CloseHandle result: $cHResult"}
            [System.GC]::Collect()

            # Create result value
            [System.Int64]$nullIndex  = 0
            $nullIndex = [System.Array]::IndexOf($buffer, [byte]0)
            if ($WriteHost -and -not $WriteHostResultsOnly) {Write-Host "Null index: $nullIndex"}
            if ($nullIndex -ge 0) {$result = $enc.GetString($buffer, 0, $nullIndex)}
            else {$result = $enc.GetString($buffer)}
            $result = $result.Trim()
            if ($WriteHost -and -not $WriteHostResultsOnly) {Write-Host "String length: $($result.Length)"}
            if ($WriteHost -and -not $WriteHostResultsOnly) {Write-Host "Content: $result"}
            if ($WriteHost -and $WriteHostResultsOnly -and -not ([System.String]::IsNullOrWhiteSpace($result))) {Write-Host $result}
        }
        else {if ($WriteHost -and -not $WriteHostResultsOnly) {Write-Host "Content not found."}}
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

    # Return result from memory space
    return $result
}


# ---  Main  ---
$ErrorActionPreference = 'Stop'
Clear-Host

[System.String]$Name   = "SPKState"
[System.String]$Scope  = 'Local'

while ($true) {
    $val = Get-MemoryMappedFile -Name $Name -Scope $Scope -WriteHost
    Start-Sleep -Seconds 1
}