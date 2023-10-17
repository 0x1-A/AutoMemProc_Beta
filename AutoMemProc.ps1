Clear-Host 
Write-Host ""
Write-Host "##########################" -ForegroundColor darkblue
Write-Host " #    AutoMemProc.ps1   #" -ForegroundColor darkblue
Write-Host "##########################" -ForegroundColor darkblue
Write-Host ""
Write-Host "Author: " -ForegroundColor Yellow -NoNewline; Write-Host "Atiah Aloufi" 
Write-Host ""

 $global:JobMetadata= @{}

function ImagePath {
    param (
        [string]$prompt = "↬ Enter the path to the memory image file or directory: ",
        [string[]]$imageFileExtensions = @("*.img", "*.dmp", "*.raw", "*.bin", "*.mem", "*.dump", "*.dat", "*.lime", "*.crash", "*.vmem") 
    )

    function ListAndSelectFilesFromDirectory($directoryPath) {
        $filesInDir = @()
        foreach ($extension in $imageFileExtensions) {
            $filesInDir += Get-ChildItem -Path $directoryPath -Filter $extension
        }

        if ($filesInDir.Count -eq 0) {
            Write-Host "No image files found in the current directory." -ForegroundColor Red
            Write-Host ""
            return $null
        }
Write-Host ""
        Write-Host "↬ Found the following image files in the directory: " -ForegroundColor Green
        $counter = 1
        $filesInDir | ForEach-Object {
            Write-Host "$counter. $_"
            $counter++
        }
        Write-Host ""

        do {
            Write-Host "↬ Enter the number of the image file you want to use (or press Enter to specify a different path): " -ForegroundColor darkyellow -NoNewLine
            $choice = Read-Host

            if (-not $choice) {
                return $null
            }

            if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $filesInDir.Count) {
                return $filesInDir[[int]$choice - 1].FullName
            } else {
                Write-Host "Invalid choice. Please select a number from the list." -ForegroundColor Red
            }
        } while ($true)
    }

    $imageFiles = ListAndSelectFilesFromDirectory "."
    if ($imageFiles) {
        return $imageFiles
    }

    while ($true) {
        Write-Host $prompt -ForegroundColor darkyellow -NoNewLine
        $inputPath = Read-Host

        if ([string]::IsNullOrEmpty($inputPath)) {
            Write-Host "The path cannot be empty. Please provide a valid path." -ForegroundColor Red
        }
        elseif (Test-Path -LiteralPath $inputPath -PathType Container) {
            $selectedFile = ListAndSelectFilesFromDirectory $inputPath
            if ($selectedFile) {
                return $selectedFile
            }
        } 
        elseif (Test-Path -LiteralPath $inputPath -PathType Leaf) {
            $fileExtension = [System.IO.Path]::GetExtension($inputPath)
            if ($imageFileExtensions -contains "*$fileExtension") {
                Write-Host "Memory image file path is valid." -ForegroundColor Green
                return $inputPath
            } else {
                Write-Host "The provided file does not have a supported extension. Please provide a valid image file path or a directory containing image files." -ForegroundColor Red
            }
        }
        else {
            Write-Host "The specified path does not exist. Please provide a valid file or directory path." -ForegroundColor Red
        }
    }
}

function VolToolPath {
    param (
        [string]$prompt = "↬ Enter the path to the Volatility Tool (e.g., /path/to/vol.py): ",
        [string]$configFilePath = "volatilityPath.txt"
    )


    $currentDirectory = Get-Location
    $volatilityToolPathInCurrentDir = Join-Path -Path $currentDirectory -ChildPath "vol.py"
    if (Test-Path -LiteralPath $volatilityToolPathInCurrentDir -PathType Leaf) {
        Write-Host "↬ Found Volatility tool in the current directory. Do you want to use this path (y/n): " -ForegroundColor Green -NoNewLine

        $useCurrentDirChoice = Read-Host
        if ($useCurrentDirChoice -eq 'y' -or $useCurrentDirChoice -eq 'yes') {
            return $volatilityToolPathInCurrentDir
        }
    }

if (Test-Path -LiteralPath $configFilePath) {
    $savedPath = Get-Content $configFilePath
    if ($savedPath -and (Test-Path -LiteralPath $savedPath -PathType Leaf)) {
        while ($true) { 
            Write-Host ""
            Write-Host "↬ Found saved Volatility path: $savedPath. Do you want to use this path (y/n): " -ForegroundColor Green -NoNewLine
            $useSavedPathChoice = Read-Host
            if ($useSavedPathChoice -eq 'y' -or $useSavedPathChoice -eq 'yes') {
                return $savedPath
            } elseif ($useSavedPathChoice -eq 'n' -or $useSavedPathChoice -eq 'no') {
               break 
            } else {
                Write-Host "Invalid choice. Please enter 'y' for yes or 'n' for no." -ForegroundColor Red
            }
        }
    }
}

    while ($true) {
        Write-Host ""
        Write-Host $prompt -ForegroundColor darkyellow -NoNewLine
        $volatilityPath = Read-Host
        if (Test-Path -LiteralPath $volatilityPath -PathType Leaf) {
            Write-Host ""
            Write-Host "↬ Do you want to save this path for future use (y/n): " -ForegroundColor darkyellow -NoNewLine
            $saveChoice = Read-Host
            if ($saveChoice -eq 'y' -or $saveChoice -eq 'yes') {
                $volatilityPath | Out-File $configFilePath
                Write-Host "Path saved for future use in $configFilePath" -ForegroundColor Green
            }
            return $volatilityPath
        } else {
        Write-Host ""
            Write-Host "The specified path does not exist or is not a valid file. Please provide a valid path." -ForegroundColor Red
        }
    }
}

function CustomCommand {
Clear-Host

    Write-Host "Welcome to Volatility CLI {We a ready include the Tool path and selected Image path to save your time}" -ForegroundColor Yellow
    Write-Host "Note: Type exit to return to Main Menu" -ForegroundColor Red
    Write-Host ""

    while ($true) {

        $prepopulatedPart = "$volatilityPath -f $memoryImagePath "
        
        Write-Host "↪" -ForegroundColor darkyellow -NoNewline
        Write-Host " $prepopulatedPart" -ForegroundColor darkyellow -NoNewline
        
        $customCommand = Read-Host

        if ($customCommand -eq 'exit') {
            Write-Host "Exiting Volatility 3.2.5.1 CLI..." -ForegroundColor green -NoNewline
            
            return
        }

        $fullCommand = "$prepopulatedPart$customCommand"


        Invoke-Expression $fullCommand

        Write-Host ""
    }
}

function Get-UniqueFolderName($baseDir) {
    $version = 1
    while (Test-Path "${baseDir}_v${version}") {
        $version++
    }
    return "${baseDir}_v${version}"
}

function Get-UniqueFileName {
    param (
        [string]$filePath
    )

    $version = 1
    $baseFileName = [System.IO.Path]::GetFileNameWithoutExtension($filePath)
    $fileExtension = [System.IO.Path]::GetExtension($filePath)
    $directory = [System.IO.Path]::GetDirectoryName($filePath)

    while (Test-Path (Join-Path -Path $directory -ChildPath "$baseFileName-v$version$fileExtension")) {
        $version++
    }

    return (Join-Path -Path $directory -ChildPath "$baseFileName-v$version$fileExtension")
}

function Ask-Overwrite {
    param (
        [string]$filePath
    )

    while ($true) {
    Write-Host ""
        Write-Host ""
        Write-Host "↪ A file with the same name already exists. Do you want to overwrite it (y/n): " -ForegroundColor Yellow -NoNewLine
        $choice = Read-Host 
        
        if ($choice -eq 'Y' -or $choice -eq 'y') {
            Write-Host "The File has been overwrite" -ForegroundColor Green
            return $filePath
        }
        elseif ($choice -eq 'N' -or $choice -eq 'n') {
            return (Get-UniqueFileName -filePath $filePath)
        }
        else {
            Write-Host "Invalid choice. Please enter 'Y' or 'N'."-ForegroundColor Red
        }
    }
}

function Ask-DirOverwrite {
    param (
        [string]$dirPath
    )

    while ($true) {
        
        Write-Host "↪ Directory $dirPath already exists. Do you want to overwrite it? (Y/N): " -ForegroundColor Yellow -NoNewLine
        $choice = Read-Host 
        
        if ($choice -eq 'Y' -or $choice -eq 'y') {
            Get-ChildItem -Path $dirPath -Recurse | Remove-Item -Force
            return $dirPath
        }
        elseif ($choice -eq 'N' -or $choice -eq 'n') {
            return (Get-UniqueFolderName -baseDir $dirPath)
        }
        else {
            Write-Host "Invalid choice. Please enter 'Y' or 'N'."-ForegroundColor Red
        }
    }
}

function Ask-InputProcessID {
    while ($true) {
        Write-Host "↪ Do you want to input a process ID (y,n): " -ForegroundColor Yellow -NoNewLine
        $choice = Read-Host
        
        if ($choice -eq 'Y' -or $choice -eq 'y') {
            return $true
        }
        elseif ($choice -eq 'N' -or $choice -eq 'n') {
        Write-Host ""
            return $false
            
        }
        else {
            Write-Host "Invalid choice. Please enter 'Y' or 'N'."-ForegroundColor Red
        }
    }
}

function Ask-RegistryKey {
    $choice = $null
    do {
        Write-Host "↪ Do you want to specify a registry key? (Y/N): " -ForegroundColor Yellow -NoNewLine
        $choice = Read-Host 
    } until ($choice -match "^(y|Y|n|N)$")

    if ($choice -match "^(y|Y)$") {
        Write-Host""
        Write-Host "↪ Enter the registry key you want to investigate (e.g., 'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths'):" -ForegroundColor Yellow
        $registryKey = Read-Host 
        return $registryKey
    }
    
    return $null
}

function Ask-UseGrep {
    $useGrep = $null
    while ($null -eq $useGrep) {
        Write-Host "↪ Would you like to use grep to search for specific terms (y/n): " -ForegroundColor Yellow -NoNewline
        $useGrep = Read-Host 
        Write-Host ""
        
        if ($useGrep -match "^[Yy]$") {
            $grepTerms = $null
            while ($null -eq $grepTerms) {
                Write-Host "↪ Enter the terms separated by commas (e.g. term1,term2): "-ForegroundColor Yellow -NoNewline
                $grepTermsInput = Read-Host

                if (-not $grepTermsInput) {
                    Write-Host "Please provide valid terms for grep." -ForegroundColor Red
                } else {
                    $grepFormattedTermsArray = $grepTermsInput -split "," | ForEach-Object { $_.Trim().Replace(' ', '\ ') }
                    $grepTerms = $grepFormattedTermsArray -join "\|"
                }
            }
            return $grepTerms
        } elseif ($useGrep -match "^[Nn]$") {
            return $null
        } else {
            Write-Host "Invalid choice. Please select y or n." -ForegroundColor Red
            $useGrep = $null
        }
    }
}

function JobCheck {
    $jobs = Get-Job

    if ($jobs.Count -eq 0) {
        Write-Host "#######################################"-ForegroundColor Yellow
        Write-Host " There are no background jobs running." -ForegroundColor Yellow
        Write-Host "#######################################"-ForegroundColor Yellow
        Write-Host ""
        return
    }

    foreach ($job in $jobs) {
        Write-Host "##############################################" -ForegroundColor DarkBlue

        $jobStatusColor = switch ($job.State) {
            "Running"  { "DarkYellow" }
            "Failed"   { "Red" }
            "Completed"{ "Green" }
            default    { "Yellow" }
        }

        Write-Host " Job Name: $($job.Name)," -NoNewline -ForegroundColor DarkBlue
        Write-Host " ID: $($job.Id)," -NoNewline -ForegroundColor DarkBlue
        Write-Host " Status: " -NoNewline -ForegroundColor DarkBlue
        Write-Host "$($job.State) " -NoNewline -ForegroundColor $jobStatusColor

        if ($global:JobMetadata.ContainsKey($job.Id) -and $global:JobMetadata[$job.Id].ContainsKey('grepTerms')) {
            Write-Host "Grep Terms: $($global:JobMetadata[$job.Id]['grepTerms'])" -NoNewline -ForegroundColor DarkBlue
        }

        Write-Host "" -ForegroundColor Yellow
        Write-Host "##############################################" -ForegroundColor DarkBlue
        Write-Host ""
    }
}

function JobRemove {
    while ($true) {
        $jobs = Get-Job

        if ($jobs.Count -eq 0) {
            Write-Host "No active background jobs." -ForegroundColor DarkBlue
            Write-Host ""
            return
        }

        Write-Host "List of Active Background Jobs:" -ForegroundColor darkYellow

        foreach ($job in $jobs) {
            $grepInfo = ""
            if ($global:JobMetadata[$job.Id] -and $global:JobMetadata[$job.Id]['GrepTerms']) {
                $grepInfo = "| Grep Terms: $($global:JobMetadata[$job.Id]['GrepTerms'])"
            }
            Write-Host "ID: $($job.Id) | Name: $($job.Name) | Status: $($job.State) $grepInfo" -ForegroundColor DarkBlue
        }

        Write-Host ""
        Write-Host "Enter the IDs of the jobs you want to remove (comma separated), type 'all' to remove all jobs, or 'exit' to cancel: " -ForegroundColor Red -NoNewLine
        $userInput = Read-Host 

        if ($userInput -eq "all") {
            $jobs | ForEach-Object {
                $_ | Stop-Job  
                $_ | Remove-Job  
            }
            Write-Host "All jobs removed successfully!" -ForegroundColor Green
            Write-Host ""
        } elseif ($userInput -eq "exit") {
            Write-Host "Job Removal cancelled." -ForegroundColor Red -NoNewLine
            Write-Host ""
            break  
        } else {
            $selectedIds = $userInput -split ',' | ForEach-Object { $_.Trim() }

            foreach ($id in $selectedIds) {
                if ($jobs.Id -contains $id) {
                    $jobToRemove = Get-Job -Id $id
                    $jobToRemove | Stop-Job  
                    $jobToRemove | Remove-Job  
                    Write-Host ""
                    Write-Host "Job with ID $id removed successfully!" -ForegroundColor Green
                    Write-Host ""
                } else {
                    Write-Host ""
                    Write-Host "No job found with ID $id, please enter valid ID" -ForegroundColor Red
                    Write-Host ""
                }
            }
        }
    }
}

function ClearAndShowList {
    Clear-Host

}

function jobsupport {
Write-Host""
Write-Host "Background Jobs Plugins List: " -ForegroundColor Darkyellow
Write-Host "- Timeline " -ForegroundColor Darkyellow
Write-Host "- " -ForegroundColor Darkyellow
Write-Host "Background Jobs Plugins List: " -ForegroundColor Darkyellow
}

function DisplayHelp {
    Write-Host ""
    Write-Host "AutoMemProc.ps1 Help" -ForegroundColor Darkyellow
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Darkyellow
    Write-Host ""
    Write-Host "... Just pick a number from displayed list and follow the prompt ;)"
    Write-Host ""
    
Write-Host "Commands:" -ForegroundColor Darkyellow
Write-Host ""

Write-Host "1} Plugins" -ForegroundColor Darkyellow
Write-Host "- " -NoNewline
Write-Host "[timeline]" -ForegroundColor yellow -NoNewline
Write-Host " Executes the Timeline plugin, provides a timeline of events."
Write-Host "- " -NoNewline
Write-Host "[dump -p]" -ForegroundColor yellow -NoNewline
Write-Host " Dump a process along with its associated content using the 'dumpfile' plugin."
Write-Host ""
Write-Host "2} Background Jobs" -ForegroundColor Darkyellow
Write-Host "- " -NoNewline
Write-Host "[job -s]" -ForegroundColor yellow -NoNewline
Write-Host " List Plugins with Background Job feature."
Write-Host "- " -NoNewline
Write-Host "[job -all]" -ForegroundColor yellow -NoNewline
Write-Host " Check the status of background jobs initiated by this tool."
Write-Host "- " -NoNewline
Write-Host "[job -r]" -ForegroundColor yellow -NoNewline
Write-Host " Remove background jobs initiated by this tool."
Write-Host ""
Write-Host "3} Miscellaneous" -ForegroundColor Darkyellow
Write-Host "- " -NoNewline
Write-Host "[help]" -ForegroundColor yellow -NoNewline
Write-Host " Help Message"

Write-Host "- " -NoNewline
Write-Host "[status]" -ForegroundColor yellow -NoNewline
Write-Host " Shows current supported plugin in the tool"

Write-Host "- " -NoNewline
Write-Host "[show]" -ForegroundColor yellow -NoNewline
Write-Host " Show currently selected live image."

Write-Host "- " -NoNewline
Write-Host "[clear]" -ForegroundColor yellow -NoNewline
Write-Host " Clear the terminal."

Write-Host "- " -NoNewline
Write-Host "[back]" -ForegroundColor yellow -NoNewline
Write-Host " To return to previous list"

Write-Host ""

    
    Write-Host "Notes:" -ForegroundColor DarkYellow
    Write-Host "- Please ensure you do not exit the tool until your job completes, as exiting while a job is active will terminate the job."
    Write-Host "- For a background job running status using Linux terminal, you can identify it using the 'ps -ef'"
    Write-Host ""
    
    Write-Host "We hope this tool simplifies your memory analysis process." -ForegroundColor Cyan
    Write-Host "Please enjoy using the tool, and do let us know if you have any suggestions" -ForegroundColor Cyan
}

function Status {
    Write-Host ""
    Write-Host @" 
    PLUGIN STATUS

-Image Identification

[DONE]    windows.info.Info           - Show OS & kernel details of the memory sample being analyzed.

-Processes and DLLs

[DONE]    windows.psscan.PsScan       - Scans for processes in a memory image.
[DONE]    windows.pslist.PsList       - Lists processes in a memory image.
[DONE]    windows.pstree.PsTree       - Lists processes in a tree based on parent PID.
[DONE]    windows.cmdline.CmdLine     - Lists process command line arguments.
[DONE]    windows.dlllist.DllList     - Lists loaded modules in a memory image.
[DONE]    windows.getsids.GetSIDs     - Lists loaded modules in a memory image.
[DONE]    windows.privileges.Privs    - Lists process token privileges.
[DONE]    windows.handles.Handles     - Displays handles opened by processes.
[DONE]    windows.verinfo.VerInfo     - Lists PE files version information.
[DONE]    windows.envars.Envars       - Display process environment variables.
[DONE]    windows.malfind.Malfind     - Lists process memory ranges with potential injected code.
[DONE]    windows.skeleton_key_check.Skeleton_Key_Check - Looks for Skeleton Key malware signs.
[DONE]    windows.svcscan.SvcScan     - Scans for windows services.
[DONE]    windows.sessions.Sessions   - Lists Processes with Session information.
[DONE]    windows.joblinks.JobLinks   - Print process job link information.

-Process Memory

[DONE]    windows.memmap.Memmap       - Prints the memory map.
[DONE]    windows.vadinfo.VadInfo     - Lists process memory ranges.
[DONE]    windows.virtmap.VirtMap     - Lists virtual mapped sections.
[DONE]    windows.vadwalk.VadWalk     - Walks the VAD tree.

-Networking

[DONE]    windows.netscan.NetScan     - Scans for network objects in a memory image.
[DONE]    windows.netstat.NetStat     - Traverses network tracking structures.

-Kernal Memory and Object

[DONE]    windows.ldrmodules.LdrModules - Lists loaded modules in a memory image.
[DONE]    windows.modscan.ModScan     - Scans for modules in a memory image.
[DONE]    windows.modules.Modules     - Lists the loaded kernel modules.
[DONE]    windows.driverscan.DriverScan - Scans for drivers present in a memory image.
[DONE]    windows.driverirp.DriverIrp - Lists IRPs for drivers in a memory image.
[DONE]    windows.filescan.FileScan   - Scans for file objects present in a memory image.
[DONE]    windows.symlinkscan.SymlinkScan - Scans for links in a memory image.
[DONE]    windows.mutantscan.MutantScan - Scans for mutexes in a memory image.
[DONE]    windows.callbacks.Callbacks - Lists kernel callbacks and notification routines.
[DONE]    windows.ssdt.SSDT           - Lists the system call table.
[DONE]    windows.devicetree.DeviceTree - Listing tree based on drivers and devices.

-Registry

[DONE]    windows.registry.hivescan.HiveScan - Scans for registry hives in a memory image.
[DONE]    windows.registry.hivelist.HiveList - Lists registry hives in a memory image.
[DONE]    windows.registry.printkey.PrintKey - Lists registry keys under a hive/key value.
[DONE]    windows.registry.certificates.Certificates - Lists certificates in registry's Certificate Store.
[DONE]    windows.getservicesids.GetServiceSIDs - Lists process token SIDs.
[DONE]    windows.registry.userassist.UserAssist - Print userassist registry keys and information.
[DONE]    windows.hashdump.Hashdump   - Dumps user hashes from memory.
[DONE]    windows.lsadump.Lsadump     - Dumps LSA secrets from memory.


-Crash Dumps, Hibernation, and Conversion

[DONE]    windows.crashinfo.Crashinfo - Lists information from a Windows crash dump.
[DONE]    windows.cachedump.Cachedump - Extracts cached credentials.

-File System

[DONE]    windows.mftscan.MFTScan     - Scans for MFT FILE objects.
[DONE]    windows.mbrscan.MBRScan     - Scans for and parses Master Boot Records (MBRs).

-Miscellaneous

[DONE]    windows.dumpfiles.DumpFiles - Dumps cached file contents.
[DONE]    timeliner.Timeliner         - Lists time-related information ordered by time.
[DONE]    windows.bigpools.BigPools   - Lists big page pools.
[DONE]    windows.poolscanner.PoolScanner - A generic pool scanner plugin.

"@ -ForegroundColor darkyellow
}

function ShowCurrentSelection {
Write-Host ""
   Write-Host "Current selected memory image file path: ($memoryImagePath)" -ForegroundColor Green
}

function RunInBackground {
    $response = $null
    do {
    Write-Host ""
    Write-Host "↪ This operation take time to Complete. Do you wish to run it in the background (y, n): " -ForegroundColor Yellow -NoNewLine
        $response = Read-Host 
        $response = $response.ToLower()
    } while ($response -ne 'y' -and $response -ne 'yes' -and $response -ne 'n' -and $response -ne 'no')

    return $response -eq 'y' -or $response -eq 'yes'
}

function jobsupport {
Write-Host""
Write-Host "Background Jobs Plugins List: " -ForegroundColor Darkyellow
Write-Host "- Timeline " -ForegroundColor yellow
Write-Host "- MemMap" -ForegroundColor yellow
Write-Host "- MBRScan" -ForegroundColor yellow
Write-Host "- DeviceTree" -ForegroundColor yellow
Write-Host "- PoolScanner" -ForegroundColor yellow
Write-Host "- BigPools" -ForegroundColor yellow

}

function Confirm-Action {
    Write-Host "↪ Are you sure you want to run this plugin (y/n): " -ForegroundColor Yellow -NoNewline
    $confirmation = Read-Host 
    Write-Host ""
    switch ($confirmation.ToLower()) {
        "y" { 
        return $true 
        Write-Host ""
        }
        "n" { 
            Write-Host "The process has been canceled based on your choice." -ForegroundColor Red
            return $false
             
        }
        default {
            Write-Host "Invalid option. Please enter 'y' or 'n'."
            return Confirm-Action
        }
    }
}

function IsValidProcessID($input) {
    return $input -match '^(\d+)(,\s*\d+)*$'
}

function Ask-InputVirtualAddress {
    $isValidInput = $false
    do {
        Write-Host "↪ Enter the Virtual Address for DumpFiles or 'cancel' to return to the list: " -ForegroundColor Yellow -NoNewline
        $virtualAddressInput = Read-Host
        if ($virtualAddressInput -eq 'cancel') {
            return $null
        }
        if ($virtualAddressInput -match '^0x[0-9a-fA-F]+$') {
            $isValidInput = $true
        } else {
            Write-Host "Invalid input. Please enter a valid Virtual Address or type 'cancel'." -ForegroundColor Red
            Write-Host ""
        }
    } 
    while (-not $isValidInput)
    return $virtualAddressInput
}

Function Dumproc  {     
if ($pluginChoice -eq 'dump -p') {

    Write-Host @"
-----------------------------------------------------------
                    DUMP - PROCESS MODE
-----------------------------------------------------------
You have selected the option to dump process memory using the 'dumpfile' plugin.

This feature allows you to extract specific process-related data from a memory image. By providing a Process ID, the tool will attempt to dump the memory content associated with that process.

Usage:
   1. Confirm whether you wish to execute the DumpFile Plugin.
   2. Enter a valid Process ID (PID) when prompted. You can provide a single PID or multiple PIDs separated by commas.
   3. The tool will process the memory image to extract data for the provided PIDs.
   4. Once completed, the dumped process data will be saved in separate directories (named after the respective process IDs) located where the memory file is stored.

Please ensure you have the appropriate permissions and enough storage space for this operation.

-----------------------------------------------------------
"@ -ForegroundColor darkyellow

    if (Confirm-Action) { 
        $memoryImageDirectory = [System.IO.Path]::GetDirectoryName($memoryImagePath)
        
        $continueRunning = $true
        $returnToList = $false  
        while ($continueRunning) {
            $isValidInput = $false
            do {
                Write-Host "↪ Enter the Process ID for DumpFiles or 'cancel' to return to the list: " -ForegroundColor Yellow -NoNewline
                $processIDInput = Read-Host
                if ($processIDInput -eq 'cancel') {
                    Write-Host "Returning to the list..." -ForegroundColor Green
                    Write-Host ""
                    $returnToList = $true  
                    break
                }
                if ($processIDInput -match '^\d+$') {
                    $isValidInput = $true
                    $processID = $processIDInput.Trim()
                } else {
                    Write-Host "Invalid input. Please enter a valid Process ID or type 'cancel'." -ForegroundColor Red
                    Write-Host ""
                }
            } 
            while (-not $isValidInput)
            
            if ($returnToList) {  
                break  
            }

            $dumpDir = Join-Path $memoryImageDirectory $processID

if (Test-Path $dumpDir) {
    Write-Host ""
    Write-Host "Directory $dumpDir already exists. Creating a new version..." -ForegroundColor Yellow
    Write-Host ""
    $version = 1
    $newDumpDir = "${dumpDir}_v${version}"
    while (Test-Path $newDumpDir) {
        $version++
        $newDumpDir = "${dumpDir}_v${version}"
    }
    $dumpDir = $newDumpDir
}

Write-Host ""
Write-Host "Using directory: $dumpDir" -ForegroundColor Green
Write-Host ""
New-Item -ItemType Directory -Path $dumpDir -Force

Set-Location -Path $dumpDir

            $outputFileName = "DumpFiles_PID_${processID}_output.txt"

            Write-Host ""
            $imageinfoOutput = & $volatilityPath -f $memoryImagePath windows.dumpfiles.DumpFiles --pid $processID

            Write-Host ""
            $imageinfoOutput | Out-File -FilePath $outputFileName -Encoding utf8
            Write-Host ""

            Write-Host "DumpFiles Plugin Output for PID $processID saved to $outputFileName" -ForegroundColor Green
            Write-Host ""

            $continueResponse = $null
            do {
                Write-Host "↪ Do you want to run another process? (y/n): " -ForegroundColor Yellow -NoNewLine
                $continueResponse = Read-Host
                Write-Host ""
                if ($continueResponse -eq 'y') {
                    $continueRunning = $true
                } elseif ($continueResponse -eq 'n') {
                    $continueRunning = $false
                    Write-Host "Returning to the list..." -ForegroundColor Green
                    Write-Host ""
                    break
                } else {
                    Write-Host "Invalid choice. Please select y or n." -ForegroundColor Red
                    Write-Host ""
                }
            } while ($continueResponse -ne 'y' -and $continueResponse -ne 'n')
        }
    }
}
}

Function timeline {
if ($pluginChoice -eq 'timeline') {
    
     if (Confirm-Action) {       
    $grepTerms = Ask-UseGrep  

    $runInBackground = RunInBackground  

    $mainProcess = {
        param($grepTerms, $volatilityPath, $memoryImagePath)

        if ($grepTerms) {
            $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
            $outputFileName = "Timeline_keywords_${cleanKeywords}.txt"
        } else {
            $outputFileName = "Timeline_output.txt"
        }

        $command = "$volatilityPath -f $memoryImagePath timeliner.Timeline"
        
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $modscanOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        if ($grepTerms) {
            $header = "Filtered by keywords: $($grepTerms)"
            $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
        }

        $modscanOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

if ($runInBackground) {
    $job = Start-Job -ScriptBlock $mainProcess -ArgumentList $grepTerms, $volatilityPath, $memoryImagePath -Name "Timeline"

    Write-Host ""
    Write-Host "########################################################" -ForegroundColor Yellow
    Write-Host " Timeline Plugin started as a background job with ID: $($job.Id)" -ForegroundColor Yellow
    Write-Host "########################################################" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Notes ↓" -ForegroundColor Yellow
    Write-Host "1- Background Job's Cancelled upon termination of the tool." -ForegroundColor Red
    Write-Host "2- Check the Status by typing job -all." -ForegroundColor Red
    Write-Host "2- Remove the Background Job's by typing job -r." -ForegroundColor Red
    Write-Host ""

    $global:JobMetadata[$job.Id] = @{
        'Name'      = "Timeline";
        'GrepTerms' = $grepTerms
    }
}

    else {
        $mainProcess.Invoke($grepTerms, $volatilityPath, $memoryImagePath)
        Write-Host "Timeline Plugin has completed and the output is saved to $outputFile" -ForegroundColor Green
    }
    }
}
}

function MainMenu {

Write-Host ""
Write-Host "=== MAIN MENU ===" -ForegroundColor DarkYellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "1" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Change Image File" -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "2" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Plugins" -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "3" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Volatility 3.2.5.1 CLI" -ForegroundColor Cyan
Write-Host ""

    Write-Host "↪ Enter your choice: " -ForegroundColor Magenta -NoNewline
    return Read-Host 
    Write-Host "" 
}

function Plugins {

Write-Host ""
Write-Host "=== Plugin Categories ===" -ForegroundColor DarkYellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "0" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Back to Main Menu" -ForegroundColor Yellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "1" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Image Identification" -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "2" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Processes and DLLs" -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "3" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Process Memory" -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "4" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Kernal Memory and Object" -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "5" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Networking" -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "6" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Registry" -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "7" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Crash Dumps, Hibernation, and Conversion" -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "8" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "File System" -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "9" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Miscellaneous" -ForegroundColor Cyan


    $jobs = Get-Job

    if ($jobs.Count -gt 0) {
        Write-Host ""
        Write-Host "=== Active Background Jobs ===" -ForegroundColor darkYellow
        Write-Host ""
        foreach ($job in $jobs) {
            $grepTerms = ""
            if ($global:JobMetadata.ContainsKey($job.Id) -and $global:JobMetadata[$job.Id].ContainsKey('grepTerms')) {
                $grepTerms = $global:JobMetadata[$job.Id]['grepTerms']
            }
            
            $jobStatusColor = switch ($job.State) {
                "Running"  { "DarkYellow" }
                "Failed"   { "Red" }
                "Completed"{ "Green" }
                default    { "Yellow" }
            }
            
            Write-Host "ID: $($job.Id) | Name: $($job.Name) | Grep Terms: $grepTerms | Status: " -NoNewline -ForegroundColor DarkBlue
            Write-Host "$($job.State)" -NoNewline -ForegroundColor $jobStatusColor
            Write-Host ""  
        }
    } else {
        Write-Host ""
        Write-Host "=== Background Jobs ===" -ForegroundColor DarkYellow
        Write-Host "#No active background jobs." -ForegroundColor yellow
    }

}

function Image-Identification {
    

    Write-Host "=== Image Identification List ===" -ForegroundColor DarkYellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "0" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Back to Plugin Categorizes" -ForegroundColor Yellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "1" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Info - Show OS & kernel details of the memory sample being analyzed." -ForegroundColor cyan

    $jobs = Get-Job

    if ($jobs.Count -gt 0) {
        Write-Host ""
        Write-Host "=== Active Background Jobs ===" -ForegroundColor darkYellow
        Write-Host ""
        foreach ($job in $jobs) {
            $grepTerms = ""
            if ($global:JobMetadata.ContainsKey($job.Id) -and $global:JobMetadata[$job.Id].ContainsKey('grepTerms')) {
                $grepTerms = $global:JobMetadata[$job.Id]['grepTerms']
            }
            
            $jobStatusColor = switch ($job.State) {
                "Running"  { "DarkYellow" }
                "Failed"   { "Red" }
                "Completed"{ "Green" }
                default    { "Yellow" }
            }
            
            Write-Host "ID: $($job.Id) | Name: $($job.Name) | Grep Terms: $grepTerms | Status: " -NoNewline -ForegroundColor DarkBlue
            Write-Host "$($job.State)" -NoNewline -ForegroundColor $jobStatusColor
            Write-Host ""  
        }
    } else {
        Write-Host ""
        Write-Host "=== Background Jobs ===" -ForegroundColor DarkYellow
        Write-Host "#No active background jobs." -ForegroundColor yellow
    }

}

function ProcessesAndDlls {
    

Write-Host "=== Processes and DLLs List ===" -ForegroundColor DarkYellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "0" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Back to Plugin Categories" -ForegroundColor Yellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "1" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "PsScan - Lists running processes from their EPROCESS blocks." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "2" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "PsList - Enumerates currently running processes" -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "3" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "PsTree - Lists processes in a tree structure based on parent process ID." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "4" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "CmdLine - Retrieves command line arguments for each process." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "5" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "DllList - Enumerates loaded modules. For quicker results, run with [Process ID]." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "6" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "GetSIDs - Displays the SIDs associated with each process." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "7" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Privs - Enumerates process token privileges." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "8" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Handles - Enumerates a process's open handles. For optimal performance, use with [Process ID] for fast result." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "9" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Envars - Lists environment variables for each process." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "10" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "VerInfo - Retrieves version information from PE files." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "11" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "MalFind - Identifies process memory ranges that could contain injected code." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "12" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Skeleton - Searches for indicators of the Skeleton Key malware." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "13" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "SvcScan - Enumerates Windows services." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "14" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Sessions - Lists processes and extracts session information from environment variables." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "15" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "JobLink - Shows job link information for processes." -ForegroundColor Cyan

    $jobs = Get-Job


    if ($jobs.Count -gt 0) {
        Write-Host ""
        Write-Host "=== Active Background Jobs ===" -ForegroundColor darkYellow
        Write-Host ""
        foreach ($job in $jobs) {
            $grepTerms = ""
            if ($global:JobMetadata.ContainsKey($job.Id) -and $global:JobMetadata[$job.Id].ContainsKey('grepTerms')) {
                $grepTerms = $global:JobMetadata[$job.Id]['grepTerms']
            }
            
            $jobStatusColor = switch ($job.State) {
                "Running"  { "DarkYellow" }
                "Failed"   { "Red" }
                "Completed"{ "Green" }
                default    { "Yellow" }
            }
            
            Write-Host "ID: $($job.Id) | Name: $($job.Name) | Grep Terms: $grepTerms | Status: " -NoNewline -ForegroundColor DarkBlue
            Write-Host "$($job.State)" -NoNewline -ForegroundColor $jobStatusColor
            Write-Host ""  
        }
    } else {
        Write-Host ""
        Write-Host "=== Background Jobs ===" -ForegroundColor DarkYellow
        Write-Host "#No active background jobs." -ForegroundColor yellow
    }

}

function ProcMemory {
    

    Write-Host "=== Process Memory List ===" -ForegroundColor DarkYellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "0" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Back to Plugin Categories" -ForegroundColor Yellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "1" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "MemMap - Prints a comprehensive memory map, showcasing how memory is allocated and used across different processes and the system." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "2" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "VadInfo - Provides information on Virtual Address Descriptors (VAD), detailing memory ranges used by processes and their allocation status." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "3" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "VirtMap - Displays the sections of memory that are virtually mapped, which helps understand memory layout and usage." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "4" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "VadWalk - Inspects the Virtual Address Descriptor (VAD) nodes of a process, which provides insights into memory allocations within the process." -ForegroundColor Cyan

    $jobs = Get-Job

    if ($jobs.Count -gt 0) {
        Write-Host ""
        Write-Host "=== Active Background Jobs ===" -ForegroundColor darkYellow
        Write-Host ""
        foreach ($job in $jobs) {
            $grepTerms = ""
            if ($global:JobMetadata.ContainsKey($job.Id) -and $global:JobMetadata[$job.Id].ContainsKey('grepTerms')) {
                $grepTerms = $global:JobMetadata[$job.Id]['grepTerms']
            }
            
            $jobStatusColor = switch ($job.State) {
                "Running"  { "DarkYellow" }
                "Failed"   { "Red" }
                "Completed"{ "Green" }
                default    { "Yellow" }
            }
            
            Write-Host "ID: $($job.Id) | Name: $($job.Name) | Grep Terms: $grepTerms | Status: " -NoNewline -ForegroundColor DarkBlue
            Write-Host "$($job.State)" -NoNewline -ForegroundColor $jobStatusColor
            Write-Host "" 
        }
    } else {
        Write-Host ""
        Write-Host "=== Background Jobs ===" -ForegroundColor DarkYellow
        Write-Host "#No active background jobs." -ForegroundColor yellow
    }

}

function Networking {
    
Write-Host "=== Networking List ===" -ForegroundColor DarkYellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "0" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Back to Plugin Categories" -ForegroundColor Yellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "1" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Netstat - Enumerates active network connections using system structures." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "2" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "NetScan - Searches for active network connections and listening ports." -ForegroundColor Cyan


    $jobs = Get-Job

    if ($jobs.Count -gt 0) {
        Write-Host ""
        Write-Host "=== Active Background Jobs ===" -ForegroundColor darkYellow
        Write-Host ""
        foreach ($job in $jobs) {
            $grepTerms = ""
            if ($global:JobMetadata.ContainsKey($job.Id) -and $global:JobMetadata[$job.Id].ContainsKey('grepTerms')) {
                $grepTerms = $global:JobMetadata[$job.Id]['grepTerms']
            }
            
            $jobStatusColor = switch ($job.State) {
                "Running"  { "DarkYellow" }
                "Failed"   { "Red" }
                "Completed"{ "Green" }
                default    { "Yellow" }
            }
            
            Write-Host "ID: $($job.Id) | Name: $($job.Name) | Grep Terms: $grepTerms | Status: " -NoNewline -ForegroundColor DarkBlue
            Write-Host "$($job.State)" -NoNewline -ForegroundColor $jobStatusColor
            Write-Host "" 
        }
    } else {
        Write-Host ""
        Write-Host "=== Background Jobs ===" -ForegroundColor DarkYellow
        Write-Host "#No active background jobs." -ForegroundColor yellow
    }
}

function KernalMemoryandObject {

Write-Host "=== Kernel Memory and Object List ===" -ForegroundColor DarkYellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "0" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Back to Plugin Categories" -ForegroundColor Yellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "1" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "LdrModules - Scans for loaded modules using the loader list." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "2" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "ModScan - Scans memory for module headers." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "3" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Modules - Lists the loaded kernel modules using module lists." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "4" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "DriverScan - Scans for loaded kernel drivers." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "5" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "DriverIrp - Lists IRP handlers for device drivers." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "6" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "FileScan - Scans for file objects. Note: May take longer without an offset." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "7" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "SymlinkScan - Scans for symbolic links in memory." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "8" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "MutantScan - Scans for mutex objects in memory." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "9" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Callbacks - Enumerates kernel callbacks and notification routines." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "10" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "SSDT - Displays the system service dispatch table entries." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "11" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "DeviceTree - Displays a tree structure of drivers and their linked devices." -ForegroundColor Cyan

    $jobs = Get-Job

    if ($jobs.Count -gt 0) {
        Write-Host ""
        Write-Host "=== Active Background Jobs ===" -ForegroundColor darkYellow
        Write-Host ""
        foreach ($job in $jobs) {
            $grepTerms = ""
            if ($global:JobMetadata.ContainsKey($job.Id) -and $global:JobMetadata[$job.Id].ContainsKey('grepTerms')) {
                $grepTerms = $global:JobMetadata[$job.Id]['grepTerms']
            }
            
            $jobStatusColor = switch ($job.State) {
                "Running"  { "DarkYellow" }
                "Failed"   { "Red" }
                "Completed"{ "Green" }
                default    { "Yellow" }
            }
            
            Write-Host "ID: $($job.Id) | Name: $($job.Name) | Grep Terms: $grepTerms | Status: " -NoNewline -ForegroundColor DarkBlue
            Write-Host "$($job.State)" -NoNewline -ForegroundColor $jobStatusColor
            Write-Host "" 
        }
    } else {
        Write-Host ""
        Write-Host "=== Background Jobs ===" -ForegroundColor DarkYellow
        Write-Host "#No active background jobs." -ForegroundColor yellow
    }
}

function Registry {
    
Write-Host "=== Registry List ===" -ForegroundColor DarkYellow

Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "0" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Back to Plugin Categories" -ForegroundColor Yellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "1" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "HiveScan - Scans memory for registry hive structures." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "2" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "HiveList - Displays available registry hives in memory." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "3" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "PrintKey - Enumerates registry keys and values under a specific hive or key." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "4" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Certificates - Enumerates certificates from the system's certificate store in the registry." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "5" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "GetServiceSIDs - Lists the Security Identifier (SID) for each service process token." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "6" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "UserAssist - Enumerates user-assist registry entries and decodes associated data." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "7" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Hashdump - Extracts user account hashes from memory for offline cracking." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "8" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Lsadump - Dumps LSA secrets, potentially revealing passwords and other sensitive information." -ForegroundColor Cyan


    $jobs = Get-Job

    if ($jobs.Count -gt 0) {
        Write-Host ""
        Write-Host "=== Active Background Jobs ===" -ForegroundColor darkYellow
        Write-Host ""
        foreach ($job in $jobs) {
            $grepTerms = ""
            if ($global:JobMetadata.ContainsKey($job.Id) -and $global:JobMetadata[$job.Id].ContainsKey('grepTerms')) {
                $grepTerms = $global:JobMetadata[$job.Id]['grepTerms']
            }
            
            $jobStatusColor = switch ($job.State) {
                "Running"  { "DarkYellow" }
                "Failed"   { "Red" }
                "Completed"{ "Green" }
                default    { "Yellow" }
            }
            
            Write-Host "ID: $($job.Id) | Name: $($job.Name) | Grep Terms: $grepTerms | Status: " -NoNewline -ForegroundColor DarkBlue
            Write-Host "$($job.State)" -NoNewline -ForegroundColor $jobStatusColor
            Write-Host ""  
        }
    } else {
        Write-Host ""
        Write-Host "=== Background Jobs ===" -ForegroundColor DarkYellow
        Write-Host "#No active background jobs." -ForegroundColor yellow
    }

}

function Crash-HAC-Dump {
    
Write-Host "=== Crash Dumps, Hibernation, and Conversion Plugins ===" -ForegroundColor DarkYellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "0" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Back to Plugin Categories" -ForegroundColor Yellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "1" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Crashinfo <--" . -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "2" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Cachedump - Extracts cached LSA secrets from memory." -ForegroundColor Cyan

    $jobs = Get-Job

    if ($jobs.Count -gt 0) {
        Write-Host ""
        Write-Host "=== Active Background Jobs ===" -ForegroundColor darkYellow
        Write-Host ""
        foreach ($job in $jobs) {
            $grepTerms = ""
            if ($global:JobMetadata.ContainsKey($job.Id) -and $global:JobMetadata[$job.Id].ContainsKey('grepTerms')) {
                $grepTerms = $global:JobMetadata[$job.Id]['grepTerms']
            }
            
            $jobStatusColor = switch ($job.State) {
                "Running"  { "DarkYellow" }
                "Failed"   { "Red" }
                "Completed"{ "Green" }
                default    { "Yellow" }
            }
            
            Write-Host "ID: $($job.Id) | Name: $($job.Name) | Grep Terms: $grepTerms | Status: " -NoNewline -ForegroundColor DarkBlue
            Write-Host "$($job.State)" -NoNewline -ForegroundColor $jobStatusColor
            Write-Host "" 
        }
    } else {
        Write-Host ""
        Write-Host "=== Background Jobs ===" -ForegroundColor DarkYellow
        Write-Host "#No active background jobs." -ForegroundColor yellow
    }


}

function File-System {
    
Write-Host "=== FileSystem Plugins ===" -ForegroundColor DarkYellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "0" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Back to Plugin Categories" -ForegroundColor Yellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "1" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "MBRScan - Scans and parses potential Master Boot Records (MBRs)." -ForegroundColor Cyan

    $jobs = Get-Job

    if ($jobs.Count -gt 0) {
        Write-Host ""
        Write-Host "=== Active Background Jobs ===" -ForegroundColor darkYellow
        Write-Host ""
        foreach ($job in $jobs) {
            $grepTerms = ""
            if ($global:JobMetadata.ContainsKey($job.Id) -and $global:JobMetadata[$job.Id].ContainsKey('grepTerms')) {
                $grepTerms = $global:JobMetadata[$job.Id]['grepTerms']
            }
            
            $jobStatusColor = switch ($job.State) {
                "Running"  { "DarkYellow" }
                "Failed"   { "Red" }
                "Completed"{ "Green" }
                default    { "Yellow" }
            }
            
            Write-Host "ID: $($job.Id) | Name: $($job.Name) | Grep Terms: $grepTerms | Status: " -NoNewline -ForegroundColor DarkBlue
            Write-Host "$($job.State)" -NoNewline -ForegroundColor $jobStatusColor
            Write-Host "" 
        }
    } else {
        Write-Host ""
        Write-Host "=== Background Jobs ===" -ForegroundColor DarkYellow
        Write-Host "#No active background jobs." -ForegroundColor yellow
    }

}

function Miscellaneous {
    
Write-Host "=== Miscellaneous Plugins ===" -ForegroundColor DarkYellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "0" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "Back to Plugin Categories" -ForegroundColor Yellow
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "1" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "PoolScanner - A generic pool scanner." -ForegroundColor Cyan
Write-Host "[" -ForegroundColor DarkYellow -NoNewline
Write-Host "2" -ForegroundColor DarkYellow -NoNewline
Write-Host "] " -ForegroundColor DarkYellow -NoNewline
Write-Host "BigPools - Description not provided." -ForegroundColor Cyan

    $jobs = Get-Job

    if ($jobs.Count -gt 0) {
        Write-Host ""
        Write-Host "=== Active Background Jobs ===" -ForegroundColor darkYellow
        Write-Host ""
        foreach ($job in $jobs) {
            $grepTerms = ""
            if ($global:JobMetadata.ContainsKey($job.Id) -and $global:JobMetadata[$job.Id].ContainsKey('grepTerms')) {
                $grepTerms = $global:JobMetadata[$job.Id]['grepTerms']
            }
            
            $jobStatusColor = switch ($job.State) {
                "Running"  { "DarkYellow" }
                "Failed"   { "Red" }
                "Completed"{ "Green" }
                default    { "Yellow" }
            }
            
            Write-Host "ID: $($job.Id) | Name: $($job.Name) | Grep Terms: $grepTerms | Status: " -NoNewline -ForegroundColor DarkBlue
            Write-Host "$($job.State)" -NoNewline -ForegroundColor $jobStatusColor
            Write-Host "" 
        }
    } else {
        Write-Host ""
        Write-Host "=== Background Jobs ===" -ForegroundColor DarkYellow
        Write-Host "#No active background jobs." -ForegroundColor yellow
    }
}

Write-Host ""
$memoryImagePath = ImagePath "↬ Enter the path to the memory image file : "

$volatilityPath = VolToolPath

if ($args -contains "-h" -or $args -contains "-help") {
    DisplayHelp
    exit
}

do {
    $choice = MainMenu
    
    switch ($choice) {

        "help" {
            DisplayHelp
        }

        "show" {
            ShowCurrentSelection 
        }

        "clear" {
            ClearAndShowList 
        }

        "status" {
            Status 
        }

1 {

    Write-Host ""
    $confirmChange = $null 
    
    while ($null -eq $confirmChange) {
        Write-Host "↪ Are you sure you want to change the Memory Image [y,n]: " -ForegroundColor Red -NoNewLine
        $userInput = Read-Host
        
        if ($userInput -eq 'Y' -or $userInput -eq 'y') {
        Write-Host ""
            $memoryImagePath = ImagePath "↬ Enter the path to the memory image file: "
            $confirmChange = $true
        } elseif ($userInput -eq 'N' -or $userInput -eq 'n') {
            $confirmChange = $false
        } else {
        Write-Host ""
            Write-Host "Invalid input. Please enter 'Y' or 'N'." -ForegroundColor Yellow
        }
    }
}
    
              2 {
                while ($true) {
                Plugins
                Write-Host ""
                Write-Host "↪ Select a Plugin: " -ForegroundColor Magenta -NoNewline
                $pluginChoice = Read-Host 
                Write-Host ""
    
                if ($pluginChoice -eq '0') {
                    break
                }

if ($pluginChoice -eq 'help') {
            DisplayHelp 
        }

if ($pluginChoice -eq 'status') {
            Status 
        }

if ($pluginChoice -eq 'clear') {
            ClearAndShowList 
        } 

if ($pluginChoice -eq 'back') {
                 break
                }

if ($pluginChoice -eq 'show') {
            ShowCurrentSelection 
        }

if ($pluginChoice -eq 'job -s') {
            jobsupport 
        } 

if ($pluginChoice -eq 'job -all') {
JobCheck
}
             
if ($pluginChoice -eq 'job -r') {
            JobRemove 
        } 
                     
if ($pluginChoice -eq 'dump -p') {
            Dumproc 
     }

if ($pluginChoice -eq 'timeline') {
            timeline 
     }                  

                elseif ($pluginChoice -eq '1') {
                    while ($true) {
                        Image-Identification
                        
                        Write-Host ""
                        Write-Host "↪ Select a Plugin: " -ForegroundColor Magenta -NoNewLine
                        $IdentificationChoice = Read-Host 
                        Write-Host ""
                        
                        if ($IdentificationChoice -eq '0') {
                            break
                        }
                        if ($IdentificationChoice -eq 'back') {
                            break
                        }

                        switch ($IdentificationChoice) 
                        {

        "status" {
            Status 
        }

        "help" {
            DisplayHelp
        }

        "show" {
            ShowCurrentSelection 
        }

        "job -s" {
             jobsupport
        }
                             
        "job -all" {
             JobCheck
        }

"job -r" {
            JobRemove 
        } 

"clear" {
            ClearAndShowList 
        }

        "dump -p" {
             Dumproc
        }

1 {

if (Confirm-Action) { 
      $outputFileName = "Info_output.txt"
        $imageinfoOutput = & $volatilityPath -f $memoryImagePath -r pretty windows.info.Info
       $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName
                    if (Test-Path -Path $outputFile) 
                         {
                                 $outputFile = Ask-Overwrite -filePath $outputFile
                                   if (-not $outputFile) 
                                   {
                                     Write-Host "Aborted by user." -ForegroundColor Red
                                   return
                                    }
                                }

                                 $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
                                 Write-Host ""
                                 Write-Host "Info Plugin Output saved to $outputFile" -ForegroundColor Green
                                 Write-Host ""
                                 }
                                 }
                                 default {

                                Write-Host "Invalid choice. Please select a valid option." -ForegroundColor Red
                                Write-Host ""

                            }
                        }
                    } 
               }
               
                elseif ($pluginChoice -eq '2') {

                    while ($true) {
                        ProcessesAndDlls
                        
                        Write-Host ""
                        Write-Host "↪ Select a Plugin: " -ForegroundColor Magenta -NoNewLine
                        $padChoice = Read-Host 
                        Write-Host ""
                        
                        if ($padChoice -eq '0') {
                            break
                        }
                        if ($padChoice -eq 'back') {
                                break
                                   }
                                   
                        switch ($padChoice) 
                        {

        "help" {
            DisplayHelp
        }

        "status" {
            Status 
        }

"clear" {
            ClearAndShowList 
        }  

        "show" {
            ShowCurrentSelection 
        }

        "job -s" {
             jobsupport
        }

        "job -all" {
             JobCheck
        }

"job -r" {
            JobRemove 
        } 

        "dump -p" {
             Dumproc
        } 

        "timeline" {
             timeline
        } 

1 {

if (Confirm-Action) { 
    $inputProcessID = Ask-InputProcessID

    if ($inputProcessID) {
    do {
        Write-Host "↪ Enter the Process IDs for PsTree (separated by commas if multiple): " -ForegroundColor Yellow -NoNewline
        $processIDs = Read-Host
        Write-Host ""

        if (-not $processIDs) {
            Write-Host "Please provide a valid input." -ForegroundColor Red
            $isValid = $false
        } else {
            $isValid = $processIDs -match '^(\d+)(,\s*\d+)*$'
            
            if (-not $isValid) {
                Write-Host "Invalid input please enter valid Process ID (separated by commas if multiple)" -ForegroundColor Red
            }
        }

    } while (-not $isValid)

    $processIDsArray = $processIDs -split "," | ForEach-Object { $_.Trim() }
}

    $grepTerms = Ask-UseGrep

    if ($inputProcessID) {
        foreach ($processID in $processIDsArray) {
            $outputFileName = "PsScan_PID_${processID}_output.txt"
            $command = "$volatilityPath -f $memoryImagePath windows.psscan.PsScan --pid $processID"
            if ($grepTerms) {
               $command += " | grep -i '$grepTerms'"
            }
            $imageinfoOutput = Invoke-Expression $command

            $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

            if (Test-Path -Path $outputFile) {
                $outputFile = Ask-Overwrite -filePath $outputFile
                if (-not $outputFile) {
                    Write-Host "Aborted by user." -ForegroundColor Red
                    return
                }
            }

            $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8

            Write-Host ""
            Write-Host "PsScan Plugin Output for PID $processID saved to $outputFile" -ForegroundColor Green
            Write-Host ""
        }
    } else {
        $outputFileName = "PsScan_output.txt"
        $command = "$volatilityPath -f $memoryImagePath windows.psscan.PsScan"
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $imageinfoOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
        Write-Host ""
        Write-Host "PsScan Plugin Output saved to $outputFile" -ForegroundColor Green
        Write-Host ""
    }
}
}

2 {

if (Confirm-Action) { 
    $inputProcessID = Ask-InputProcessID

    if ($inputProcessID) {
    do {
        Write-Host ""
        Write-Host "↪ Enter the Process IDs for PsTree (separated by commas if multiple): " -ForegroundColor Yellow -NoNewline
        $processIDs = Read-Host
        Write-Host ""

        if (-not $processIDs) {
            Write-Host "Please provide a valid input." -ForegroundColor Red
            $isValid = $false
        } else {
            $isValid = $processIDs -match '^(\d+)(,\s*\d+)*$'
            
            if (-not $isValid) {
                Write-Host "Invalid input please enter valid Process ID (separated by commas if multiple)" -ForegroundColor Red
            }
        }

    } while (-not $isValid)

    $processIDsArray = $processIDs -split "," | ForEach-Object { $_.Trim() }
}


    $grepTerms = Ask-UseGrep

    if ($inputProcessID) {
        foreach ($processID in $processIDsArray) {
            $outputFileName = "PsList_PID_${processID}_output.txt"
            $command = "$volatilityPath -f $memoryImagePath windows.pslist.PsList --pid $processID"
            if ($grepTerms) {
                $command += " | grep -i '$grepTerms'"
            }
            $imageinfoOutput = Invoke-Expression $command

            $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

            if (Test-Path -Path $outputFile) {
                $outputFile = Ask-Overwrite -filePath $outputFile
                if (-not $outputFile) {
                    Write-Host "Aborted by user." -ForegroundColor Red
                    return
                }
            }

            $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8

            Write-Host ""
            Write-Host "PsList Plugin Output for PID $processID saved to $outputFile" -ForegroundColor Green
            Write-Host ""
        }
    } else {
        $outputFileName = "PsList_output.txt"
        $command = "$volatilityPath -f $memoryImagePath windows.pslist.PsList"
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $imageinfoOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
        Write-Host ""
        Write-Host "PsList Plugin Output saved to $outputFile" -ForegroundColor Green
        Write-Host ""
    }
}
}

3 {

if (Confirm-Action) { 
    $inputProcessID = Ask-InputProcessID

    if ($inputProcessID) {
    do {
        Write-Host ""
        Write-Host "↪ Enter the Process IDs for PsTree (separated by commas if multiple): " -ForegroundColor Yellow -NoNewline
        $processIDs = Read-Host
        Write-Host ""

        if (-not $processIDs) {
            Write-Host "Please provide a valid input." -ForegroundColor Red
            $isValid = $false
        } else {
            $isValid = $processIDs -match '^(\d+)(,\s*\d+)*$'
            
            if (-not $isValid) {
                Write-Host "Invalid input please enter valid Process ID (separated by commas if multiple)" -ForegroundColor Red
            }
        }

    } while (-not $isValid)

    $processIDsArray = $processIDs -split "," | ForEach-Object { $_.Trim() }
}

    $grepTerms = Ask-UseGrep

    if ($inputProcessID) {
        foreach ($processID in $processIDsArray) {
            $outputFileName = "PsTree_PID_${processID}_output.txt"
            $command = "$volatilityPath -f $memoryImagePath windows.pstree.PsTree --pid $processID"
            if ($grepTerms) {
                $command += " | grep -i '$grepTerms'"
            }
            $imageinfoOutput = Invoke-Expression $command

            $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

            if (Test-Path -Path $outputFile) {
                $outputFile = Ask-Overwrite -filePath $outputFile
                if (-not $outputFile) {
                    Write-Host "Aborted by user." -ForegroundColor Red
                    return
                }
            }

            $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8

            Write-Host ""
            Write-Host "PsTree Plugin Output for PID $processID saved to $outputFile" -ForegroundColor Green
            Write-Host ""
        }
    } else {
        $outputFileName = "PsTree_output.txt"
        $command = "$volatilityPath -f $memoryImagePath windows.pstree.PsTree"
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $imageinfoOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
        Write-Host ""
        Write-Host "PsTree Plugin Output saved to $outputFile" -ForegroundColor Green
        Write-Host ""
    }
}
}

4 {

if (Confirm-Action) { 
    $inputProcessID = Ask-InputProcessID

    if ($inputProcessID) {
    do {
        Write-Host ""
        Write-Host "↪ Enter the Process IDs for PsTree (separated by commas if multiple): " -ForegroundColor Yellow -NoNewline
        $processIDs = Read-Host
        Write-Host ""

        if (-not $processIDs) {
            Write-Host "Please provide a valid input." -ForegroundColor Red
            $isValid = $false
        } else {
            $isValid = $processIDs -match '^(\d+)(,\s*\d+)*$'
            
            if (-not $isValid) {
                Write-Host "Invalid input please enter valid Process ID (separated by commas if multiple)" -ForegroundColor Red
            }
        }

    } while (-not $isValid)

    $processIDsArray = $processIDs -split "," | ForEach-Object { $_.Trim() }
}

    $grepTerms = Ask-UseGrep

    if ($inputProcessID) {
        foreach ($processID in $processIDsArray) {
            $outputFileName = "CmdLine_PID_${processID}_output.txt"
            $command = "$volatilityPath -f $memoryImagePath windows.cmdline.CmdLine --pid $processID"
            if ($grepTerms) {
                $command += " | grep -i '$grepTerms'"
            }
            $imageinfoOutput = Invoke-Expression $command

            $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

            if (Test-Path -Path $outputFile) {
                $outputFile = Ask-Overwrite -filePath $outputFile
                if (-not $outputFile) {
                    Write-Host "Aborted by user." -ForegroundColor Red
                    return
                }
            }

            $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8

            Write-Host ""
            Write-Host "CmdLine Plugin Output for PID $processID saved to $outputFile" -ForegroundColor Green
            Write-Host ""
        }
    } else {
        $outputFileName = "CmdLine_output.txt"
        $command = "$volatilityPath -f $memoryImagePath windows.cmdline.CmdLine"
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $imageinfoOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
        Write-Host ""
        Write-Host "CmdLine Plugin Output saved to $outputFile" -ForegroundColor Green
        Write-Host ""
    }
}
}

5 {

if (Confirm-Action) { 
    $inputProcessID = Ask-InputProcessID

    if ($inputProcessID) {
    do {
        Write-Host ""
        Write-Host "↪ Enter the Process IDs for PsTree (separated by commas if multiple): " -ForegroundColor Yellow -NoNewline
        $processIDs = Read-Host
        Write-Host ""

        if (-not $processIDs) {
            Write-Host "Please provide a valid input." -ForegroundColor Red
            $isValid = $false
        } else {
            $isValid = $processIDs -match '^(\d+)(,\s*\d+)*$'
            
            if (-not $isValid) {
                Write-Host "Invalid input please enter valid Process ID (separated by commas if multiple)" -ForegroundColor Red
            }
        }

    } while (-not $isValid)

    $processIDsArray = $processIDs -split "," | ForEach-Object { $_.Trim() }
}

    $grepTerms = Ask-UseGrep

    if ($inputProcessID) {
        foreach ($processID in $processIDsArray) {
            $outputFileName = "DllList_PID_${processID}_output.txt"
            $command = "$volatilityPath -f $memoryImagePath windows.dlllist.DllList--pid $processID"
            if ($grepTerms) {
                $command += " | grep -i '$grepTerms'"
            }
            $imageinfoOutput = Invoke-Expression $command

            $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

            if (Test-Path -Path $outputFile) {
                $outputFile = Ask-Overwrite -filePath $outputFile
                if (-not $outputFile) {
                    Write-Host "Aborted by user." -ForegroundColor Red
                    return
                }
            }

            $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8

            Write-Host ""
            Write-Host "DllList Plugin Output for PID $processID saved to $outputFile" -ForegroundColor Green
            Write-Host ""
        }
    } else {
        $outputFileName = "DllList_output.txt"
        $command = "$volatilityPath -f $memoryImagePath windows.dlllist.DllList"
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $imageinfoOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
        Write-Host ""
        Write-Host "DllList Plugin Output saved to $outputFile" -ForegroundColor Green
        Write-Host ""
    }
}
}

6 {

if (Confirm-Action) { 
    $inputProcessID = Ask-InputProcessID

    if ($inputProcessID) {
    do {
        Write-Host ""
        Write-Host "↪ Enter the Process IDs for GetSIDs (separated by commas if multiple): " -ForegroundColor Yellow -NoNewline
        $processIDs = Read-Host
        Write-Host ""

        if (-not $processIDs) {
            Write-Host "Please provide a valid input." -ForegroundColor Red
            $isValid = $false
        } else {
            $isValid = $processIDs -match '^(\d+)(,\s*\d+)*$'
            
            if (-not $isValid) {
                Write-Host "Invalid input please enter valid Process ID (separated by commas if multiple)" -ForegroundColor Red
            }
        }

    } while (-not $isValid)

    $processIDsArray = $processIDs -split "," | ForEach-Object { $_.Trim() }
}

    $grepTerms = Ask-UseGrep

    if ($inputProcessID) {
        foreach ($processID in $processIDsArray) {
            $outputFileName = "GetSIDs_PID_${processID}_output.txt"
            $command = "$volatilityPath -f $memoryImagePath windows.getsids.GetSIDs --pid $processID"
            if ($grepTerms) {
                $command += " | grep -i '$grepTerms'"
            }
            $imageinfoOutput = Invoke-Expression $command

            $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

            if (Test-Path -Path $outputFile) {
                $outputFile = Ask-Overwrite -filePath $outputFile
                if (-not $outputFile) {
                    Write-Host "Aborted by user." -ForegroundColor Red
                    return
                }
            }

            $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8

            Write-Host ""
            Write-Host "GetSIDs Plugin Output for PID $processID saved to $outputFile" -ForegroundColor Green
            Write-Host ""
        }
    } else {
        $outputFileName = "GetSIDs_output.txt"
        $command = "$volatilityPath -f $memoryImagePath windows.getsids.GetSIDs"
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $imageinfoOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
        Write-Host ""
        Write-Host "GetSIDs Plugin Output saved to $outputFile" -ForegroundColor Green
        Write-Host ""
    }
}
}

7 {
if (Confirm-Action) { 
    $inputProcessID = Ask-InputProcessID

    if ($inputProcessID) {
    do {
        Write-Host ""
        Write-Host "↪ Enter the Process IDs for PsTree (separated by commas if multiple): " -ForegroundColor Yellow -NoNewline
        $processIDs = Read-Host
        Write-Host ""

        if (-not $processIDs) {
            Write-Host "Please provide a valid input." -ForegroundColor Red
            $isValid = $false
        } else {
            $isValid = $processIDs -match '^(\d+)(,\s*\d+)*$'
            
            if (-not $isValid) {
                Write-Host "Invalid input please enter valid Process ID (separated by commas if multiple)" -ForegroundColor Red
            }
        }

    } while (-not $isValid)

    $processIDsArray = $processIDs -split "," | ForEach-Object { $_.Trim() }
}

    $grepTerms = Ask-UseGrep

    if ($inputProcessID) {
        foreach ($processID in $processIDsArray) {
            $outputFileName = "Privs_PID_${processID}_output.txt"
            $command = "$volatilityPath -f $memoryImagePath windows.privileges.Privs --pid $processID"
            if ($grepTerms) {
                $command += " | grep -i '$grepTerms'"
            }
            $imageinfoOutput = Invoke-Expression $command

            $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

            if (Test-Path -Path $outputFile) {
                $outputFile = Ask-Overwrite -filePath $outputFile
                if (-not $outputFile) {
                    Write-Host "Aborted by user." -ForegroundColor Red
                    return
                }
            }

            $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8

            Write-Host ""
            Write-Host "Privs Plugin Output for PID $processID saved to $outputFile" -ForegroundColor Green
            Write-Host ""
        }
    } else {
        $outputFileName = "Privs_output.txt"
        $command = "$volatilityPath -f $memoryImagePath windows.privileges.Privs"
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $imageinfoOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
        Write-Host ""
        Write-Host "Privs Plugin Output saved to $outputFile" -ForegroundColor Green
        Write-Host ""
    }
}
}

8 {
if (Confirm-Action) { 
    $inputProcessID = Ask-InputProcessID

    if ($inputProcessID) {
    do {
        Write-Host ""
        Write-Host "↪ Enter the Process IDs for PsTree (separated by commas if multiple): " -ForegroundColor Yellow -NoNewline
        $processIDs = Read-Host
        Write-Host ""

        if (-not $processIDs) {
            Write-Host "Please provide a valid input." -ForegroundColor Red
            $isValid = $false
        } else {
            $isValid = $processIDs -match '^(\d+)(,\s*\d+)*$'
            
            if (-not $isValid) {
                Write-Host "Invalid input please enter valid Process ID (separated by commas if multiple)" -ForegroundColor Red
            }
        }

    } while (-not $isValid)

    $processIDsArray = $processIDs -split "," | ForEach-Object { $_.Trim() }
} 

    $grepTerms = Ask-UseGrep

    if ($inputProcessID) {
        foreach ($processID in $processIDsArray) {
            $outputFileName = "Handles_PID_${processID}_output.txt"
            $command = "$volatilityPath -f $memoryImagePath windows.handles.Handles --pid $processID"
            if ($grepTerms) {
                $command += " | grep -i '$grepTerms'"
            }
            $imageinfoOutput = Invoke-Expression $command

            $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

            if (Test-Path -Path $outputFile) {
                $outputFile = Ask-Overwrite -filePath $outputFile
                if (-not $outputFile) {
                    Write-Host "Aborted by user." -ForegroundColor Red
                    return
                }
            }

            $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8

            Write-Host ""
            Write-Host "Handles Plugin Output for PID $processID saved to $outputFile" -ForegroundColor Green
            Write-Host ""
        }
    } else {
        $outputFileName = "Handles_output.txt"
        $command = "$volatilityPath -f $memoryImagePath windows.handles.Handles"
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $imageinfoOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
        Write-Host ""
        Write-Host "Handles Plugin Output saved to $outputFile" -ForegroundColor Green
        Write-Host ""
    }
}
}

9 {
if (Confirm-Action) { 
    $inputProcessID = Ask-InputProcessID

    if ($inputProcessID) {
    do {
        Write-Host ""
        Write-Host "↪ Enter the Process IDs for PsTree (separated by commas if multiple): " -ForegroundColor Yellow -NoNewline
        $processIDs = Read-Host
        Write-Host ""

        if (-not $processIDs) {
            Write-Host "Please provide a valid input." -ForegroundColor Red
            $isValid = $false
        } else {
            $isValid = $processIDs -match '^(\d+)(,\s*\d+)*$'
            
            if (-not $isValid) {
                Write-Host "Invalid input please enter valid Process ID (separated by commas if multiple)" -ForegroundColor Red
            }
        }

    } while (-not $isValid)

    $processIDsArray = $processIDs -split "," | ForEach-Object { $_.Trim() }
}

    $grepTerms = Ask-UseGrep

    if ($inputProcessID) {
        foreach ($processID in $processIDsArray) {
            $outputFileName = "Envars_PID_${processID}_output.txt"
            $command = "$volatilityPath -f $memoryImagePath windows.envars.Envars --pid $processID"
            if ($grepTerms) {
                $command += " | grep -i '$grepTerms'"
            }
            $imageinfoOutput = Invoke-Expression $command

            $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

            if (Test-Path -Path $outputFile) {
                $outputFile = Ask-Overwrite -filePath $outputFile
                if (-not $outputFile) {
                    Write-Host "Aborted by user." -ForegroundColor Red
                    return
                }
            }

            $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8

            Write-Host ""
            Write-Host "Envars Plugin Output for PID $processID saved to $outputFile" -ForegroundColor Green
            Write-Host ""
        }
    } else {
        $outputFileName = "Envars_output.txt"
        $command = "$volatilityPath -f $memoryImagePath windows.envars.Envars"
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $imageinfoOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
        Write-Host ""
        Write-Host "Envars Plugin Output saved to $outputFile" -ForegroundColor Green
        Write-Host ""
    }
}
}

10 {
if (Confirm-Action) { 
    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "VerInfo_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "VerInfo_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.verinfo.VerInfo"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "VerInfo Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""

}
}

11 {
if (Confirm-Action) { 
    $inputProcessID = Ask-InputProcessID

    if ($inputProcessID) {
    do {
        Write-Host ""
        Write-Host "↪ Enter the Process IDs for PsTree (separated by commas if multiple): " -ForegroundColor Yellow -NoNewline
        $processIDs = Read-Host
        Write-Host ""

        if (-not $processIDs) {
            Write-Host "Please provide a valid input." -ForegroundColor Red
            $isValid = $false
        } else {
            $isValid = $processIDs -match '^(\d+)(,\s*\d+)*$'
            
            if (-not $isValid) {
                Write-Host "Invalid input please enter valid Process ID (separated by commas if multiple)" -ForegroundColor Red
            }
        }

    } while (-not $isValid)

    $processIDsArray = $processIDs -split "," | ForEach-Object { $_.Trim() }
} 

    $grepTerms = Ask-UseGrep

    if ($inputProcessID) {
        foreach ($processID in $processIDsArray) {
            $outputFileName = "Malfind_PID_${processID}_output.txt"
            $command = "$volatilityPath -f $memoryImagePath windows.malfind.Malfind --pid $processID"
            if ($grepTerms) {
                $command += " | grep -i '$grepTerms'"
            }
            $imageinfoOutput = Invoke-Expression $command

            $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

            if (Test-Path -Path $outputFile) {
                $outputFile = Ask-Overwrite -filePath $outputFile
                if (-not $outputFile) {
                    Write-Host "Aborted by user." -ForegroundColor Red
                    return
                }
            }

            $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8

            Write-Host ""
            Write-Host "Malfind Plugin Output for PID $processID saved to $outputFile" -ForegroundColor Green
            Write-Host ""
        }
    } else {
        $outputFileName = "Malfind_output.txt"
        $command = "$volatilityPath -f $memoryImagePath windows.malfind.Malfind"
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $imageinfoOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
        Write-Host ""
        Write-Host "Malfind Plugin Output saved to $outputFile" -ForegroundColor Green
        Write-Host ""
    }
}
}

12 {
                                if (Confirm-Action) { 


                                $outputFileName = "Skeleton_output.txt"
                                $imageinfoOutput = & $volatilityPath -f $memoryImagePath windows.skeleton_key_check.Skeleton_Key_Check
                                $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName
                                 

                                if (Test-Path -Path $outputFile) 
                                {
                                 $outputFile = Ask-Overwrite -filePath $outputFile
                                   if (-not $outputFile) 
                                   {
                                     Write-Host "Aborted by user." -ForegroundColor Red
                                   return
                                    }
                                }
                                 $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
                                 Write-Host ""
                                 Write-Host "Skeleton Plugin Output saved to $outputFile" -ForegroundColor Green
                                 Write-Host ""
                                 }
 }
            
13 {

if (Confirm-Action) { 
    $inputProcessID = Ask-InputProcessID

    if ($inputProcessID) {
    do {
        Write-Host ""
        Write-Host "↪ Enter the Process IDs for PsTree (separated by commas if multiple): " -ForegroundColor Yellow -NoNewline
        $processIDs = Read-Host
        Write-Host ""

        if (-not $processIDs) {
            Write-Host "Please provide a valid input." -ForegroundColor Red
            $isValid = $false
        } else {
            $isValid = $processIDs -match '^(\d+)(,\s*\d+)*$'
            
            if (-not $isValid) {
                Write-Host "Invalid input please enter valid Process ID (separated by commas if multiple)" -ForegroundColor Red
            }
        }

    } while (-not $isValid)

    $processIDsArray = $processIDs -split "," | ForEach-Object { $_.Trim() }
}

    $grepTerms = Ask-UseGrep

    if ($inputProcessID) {
        foreach ($processID in $processIDsArray) {
            $outputFileName = "SvcScan_PID_${processID}_output.txt"
            $command = "$volatilityPath -f $memoryImagePath windows.svcscan.SvcScan --pid $processID"
            if ($grepTerms) {
                $command += " | grep -i '$grepTerms'"
            }
            $imageinfoOutput = Invoke-Expression $command

            $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

            if (Test-Path -Path $outputFile) {
                $outputFile = Ask-Overwrite -filePath $outputFile
                if (-not $outputFile) {
                    Write-Host "Aborted by user." -ForegroundColor Red
                    return
                }
            }

            $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8

            Write-Host ""
            Write-Host "SvcScan Plugin Output for PID $processID saved to $outputFile" -ForegroundColor Green
            Write-Host ""
        }
    } else {
        $outputFileName = "SvcScan_output.txt"
        $command = "$volatilityPath -f $memoryImagePath windows.svcscan.SvcScan"
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $imageinfoOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
        Write-Host ""
        Write-Host "SvcScan Plugin Output saved to $outputFile" -ForegroundColor Green
        Write-Host ""
    }
}
}

14 {

if (Confirm-Action) { 
    $inputProcessID = Ask-InputProcessID

    if ($inputProcessID) {
    do {
        Write-Host ""
        Write-Host "↪ Enter the Process IDs for PsTree (separated by commas if multiple): " -ForegroundColor Yellow -NoNewline
        $processIDs = Read-Host
        Write-Host ""

        if (-not $processIDs) {
            Write-Host "Please provide a valid input." -ForegroundColor Red
            $isValid = $false
        } else {
            $isValid = $processIDs -match '^(\d+)(,\s*\d+)*$'
            
            if (-not $isValid) {
                Write-Host "Invalid input please enter valid Process ID (separated by commas if multiple)" -ForegroundColor Red
            }
        }

    } while (-not $isValid)

    $processIDsArray = $processIDs -split "," | ForEach-Object { $_.Trim() }
}

    $grepTerms = Ask-UseGrep

    if ($inputProcessID) {
        foreach ($processID in $processIDsArray) {
            $outputFileName = "Sessions_PID_${processID}_output.txt"
            $command = "$volatilityPath -f $memoryImagePath windows.sessions.Sessions--pid $processID"
            if ($grepTerms) {
                $command += " | grep -i '$grepTerms'"
            }
            $imageinfoOutput = Invoke-Expression $command

            $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

            if (Test-Path -Path $outputFile) {
                $outputFile = Ask-Overwrite -filePath $outputFile
                if (-not $outputFile) {
                    Write-Host "Aborted by user." -ForegroundColor Red
                    return
                }
            }

            $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8

            Write-Host ""
            Write-Host "Sessions Plugin Output for PID $processID saved to $outputFile" -ForegroundColor Green
            Write-Host ""
        }
    } else {
        $outputFileName = "Sessions_output.txt"
        $command = "$volatilityPath -f $memoryImagePath windows.sessions.Sessions"
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $imageinfoOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
        Write-Host ""
        Write-Host "Sessions Plugin Output saved to $outputFile" -ForegroundColor Green
        Write-Host ""
    }
}
}

15 { 
    
if (Confirm-Action) { 
    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "JobLinks_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "JobLinks_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.joblinks.JobLinks"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "JobLinks Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""
}
}

                            default {
                                Write-Host "Invalid choice. Please select a valid option." -ForegroundColor Red
                                Write-Host ""

                            }
                        }
                    } 
               }

                elseif ($pluginChoice -eq '3') {

                    while ($true) {
                        ProcMemory
                        
                        Write-Host ""
                        Write-Host "↪ Select a Plugin: " -ForegroundColor Magenta -NoNewLine
                        $ProcMemChoice = Read-Host 
                        Write-Host ""
         
                        if ($ProcMemChoice -eq '0') {
                            break
                        }
                        if ($ProcMemChoice -eq 'back') {
                                break
                                   }
                                   
                        switch ($ProcMemChoice) 
                        {

        "help" {
            DisplayHelp
        }

        "status" {
            Status 
        }

"clear" {
            ClearAndShowList 
        }  

        "show" {
            ShowCurrentSelection 
        }

        "job -s" {
             jobsupport
        }
                              
        "job -all" {
             JobCheck
        }


"job -r" {
            JobRemove 
        } 

        "dump -p" {
             Dumproc
        } 


        "timeline" {
             timeline
        }                  

1 {

if (Confirm-Action) { 

    $grepTerms = Ask-UseGrep  

    $runInBackground = RunInBackground  

    $mainProcess = {
        param($grepTerms, $volatilityPath, $memoryImagePath)

        if ($grepTerms) {
            $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
            $outputFileName = "Memmap_keywords_${cleanKeywords}.txt"
        } else {
            $outputFileName = "Memmap_output.txt"
        }

        $command = "$volatilityPath -f $memoryImagePath -r pretty windows.memmap.Memmap"
        
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $memmapOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        if ($grepTerms) {
            $header = "Filtered by keywords: $($grepTerms)"
            $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
        }

        $memmapOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    if ($runInBackground) {
        $job = Start-Job -ScriptBlock $mainProcess -ArgumentList $grepTerms, $volatilityPath, $memoryImagePath -Name "Memmap"
        Write-Host ""
        Write-Host "########################################################" -ForegroundColor Yellow
        Write-Host " Memmap Plugin started as a background job with ID: $($job.Id)" -ForegroundColor Yellow
        Write-Host "########################################################" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Notes ↓" -ForegroundColor Yellow
        Write-Host "1- Background Job's Chancled upon termination of the tool." -ForegroundColor Red
        Write-Host "2- Check the Status by typing jobcheck."-ForegroundColor Red
        Write-Host ""
    } else {
        $mainProcess.Invoke($grepTerms, $volatilityPath, $memoryImagePath)
        Write-Host "Memmap Plugin has completed and the output is saved to $outputFile" -ForegroundColor Green
    }
}
}

2 {

if (Confirm-Action) { 
    $inputProcessID = Ask-InputProcessID

    if ($inputProcessID) {
    do {
        Write-Host ""
        Write-Host "↪ Enter the Process IDs for PsTree (separated by commas if multiple): " -ForegroundColor Yellow -NoNewline
        $processIDs = Read-Host
        Write-Host ""

        if (-not $processIDs) {
            Write-Host "Please provide a valid input." -ForegroundColor Red
            $isValid = $false
        } else {
            $isValid = $processIDs -match '^(\d+)(,\s*\d+)*$'
            
            if (-not $isValid) {
                Write-Host "Invalid input please enter valid Process ID (separated by commas if multiple)" -ForegroundColor Red
            }
        }

    } while (-not $isValid)

    $processIDsArray = $processIDs -split "," | ForEach-Object { $_.Trim() }
} 

    $grepTerms = Ask-UseGrep

    if ($inputProcessID) {
        foreach ($processID in $processIDsArray) {
            $outputFileName = "VadInfo_PID_${processID}_output.txt"
            $command = "$volatilityPath -f $memoryImagePath windows.vadinfo.VadInfo --pid $processID"
            if ($grepTerms) {
                $command += " | grep -i '$grepTerms'"
            }
            $imageinfoOutput = Invoke-Expression $command

            $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

            if (Test-Path -Path $outputFile) {
                $outputFile = Ask-Overwrite -filePath $outputFile
                if (-not $outputFile) {
                    Write-Host "Aborted by user." -ForegroundColor Red
                    return
                }
            }

            $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8

            Write-Host ""
            Write-Host "VadInfo Plugin Output for PID $processID saved to $outputFile" -ForegroundColor Green
            Write-Host ""
        }
    } else {
        $outputFileName = "VadInfo_output.txt"
        $command = "$volatilityPath -f $memoryImagePath windows.vadinfo.VadInfo"
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $imageinfoOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
        Write-Host ""
        Write-Host "VadInfo Plugin Output saved to $outputFile" -ForegroundColor Green
        Write-Host ""
    }
}
}

                             3 {
                                   if (Confirm-Action) { 
                                      $outputFileName = "VirtMap_output.txt"
                                      $imageinfoOutput = & $volatilityPath -f $memoryImagePath -r pretty windows.virtmap.VirtMap
                                $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName
                                 
                                if (Test-Path -Path $outputFile) 
                                {
                                 $outputFile = Ask-Overwrite -filePath $outputFile
                                   if (-not $outputFile) 
                                   {
                                     Write-Host "Aborted by user." -ForegroundColor Red
                                   return
                                    }
                                }

                                 $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
                                 Write-Host ""
                                 Write-Host "Memmap Plugin Output saved to $outputFile" -ForegroundColor Green
                                 Write-Host ""
                                 }
                                   }  
                        
4 {

if (Confirm-Action) { 
    $inputProcessID = Ask-InputProcessID

    if ($inputProcessID) {
    do {
        Write-Host ""
        Write-Host "↪ Enter the Process IDs for PsTree (separated by commas if multiple): " -ForegroundColor Yellow -NoNewline
        $processIDs = Read-Host
        Write-Host ""

        if (-not $processIDs) {
            Write-Host "Please provide a valid input." -ForegroundColor Red
            $isValid = $false
        } else {
            $isValid = $processIDs -match '^(\d+)(,\s*\d+)*$'
            
            if (-not $isValid) {
                Write-Host "Invalid input please enter valid Process ID (separated by commas if multiple)" -ForegroundColor Red
            }
        }

    } while (-not $isValid)

    $processIDsArray = $processIDs -split "," | ForEach-Object { $_.Trim() }
}

    $grepTerms = Ask-UseGrep

    if ($inputProcessID) {
        foreach ($processID in $processIDsArray) {
            $outputFileName = "VadWalk_PID_${processID}_output.txt"
            $command = "$volatilityPath -f $memoryImagePath windows.vadwalk.VadWalk --pid $processID"
            if ($grepTerms) {
                $command += " | grep -i '$grepTerms'"
            }
            $imageinfoOutput = Invoke-Expression $command

            $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

            if (Test-Path -Path $outputFile) {
                $outputFile = Ask-Overwrite -filePath $outputFile
                if (-not $outputFile) {
                    Write-Host "Aborted by user." -ForegroundColor Red
                    return
                }
            }

            $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8

            Write-Host ""
            Write-Host "VadWalk Plugin Output for PID $processID saved to $outputFile" -ForegroundColor Green
            Write-Host ""
        }
    } else {
        $outputFileName = "VadWalk_output.txt"
        $command = "$volatilityPath -f $memoryImagePath windows.vadwalk.VadWalk"
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $imageinfoOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
        Write-Host ""
        Write-Host "VadWalk Plugin Output saved to $outputFile" -ForegroundColor Green
        Write-Host ""
    }
}
}
        default {

                                Write-Host "Invalid choice. Please select a valid option." -ForegroundColor Red
                                Write-Host ""

                            }
                        }
                    } 
               }

                elseif ($pluginChoice -eq '4') {

                    while ($true) {
                        KernalMemoryandObject
                        Write-Host ""
                        Write-Host "↪ Select a Plugin: " -ForegroundColor Magenta -NoNewline
                        $KMAOChoice = Read-Host 

                        if ($KMAOChoice -eq '0') {
                            break
                        }
                        if ($KMAOChoice -eq 'back') {
                                break
                                   }
 
                        switch ($KMAOChoice) {

        "help" {
            DisplayHelp
        }

        "status" {
            Status 
        }

"clear" {
            ClearAndShowList 
        }  

        "show" {
            ShowCurrentSelection 
        }

        "job -s" {
             jobsupport
        }

        "job -all" {
             JobCheck
        }

"job -r" {
            JobRemove 
        } 

        "dump -p" {
             Dumproc
        } 

        "timeline" {
             timeline
        }       

1 {

if (Confirm-Action) { 
    $inputProcessID = Ask-InputProcessID

    if ($inputProcessID) {
    do {
        Write-Host ""
        Write-Host "↪ Enter the Process IDs for PsTree (separated by commas if multiple): " -ForegroundColor Yellow -NoNewline
        $processIDs = Read-Host
        Write-Host ""

        if (-not $processIDs) {
            Write-Host "Please provide a valid input." -ForegroundColor Red
            $isValid = $false
        } else {
            $isValid = $processIDs -match '^(\d+)(,\s*\d+)*$'
            
            if (-not $isValid) {
                Write-Host "Invalid input please enter valid Process ID (separated by commas if multiple)" -ForegroundColor Red
            }
        }

    } while (-not $isValid)

    $processIDsArray = $processIDs -split "," | ForEach-Object { $_.Trim() }
}

    $grepTerms = Ask-UseGrep

    if ($inputProcessID) {
        foreach ($processID in $processIDsArray) {
            $outputFileName = "LdrModules_PID_${processID}_output.txt"
            $command = "$volatilityPath -f $memoryImagePath windows.ldrmodules.LdrModules --pid $processID"
            if ($grepTerms) {
                $command += " | grep -i '$grepTerms'"
            }
            $imageinfoOutput = Invoke-Expression $command

            $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

            if (Test-Path -Path $outputFile) {
                $outputFile = Ask-Overwrite -filePath $outputFile
                if (-not $outputFile) {
                    Write-Host "Aborted by user." -ForegroundColor Red
                    return
                }
            }

            $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8

            Write-Host ""
            Write-Host "LdrModules Plugin Output for PID $processID saved to $outputFile" -ForegroundColor Green
            Write-Host ""
        }
    } else {
        $outputFileName = "VadWalk_output.txt"
        $command = "$volatilityPath -f $memoryImagePath windows.ldrmodules.LdrModules"
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $imageinfoOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
        Write-Host ""
        Write-Host "LdrModules Plugin Output saved to $outputFile" -ForegroundColor Green
        Write-Host ""
    }
}
}

2 {

if (Confirm-Action) { 

    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "ModScan_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "ModScan_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.modscan.ModScan"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "ModScan Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""

}
}
3 {

if (Confirm-Action) { 
    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "Modules_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "Modules_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.modules.Modules"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "Modules Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""

}
}

4 {

if (Confirm-Action) { 
    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "DriverScan_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "DriverScan_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.driverscan.DriverScan"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "DriverScan Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""

}
}

5 {

if (Confirm-Action) { 
    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "DriverIrp_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "DriverIrp_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.driverirp.DriverIrp"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "DriverIrp Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""

}
}

6 {

if (Confirm-Action) { 
    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "FileScan_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "FileScan_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.filescan.FileScan"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "FileScan Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""

}
}

7 {

if (Confirm-Action) { 
    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "SymlinkScan_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "SymlinkScan_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.symlinkscan.SymlinkScan"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "SymlinkScan Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""

}
}

8 {

if (Confirm-Action) { 
    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "MutantScan_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "MutantScan_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.mutantscan.MutantScan"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "MutantScan Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""

}
}

9 {

if (Confirm-Action) { 
    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "Callbacks_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "Callbacks_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.callbacks.Callbacks"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "Callbacks Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""

}
}

10 {

if (Confirm-Action) { 
    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "SSDT_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "SSDT_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.ssdt.SSDT"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "SSDT Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""

}
}

11 {
    
     if (Confirm-Action) {       
    $grepTerms = Ask-UseGrep 

    $runInBackground = RunInBackground 

    $mainProcess = {
        param($grepTerms, $volatilityPath, $memoryImagePath)

        if ($grepTerms) {
            $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
            $outputFileName = "DeviceTree_keywords_${cleanKeywords}.txt"
        } else {
            $outputFileName = "DeviceTree_output.txt"
        }

        $command = "$volatilityPath -f $memoryImagePath windows.devicetree.DeviceTree"
        
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $modscanOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        if ($grepTerms) {
            $header = "Filtered by keywords: $($grepTerms)"
            $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
        }

        $modscanOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

if ($runInBackground) {
    $job = Start-Job -ScriptBlock $mainProcess -ArgumentList $grepTerms, $volatilityPath, $memoryImagePath -Name "DeviceTree"

    Write-Host ""
    Write-Host "########################################################" -ForegroundColor Yellow
    Write-Host " Timeline Plugin started as a background job with ID: $($job.Id)" -ForegroundColor Yellow
    Write-Host "########################################################" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Notes ↓" -ForegroundColor Yellow
    Write-Host "1- Background Job's Cancelled upon termination of the tool." -ForegroundColor Red
    Write-Host "2- Check the Status by typing jobcheck." -ForegroundColor Red
    Write-Host ""

    $global:JobMetadata[$job.Id] = @{
        'Name'      = "DeviceTree";
        'GrepTerms' = $grepTerms
    }
}
    else {

        $mainProcess.Invoke($grepTerms, $volatilityPath, $memoryImagePath)
        Write-Host "DeviceTree Plugin has completed and the output is saved to $outputFile" -ForegroundColor Green
    }
    }
}
                     default {
                                Write-Host "Invalid choice. Please select a valid option." -ForegroundColor Red
                                Write-Host ""
                            }
                }
                }
                }   

                   elseif ($pluginChoice -eq '5') {

                    while ($true) {
                        Networking
                        
                        Write-Host ""
                        Write-Host "↪ Select a Plugin: " -ForegroundColor Magenta -NoNewline
                        $netChoice = Read-Host 

                        if ($netChoice -eq '0') {
                            break
                        }       
                        if ($netChoice -eq 'back') {
                                break
                                   }
                                       
                        switch ($netChoice) {

        "help" {
            DisplayHelp
        }

        "status" {
            Status 
        }

"clear" {
            ClearAndShowList 
        }  

        "show" {
            ShowCurrentSelection 
        }

        "job -s" {
             jobsupport
        }

        "job -all" {
             JobCheck
        }

"job -r" {
            JobRemove 
        } 

        "dump -p" {
             Dumproc
        } 

        "timeline" {
             timeline
        } 

1 {

if (Confirm-Action) { 
    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "Netstat_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "Netstat_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.netstat"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "Netstat Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""

}
}

2 {

if (Confirm-Action) { 
    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "NetScan_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "NetScan_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.netscan.NetScan"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "NetScan Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""

}
}
               
default {
    Write-Host "Invalid choice. Please select a valid option." -ForegroundColor Red
    Write-Host ""
        }

 }
     }
   }

                              elseif ($pluginChoice -eq '6') {

                               while ($true) {
                               Registry
                               Write-Host ""
                                Write-Host "↪ Select a Plugin: " -ForegroundColor Magenta -NoNewline
                             $RegChoice = Read-Host 

                               if ($RegChoice -eq '0') {
                                break
                                   }
                                   if ($RegChoice -eq 'back') {
                                break
                                   }
                                   
                        
                             switch ($RegChoice) {

        "help" {
            DisplayHelp
        }

        "status" {
            Status 
        }

"clear" {
            ClearAndShowList 
        }  

        "show" {
            ShowCurrentSelection 
        }

        "job -s" {
             jobsupport
        }

        "job -all" {
             JobCheck
        }


"job -r" {
            JobRemove 
        } 
        
        "dump -p" {
             Dumproc
        } 
        
        "timeline" {
             timeline
        }          

1 {
if (Confirm-Action) { 
    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "HiveScan_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "HiveScan_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.registry.hivescan.HiveScan"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "HiveScan Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""

}
}

2 {

if (Confirm-Action) { 
    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "HiveList_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "HiveList_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.registry.hivelist.HiveList"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "HiveList Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""

}
}

                           3 {
                                 if (Confirm-Action) {     
                                 $registryKey = Ask-RegistryKey
                                 if ($registryKey) {
                                        $sanitizedKey = $registryKey -replace '[\\/:"*?<>|]+', '_'
                                 $outputFileName = "PrintKey_${sanitizedKey}_output.txt"
                         $imageinfoOutput = & $volatilityPath -f $memoryImagePath windows.registry.printkey.PrintKey --key $registryKey
                                 }       
                                 else {                   
                                 $outputFileName = "PrintKey_output_nokey.txt"
                                 $imageinfoOutput = & $volatilityPath -f $memoryImagePath windows.registry.printkey.PrintKey                     
                                 }
                                 $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName
                                 if (Test-Path -Path $outputFile) {
                                 $outputFile = Ask-Overwrite -filePath $outputFile
                                 if (-not $outputFile) {
                                 Write-Host "Aborted by user." -ForegroundColor Red
                                 return
                                 }
                               }
                                $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
                                Write-Host ""
                                Write-Host "PrintKey Plugin Output saved to $outputFile" -ForegroundColor Green
                                Write-Host ""
                               }
}

4 { 

if (Confirm-Action) { 
    $memoryImageDirectory = [System.IO.Path]::GetDirectoryName($memoryImagePath)
    $certificatesDir = Join-Path $memoryImageDirectory "Certificates"

    if (Test-Path $certificatesDir) {
        Write-Host ""
        $newDir = Ask-DirOverwrite -dirPath $certificatesDir

        if (-not $newDir) {
            Write-Host "Operation aborted by user." -ForegroundColor Red
            return
        }

        if ($newDir -ne $certificatesDir) {
            New-Item -ItemType Directory -Path $newDir
            $certificatesDir = $newDir
        }

    } else {
        Write-Host ""
        New-Item -ItemType Directory -Path $certificatesDir
    }

    Set-Location -Path $certificatesDir

    Write-Host ""
    $command = "$volatilityPath -f $memoryImagePath windows.registry.certificates.Certificates"
    $imageinfoOutput = Invoke-Expression $command

    Write-Host ""
    $outputFileName = "Certificates_output.txt"
    $outputFile = Join-Path $certificatesDir $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "Certificates Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""

    Set-Location -Path $PSScriptRoot
}
}

5 {

if (Confirm-Action) { 
    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "GetServiceSIDs_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "GetServiceSIDs_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.getservicesids.GetServiceSIDs"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "GetServiceSIDs Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""

}
}

6 {

if (Confirm-Action) { 
    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "UserAssist_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "UserAssist_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.registry.userassist.UserAssist"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "UserAssist Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""

}
}

7 {

if (Confirm-Action) { 
    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "Hashdump_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "Hashdump_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.hashdump.Hashdump"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "Hashdump Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""

}
}
                        8 {
                                     if (Confirm-Action) { 
                                      $outputFileName = "Lsadump_output.txt"
                                      $imageinfoOutput = & $volatilityPath -f $memoryImagePath -r pretty windows.lsadump.Lsadump
                                      

                                $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName
                                 
                                if (Test-Path -Path $outputFile) 
                                {
                                 $outputFile = Ask-Overwrite -filePath $outputFile
                                   if (-not $outputFile) 
                                   {
                                     Write-Host "Aborted by user." -ForegroundColor Red
                                   return
                                    }
                                }
                                 $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8
                                 Write-Host ""
                                 Write-Host "Lsadump Plugin Output saved to $outputFile" -ForegroundColor Green
                                 Write-Host ""
                                 }
                                 }
                                 
                               default {
                                
                                Write-Host "Invalid choice. Please select a valid option." -ForegroundColor Red
                                
                            }
                }
                }
                }        

                     elseif ($pluginChoice -eq '7') { 
                     
                    while ($true) {
                        Crash-HAC-Dump
                        
                        Write-Host ""
                        Write-Host "↪ Select a Plugin: " -ForegroundColor Magenta -NoNewline
                        $CHCChoice = Read-Host 

                        if ($CHCChoice -eq '0') {
                            break
                        }        
                        if ($CHCChoice -eq 'back') {
                            break
                        }    
                        switch ($CHCChoice) {

        "help" {
            DisplayHelp
        }

        "status" {
            Status 
        }

"clear" {
            ClearAndShowList 
        }  

        "show" {
            ShowCurrentSelection 
        }

        "job -s" {
             jobsupport
        }

        "job -all" {
             JobCheck
        }

"job -r" {
            JobRemove 
        } 

        "dump -p" {
             Dumproc
        } 

        "timeline" {
             timeline
        }     

1 {

if (Confirm-Action) { 
    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "Crashinfo_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "Crashinfo_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.crashinfo.Crashinfo"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "Crashinfo Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""
}
}

2 {

if (Confirm-Action) { 
    $grepTerms = Ask-UseGrep

    if ($grepTerms) {
        $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
        $outputFileName = "Cachedump_keywords_${cleanKeywords}.txt"
    } else {
        $outputFileName = "Cachedump_output.txt"
    }

    $command = "$volatilityPath -f $memoryImagePath windows.cachedump.Cachedump"
    if ($grepTerms) {
        $command += " | grep -i '$grepTerms'"
    }
    $imageinfoOutput = Invoke-Expression $command

    $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

    if (Test-Path -Path $outputFile) {
        $outputFile = Ask-Overwrite -filePath $outputFile
        if (-not $outputFile) {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    }

    if ($grepTerms) {
        $header = "Filtered by keywords: $($grepTerms)"
        $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

    $imageinfoOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append

    Write-Host ""
    Write-Host "Cachedump Plugin Output saved to $outputFile" -ForegroundColor Green
    Write-Host ""
}
}
               
default {
    Write-Host "Invalid choice. Please select a valid option." -ForegroundColor Red
    Write-Host ""
        }

 }
     }
   }
               
elseif ($pluginChoice -eq '8') {
                    while ($true) {
                         File-System
                        
                        Write-Host ""
                        Write-Host "↪ Select a Plugin: " -ForegroundColor Magenta -NoNewline
                        $fsChoice = Read-Host 

                        if ($fsChoice -eq '0') {
                            break
                        }        
                        if ($fsChoice -eq 'back') {
                            break
                        }    
                        switch ($fsChoice) {


        "help" {
            DisplayHelp
        }

        "status" {
            Status 
        }

"clear" {
            ClearAndShowList 
        }  


        "show" {
            ShowCurrentSelection 
        }


        "job -s" {
             jobsupport
        }

        "job -all" {
             JobCheck
        }

"job -r" {
            JobRemove 
        } 
        
        "dump -p" {
             Dumproc
        } 

        "timeline" {
             timeline
        } 
1 { 
    
     if (Confirm-Action) {       
    $grepTerms = Ask-UseGrep

    $runInBackground = RunInBackground
    
    $mainProcess = {
        param($grepTerms, $volatilityPath, $memoryImagePath)

        if ($grepTerms) {
            $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
            $outputFileName = "MBRScan_keywords_${cleanKeywords}.txt"
        } else {
            $outputFileName = "MBRScan_output.txt"
        }

        $command = "$volatilityPath -f $memoryImagePath windows.mbrscan.MBRScan"
        
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $modscanOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        if ($grepTerms) {
            $header = "Filtered by keywords: $($grepTerms)"
            $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
        }

        $modscanOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

if ($runInBackground) {

    $job = Start-Job -ScriptBlock $mainProcess -ArgumentList $grepTerms, $volatilityPath, $memoryImagePath -Name "MBRScan"

    Write-Host ""
    Write-Host "########################################################" -ForegroundColor Yellow
    Write-Host " BigPools Plugin started as a background job with ID: $($job.Id)" -ForegroundColor Yellow
    Write-Host "########################################################" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Notes ↓" -ForegroundColor Yellow
    Write-Host "1- Background Job's Cancelled upon termination of the tool." -ForegroundColor Red
    Write-Host "2- Check the Status by typing jobcheck." -ForegroundColor Red
    Write-Host ""

    $global:JobMetadata[$job.Id] = @{
        'Name'      = "MBRScan";
        'GrepTerms' = $grepTerms
    }
}
 
    else {
        $mainProcess.Invoke($grepTerms, $volatilityPath, $memoryImagePath)
        Write-Host "MBRScan Plugin has completed and the output is saved to $outputFile" -ForegroundColor Green
    }
    }
}


default {
    Write-Host ""
    Write-Host "Invalid choice. Please select a valid option." -ForegroundColor Red
        }

 }
     }
   }
              
elseif ($pluginChoice -eq '9') {
                    while ($true) {
Miscellaneous
                        
                        Write-Host ""
                        Write-Host "↪ Select a Plugin: " -ForegroundColor Magenta -NoNewline
                        $MiscellaneousChoice = Read-Host 

                        if ($MiscellaneousChoice -eq '0') {
                            break
                        }        
                        if ($MiscellaneousChoice -eq 'back') {
                            break
                        }    
                        switch ($MiscellaneousChoice) {

        "help" {
            DisplayHelp
        }

        "status" {
            Status 
        }

         "clear" {
            ClearAndShowList 
        }  

        "show" {
            ShowCurrentSelection 
        }

        "job -s" {
             jobsupport
        }
                              
        "job -all" {
             JobCheck
        }

"job -r" {
            JobRemove 
        } 

        "dump -p" {
             Dumproc
        } 
        
        "timeline" {
             timeline
        } 
                       
1{ 
    
     if (Confirm-Action) {       
    $grepTerms = Ask-UseGrep 

    $runInBackground = RunInBackground

    $mainProcess = {
        param($grepTerms, $volatilityPath, $memoryImagePath)

        if ($grepTerms) {
            $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
            $outputFileName = "PoolScanner_keywords_${cleanKeywords}.txt"
        } else {
            $outputFileName = "PoolScanner_output.txt"
        }

        $command = "$volatilityPath -f $memoryImagePath windows.poolscanner.PoolScanner"
        
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $modscanOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        if ($grepTerms) {
            $header = "Filtered by keywords: $($grepTerms)"
            $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
        }

        $modscanOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

if ($runInBackground) {
    $job = Start-Job -ScriptBlock $mainProcess -ArgumentList $grepTerms, $volatilityPath, $memoryImagePath -Name "PoolScanner"

    Write-Host ""
    Write-Host "########################################################" -ForegroundColor Yellow
    Write-Host " PoolScanner Plugin started as a background job with ID: $($job.Id)" -ForegroundColor Yellow
    Write-Host "########################################################" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Notes ↓" -ForegroundColor Yellow
    Write-Host "1- Background Job's Cancelled upon termination of the tool." -ForegroundColor Red
    Write-Host "2- Check the Status by typing jobcheck." -ForegroundColor Red
    Write-Host ""

    $global:JobMetadata[$job.Id] = @{
        'Name'      = "PoolScanner";
        'GrepTerms' = $grepTerms
    }
}

    
    else {
        $mainProcess.Invoke($grepTerms, $volatilityPath, $memoryImagePath)
        Write-Host "PoolScanner Plugin has completed and the output is saved to $outputFile" -ForegroundColor Green
    }
    }
}

2 { 
    
     if (Confirm-Action) {       
    $grepTerms = Ask-UseGrep 

    $runInBackground = RunInBackground 

    $mainProcess = {
        param($grepTerms, $volatilityPath, $memoryImagePath)

        if ($grepTerms) {
            $cleanKeywords = ($grepTerms -split ',' | ForEach-Object { $_.Trim() -replace '[^\w\d]', '_' }) -join "_"
            $outputFileName = "BigPools_keywords_${cleanKeywords}.txt"
        } else {
            $outputFileName = "BigPools_output.txt"
        }

        $command = "$volatilityPath -f $memoryImagePath windows.bigpools.BigPools"
        
        if ($grepTerms) {
            $command += " | grep -i '$grepTerms'"
        }
        $modscanOutput = Invoke-Expression $command

        $outputFile = Join-Path -Path (Get-Item $memoryImagePath).DirectoryName -ChildPath $outputFileName

        if (Test-Path -Path $outputFile) {
            $outputFile = Ask-Overwrite -filePath $outputFile
            if (-not $outputFile) {
                Write-Host "Aborted by user." -ForegroundColor Red
                return
            }
        }

        if ($grepTerms) {
            $header = "Filtered by keywords: $($grepTerms)"
            $header | Out-File -FilePath $outputFile -Encoding utf8 -Append
        }

        $modscanOutput | Out-File -FilePath $outputFile -Encoding utf8 -Append
    }

if ($runInBackground) {

    $job = Start-Job -ScriptBlock $mainProcess -ArgumentList $grepTerms, $volatilityPath, $memoryImagePath -Name "BigPools"

    Write-Host ""
    Write-Host "########################################################" -ForegroundColor Yellow
    Write-Host " BigPools Plugin started as a background job with ID: $($job.Id)" -ForegroundColor Yellow
    Write-Host "########################################################" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Notes ↓" -ForegroundColor Yellow
    Write-Host "1- Background Job's Cancelled upon termination of the tool." -ForegroundColor Red
    Write-Host "2- Check the Status by typing jobcheck." -ForegroundColor Red
    Write-Host ""

    $global:JobMetadata[$job.Id] = @{
        'Name'      = "BigPools";
        'GrepTerms' = $grepTerms
    }
}

    
    else {
        $mainProcess.Invoke($grepTerms, $volatilityPath, $memoryImagePath)
        Write-Host "BigPools Plugin has completed and the output is saved to $outputFile" -ForegroundColor Green
    }
    }
}


default {
Write-Host ""
    Write-Host "Invalid choice. Please select a valid option." -ForegroundColor Red
        }

 }
     }
   }
                    if ($pluginChoice -notmatch '^(0|1|2|3|4|5|6|7|8|timeline|job -s|job -all|job -r|help|show|clear|back|dump -p|status)$') {
                    Write-Host "Invalid Plugin ID choice. Please select a valid option." -ForegroundColor Red
}

                }
                }         

                '3' {

            CustomCommand

        }
            
        'exit' {
        Write-Host "Thank you for using The Tool ;)"  -ForegroundColor Green
        Write-Host ""
            exit
        }

default {
Write-Host ""
            Write-Host "Invalid Plugin ID choice. Please select a valid option." -ForegroundColor Red
        }
    }
} while ($true)
