## PLUGIN STATUS

  - Image Identification

    | Plugin | Description |
    | windows.info.Info | Show OS & kernel details of the memory sample being analyzed |
    
    - windows.info.Info
      - Show OS & kernel details of the memory sample being analyzed

  - Processes and DLLs
    
    - windows.psscan.PsScan
      - Scans for processes in a memory image.
    - windows.pslist.PsList
      - Lists processes in a memory image.
    - windows.pstree.PsTree
      - Lists processes in a tree based on parent PID.
    - windows.cmdline.CmdLine
      - Lists process command line arguments.
    - windows.dlllist.DllList
      - Lists loaded modules in a memory image.
    - windows.getsids.GetSIDs
      - Lists loaded modules in a memory image.
    - windows.privileges.Privs
      - Lists process token privileges.
    - windows.handles.Handles
      - Displays handles opened by processes.
    - windows.verinfo.VerInfo
      - Lists PE files version information.
    - windows.envars.Envars
      - Display process environment variables.
    - windows.malfind.Malfind
      - Lists process memory ranges with potential injected code.
    - windows.skeleton_key_check.Skeleton_Key_Check - Looks for Skeleton Key malware signs.
    - windows.svcscan.SvcScan
      - Scans for windows services.
    - windows.sessions.Sessions
      - Lists Processes with Session information.
    - windows.joblinks.JobLinks
      - Print process job link information.

  - Process Memory

    - windows.memmap.Memmap
      - Prints the memory map.
    - windows.vadinfo.VadInfo
      - Lists process memory ranges.
    - windows.virtmap.VirtMap
      - Lists virtual mapped sections.
    - windows.vadwalk.VadWalk
      - Walks the VAD tree.

  - Networking

    - windows.netscan.NetScan
      - Scans for network objects in a memory image.
    - windows.netstat.NetStat
      - Traverses network tracking structures.

  - Kernal Memory and Object

    - windows.ldrmodules.LdrModules
      - Lists loaded modules in a memory image.
    - windows.modscan.ModScan
      - Scans for modules in a memory image.
    - windows.modules.Modules
      - Lists the loaded kernel modules.
    - windows.driverscan.DriverScan
      - Scans for drivers present in a memory image.
    - windows.driverirp.DriverIrp
      - Lists IRPs for drivers in a memory image.
    - windows.filescan.FileScan
      - Scans for file objects present in a memory image.
    - windows.symlinkscan.SymlinkScan
      - Scans for links in a memory image.
    - windows.mutantscan.MutantScan
      - Scans for mutexes in a memory image.
    - windows.callbacks.Callbacks
      - Lists kernel callbacks and notification routines.
    - windows.ssdt.SSDT
      - Lists the system call table.
    - windows.devicetree.DeviceTree
      - Listing tree based on drivers and devices.

  - Registry

    - windows.registry.hivescan.HiveScan
      - Scans for registry hives in a memory image.
    - windows.registry.hivelist.HiveList
      - Lists registry hives in a memory image.
    - windows.registry.printkey.PrintKey
      - Lists registry keys under a hive/key value.
    - windows.registry.certificates.Certificates
      - Lists certificates in registry's Certificate Store.
    - windows.getservicesids.GetServiceSIDs
      - Lists process token SIDs.
    - windows.registry.userassist.UserAssist
      - Print userassist registry keys and information.
    - windows.hashdump.Hashdump
      - Dumps user hashes from memory.
    - windows.lsadump.Lsadump
      - Dumps LSA secrets from memory.


  - Crash Dumps, Hibernation, and Conversion

    - windows.crashinfo.Crashinfo
      - Lists information from a Windows crash dump.
    - windows.cachedump.Cachedump
      - Extracts cached credentials.

  - File System

    - windows.mftscan.MFTScan
      - Scans for MFT FILE objects.
    - windows.mbrscan.MBRScan
      - Scans for and parses Master Boot Records (MBRs).

  - Miscellaneous

    - windows.dumpfiles.DumpFiles
      - Dumps cached file contents.
    - timeliner.Timeliner
      - Lists time-related information ordered by time.
    - windows.bigpools.BigPools
      - Lists big page pools.
    - windows.poolscanner.PoolScanner
      - A generic pool scanner plugin.
