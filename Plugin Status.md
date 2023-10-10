## PLUGIN STATUS

  - Image Identification
     -  [DONE]    windows.info.Info           { Show OS & kernel details of the memory sample being analyzed}

  - Processes and DLLs

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

  - Process Memory

    [DONE]    windows.memmap.Memmap       - Prints the memory map.
    [DONE]    windows.vadinfo.VadInfo     - Lists process memory ranges.
    [DONE]    windows.virtmap.VirtMap     - Lists virtual mapped sections.
    [DONE]    windows.vadwalk.VadWalk     - Walks the VAD tree.

  - Networking

    [DONE]    windows.netscan.NetScan     - Scans for network objects in a memory image.
    [DONE]    windows.netstat.NetStat     - Traverses network tracking structures.

  - Kernal Memory and Object

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

  - Registry

    [DONE]    windows.registry.hivescan.HiveScan - Scans for registry hives in a memory image.
    [DONE]    windows.registry.hivelist.HiveList - Lists registry hives in a memory image.
    [DONE]    windows.registry.printkey.PrintKey - Lists registry keys under a hive/key value.
    [DONE]    windows.registry.certificates.Certificates - Lists certificates in registry's Certificate Store.
    [DONE]    windows.getservicesids.GetServiceSIDs - Lists process token SIDs.
    [DONE]    windows.registry.userassist.UserAssist - Print userassist registry keys and information.
    [DONE]    windows.hashdump.Hashdump   - Dumps user hashes from memory.
    [DONE]    windows.lsadump.Lsadump     - Dumps LSA secrets from memory.


  - Crash Dumps, Hibernation, and Conversion

   [DONE]    windows.crashinfo.Crashinfo - Lists information from a Windows crash dump.
   [DONE]    windows.cachedump.Cachedump - Extracts cached credentials.

  - File System

   [DONE]    windows.mftscan.MFTScan     - Scans for MFT FILE objects.
   [DONE]    windows.mbrscan.MBRScan     - Scans for and parses Master Boot Records (MBRs).

  - Miscellaneous

   [DONE]    windows.dumpfiles.DumpFiles - Dumps cached file contents.
   [DONE]    timeliner.Timeliner         - Lists time-related information ordered by time.
   [DONE]    windows.bigpools.BigPools   - Lists big page pools.
   [DONE]    windows.poolscanner.PoolScanner - A generic pool scanner plugin.
