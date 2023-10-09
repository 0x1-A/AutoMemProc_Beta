# AutoMemProc

- AutoMemProc is a tool designed to simplify and streamline the process of analyzing memory dumps. Its main goal is to act 
  as an interface for the Volatility framework, enhancing the user experience with automation and user-friendly prompts.

Key Features:
- User-friendly interface: AutoMemProc provides clear prompts, asking users to input paths to memory images or choose from 
  existing images.
- Automatic Image Detection: Upon providing a directory, the tool lists all memory image files present, allowing users to 
  easily select the image they wish to analyze.
- Saved Paths: The tool has the capability to remember certain paths, such as the path to the Volatility executable, to 
  speed up repeated analyses.
- Plugin Interface: Once an image is chosen, the tool provides a menu system, letting users select and run various - 
  Volatility plugins directly from the interface.
- Error Handling: AutoMemProc contains checks to handle errors gracefully, such as empty paths or invalid inputs, and guide 
  users in correcting them.

Target Audience:
 - Digital forensics professionals or researchers who often analyze memory dumps.
   Incident responders looking to quickly triage potentially compromised systems.
   Educators or students in cybersecurity courses where memory analysis is a topic.

Optimized Environment:
- AutoMemProc is optimized for Unix environments, ensuring compatibility and smooth operation on systems like Linux.

## Requirements

1. Volatility 3.2.5.0
2. Powershell.
3. Symbol Tables for (Offline Analysis). 

## Volatility 3.2.5.1

```shell
https://github.com/volatilityfoundation/volatility3/archive/refs/tags/v2.5.0.tar.gz
```

## Powershell

```shell
https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-linux?view=powershell-7.3
```

## Symbol Tables

```shell
https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
```
The hashes to verify whether any of the symbol pack files have downloaded successfully or have changed can be found at:

```shell
https://downloads.volatilityfoundation.org/volatility3/symbols/SHA256SUMS 
```
```shell
https://downloads.volatilityfoundation.org/volatility3/symbols/SHA1SUMS
```
```shell
https://downloads.volatilityfoundation.org/volatility3/symbols/MD5SUMS
```
- Symbol tables zip files must be placed, as named, into the `volatility3/symbols` directory (or just the symbols directory next to the executable file).
- Windows symbols that cannot be found will be queried, downloaded, generated and cached.
- Important: The first run of volatility with new symbol files will require the cache to be updated.  The symbol packs contain a large number of symbol files and so may take some time to update!
However, this process only needs to be run once on each new symbol file, so assuming the pack stays in the same location will not need to be done again.  Please also note it can be interrupted and next run will restart itself.

## Quick Start

Once the above requriment downloaded and installed, 

1. Tool Execution: 

```shell
pwsh automemproc.ps1
```

2. If the tool in the same folder as memory image files, select from the displayed list. if no, type folder that stored Memory Image files or spicify file. 

Example:

```note
/home/test/Desktop/memory/
```

```note
/home/test/Desktop/memory/memory.img
```

```note
~/Desktop/memory/
```

3. Once memory image selected, type were volatility is located, 

Example:

```note
/opt/volatility3.2.5.1/vol.py
```

## Recommendtion

- Store automemproc.ps1 in the same folder as the imagefile for quick detection.

## Contact

For information or requests, contact:

Twitter: @atiahlaoufi
