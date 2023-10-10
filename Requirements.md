## Requirements

1. Unix Environment (Linux, ubuntu ..etc).
2. Powershell.
3. Volatility 3.2.5.0 (Volatility 3 requires Python 3.7.0 or later).
4. Symbol Tables for (Offline Analysis). 

## Powershell

```shell
https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-linux?view=powershell-7.3
```

## Volatility 3.2.5.1

How to Install

```shell
https://github.com/volatilityfoundation/volatility3
```
What to Install

```shell
https://github.com/volatilityfoundation/volatility3/archive/refs/tags/v2.5.0.tar.gz
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
