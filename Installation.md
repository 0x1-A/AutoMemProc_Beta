# Installation Process

 ``` shell
  sudo apt update 
  ```

## Utilities

**tar**
 ``` shell
sudo apt install tar
  ```

**wget**
 ``` shell
sudo apt install wget
  ```

**pip**
 ``` shell
sudo apt install pip
  ```

## Powershell

 ``` shell
sudo snap install powershell --classic
  ```

## Python

**Check Python3 Availability**

 ``` shell
python3 --version
  ```

**If Yes**

install the required packages for Python (it's recommended to avoid any issue during installation of Votaility 3)

 ``` shell
sudo apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev wget
  ```

**If No**

 ``` shell
sudo apt install software-properties-common
  ```

 ``` shell
sudo add-apt-repository ppa:deadsnakes/ppa
  ```

 ``` shell
sudo apt install python3.12
  ```

 ``` shell
sudo apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev wget
  ```

**Votaility 3**

 ``` shell
sudo wget https://github.com/volatilityfoundation/volatility3/archive/refs/tags/v2.5.0.tar.gz
  ```

 ``` shell
sudo tar -xzvf v2.5.0.tar.gz
  ```

 ``` shell
cd volatility3-2.5.0
  ```

 ``` shell
sudo pip3 install -r requirements.txt
  ```

 ``` shell
python3 vol.py -h
  ```

## Symbol Tables

```shell
https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
```

- Symbol tables zip files must be placed, as named, into the `volatility3/symbols` directory (or just the symbols directory next to the executable file).
- Windows symbols that cannot be found will be queried, downloaded, generated and cached.
- Important: The first run of volatility with new symbol files will require the cache to be updated.  The symbol packs contain a large number of symbol files and so may take some time to update!
However, this process only needs to be run once on each new symbol file, so assuming the pack stays in the same location will not need to be done again.  Please also note it can be interrupted and next run will restart itself.

# AutoMemProc

 ``` shell
pwsh AutoMemProc.ps1
  ```





