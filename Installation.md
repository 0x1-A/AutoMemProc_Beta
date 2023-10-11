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

**Check Python3 if it's installed** 

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

# AutoMemProc

 ``` shell
pwsh AutoMemProc.ps1
  ```





