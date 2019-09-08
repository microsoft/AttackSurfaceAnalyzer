# escape=`
FROM mcr.microsoft.com/windows:1903 

COPY choco.ps1 C:\choco.ps1

COPY publish C:\asa

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]
RUN Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

ENTRYPOINT ["powershell", "Set-ExecutionPolicy Bypass -Scope Process -Force; C:\\choco.ps1"]