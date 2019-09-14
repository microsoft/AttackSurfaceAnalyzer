# escape=`
FROM mcr.microsoft.com/windows:1903 

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]
RUN Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

COPY Detonate.ps1 C:\Detonate.ps1

COPY publish C:\asa
ENTRYPOINT ["powershell", "Set-ExecutionPolicy Bypass -Scope Process -Force; C:\\Detonate.ps1"]