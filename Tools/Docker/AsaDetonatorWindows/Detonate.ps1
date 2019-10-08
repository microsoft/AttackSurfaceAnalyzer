# Default timeout 30 minutes
$Timeout = 1800

$RunName = Get-Content C:\input\RunName

$ScriptBlock = {
    param($RunName) 
    C:\Asa\Asa.exe collect - --runid "$($RunName):BeforeInstall" --databasefilename "$($RunName).sqlite"
    C:\input\Install.ps1
    C:\Asa\Asa.exe collect -a --runid "$($RunName):AfterInstall" --databasefilename "$($RunName).sqlite"
    C:\input\Uninstall.ps1
    C:\Asa\Asa.exe collect -a --runid "$($RunName):AfterUninstall" --databasefilename "$($RunName).sqlite"
    C:\Asa\Asa.exe export-collect --firstrunid "$($RunName):BeforeInstall" --secondrunid "$($RunName):AfterInstall" --databasefilename "$($RunName).sqlite" --outputpath C:\output
    C:\Asa\Asa.exe export-collect --firstrunid "$($RunName):BeforeInstall" --secondrunid "$($RunName):AfterUninstall" --databasefilename "$($RunName).sqlite" --outputpath C:\output
    C:\Asa\Asa.exe export-collect --firstrunid "$($RunName):AfterInstall" --secondrunid "$($RunName):AfterUninstall" --databasefilename "$($RunName).sqlite" --outputpath C:\output
}

Write-Host "Starting $RunName"
$job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $RunName
$jobTimer = [Diagnostics.Stopwatch]::StartNew()

# Sleep a second to let the job get started
Start-Sleep -Seconds 1

# Sleep until finished or timeout
while ($job.State -eq "Running" -and $jobTimer.Elapsed.TotalSeconds -le $Timeout) {
    Start-Sleep -Seconds 1
    $logEntry = Receive-Job $job
    if ($logEntry.length -gt 0){
        foreach($line in $logEntry){
            Write-Host $line
        }
        $logEntry | Out-File C:\logs\$RunName.log -Append
    }
}

