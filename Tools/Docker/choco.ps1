$Timeout = 1800
$RetryInterval = 1

foreach($line in Get-Content D:\input\testdata) {
    Write-Host $line
    if ($line.length -gt 1){
        $ScriptBlock = {
            param($line) 
            C:\asa\AsaCli.exe collect -a --runid "$($line):BeforeInstall" --databasefilename "$($line).sqlite"
            choco install $($line) -fy
            C:\asa\AsaCli.exe collect -a --runid "$($line):AfterInstall" --databasefilename "$($line).sqlite"
            choco uninstall $($line) -fy
            C:\asa\AsaCli.exe collect -a --runid "$($line):AfterUninstall" --databasefilename "$($line).sqlite"
            C:\asa\AsaCli.exe export-collect --firstrunid "$($line):BeforeInstall" --secondrunid "$($line):AfterInstall" --databasefilename "$($line).sqlite" --outputpath C:\output
            C:\asa\AsaCli.exe export-collect --firstrunid "$($line):BeforeInstall" --secondrunid "$($line):AfterUninstall" --databasefilename "$($line).sqlite" --outputpath C:\output
            C:\asa\AsaCli.exe export-collect --firstrunid "$($line):AfterInstall" --secondrunid "$($line):AfterUninstall" --databasefilename "$($line).sqlite" --outputpath C:\output
        }

        $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $_
        $jobTimer = [Diagnostics.Stopwatch]::StartNew()
        sleep -Seconds 1

        while ($job.State -eq "Running" -and $jobTimer.Elapsed.TotalSeconds -le $Timeout) {
            ## Check the time
            $totalSecs = [math]::Round($jobTimer.Elapsed.TotalSeconds)
            sleep -Seconds 1
        }
        Receive-Job -Job $job | Out-File c:\Test.log -Append
        if ($jobTimer.Elapsed.TotalSeconds -gt $Timeout){
            Add-Content -Path D:\ChocoDocker\TimedOut.txt -Value $_
        }
    }
}