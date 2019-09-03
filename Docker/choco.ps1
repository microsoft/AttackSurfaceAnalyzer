foreach($line in Get-Content C:\input\testdata) {
    Write-Host $line
    if ($line.length -gt 1){
        C:\asa\AsaCli.exe collect -a --runid "$($line):BeforeInstall" --databasefilename "$($line).sqlite"
        choco install $($line) -fy
        C:\asa\AsaCli.exe collect -a --runid "$($line):AfterInstall" --databasefilename "$($line).sqlite"
        choco uninstall $($line) -fy
        C:\asa\AsaCli.exe collect -a --runid "$($line):AfterUninstall" --databasefilename "$($line).sqlite"
        C:\asa\AsaCli.exe export-collect --firstrunid "$($line):BeforeInstall" --secondrunid "$($line):AfterInstall" --databasefilename "$($line).sqlite" --outputpath C:\output
        C:\asa\AsaCli.exe export-collect --firstrunid "$($line):BeforeInstall" --secondrunid "$($line):AfterUninstall" --databasefilename "$($line).sqlite" --outputpath C:\output
        C:\asa\AsaCli.exe export-collect --firstrunid "$($line):AfterInstall" --secondrunid "$($line):AfterUninstall" --databasefilename "$($line).sqlite" --outputpath C:\output
        Remove-Item "$line.sqlite"
    }
}