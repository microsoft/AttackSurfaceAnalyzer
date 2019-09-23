# Default timeout 30 minutes
$Timeout = 1800

cat /input/RunName | $RunName

timeout --signal=SIGINT $Timeout /Asa/Asa collect -a --runid "$($RunName):BeforeInstall" --databasefilename "$($RunName).sqlite"
timeout --signal=SIGINT $Timeout /input/Install.sh
timeout --signal=SIGINT $Timeout /Asa/Asa collect -a --runid "$($RunName):AfterInstall" --databasefilename "$($RunName).sqlite"
timeout --signal=SIGINT $Timeout /input/Uninstall.sh
timeout --signal=SIGINT $Timeout /Asa/Asa collect -a --runid "$($RunName):AfterUninstall" --databasefilename "$($RunName).sqlite"
timeout --signal=SIGINT $Timeout /Asa/Asa export-collect --firstrunid "$($RunName):BeforeInstall" --secondrunid "$($RunName):AfterInstall" --databasefilename "$($RunName).sqlite" --outputpath /output
timeout --signal=SIGINT $Timeout /Asa/Asa export-collect --firstrunid "$($RunName):BeforeInstall" --secondrunid "$($RunName):AfterUninstall" --databasefilename "$($RunName).sqlite" --outputpath /output
timeout --signal=SIGINT $Timeout /Asa/Asa export-collect --firstrunid "$($RunName):AfterInstall" --secondrunid "$($RunName):AfterUninstall" --databasefilename "$($RunName).sqlite" --outputpath /output