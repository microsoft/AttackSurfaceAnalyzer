foreach($line in Get-Content C:\Users\Gstoc\Documents\GitHub\AttackSurfaceAnalyzer\Tools\Docker\chocolist.txt) {
    Write-Host "$line"
    Clear-Content D:\input\Install.ps1
    Add-Content D:\input\Install.ps1 "choco install $($line) -fy"
    Clear-Content D:\input\Uninstall.ps1
    Add-Content D:\input\Uninstall.ps1 "choco uninstall $($line) -fy"
    Add-Content D:\input\RunName "$($line)"
    docker container rm AsaDetonator
    docker-compose up --build
    Add-Content C:\Users\Gstoc\Documents\GitHub\AttackSurfaceAnalyzer\Tools\Docker\processed.txt "$line"
}