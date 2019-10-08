foreach($line in Get-Content C:\Users\Gstoc\Documents\GitHub\AttackSurfaceAnalyzer\Tools\Docker\AsaDetonatorWindows\chocolist.txt) {
    Write-Host "$line"
    Clear-Content D:\input\Install.ps1
    Add-Content D:\input\Install.ps1 "choco install $($line) -fy --no-progress"
    Clear-Content D:\input\Uninstall.ps1
    Add-Content D:\input\Uninstall.ps1 "choco uninstall $($line) -fy"
    Clear-Content D:\input\RunName
    Add-Content D:\input\RunName "$($line)"
    docker container rm -f AsaDetonator
    docker-compose up --build
    Add-Content C:\Users\Gstoc\Documents\GitHub\AttackSurfaceAnalyzer\Tools\Docker\AsaDetonatorWindows\processed.txt "$line"
}