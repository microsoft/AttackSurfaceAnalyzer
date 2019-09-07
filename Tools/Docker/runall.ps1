foreach($line in Get-Content D:\ChocoDocker\chocolist.txt) {
    Write-Host "$line"
    Clear-Content D:\input\testdata
    Add-Content D:\input\testdata "$line"
    docker container rm chocotester
    docker-compose up --build
    Add-Content D:\ChocoDocker\processed.txt "$line"
}