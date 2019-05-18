AttackSurfaceAnalyzerCli.exe collect -a
AttackSurfaceAnalyzerCli.exe export-collect --outputpath output --explodedoutput
AttackSurfaceAnalyzerCli.exe config --trim-to-latest

cd output

Get-ChildItem -Recurse -Directory | ForEach-Object {
    $dir = $_
    Get-ChildItem -File -Filter *_* $_ | ForEach-Object{
        if ( $(Get-content $_ | Measure-Object –Line).Lines -gt 1){
            Write-Host "Parsing non-empty file $_"
            $c = "windows"
            $p = Get-Content ~/CREDENTIAL
            $u = Get-Content ~/USER
            Get-Content .\TestObj.txt | Select-String -SimpleMatch -Pattern "path" | ForEach-Object{
                    $a = $_.Line.Split('"')[1]
                    Write-Host $a
            }
            "C:\Program Files\MongoDb\4.0\bin\mongoimport.exe" -h noise-mongodb.documents.azure.com:10255 --ssl -c $c -u $u -p $p --jsonArray $f
        } else {
            Write-Host "Skipping empty file $_"
        }
    }
    Delete-Item -Path $dir.FullName
#    Write-Host "Deleting $dir"
}



cd ..