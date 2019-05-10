AttackSurfaceAnalyzerCli.exe collect -a
AttackSurfaceAnalyzerCli.exe export-collect --outputpath output --explodedoutput
AttackSurfaceAnalyzerCli.exe config --trim-to-latest

cd output

Get-ChildItem -Recurse -Directory | ForEach-Object {
    $dir = $_
    Get-ChildItem -File -Filter *_* $_ | ForEach-Object{
        Write-Host $(Get-content $_ | Measure-Object –Line)
        if ( $(Get-content $_ | Measure-Object –Line).Lines -gt 1){
            Write-Host "Parsing non-empty file $_"
            $c = $_.split("-")[0]
            $c = "windows_$c"
            $p = Get-Content ~/CREDENTIAL
            $u = GET_CONTENT ~/USER
            "C:\Program Files\MongoDb\4.0\bin\mongoimport.exe" -h noise-mongodb.documents.azure.com:10255 --ssl -c $c -u $u -p $p --jsonArray $f
        } else {
            Write-Host "Skipping empty file $_"
        }
    }
    Delete-Item -Path $dir.FullName
#    Write-Host "Deleting $dir"
}



cd ..