$wd = pwd

if (-not (Test-Path ~\stage) ){
    New-Item -Path ~\stage -ItemType "directory"
}
if (-not (Test-Path ~\stage\output) ){
    New-Item -Path ~\stage\output -ItemType "directory"
}
if (-not (Test-Path ~\stage\ingested) ){
    New-Item -Path ~\stage\ingested -ItemType "directory"
}
cd ~\stage

~\AsaCli\res\AttackSurfaceAnalyzerCli.exe collect -a --no-filters --debug
~\AsaCli\res\AttackSurfaceAnalyzerCli.exe export-collect --outputpath output --explodedoutput
~\AsaCli\res\AttackSurfaceAnalyzerCli.exe config --trim-to-latest

Get-ChildItem -Recurse -Directory output -ErrorAction Stop  | ForEach-Object {
    $dir = $_
    Get-ChildItem -File -Filter *_* $_.FullName -ErrorAction Stop | ForEach-Object{
        if ( $(Get-Content $_.FullName | Measure-Object –Line).Lines -gt 1){
            Write-Host "Parsing non-empty file $_"
            $c = $_.Name.Split("-")[0]
            $c = "windows_$c"
            $p = Get-Content C:\Users\noise\CREDENTIAL.txt
            $u = Get-Content C:\Users\noise\USER.txt
            
            C:\Program` Files\MongoDB\Server\4.0\bin\mongoimport.exe -h noise-mongodb.documents.azure.com:10255 --ssl -c $c -u $u -p $p --verbose --jsonArray --file $_.FullName 2>&1 | %{ "$_" }
        } else {
            Write-Host "Skipping empty file $_"
        }
    }
    Move-Item -Recurse -Path output\$dir -Destination ingested\$dir
}

cd $wd