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

$p = Get-Content ~/CREDENTIAL.txt
$u = Get-Content ~/USER.txt
$c = "windows"


$files = New-Object Collections.Generic.List[string]
$registry = New-Object Collections.Generic.List[string]


Get-ChildItem -Recurse -Directory output | ForEach-Object {
    $dir = $_.FullName
    Get-ChildItem -File -Filter files_* $dir | ForEach-Object{
        if ( $(Get-Item $_.FullName).Length -lt 50000000 ){
            if ( $(Get-Item $_.FullName).Length -gt 2){
                Write-Host "Parsing $_"
                Get-Content $_.FullName | Select-String -SimpleMatch -Pattern "`"Path`"" | ForEach-Object{
                    $a = $_.Line.Split('`"')[3]
                    $files.add($a)
                }
            }
            else{
                Write-Host "Skipping $_. Empty file."
            }
        }
        else{
            Write-Host "Skipping $_. Too large."
        }
    }

    Get-ChildItem -File -Filter registry_* $dir | ForEach-Object{
        if ( $(Get-Item $_.FullName).Length -lt 50000000 ){
            if ( $(Get-Item $_.FullName).Length -gt 2){
                Write-Host "Parsing $_"
                Get-Content $_.FullName | Select-String -SimpleMatch -Pattern "`"Key`"" | ForEach-Object{
                    $a = $_.Line.Split('`"')[3]
                    $registry.add($a)
                }
            }
            else{
                Write-Host "Skipping $_. Empty file."
            }
        }
        else{
            Write-Host "Skipping $_. Too large."
        }
    }

    $files = $files | sort -unique
    Add-Content ~\files.txt $files

    $registry = $registry | sort -unique
    Add-Content ~\registry.txt $registry

    if ($files.Count -gt 0){
        C:\Program` Files\Microsoft` SQL` Server\Client` SDK\ODBC\110\Tools\Binn\bcp.exe windows_files in C:\users\noise\files.txt -S asa-noise-2.database.windows.net -d asa-noise -U $u -P $p -q -c -t
    }

    if ($registry.Count -gt 0){
        C:\Program` Files\Microsoft` SQL` Server\Client` SDK\ODBC\110\Tools\Binn\bcp.exe registry in C:\users\noise\registry.txt -S asa-noise-2.database.windows.net -d asa-noise -U $u -P $p -q -c -t
    }
    
    $files=New-Object Collections.Generic.List[string]
    del C:\users\noise\files.txt
     
    $registry=New-Object Collections.Generic.List[string]
    del C:\users\noise\registry.txt

    Move-Item -Path $dir -Destination ~\stage\ingested\    
}
