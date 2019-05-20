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

$files = @()
$registry = @()

Get-ChildItem -Recurse -Directory output | ForEach-Object {
    $dir = $_.FullName
    Get-ChildItem -File -Filter files_* $dir | ForEach-Object{
        if ( $(Get-content $_.FullName | Measure-Object -Line).Lines -gt 1){
            Get-Content $_.FullName | Select-String -SimpleMatch -Pattern "`"Path`"" | ForEach-Object{
                $a = $_.Line.Split('`"')[3]
                $files += "$a"
            }
        }
    }
    $files = $files | sort -unique

    Add-Content ~\files.txt $files

    Get-ChildItem -File -Filter registry_* $dir | ForEach-Object{
        if ( $(Get-content $_.FullName | Measure-Object -Line).Lines -gt 1){
            Get-Content $_.FullName | Select-String -SimpleMatch -Pattern "`"Key`"" | ForEach-Object{
                $a = $_.Line.Split('`"')[3]
                $registry += "$a"
            }
        }
    }

    $registry = $registry | sort -unique
    Add-Content ~\registry.txt $registry

    $registry=@()
    $files=@()

    Move-Item -Path $dir -Destination ~\stage\ingested\
}

C:\Program` Files\Microsoft` SQL` Server\Client` SDK\ODBC\110\Tools\Binn\bcp.exe windows_files in ~\files.txt -S asa-noise-2.database.windows.net -d asa-noise -U $u -P $p -q -c -t
C:\Program` Files\Microsoft` SQL` Server\Client` SDK\ODBC\110\Tools\Binn\bcp.exe registry in ~\registry.txt -S asa-noise-2.database.windows.net -d asa-noise -U $u -P $p -q -c -t

del C:\users\noise\files.txt
del C:\users\noise\registry.txt