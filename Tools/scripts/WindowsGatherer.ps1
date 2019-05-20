AttackSurfaceAnalyzerCli.exe collect -a
AttackSurfaceAnalyzerCli.exe export-collect --outputpath output --explodedoutput
AttackSurfaceAnalyzerCli.exe config --trim-to-latest

cd output

$p = Get-Content ~/CREDENTIAL
$u = Get-Content ~/USER
$c = "windows"


$files = @()
$registry = @()


Get-ChildItem -Recurse -Directory | ForEach-Object {
    $dir = $_
    Get-ChildItem -File -Filter files_* $dir | ForEach-Object{
        if ( $(Get-content $_.FullName | Measure-Object -Line).Lines -gt 1){
            Get-Content $_.FullName | Select-String -SimpleMatch -Pattern "`"Path`"" | ForEach-Object{
                $a = $_.Line.Split('`"')[3]
                $files += "INSERT INTO FILES (Path) VALUES (`"$a`");"
            }
        }
    }
    
    Get-ChildItem -File -Filter registry_* $_ | ForEach-Object{
        if ( $(Get-content $_.FullName | Measure-Object -Line).Lines -gt 1){
            Get-Content $_.FullName | Select-String -SimpleMatch -Pattern "`"Key`"" | ForEach-Object{
                $a = $_.Line.Split('`"')[3]
                $registry += "INSERT INTO REGISTRY (Key) VALUES (`"$a`");"
            }
        }
    }
}
# Dedupe modified results which report the path twice
$files = $files | sort -unique
$registry = $registry | sort -unique

Add-Content data.sql $files
Add-Content data.sql $registry

Get-Content data.sql | "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -h asa-noise-2.database.windows.net -u $u -p $p asa-noise 
del data.sql

cd ..