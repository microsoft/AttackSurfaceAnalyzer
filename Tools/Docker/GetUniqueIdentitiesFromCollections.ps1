$numJobs = 0
$maxNumJobs = 12
Get-ChildItem D:\output | %{

  $ScriptBlock = {
    param($name) 
    Get-Content $name.FullName | awk '/Identity.:/{ gsub(\",\",\"\"); gsub(\"\\\"\",\"\"); gsub(\" \",\"\"); sub(\"Identity:\",\"\"); print }' | Sort-Object -Unique | Out-File -FilePath "D:\parsing\${name}"
  }

  Write-Host "processing $_..."
  while($numJobs -ge $maxNumJobs){
    Start-Sleep 1
    $numJobs = (Get-Job -state "Running" | Measure-Object).Count
  }
  Start-Job $ScriptBlock -ArgumentList $_
  $numJobs = (Get-Job -state "Running" | Measure-Object).Count
}