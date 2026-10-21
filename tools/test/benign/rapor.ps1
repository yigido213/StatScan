$dosyalar = Get-ChildItem -Path $HOME\Belgeler -Filter *.txt
foreach ($d in $dosyalar) { Write-Output ('{0} {1}' -f $d.Name, $d.Length) }
$s = Invoke-RestMethod -Uri 'https://api.github.com/repos/PowerShell/PowerShell/releases/latest'
Write-Output $s.tag_name
