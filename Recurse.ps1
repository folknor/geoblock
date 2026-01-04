$fileNames = Get-ChildItem -Path $PSScriptRoot\Zones -Recurse -Include *.zone
for ($i=0; $i -lt $fileNames.Count; $i++) {
	& "$PSScriptRoot\Import-Firewall-Blocklist.ps1" $fileNames[$i]
}