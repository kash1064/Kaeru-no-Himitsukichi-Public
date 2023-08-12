if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))  
{  
  $arguments = "& '" +$myinvocation.mycommand.definition + "'"
  Start-Process powershell -Verb runAs -ArgumentList $arguments
  Break
}

# Settings of Full memory dump
$crashControlRegPath = "HKLM:System\CurrentControlSet\Control\CrashControl"
$isExistKey = Test-Path -LiteralPath $crashControlRegPath
if ($isExistKey -eq $False) {
	New-Item -Path $crashControlRegPath
}
New-ItemProperty -LiteralPath $CrashControlRegPath -Name "CrashDumpEnabled" -PropertyType "DWord" -Value "1" -Force
New-ItemProperty -LiteralPath $CrashControlRegPath -Name "AutoReboot" -PropertyType "DWord" -Value "1" -Force
New-ItemProperty -LiteralPath $CrashControlRegPath -Name "DumpFile" -PropertyType "ExpandString" -Value "%SystemRoot%\FULL_MEMORY.DMP" -Force
New-ItemProperty -LiteralPath $CrashControlRegPath -Name "LogEvent" -PropertyType "DWord" -Value "1" -Force

# Disable CrashOnCtrlScroll
$parameterRegPaths = @("HKLM:System\CurrentControlSet\Services\i8042prt\Parameters",
					  "HKLM:System\CurrentControlSet\Services\kbdhid\Parameters",
					  "HKLM:System\CurrentControlSet\Services\hyperkbd\Parameters"
					)
foreach ($parameterRegPath in $parameterRegPaths) {
	$isExistKey = Test-Path -LiteralPath $parameterRegPath
	if ($isExistKey -eq $False) {
		New-Item -Path $parameterRegPath
	}
	New-ItemProperty -LiteralPath $parameterRegPath -Name "CrashOnCtrlScroll" -PropertyType "DWord" -Value "0" -Force
}

# Settings of Full application dump
$localDumpsRegPath = "HKLM:SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"
$isExistKey = Test-Path -LiteralPath $localDumpsRegPath
if ($isExistKey -eq $False) {
	New-Item -Path $localDumpsRegPath
}
New-ItemProperty -LiteralPath $localDumpsRegPath -Name "DumpFolder" -PropertyType "ExpandString" -Value "%LOCALAPPDATA%\CrashDumps" -Force
New-ItemProperty -LiteralPath $localDumpsRegPath -Name "DumpCount" -PropertyType "DWord" -Value "2" -Force
New-ItemProperty -LiteralPath $localDumpsRegPath -Name "DumpType" -PropertyType "DWord" -Value "2" -Force

# Setting alt dump key
$parameterRegPaths = @("HKLM:System\CurrentControlSet\Services\i8042prt\crashdump",
					  "HKLM:System\CurrentControlSet\Services\kbdhid\crashdump",
					  "HKLM:System\CurrentControlSet\Services\hyperkbd\crashdump"
					)
foreach ($parameterRegPath in $parameterRegPaths) {
	$isExistKey = Test-Path -LiteralPath $parameterRegPath
	if ($isExistKey -eq $False) {
		New-Item -Path $parameterRegPath
	}
	New-ItemProperty -LiteralPath $parameterRegPath -Name "Dump1Keys" -PropertyType "DWord" -Value "0x2" -Force
	New-ItemProperty -LiteralPath $parameterRegPath -Name "Dump2Key" -PropertyType "DWord" -Value "0x3d" -Force
}

# Change PageFileSize
$totalPhysicalMemSize = $([Math]::Round((Get-WmiObject Win32_OperatingSystem).TotalVisibleMemorySize / 1024))
$freeStorageSizeofC = $([Math]::Round(((Get-PSDrive C).Free / 1024 / 1024)))
$pageFileSize = $totalPhysicalMemSize + 400
$pageFileSetting = "c:\pagefile.sys $pageFileSize $pageFileSize"
if (($freeStorageSizeofC -gt $pageFileSize) -eq $True) {
	New-ItemProperty -LiteralPath "HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -PropertyType "MultiString" -Value $pageFileSetting -Force
} else {
	Write-Warning "C drive space is too small."
}