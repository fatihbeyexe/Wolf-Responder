param (
    [Parameter(Position=0, Mandatory=$false, HelpMessage="Name of the configuration XML file.")]
    [string]$ConfigFile,
    [Parameter(Position=1, Mandatory=$false, HelpMessage="Name of the IOC file.")]
    [string]$IOCFile,
	[Parameter(Position=2, Mandatory=$false, HelpMessage="Mode for script. 'Delete' for deletion, 'Detect' for just detecting")]
    [string]$Mode
)
function ShowBanner{
	$WolfResponderBanner = 
	@"
                      __      __      .__   _____                                  
                     /  \    /  \____ |  |_/ ____\                                 
                     \   \/\/   /  _ \|  |\   __\                                  
                      \        (  <_> )  |_|  |                                    
                       \__/\  / \____/|____/__|                                    
                            \/                              
                                                       .___            
        _______  ____   ___________   ____   ____    __| _/___________ 
        \_  __ \/ __ \ /  ___|____ \ /  _ \ /    \  / __ |/ __ \_  __ \
         |  | \|  ___/ \___ \|  |_> >  <_> )   |  \/ /_/ \  ___/|  | \/
         |__|   \___  >____  >   __/ \____/|___|  /\____ |\___  >__|   
                    \/     \/|__|               \/      \/    \/       
        
"@

	Write-Host $WolfResponderBanner -ForegroundColor Red
	Write-Host "`tTool    :: WolfResponder`n`tAuthor  :: Fatih YILMAZ`n`tTwitter :: @fatihbeyexe`n`tBlog    :: https://onlyf8.com `n`tGithub  :: https://github.com/fatihbeyexe/Wolf-Responder" -ForegroundColor Magenta
}
function ShowHelp{
	Write-Host "Wolf-Responder is a automated tool for IOC deletion. Usage:" -ForegroundColor Green
	Write-Host "1- " -ForegroundColor Red -NoNewLine 
	Write-Host "You need to give IOC's that you have with in a text file with `n   new line for each IOC and give this file name (just file name) as " -ForegroundColor Green -NoNewLine 
	Write-Host "-IOCFile " -ForegroundColor Red -NoNewLine
	Write-Host "parameter " -ForegroundColor Green
	Write-Host "`t1.2- " -ForegroundColor Red -NoNewLine 
	Write-Host "In this file you need to give IOC's with its tag (seperate with " -ForegroundColor Green -NoNewLine 
	Write-Host "'?'" -ForegroundColor Red	 -NoNewLine 
	Write-Host "). For example " -ForegroundColor Green 
	Write-Host "`t`t`t`t`t`t`t`t`t`t`t'File?C:\Users\user\Desktop\malware.exe' " -ForegroundColor Red -NoNewLine
	Write-Host "or " -ForegroundColor Green  
	Write-Host "`t`t`t`t`t`t`t`t`t`t`t'Hash?11f06c76248c172c5bc1f56590740dce' " -ForegroundColor Red -NoNewLine
	Write-Host "etc." -ForegroundColor Green
	Write-Host "`t1.3- " -ForegroundColor Red -NoNewLine 
	Write-Host "These are the IOC tags that are avaliable = > " -ForegroundColor Green 
	Write-Host "`t`t'File' " -ForegroundColor Red -NoNewLine
	Write-Host "give absolute file path and name," -ForegroundColor Green
	Write-Host "`t`t'Task' " -ForegroundColor Red -NoNewLine
	Write-Host "give task name," -ForegroundColor Green
	Write-Host "`t`t'Reg' " -ForegroundColor Red -NoNewLine
	Write-Host "give registry key and value for example " -ForegroundColor Green 
	Write-Host "`t`t      Reg?<RegKey>?<RegValue>?<RegOperation (Delete or Change>?<ChangeValue if Operation is Change>, " -ForegroundColor red
	Write-Host "`t`t'Service' " -ForegroundColor Red -NoNewLine
	Write-Host "give service name," -ForegroundColor Green
	Write-Host "`t`t'Hash' " -ForegroundColor Red -NoNewLine
	Write-Host "give " -ForegroundColor Green -NoNewLine
	Write-Host "MD5 " -ForegroundColor Red -NoNewLine
	Write-Host "hash of file. " -ForegroundColor Green
	Write-Host "2- " -ForegroundColor Red -NoNewLine
	Write-Host "You need to set configuration variables in config.xml file `n   (file name can be change, you need to give this file name as " -ForegroundColor Green -NoNewLine 
	Write-Host "-ConfigFile " -ForegroundColor Red -NoNewLine 
	Write-Host "parameter) " -ForegroundColor Green 
	Write-Host "`t2.2- " -ForegroundColor Red -NoNewLine 
	Write-Host "In XML file there are following 4 values;" -ForegroundColor Green
	Write-Host "`t`t'Speed' " -ForegroundColor Red -NoNewLine
	Write-Host "`tis a delimiter for hash search feature. '1' is " -ForegroundColor Green -NoNewLine
	Write-Host "fastest,"-ForegroundColor Red -NoNewLine
	Write-Host "'10' is " -ForegroundColor Green -NoNewLine
	Write-Host "slowest," -ForegroundColor Red 
	Write-Host "`t`t'Max_FileSize' " -ForegroundColor Red -NoNewLine
	Write-Host " is a delimiter for max file size of hash file. When you give Hash for IOC, " -ForegroundColor Green 
	Write-Host "`t`t`t`ttool will scan all your system and calculate hash of each file that file size" -ForegroundColor Green 
	Write-Host "`t`t`t`tis less than that value in MB." -ForegroundColor Green 
	Write-Host "`t`t'ExcludedPaths' " -ForegroundColor Red -NoNewLine
	Write-Host "is a delimiter for Excluded paths. When you give Hash for IOC," -ForegroundColor Green
	Write-Host "`t`t`t`ttool will scan all your system and calculate hash of each file. You can make" -ForegroundColor Green
	Write-Host "`t`t`t`texclusion for this scan. For example " -ForegroundColor Green -NoNewLine
	Write-Host "'C:\Windows' " -ForegroundColor Red -NoNewLine
	Write-Host "is not necessary for looking in some cases." -ForegroundColor Green
	Write-Host "`t`t`t`tThis variable can be multiple. You can give multiple exclusion path but seperated XML line." -ForegroundColor Green
	Write-Host "`t`t`t`tFor example: " -ForegroundColor Green -NoNewLine
	Write-Host "'<ExcludedPaths>C:\Windows</ExcludedPaths> <ExcludedPaths>C:\Python27</ExcludedPaths>'" -ForegroundColor Red
	Write-Host "`t`t'DatabaseUpdate'" -ForegroundColor Red -NoNewLine
	Write-Host "is a " -ForegroundColor Green -NoNewLine
	Write-Host "'TRUE/FALSE' " -ForegroundColor Red -NoNewLine
	Write-Host "condition for database. When you give Hash for IOC," -ForegroundColor Green
	Write-Host "`t`t`t`ttool will scan all your system and calculate hash of each file and store file names and hashes" -ForegroundColor Green
	Write-Host "`t`t`t`tin a database file. If you will run this script more than once, you don't need to scan all system" -ForegroundColor Green
	Write-Host "`t`t`t`tagain. If you don't want to update database, make this variable " -ForegroundColor Green -NoNewLine
	Write-Host "'FALSE'" -ForegroundColor Red
	Write-Host "3- " -ForegroundColor Red -NoNewLine 
	Write-Host "You need to specify mode for script. There are 2 mode;" -ForegroundColor Green
	Write-Host "`t`t`t`t'Delete' " -ForegroundColor Red -NoNewLine
	Write-Host "given(in IOC file) IOC values will be delete if detect." -ForegroundColor Green 
	Write-Host "`t`t`t`t'Detect' " -ForegroundColor Red -NoNewLine
	Write-Host "given(in IOC file) IOC values won't be delete, script will just detect and log them." -ForegroundColor Green 
	Write-Host "Example usage" -ForegroundColor Red -NoNewLine
	Write-Host " : .\wolfrespond.ps1 " -ForegroundColor Green -NoNewLine
	Write-Host "-ConfigFile " -ForegroundColor Red -NoNewLine
	Write-Host "<Your XML File> " -ForegroundColor Green -NoNewLine
	Write-Host "-IOCFile " -ForegroundColor Red -NoNewLine
	Write-Host "<Your IOC File> " -ForegroundColor Green -NoNewLine
	Write-Host "-Mode " -ForegroundColor Red -NoNewLine
	Write-Host "<Detect or Delete>" -ForegroundColor Green 
	Write-Host "`t`t.\wolfrespond.ps1 " -ForegroundColor Green -NoNewLine
	Write-Host "-ConfigFile " -ForegroundColor Red -NoNewLine
	Write-Host "config.xml " -ForegroundColor Green -NoNewLine
	Write-Host "-IOCFile " -ForegroundColor Red -NoNewLine
	Write-Host "ioc.txt " -ForegroundColor Green -NoNewLine
	Write-Host "-Mode " -ForegroundColor Red -NoNewLine
	Write-Host "Delete" -ForegroundColor Green -NoNewLine}
function Create_File_Database{
	param(
	$Update 
	)
	$isScanFinished=$false
	if(Test-Path -Path $dbFolder){
		$isScanFinished=(Get-Content -Path $dbFolder -Raw ).contains("END OF DB")
	}
	if($Update -eq $false -AND $isScanFinished){
		Write-Host "[INFO] DB will not be update" -ForegroundColor Red
		return
	}
	Set-Content -Path $dbFolder -Value "BEGINNING OF DB"
	foreach($volume in $volumeNames){
		Write-Host "[INFO] Scanning hashes for $($volume)" -ForegroundColor Green
		hashFiles -DriveLetter $volume
	}
	Add-Content -Path $dbFolder -Value "END OF DB" -Encoding UTF8
	}	
function hashFiles{
	param(
	$DriveLetter
	)
	$filesForRootFolder = Get-ChildItem -Path $DriveLetter -File  -Force | Where-Object { $_.Length -le $maxFileSize }

	$files = Get-ChildItem -Path $DriveLetter -Recurse -Directory -Force | Where-Object FullName -notmatch $excludedPaths | ForEach-Object {
		Start-Sleep -Milliseconds ($scriptSpeed*10) 
		Get-ChildItem -Path $_.FullName -File  -Force | Where-Object { $_.Length -le $maxFileSize }
	}
	$files = $files + $filesForRootFolder
	foreach ($file in $files) {
	    $hash = Get-FileHash -Path $file.FullName -Algorithm MD5 -ErrorAction SilentlyContinue
		Start-Sleep -Milliseconds ($scriptSpeed*10)
		$line = "$($file.FullName), $($hash.Hash)"
	    $line | Add-Content -Path $dbFolder -Encoding UTF8
	}}
function IOC_Deleter{
	function Get-Tasks{
	param (
	[Parameter(mandatory=$true)]
	$taskFolder
	)
    $folderQueue = New-Object System.Collections.Queue
    $folderQueue.Enqueue($taskFolder)
    $taskList = @()
    while ($folderQueue.Count -gt 0) {
        $currentFolder = $folderQueue.Dequeue()
        $Tasks = $currentFolder.GetTasks(0)
        foreach ($Task in $Tasks) {
            $Actions = $Task.Definition.Actions
            foreach ($Action in $Actions) {
				$temporaryTaskVariable = [PSCustomObject]@{
				TaskName = $Task.Name
				Command = $Action.Path + " " + $Action.Arguments
					}
				$taskList += $temporaryTaskVariable
				}
			}
        $SubFolders = $currentFolder.GetFolders(0)
        foreach ($SubFolder in $SubFolders) {
            $folderQueue.Enqueue($SubFolder)
			}
		}
    return $taskList
	}
	function Filter-Tasks{
		param(
		[Parameter(mandatory=$true)]
		$Tasks,
		[Parameter(mandatory=$true)]
		$Keyword
		)
		$filteredTasks = @()
		foreach ($Task in $Tasks) {
			if ($Task.TaskName -match $Keyword.replace("\","\\") -OR $Task.Command -match $Keyword.replace("\","\\")) {
				$filteredTasks += $Task
				}
			}
		return $filteredTasks
		}
	function Get-TaskProperties{
		param(
		[Parameter(mandatory=$true)]
		$taskProperty
		)
	$taskScheduler = New-Object -ComObject Schedule.Service
	$taskScheduler.Connect()
	$rootFolder = $taskScheduler.GetFolder("\")
	$allTasks = Get-Tasks -taskFolder $rootFolder
	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($TaskScheduler) | Out-Null
	return (Filter-Tasks -Tasks $allTasks -Keyword $taskProperty)
		}
	function Delete-Service {
		param (
			[string]$ServiceNameOrPath,
			[bool]$ServicePathForDelete,
			[bool]$ServiceName
		)
		$serviceDeletionOutput=""
		if($ServicePathForDelete -eq $true){
			$service = Get-WmiObject Win32_Service | Where-Object { $_.PathName -match $ServiceNameOrPath.replace("\","\\")}
			}
		else{
			$service = Get-WmiObject Win32_Service | Where-Object { $_.Name -match $ServiceNameOrPath.replace("\","\\")}
			}
		if($Mode -eq "Delete" -and $service){
				if($ServicePathForDelete -eq $true){
					$serviceDeletionOutput = sc.exe delete $service.Name
				}
				else{
					$serviceDeletionOutput = sc.exe delete $ServiceNameOrPath
				}
				if($serviceDeletionOutput -match "SUCCESS"){
					Write-Host "`t[INFO] Service $($service.DisplayName) stopped and deleted." -ForegroundColor Green
					Add-Content -Path $runtimeLogFolder -Value "$($service.DisplayName) stopped and deleted," -Encoding UTF8
				}
				else{
					Write-Host "`t[INFO] Service $($service.DisplayName) couldn't delete." -ForegroundColor Green
					Add-Content -Path $runtimeLogFolder -Value "$($service.DisplayName) couldn't delete," -Encoding UTF8
				}
			}
		elseif($Mode -eq "Detect" -and $service){
			Write-Host "`t[INFO] $($ServiceNameOrPath) service detect ." -ForegroundColor Green
			Add-Content -Path $runtimeLogFolder -Value "$($service.DisplayName) service detect," -Encoding UTF8
			}
		elseif(($Mode -eq "Detect" -OR $Mode -eq "Delete") -AND -not $service) {
			Write-Host "`t[INFO] $($ServiceNameOrPath) service couldn't find ." -ForegroundColor Green
			Add-Content -Path $runtimeLogFolder -Value "$($ServiceNameOrPath) couldn't find," -Encoding UTF8
			}
		}
    function Control-Service{
		param(
		$ServicePath
		)
		$service = Get-WmiObject Win32_Service | Where-Object { $_.PathName -match $ServicePath.replace("\","\\")}
		return $service
		}
	function Delete-File{
    	param(
    	$FileName
    	)
		$processes=Get-WmiObject Win32_Process | Select-Object ProcessId, CommandLine
		$isFileExist = Test-Path $FileName
		if($Mode -eq "Delete" -and $isFileExist){
				$runningProcessID = $processes | Foreach-Object { if($_ -match $FileName.replace("\","\\")){return $_.ProcessId}}
				$fileTaskProperties=Get-TaskProperties -taskProperty $FileName
				$fileServiceProperties = Control-Service -ServicePath $FileName
				if($fileTaskProperties){
					Delete-Task -TaskProperties $fileTaskProperties
				}
				if($fileServiceProperties){
					Delete-Service -ServiceNameOrPath $fileServiceProperties.Name -ServiceName $true
				}
				if($runningProcessID){
					Stop-Process -Id $runningProcessID -Force 
					Add-Content -Path $runtimeLogFolder -Value "$($FileName) file was detect as a running process and stopped," -Encoding UTF8
					Write-Host "`t[INFO] $($FileName) file was detect as a running process and stopped." -ForegroundColor Green 
				}
				Remove-Item $FileName -Force
				if (-not (Test-Path $FileName)) {
					Add-Content -Path $runtimeLogFolder -Value "$($FileName) file deleted," -Encoding UTF8
					Write-Host "`t[INFO] $($FileName) file deleted." -ForegroundColor Green 
					} 
				elseif(Test-Path $FileName) {
					Add-Content -Path $runtimeLogFolder -Value "$($FileName) file couldn't delete," -Encoding UTF8
					Write-Host "`t[INFO] $($FileName) file couldn't delete." -ForegroundColor Green 
					}
			}
		elseif($Mode -eq "Detect" -and $isFileExist){
				$runningProcessID = $processes | Foreach-Object { if($_ -match $FileName.replace("\","\\")){return $_.ProcessId}}
				$fileTaskProperties=Get-TaskProperties -taskProperty $FileName
				$fileServiceProperties = Control-Service -ServicePath $FileName
				if($fileTaskProperties){
					Delete-Task -TaskProperties $fileTaskProperties
				}
				if($fileServiceProperties){
					Delete-Service -ServiceNameOrPath $fileServiceProperties.Name -ServiceName $true
				}
				if($runningProcessID){
					Add-Content -Path $runtimeLogFolder -Value "$($FileName) file detected as a running process ID => $($runningProcessID)," -Encoding UTF8
					Write-Host "`t[INFO] $($FileName) file detected as a running process ID => $($runningProcessID)." -ForegroundColor Green
				}
				Add-Content -Path $runtimeLogFolder -Value "$($FileName) file detected," -Encoding UTF8
				Write-Host "`t[INFO] $($FileName) file detected." -ForegroundColor Green
			}
		elseif(($Mode -eq "Detect" -OR $Mode -eq "Delete") -AND -not $isFileExist){
			Add-Content -Path $runtimeLogFolder -Value "$($FileName) file doesn't exist," -Encoding UTF8
			Write-Host "`t[INFO] $($FileName) file doesn't exist." -ForegroundColor Green
			}
        }
    function Delete-Task{
    	param(
    	$TaskProperties
    	)
		foreach($taskProperty in $TaskProperties){
			$taskEndingOutput = ""
			$taskDeleteOutput = ""
			$taskQueryOutput = schtasks.exe /Query /TN $taskProperty.TaskName 2>&1
			if($Mode -eq "Delete"){
					$taskEndingOutput = schtasks.exe /End /TN $taskProperty.TaskName 2>&1
					if($taskEndingOutput -match "ERROR:"){
						Add-Content -Path $runtimeLogFolder -Value "'TaskName : $($taskProperty.TaskName)' 'Task CommandLine : $($taskProperty.Command)' couldn't ended. Error => $($taskEndingOutput)," -Encoding UTF8
						Write-Host "`t[INFO] 'TaskName : $($taskProperty.TaskName)' 'Task CommandLine : $($taskProperty.Command)' couldn't ended. Error => $($taskEndingOutput)." -ForegroundColor Green
						return
						}
					$taskDeleteOutput = schtasks.exe /Delete /TN $taskProperty.TaskName /F
					if($taskDeleteOutput -match "ERROR:"){
						Add-Content -Path $runtimeLogFolder -Value "'TaskName : $($taskProperty.TaskName)' 'Task CommandLine : $($taskProperty.Command)' couldn't deleted. Error => $($taskDeleteOutput)," -Encoding UTF8
						Write-Host "`t[INFO] 'TaskName : $($taskProperty.TaskName)' 'Task CommandLine : $($taskProperty.Command)' couldn't deleted. Error => $($taskDeleteOutput)." -ForegroundColor Green
						return
						}
					Add-Content -Path $runtimeLogFolder -Value "'TaskName : $($taskProperty.TaskName)' 'Task CommandLine : $($taskProperty.Command)' deleted," -Encoding UTF8
					Write-Host "`t[INFO] 'TaskName : $($taskProperty.TaskName)' 'Task CommandLine : $($taskProperty.Command)' deleted." -ForegroundColor Green
			}
			elseif($Mode -eq "Detect"){
					Add-Content -Path $runtimeLogFolder -Value "'TaskName : $($taskProperty.TaskName)' 'Task CommandLine : $($taskProperty.Command)' detected," -Encoding UTF8
					Write-Host "`t[INFO] 'TaskName : $($taskProperty.TaskName)' 'Task CommandLine : $($taskProperty.Command)' detected." -ForegroundColor Green
				}
		}
		}	
    function Delete-Registry{
    	param (
    	$registryKeyName,
		$registryKeyValue,
		$registryOperation,
		$newValueData
    	)
		$isRegExist = Test-Path $registryKeyName
		if (($Mode -eq "Detect" -OR $Mode -eq "Delete") -AND -not $isRegExist) {
			Add-Content -Path $runtimeLogFolder -Value "$($registryKeyName) key couldn't find," -Encoding UTF8
			Write-Host "`t[INFO] $($registryKeyName) key couldn't find." -ForegroundColor Green
			return
			}
		elseif(($Mode -eq "Detect" -OR $Mode -eq "Delete") -AND $isRegExist) {
			$registryKeyTemp = Get-Item -LiteralPath $registryKeyName
			$isValueExist = $registryKeyTemp.GetValue($registryKeyValue, $null)
			if(-not $isValueExist){
				Add-Content -Path $runtimeLogFolder -Value "$($registryKeyName)\$($registryKeyValue) value couldn't find," -Encoding UTF8
				Write-Host "`t[INFO] $($registryKeyName)\$($registryKeyValue) value couldn't find." -ForegroundColor Green
				return
			}
			}
		if($Mode -eq "Delete"){
			if($registryOperation -eq "Delete"){
				Remove-ItemProperty -Path $registryKeyName -Name $registryKeyValue 
				if($?){
					Add-Content -Path $runtimeLogFolder -Value "$($registryKeyName)\$($registryKeyValue) key deleted," -Encoding UTF8
					Write-Host "`t[INFO] $($registryKeyName)\$($registryKeyValue) key deleted." -ForegroundColor Green
				}
				else{
					Add-Content -Path $runtimeLogFolder -Value "$($Error[0].Exception.Message) => $($registryKeyName)\$($registryKeyValue) key couldn't deleted," -Encoding UTF8
					Write-Host "`t[INFO] $($Error[0].Exception.Message) => $($registryKeyName)\$($registryKeyValue) key couldn't deleted." -ForegroundColor Green
				}	
				}
			elseif($registryOperation -eq "Change" -AND $newValueData){
				Set-ItemProperty -Path $registryKeyName -Name $registryKeyValue -Value $newValueData 
				if($?){
					Add-Content -Path $runtimeLogFolder -Value "$($registryKeyName)\$($registryKeyValue) key value changed to $($newValueData)," -Encoding UTF8
					Write-Host "`t[INFO] $($registryKeyName)\$($registryKeyValue) key value changed to $($newValueData)." -ForegroundColor Green
				}
				else{
					Add-Content -Path $runtimeLogFolder -Value "$($Error[0].Exception.Message) => $($registryKeyName)\$($registryKeyValue) key value couldn't change," -Encoding UTF8
					Write-Host "`t[INFO] $($Error[0].Exception.Message) => $($registryKeyName)\$($registryKeyValue) key value couldn't change." -ForegroundColor Green
				}
				}
			}
		elseif($Mode -eq "Detect"){
			Add-Content -Path $runtimeLogFolder -Value "$($registryKeyName)\$($registryKeyValue) key and value detect," -Encoding UTF8
			Write-Host "`t[INFO] $($registryKeyName)\$($registryKeyValue) key and value detect." -ForegroundColor Green
			}
		}
	
    $iocType=""
	$hashFlag=$false
    foreach ($ioc in $IOCs){
    	$iocType=$ioc.split("?")[0]
    	$splittedIOC=$ioc.split("?")[1]
		Write-Host "[INFO] Operation for $($splittedIOC) is running" -ForegroundColor Yellow
    	if($iocType -match "File"){
    		Delete-File $splittedIOC
    		}
    	elseif($iocType -match ("Reg")){
			$characterToCount = '\?'
			$iocRegKeyName = ""
			$iocRegKeyValue = ""
			$iocRegOperation = ""
			$Occurrences = ($ioc | Select-String -Pattern $characterToCount -AllMatches).Matches.Count
			$iocRegKeyName = $ioc.split("?")[1]
			$iocRegKeyValue = $ioc.split("?")[2]
			$iocRegOperation = $ioc.split("?")[3] 
			if($Occurrences -ne 4 -AND $iocRegOperation -eq "Change"){
				Add-Content -Path $runtimeLogFolder -Value "$($iocRegKeyName)\$($iocRegKeyValue) key value couldn't change because new value didn't specified," -Encoding UTF8
				Write-Host "`t[INFO] $($iocRegKeyName)\$($iocRegKeyValue) key value couldn't change because new value didn't specified." -ForegroundColor Green
				}
			elseif($Occurrences -ne 3 -AND $iocRegOperation -eq "Delete"){
				Add-Content -Path $runtimeLogFolder -Value "$($iocRegKeyName)\$($iocRegKeyValue) didn't change because you give 'new value' parameter but give 'Delete' operation," -Encoding UTF8
				Write-Host "`t[INFO] $($iocRegKeyName)\$($iocRegKeyValue) didn't change because you give 'new value' parameter but give 'Delete' operation." -ForegroundColor Green
				}
			elseif($Occurrences -eq 3){
				Delete-Registry -registryKeyName $iocRegKeyName -registryKeyValue $iocRegKeyValue -registryOperation $iocRegOperation
				}
			elseif($Occurrences -eq 4){
				Delete-Registry -registryKeyName $iocRegKeyName -registryKeyValue $iocRegKeyValue -registryOperation $iocRegOperation -newValueData $ioc.split("?")[4]
				}
    		}
    	elseif($iocType -match ("Task")){
			if($splittedIOC){
				$taskProp=Get-TaskProperties -taskProperty $splittedIOC
				if($taskProp){
					Delete-Task -TaskProperties $taskProp
					}
				else{
				Add-Content -Path $runtimeLogFolder -Value "'TaskName : $($splittedIOC)' couldn't find," -Encoding UTF8
				Write-Host "`t[INFO] 'TaskName : $($splittedIOC)' couldn't find." -ForegroundColor Green
					}
			}
    		}
		elseif($iocType -match ("Service")){
			Delete-Service -ServiceNameOrPath $splittedIOC -ServiceName $true
			}
		elseif($iocType -match ("Hash")){
			if($hashFlag -eq $false){
				Create_File_Database -Update $dbUpdateSwitch
				$hashFlag=$true
				}
			HashSearch -MD5Hash $splittedIOC
			}
    }
	}
function HashSearch{
	param(
		[Parameter(mandatory=$true)]
        [string] $MD5Hash
	)
	$detectFlag=0
	$dbContent=Get-Content -Path $dbFolder
	if($Mode -eq "Detect"){
		foreach($line in $dbContent){
			$fileNameFromHash=$line.split(",")[0]
			$fileHash=$line.split(",")[1]
			if($fileHash -match $MD5Hash){
				if(Test-Path $fileNameFromHash){
					Add-Content -Path $runtimeLogFolder -Value "$($fileNameFromHash) file that has $($MD5Hash) MD5 hash value is detected ," -Encoding UTF8
					Write-Host "`t[INFO] $($fileNameFromHash) file that has $($MD5Hash) MD5 hash value is detected." -ForegroundColor Green
					$detectFlag = 1
					}
				else{
					Add-Content -Path $runtimeLogFolder -Value "$($fileNameFromHash) file that has $($MD5Hash) MD5 hash value is detected in database but doesn't exist in path ," -Encoding UTF8
					Write-Host "`t[INFO] $($fileNameFromHash) file that has $($MD5Hash) MD5 hash value is detected in database but doesn't exist in path." -ForegroundColor Green
					$detectFlag = 1
					}
				}
			}
		}
	elseif($Mode -eq "Delete"){
		foreach($line in $dbContent){
			$fileNameFromHash=$line.split(",")[0]
			$fileHash=$line.split(",")[1]
			if($fileHash -match $MD5Hash){
				if(Test-Path $fileNameFromHash){
					Delete-File -FileName $fileNameFromHash
					Add-Content -Path $runtimeLogFolder -Value "$($fileNameFromHash) file that has $($MD5Hash) MD5 hash value is deleted ," -Encoding UTF8
					Write-Host "`t[INFO] $($fileNameFromHash) file that has $($MD5Hash) MD5 hash value is deleted." -ForegroundColor Green
					$detectFlag = 1
					}
				else{
					Add-Content -Path $runtimeLogFolder -Value "$($fileNameFromHash) file that has $($MD5Hash) MD5 hash value is detected in database but doesn't exist in path ," -Encoding UTF8
					Write-Host "`t[INFO] $($fileNameFromHash) file that has $($MD5Hash) MD5 hash value is detected in database but doesn't exist in path." -ForegroundColor Green
					$detectFlag = 1
					}
				}
			}
		}
	if($detectFlag -eq 0){
			Add-Content -Path $runtimeLogFolder -Value "$($MD5Hash) MD5 hash value doesn't exist," -Encoding UTF8
			Write-Host "`t[INFO] $($MD5Hash) MD5 hash value doesn't exist." -ForegroundColor Green
		}
	}
function Start-Script{
	ShowBanner
	$xmlPath = Join-Path $pwd $ConfigFile
	$xmlContent= [xml](Get-Content -Path $xmlPath)
	$iocPath = Join-Path $pwd $IOCFile
	$IOCs=(Get-Content -Path $iocPath)
	$physicalDisks = Get-WmiObject -Class Win32_DiskDrive | Where-Object { $_.MediaType -ne "Removable Media" }
	$volumeNames = @()
	foreach ($disk in $physicalDisks) {
		$partitions = Get-WmiObject -Class Win32_DiskPartition | Where-Object { $_.DiskIndex -eq $disk.Index }
		foreach ($partition in $partitions) {
			$logicalDisks = Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} WHERE AssocClass = Win32_LogicalDiskToPartition"
			foreach ($logicalDisk in $logicalDisks) {
				$volumeNames += [string]$logicalDisk.DeviceID + "\"
			}
		}
	}
	$Hostname = hostname
	$maxFileSize = [int]($xmlContent.Configuration.Max_FileSize)
	$maxFileSize = $maxFileSize *1MB
	$scriptSpeed = [int]($xmlContent.Configuration.Speed)
	if($scriptSpeed -lt 1){$scriptSpeed = 1}
	if($scriptSpeed -gt 10){$scriptSpeed = 10}
	$excludedPaths += ($xmlContent.Configuration.ExcludedPaths).replace("\","\\") -join "|"
	$dbUpdateSwitch = ($xmlContent.Configuration.DatabaseUpdate)
	$dbFolder = "C:\ProgramData\WolfResponder.db"
	$dateString = Get-Date -Format "HH_mm_dd_MM_yyyy"
	$runtimeLogFolder = [string]($pwd)+"\$($Hostname)_runtimeLog_"+$dateString+".txt"
	Set-Content -Path $runtimeLogFolder -Value "$($Hostname),"
	Write-Host "[INFO] Max file size => $($maxFileSize/(1024*1024))MB" -ForegroundColor Green
	Write-Host "[INFO] ScriptSpeed => $($scriptSpeed)" -ForegroundColor Green
	Write-Host "[INFO] Excluded Paths => $($excludedPaths)" -ForegroundColor Green
	Write-Host "[INFO] Volumes that will be scan => $($volumeNames)" -ForegroundColor Green
	Write-Host "[INFO] File and hashes database path => $($dbFolder)" -ForegroundColor Green
	Write-Host "[INFO] Runtime log path => $($runtimeLogFolder)" -ForegroundColor Green
	Write-Host "[?]Script will be run with these configurations, do you wanna continue?(Y\N)" -ForegroundColor red
	$userAnswer = Read-Host  
	if($userAnswer -eq "Y"){
		Write-Host "[INFO] Script will be run" -ForegroundColor Green
		IOC_Deleter
		}
	else{
		Write-Host "[INFO] Script is stopped" -ForegroundColor Green
		exit
		}
	}
$errorActionPreference = "SilentlyContinue"
if ($ConfigFile -eq "--help" -or $ConfigFile -eq "-h") {
	ShowBanner
	ShowHelp
	exit
	}
if (-not $ConfigFile -or -not $IOCFile -or -not $Mode) {
    Write-Host "Both ConfigFile, IOCFile and Mode parameters are required. Use --help for more information." -ForegroundColor Red
    exit 
	}
elseif($ConfigFile -and $IOCFile -and $Mode){
	$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
	if (-not $isAdmin) {
		Write-Host "[INFO] Please start this script with admin rights" -ForegroundColor Red
		exit
		}
	elseif ($isAdmin){
		Start-Script
		}
	}
