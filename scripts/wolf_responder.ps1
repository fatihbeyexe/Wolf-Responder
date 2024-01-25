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
	function deleteService {
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
    function controlService{
		param(
		$ServicePath
		)
		$service = Get-WmiObject Win32_Service | Where-Object { $_.PathName -match $ServicePath.replace("\","\\")}
		return $service
		}
	function deleteFile{
    	param(
    	$FileName
    	)
		$processes=Get-WmiObject Win32_Process | Select-Object ProcessId, CommandLine
		$isFileExist = Test-Path $FileName
		if($Mode -eq "Delete" -and $isFileExist){
				$runningProcessID = $processes | Foreach-Object { if($_ -match $FileName.replace("\","\\")){return $_.ProcessId}}
				$fileTaskProperties=retrieveTaskInfo -searchCommand $FileName -fromDeleteFile $true
				$fileServiceProperties = controlService -ServicePath $FileName
				if($fileTaskProperties){
					deleteTask -TaskProperties $fileTaskProperties
				}
				if($fileServiceProperties){
					deleteService -ServiceNameOrPath $fileServiceProperties.Name -ServiceName $true
				}
				if($runningProcessID){
					Stop-Process -Id $runningProcessID -Force 
					Add-Content -Path $runtimeLogFolder -Value "$($FileName) file was detect as a running process and stopped," -Encoding UTF8
					Write-Host "`t[INFO] $($FileName) file was detect as a running process and stopped." -ForegroundColor Green 
				}
				del $FileName
				Add-Content -Path $runtimeLogFolder -Value "$($FileName) file deleted," -Encoding UTF8
				Write-Host "`t[INFO] $($FileName) file deleted." -ForegroundColor Green 
			}
		elseif($Mode -eq "Detect" -and $isFileExist){
				$runningProcessID = $processes | Foreach-Object { if($_ -match $FileName.replace("\","\\")){return $_.ProcessId}}
				$fileTaskProperties=retrieveTaskInfo -searchCommand $FileName -fromDeleteFile $true
				$fileServiceProperties = controlService -ServicePath $FileName
				if($fileTaskProperties){
					deleteTask -TaskProperties $fileTaskProperties
				}
				if($fileServiceProperties){
					deleteService -ServiceNameOrPath $fileServiceProperties.Name -ServiceName $true
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
    function deleteTask{
    	param(
    	$TaskProperties
    	)
		$isTaskExist = (Get-ScheduledTask -TaskName $TaskProperties.TaskName)
		if($Mode -eq "Delete" -and $isTaskExist){
				if($TaskProperties.State -eq "Running"){
					Stop-ScheduledTask -TaskName $TaskProperties.TaskName  
				}
				Unregister-ScheduledTask -TaskName $TaskProperties.TaskName -Confirm:$false
				Add-Content -Path $runtimeLogFolder -Value "$($TaskProperties.TaskName) stopped and deleted. task command line => $($TaskProperties.Command)," -Encoding UTF8
				Write-Host "`t[INFO] $($TaskProperties.TaskName) stopped and deleted. task command line => $($TaskProperties.Command)." -ForegroundColor Green
		}
    	elseif($Mode -eq "Detect" -and $isTaskExist){
				Add-Content -Path $runtimeLogFolder -Value "$($TaskProperties.TaskName) detected. task command line => $($TaskProperties.Command)," -Encoding UTF8
				Write-Host "`t[INFO] $($TaskProperties.TaskName) detected. task command line => $($TaskProperties.Command)." -ForegroundColor Green
			}
		elseif(($Mode -eq "Detect" -OR $Mode -eq "Delete") -AND -not $isTaskExist){
				Add-Content -Path $runtimeLogFolder -Value "$($TaskName.TaskName) couldn't find," -Encoding UTF8
				Write-Host "`t[INFO] $($TaskName.TaskName) couldn't find." -ForegroundColor Green
			}
		}
    function deleteReg{
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
	function retrieveTaskInfo{
		param(
        [string]$searchCommand,
		[bool]$fromDeleteFile,
		[bool]$fromTaskName
		)
		foreach ($task in $taskList) {
			if($fromDeleteFile -eq $true){
				$taskAction = $task.Actions | Where-Object { $_.Execute -like "*$searchCommand*" }
				}
			elseif($fromTaskName -eq $true){
				$taskAction = $task.TaskName | Where-Object { $_ -like "*$searchCommand*" }
				}
			if ($taskAction) {
				$taskName = $task.TaskName
				$taskCommand = $taskAction
				$taskStatus = $task.State
				[PSCustomObject]@{
					TaskName   = $taskName
					Command    = $taskCommand.Execute
					Status     = $taskStatus
				}
				}
			}
		}
	$taskList = Get-ScheduledTask
    $IOC_Type=""
	$hashFlag=$false
    foreach ($ioc in $IOCs){
    	$IOC_Type=$ioc.split("?")[0]
    	$splittedIOC=$ioc.split("?")[1]
		Write-Host "[INFO] Operation for $($splittedIOC) is running" -ForegroundColor Yellow
    	if($IOC_Type -eq "File"){
    		deleteFile $splittedIOC
    		}
    	elseif($IOC_Type.equals("Reg")){
			$characterToCount = '\?'
			$iocRegKeyName = ""
			$iocRegKeyValue = ""
			$iocRegOperation = ""
			$occurrences = ($ioc | Select-String -Pattern $characterToCount -AllMatches).Matches.Count
			$iocRegKeyName = $ioc.split("?")[1]
			$iocRegKeyValue = $ioc.split("?")[2]
			$iocRegOperation = $ioc.split("?")[3] 
			if($occurrences -ne 4 -AND $iocRegOperation -eq "Change"){
				Add-Content -Path $runtimeLogFolder -Value "$($iocRegKeyName)\$($iocRegKeyValue) key value couldn't change because new value didn't specified," -Encoding UTF8
				Write-Host "`t[INFO] $($iocRegKeyName)\$($iocRegKeyValue) key value couldn't change because new value didn't specified." -ForegroundColor Green
				}
			elseif($occurrences -ne 3 -AND $iocRegOperation -eq "Delete"){
				Add-Content -Path $runtimeLogFolder -Value "$($iocRegKeyName)\$($iocRegKeyValue) didn't change because you give 'new value' parameter but give 'Delete' operation," -Encoding UTF8
				Write-Host "`t[INFO] $($iocRegKeyName)\$($iocRegKeyValue) didn't change because you give 'new value' parameter but give 'Delete' operation." -ForegroundColor Green
				}
			elseif($occurrences -eq 3){
				deleteReg -registryKeyName $iocRegKeyName -registryKeyValue $iocRegKeyValue -registryOperation $iocRegOperation
				}
			elseif($occurrences -eq 4){
				deleteReg -registryKeyName $iocRegKeyName -registryKeyValue $iocRegKeyValue -registryOperation $iocRegOperation -newValueData $ioc.split("?")[4]
				}
    		}
    	elseif($IOC_Type.equals("Task")){
    		$taskProp=retrieveTaskInfo -searchCommand $splittedIOC -fromTaskName $true
			deleteTask -TaskProperties $taskProp
    		}
		elseif($IOC_Type.equals("Service")){
			deleteService -ServiceNameOrPath $splittedIOC -ServiceName $true
			}
		elseif($IOC_Type.equals("Hash")){
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
					deleteFile -FileName $fileNameFromHash
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
	$physicalDisks = Get-Disk
	$partitions = $physicalDisks | Get-Partition 
	$volumeNames = @()
	foreach ($partition in $partitions){
		if($partition.DriveLetter){
			$volumeNames += $partition.DriveLetter + ":\"
			}
		}
	$hostname = hostname
	$maxFileSize = [int]($xmlContent.Configuration.Max_FileSize)
	$maxFileSize = $maxFileSize *1MB
	$scriptSpeed = [int]($xmlContent.Configuration.Speed)
	if($scriptSpeed -lt 1){$scriptSpeed = 1}
	if($scriptSpeed -gt 10){$scriptSpeed = 10}
	$excludedPaths += ($xmlContent.Configuration.ExcludedPaths).replace("\","\\") -join "|"
	$dbUpdateSwitch = ($xmlContent.Configuration.DatabaseUpdate)
	$dbFolder = "C:\ProgramData\WolfResponder.db"
	$dateString = Get-Date -Format "HH_mm_dd_MM_yyyy"
	$runtimeLogFolder = [string]($pwd)+"\$($hostname)_runtimeLog_"+$dateString+".txt"
	Set-Content -Path $runtimeLogFolder -Value "$($hostname),"
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
