# 2019 Adrian Rey based on:
# >>> Matthew Fugel (matthewfugel.wordpress.com) and
# >>> Andy Syrewicze (https://www.altaro.com/hyper-v/powershell-script-deploy-vms-configure-guest-os-one-go/) work
# VM auto-deployment script 1.0 - 10/2019

Write-Host "Welcome to the VM auto-deployment script. `n" -ForegroundColor Green

# Switch to choose DC or Client machine
    Write-Host "What would you like to deploy? `n" -ForegroundColor Yellow
    Write-Host "Choose [1] for a Domain Controller" -ForegroundColor Yellow
    Write-Host "Choose [2] for a Client machine `n" -ForegroundColor Yellow
    do { $dccl = Read-Host "Please choose an option"
    } while ($dccl -lt 1 -or $dccl -gt 2)

# If it is a DC set $DC=1. If it is a Client, set $DC=0.
switch ($dccl){
    1 {$dc = 1}
    2 {$dc = 0} }

$workgroup = 0
$pdc = 0

# DC part. Specify if there is a domain or not. If there is, ask for the name. If not, ask for a name to create it.
if ($dc -eq 1 ){

    do {$domain = Read-Host "Is there already a domain in the environment (Y/N)?"
    } while ($domain -ne "y" -and $domain -ne "n")

    # If the domain already exists, ask for the name
    if ($domain -eq "y"){
        $DomainName = Read-Host "What is the domain name?" }

    # If the user wants to create it, ask for a new name
    else {
        $pdc = 1
        $DomainName = Read-Host "Please, enter a domain name to create it"
        Write-Host "This machine will be the first Domain Controller in a new Forest `n" -ForegroundColor Red -BackgroundColor Yellow
        Write-Host "Now, select the desired Domain/Forest functional level"
        Write-Host "Choose [2] for a Windows Server 2003" -ForegroundColor Yellow
        Write-Host "Choose [3] for a Windows Server 2008" -ForegroundColor Yellow
        Write-Host "Choose [4] for a Windows Server 2008 R2" -ForegroundColor Yellow
        Write-Host "Choose [5] for a Windows Server 2012" -ForegroundColor Yellow
        Write-Host "Choose [6] for a Windows Server 2012 R2" -ForegroundColor Yellow
        Write-Host "Choose [7] for a Windows Server 2016 / 2019" -ForegroundColor Yellow
        do {
        $FL = Read-Host "Please choose an option" } while ($FL -lt 2 -or $FL -gt 7)
        Write-Host "`n"
        }

# Client part (not a Domain Controller).
else {

    # Ask if there is a domain in the environment
    do {$domain = Read-Host "Is there a domain in the environment (Y/N)?"
    } while ($domain -ne "y" -and $domain -ne "n")

    # If the domain already exists, ask for the name
    if ($domain -eq "y"){
        $DomainName = Read-Host "What is the domain name?" }

    # If there isn't a domain, then set $WORKGROUP=1 and warm the user that the machine will be on Workgroup
    else {
    $workgroup = 1
    Write-Host "This machine will be part of the default WORKGROUP `n" -ForegroundColor Red -BackgroundColor Yellow } }

# Ask to choose OS version
Write-Host "Please, choose the OS version: `n" -ForegroundColor Yellow

# Switch to set the parent path by the OS version
if ($dc -eq 1){
        Write-Host -NoNewLine "Select [1] for Windows Server 2012 R2  " -ForegroundColor Yellow
        Write-Host "--> NOTE: WS 2012 R2 CAN'T BE AUTO-MANAGED" -ForegroundColor Red -BackgroundColor Yellow
        Write-Host "Select [2] for Windows Server 2016" -ForegroundColor Yellow
        Write-Host "Select [3] for Windows Server 2019" -ForegroundColor Yellow
        do { $version = Read-Host "Please choose an option between 1 and 3"
        } while ($version -lt 1 -or $version -gt 3) }

else{
        Write-Host -NoNewLine "Select [1] for Windows Server 2012 R2  " -ForegroundColor Yellow
        Write-Host "--> NOTE: WS 2012 R2 CAN'T BE AUTO-MANAGED" -ForegroundColor Red -BackgroundColor Yellow
        Write-Host "Select [2] for Windows Server 2016" -ForegroundColor Yellow
        Write-Host "Select [3] for Windows Server 2019" -ForegroundColor Yellow
        Write-Host "Select [4] for Windows 10 - 1809" -ForegroundColor Yellow
        Write-Host "Select [5] for Windows 10 - 1903 `n" -ForegroundColor Yellow
        do { $version = Read-Host "Please choose an option between 1 and 5"
        } while ($version -lt 1 -or $version -gt 5) }

# Unattended parent routes (modify if necessary)
switch ($version) {
1 {$templatePath = "D:\Hyper-V\UNATTENDED\u2012r2.vhdx"
    $OS = "Windows Server 2012 R2"}
2 {$templatePath = "D:\Hyper-V\UNATTENDED\u2016.vhdx"
    $OS = "Windows Server 2016"}
3 {$templatePath = "D:\Hyper-V\UNATTENDED\u2019.vhdx"
    $OS = "Windows Server 2019"}
4 {$templatePath = "D:\Hyper-V\UNATTENDED\u1809.vhdx"
    $OS = "Windows 10 - 1809"}
5 {$templatePath = "D:\Hyper-V\UNATTENDED\u1903.vhdx"
    $OS = "Windows 10 - 1903"} }

# Tell user what option he has chosen
Write-Host "You have chosen" $OS "version for your Virtual Machine `n" -ForegroundColor Green

# Starting to set VM variables
$VMFolderPath = "D:\Hyper-V\Script-Machines" # D:\Hyper-V\Script-Machines by default,
Write-Host "Your VM will be stored in" $VMFolderPath "directory `n" -ForegroundColor Green
#$diffName = "Differencing Disk Initial Deployment" # Checkpoint name (optional)

#Domain tag for folder name
if ($workgroup -ne 1) {
$pos = $DomainName.IndexOf(".")
$DomainTag = ($DomainName.Substring(0, $pos)).ToUpper() }

# Ask for the VM name and check if it exists
do {
  $ComputerName = read-host "Please enter a VM Name to create"
  if ($workgroup -ne 1) {
  $VMName = $DomainTag + "`_" + $ComputerName }
  else { $VMName = $ComputerName }
  $VM = Get-VM -name $VMName -ErrorAction SilentlyContinue
  if($VM -eq $null) { Write-Host "The new Virtual Machine will be named" $VMName -ForegroundColor Green }
  else { Write-Host "THE VIRTUAL MACHINE ALREADY EXISTS" -ForegroundColor Red -BackgroundColor Yellow }
} until ($VM -eq $null)

$IP = read-host "Please enter the VM local IP" # Ask for the IP
$DNS = read-host "Please enter the VM DNS server" # Ask for DNS server
$SubMaskBit = "24" # Set a /24 net

# Ask for a Virtual Switch name and check if it exists
$vSwitch = read-host "Please enter a Virtual Switch Name to create"
$VS = Get-VMSwitch -name $vSwitch -ErrorAction SilentlyContinue
if($VS -eq $null) { Write-Host "Creating new Virtual Switch with name" $vSwitch -ForegroundColor Green
  New-VMSwitch -name $vSwitch -SwitchType Private | Out-Null }
else { Write-Host "THE SWITCH ALREADY EXISTS `n" -ForegroundColor Red -BackgroundColor Yellow }

# For Windows Server, the user is 'Administrator'
if ($version -lt 4){
	$User = "Administrator" }
# For Windows 10, the user is 'User'
else { $User = "User" }

# Setting local credentials for sysprep VM image
$LocalUser = "$ComputerName\$User"
$LocalPWord = ConvertTo-SecureString -String "Pa`$`$w0rd" -AsPlainText -Force
$LocalCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $LocalUser, $LocalPWord

# Domain credentials, used for create a new forest/domain and for join the machine to an existing domain
$DomainUser = "$DomainName\Administrator"
$DomainPWord = ConvertTo-SecureString -String "Pa`$`$w0rd" -AsPlainText -Force
$DomainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $DomainUser, $DomainPWord

Write-Host "`nThe new Virtual Machine will be named" $VMName "and its settings are:" -ForegroundColor Green
Write-Host "Virtual Switch name: " $vSwitch -ForegroundColor Green -BackgroundColor Black
Write-Host "IP: " $IP -ForegroundColor Green -BackgroundColor Black
Write-Host "DNS server: " $DNS -ForegroundColor Green -BackgroundColor Black
if ($workgroup -eq 0) {
Write-Host "Domain name: " $DomainName -ForegroundColor Green -BackgroundColor Black }

#Set the parent VHDX as Read-Only
Set-ItemProperty -Path $templatePath -Name IsReadOnly -Value $true

#Create a folder for the new VM, check if exists.
If (Test-Path ($VMFolderPath + "\" + $VMName)) {
 Write-Host "FOLDER ALREADY EXISTS. EXITING." -ForegroundColor Red -BackgroundColor Yellow
 exit }
If ((Test-Path $templatePath) -eq $false) {
 Write-Host "COULDN'T FIND YOUR TEMPLATE. EXITING." -ForegroundColor Red -BackgroundColor Yellow
 exit }
$path = new-item $VMFolderPath\$VMName -ItemType Directory

#Create the Differencing Disk VHD
$VHD = New-VHD -Path ($path.FullName + "\" + $VMName + ".vhdx") -ParentPath $templatePath -Differencing

#Create the Virtual Machine; point to the Differential VHD
# Sets 4GB of RAM for Windows 10 and 2GB of RAM for all the others
if ($version -gt 3){
    new-vm -Name $VMName -Path $VMFolderPath -VHDPath $VHD.Path -BootDevice VHD -Generation 2 -SwitchName $vSwitch | `
     Set-VMMemory -DynamicMemoryEnabled $true `
     -MaximumBytes 4GB -MinimumBytes 512MB -StartupBytes 2GB}
 else {
    new-vm -Name $VMName -Path $VMFolderPath -VHDPath $VHD.Path -BootDevice VHD -Generation 2 -SwitchName $vSwitch | `
     Set-VMMemory -DynamicMemoryEnabled $true `
     -MaximumBytes 2GB -MinimumBytes 512MB -StartupBytes 1GB}

#Checkpoint the VM in case you want to roll it back to before its initial boot // Uncoment if you want to have the Checkpoint
#Get-VM $VMName -ComputerName localhost | checkpoint-vm -SnapshotName $diffName

#Turn it up
Write-Host "Starting" $VMName "Virtual Machine" -ForegroundColor Green
Start-vm $VMName

# Exit if OS is Windows Server 2012 R2
if ($version -eq 1){
    Write-Host "Windows Server 2012 R2 can't be auto-configured, so my job has finished. Bye!"
    exit}

# If it is another OS, proceed with the configuration
else {
	# After the inital provisioning, we wait until PowerShell Direct is functional and working within the guest VM before moving on.
    # Big thanks to Ben Armstrong for the below useful Wait code
    Write-Verbose “Waiting for PowerShell Direct to start on VM [$VMName]” -Verbose
       while ((icm -VMName $VMName -Credential $LocalCredential {“Test”} -ea SilentlyContinue) -ne “Test”) {Sleep -Seconds 1}

    Write-Verbose "PowerShell Direct responding on VM [$VMName]. Moving On...." -Verbose
    Write-Verbose "Configuring VM [$VMName]..." -Verbose

    # Next we configure the networking for the new VM.
    Invoke-Command -VMName $VMName -Credential $LocalCredential -ScriptBlock {
        param ($VMName, $IP, $SubMaskBit, $DFGW, $DNS, $ComputerName)
        New-NetIPAddress -IPAddress "$IP" -InterfaceAlias "Ethernet" -PrefixLength "$SubMaskBit" | Out-Null
        Set-DnsClientServerAddress -InterfaceAlias “Ethernet” -Addresses $DNS
        $DCEffectiveIP = Get-NetIPAddress -InterfaceAlias "Ethernet" | Select-Object IPAddress
        Write-Verbose "Assigned IPv4 and IPv6 IPs for VM [$VMName] are as follows" -Verbose
        Write-Host $DCEffectiveIP | Format-List
        Write-Verbose "Updating Hostname for VM [$VMName]" -Verbose
        Rename-Computer -NewName $ComputerName
        } -ArgumentList $VMName, $IP, $SubMaskBit, $DFGW, $DNS, $ComputerName

	Write-Verbose "Rebooting VM [$VMName] to apply changes" -Verbose
	Stop-VM -Name $VMName
	Start-VM -Name $VMName

	# After the inital provisioning, we wait until PowerShell Direct is functional and working within the guest VM before moving on.
    # Big thanks to Ben Armstrong for the below useful Wait code
    Write-Verbose “Waiting for PowerShell Direct to start on VM [$VMName]” -Verbose
       while ((icm -VMName $VMName -Credential $LocalCredential {“Test”} -ea SilentlyContinue) -ne “Test”) {Sleep -Seconds 1}

    Write-Verbose "PowerShell Direct responding on VM [$VMName]. Moving On...." -Verbose

#DC configuration in an new forest
if ($pdc -eq 1 -and $version -gt 1 -and $version -lt 4) {

    # Set domain and forest FL if has to, also set the DSRM password for a new forest.
    $DSRMPWord = ConvertTo-SecureString -String "Pa`$`$w0rd" -AsPlainText -Force # DSRM Password for the new forest

    # Next we'll proceed by installing the Active Directory Role and then configuring the machine as a new DC in a new AD Forest
    Invoke-Command -VMName $VMName -Credential $LocalCredential -ScriptBlock {
        param ($VMName, $FL, $DomainName, $DomainTag, $DSRMPWord)
        Write-Verbose "Installing Active Directory Services on VM [$VMName]" -Verbose
        Install-WindowsFeature -Name "AD-Domain-Services" -IncludeManagementTools
        Write-Verbose "Configuring New Domain with Name [$DomainName] on VM [$VMName]" -Verbose
        Install-ADDSForest -ForestMode $FL -DomainMode $FL -DomainName $DomainName -DomainNetbiosName $DomainTag -InstallDns -CreateDnsDelegation:$false -NoDNSonNetwork -SafeModeAdministratorPassword $DSRMPWord -Force -NoRebootOnCompletion
        } -ArgumentList $VMName, $FL, $DomainName, $DomainTag, $DSRMPWord

	Write-Verbose "Rebooting VM [$VMName] to complete installation of the new forest" -Verbose
	Stop-VM -Name $VMName
	Start-VM -Name $VMName
		}

#DC configuration in an existing forest
elseif ($pdc -eq 0 -and $dc -eq 1 -and $version -lt 4) {

    # Next we'll proceed by installing the Active Directory Role and then configuring the machine as a new DC in an existing AD Forest
    Invoke-Command -VMName $VMName -Credential $LocalCredential -ScriptBlock {
        param ($VMName, $DomainCredential, $DomainName, $DSRMPWord)
        Write-Verbose "Installing Active Directory Services on VM [$VMName]" -Verbose
        Install-WindowsFeature -Name "AD-Domain-Services" -IncludeManagementTools
        Write-Verbose "Joining VM [$VMName] to Domain [$DomainName]" -Verbose
        Install-ADDSDomainController -InstallDns -Credential $DomainCredential -DomainName $DomainName -Force -NoRebootOnCompletion -SafeModeAdministratorPassword $DSRMPWord
        } -ArgumentList $VMName, $DomainCredential, $DomainName, $DSRMPWord

	Write-Verbose "Rebooting VM [$VMName] to complete installation of the new DC" -Verbose
	Stop-VM -Name $VMName
	Start-VM -Name $VMName	}

# Client configuration (Domain Join)
elseif ($dc -eq 0 -and $workgroup -eq 0) {

    # Next we'll proceed by joining the client to the domain
    Invoke-Command -VMName $VMName -Credential $LocalCredential -ScriptBlock {
        param ($VMName, $ComputerName, $LocalCredential, $DomainName, $DomainCredential)
        Write-Verbose "Joining VM [$VMName] to Domain [$DomainName]" -Verbose
        Add-Computer -ComputerName $ComputerName -LocalCredential $LocalCredential -DomainName $DomainName -Credential $DomainCredential -Force
        } -ArgumentList $VMName, $ComputerName, $LocalCredential, $DomainName, $DomainCredential

	Write-Verbose "Rebooting VM [$VMName] to complete installation of the new client machine" -Verbose
	Stop-VM -Name $VMName
	Start-VM -Name $VMName	}
}

if ($workgroup -ne 1) {
	Write-Verbose “Waiting for PowerShell Direct to start on VM [$VMName]” -Verbose
	while ((icm -VMName $VMName -Credential $DomainCredential {“Test”} -ea SilentlyContinue) -ne “Test”) {Sleep -Seconds 1}

	Write-Verbose "PowerShell Direct responding on VM [$VMName]. Moving On...." -Verbose
	Write-Verbose "Disabling Firewall and Lockscreen..." -Verbose

  # Disabling all firewall settings.
  # Also disabling lockscreen
  Invoke-Command -VMName $VMName -Credential $DomainCredential -ScriptBlock {
    Set-NetFirewallProfile -Profile * -Enabled False | Out-Null
    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization –Force | Out-Null # This line and the next one disable the lockscreen
    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -PropertyType DWord -Value 1 –Force | Out-Null
	  if ($dc -eq 1) {
	     Set-ADUser -Identity $User -PasswordNeverExpires:$true
	     Set-LocalUser -Name $User -PasswordNeverExpires:$true	}
	  else {
	     $DomainGroup = "Domain Users"
	     $LocalGroup  = "Remote Desktop Users"
	     $Computer    = $env:computername
	     $Domain      = $env:userdomain
	([ADSI]"WinNT://$Computer/$LocalGroup,group").psbase.Invoke("Add",([ADSI]"WinNT://$Domain/$DomainGroup").path)
	Set-LocalUser -Name $using:User -PasswordNeverExpires:$true }
    Write-Verbose "VM deploy completed!!!!" -Verbose } -ArgumentList $VMName, $DomainCredential, $User }

else {

	Write-Verbose “Waiting for PowerShell Direct to start on VM [$VMName]” -Verbose
	while ((icm -VMName $VMName -Credential $LocalCredential {“Test”} -ea SilentlyContinue) -ne “Test”) {Sleep -Seconds 1}

	Write-Verbose "PowerShell Direct responding on VM [$VMName]. Moving On...." -Verbose
	Write-Verbose "Disabling Firewall and Lockscreen..." -Verbose

	Invoke-Command -VMName $VMName -Credential $LocalCredential -ScriptBlock {
    Set-NetFirewallProfile -Profile * -Enabled False | Out-Null
    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization –Force | Out-Null # This line and the next one disable the lockscreen
    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -PropertyType DWord -Value 1 –Force | Out-Null
    Set-LocalUser -Name $using:User -PasswordNeverExpires:$true } -ArgumentList $VMName, $LocalCredential

Write-Verbose "VM deploy completed!!!!" -Verbose }
# End script
