<#
.SYNOPSIS
    CyberPatriot Windows 11 hardening and audit helper (interactive, logged, reversible where possible).

.DESCRIPTION
    Modules: backup, users/groups, password+lockout policy, registry hardening, services,
    Windows features/SMB, firewall, Defender, audit policy, updates, and forensic-style reports.
    Reads authorized-users.txt / authorized-admins.txt / keep-services.txt from the script folder.
    Nothing is deleted without confirmation unless you deliberately choose otherwise.

.PARAMETER Auto
    Non-interactive. Applies hardening with defaults. Never removes users/groups/shares in Auto mode.

.PARAMETER RdpRequired / WebServerRequired / SshRequired / PrintingRequired
    Tell the script the competition README requires that service so it is NOT disabled.

.EXAMPLE
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\CP-Win11-Harden.ps1

.EXAMPLE
    .\CP-Win11-Harden.ps1 -Auto -RdpRequired
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$Auto,
    [switch]$RdpRequired,
    [switch]$WebServerRequired,
    [switch]$SshRequired,
    [switch]$PrintingRequired
)

$ErrorActionPreference = 'Continue'
$Script:Root = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$Script:Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Script:OutDir = Join-Path $Script:Root "CP-Output-$Script:Stamp"
$Script:RepDir = Join-Path $Script:OutDir 'reports'
New-Item -ItemType Directory -Path $Script:RepDir -Force | Out-Null
$Script:LogFile = Join-Path $Script:OutDir 'actions.log'
$Script:Cfg = @{ Rdp = $false; Web = $false; Ssh = $false; Print = $false }

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
function Write-Log {
    param([string]$Msg, [ValidateSet('INFO','OK','WARN','ERR','HEAD')][string]$Level = 'INFO')
    $colors = @{ INFO = 'Gray'; OK = 'Green'; WARN = 'Yellow'; ERR = 'Red'; HEAD = 'Cyan' }
    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Msg
    Write-Host $line -ForegroundColor $colors[$Level]
    Add-Content -Path $Script:LogFile -Value $line
}

function Confirm-Action {
    param([string]$Prompt, [bool]$DefaultYes = $false)
    if ($Auto) { return $DefaultYes }
    $suffix = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
    $a = Read-Host "$Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($a)) { return $DefaultYes }
    return ($a -match '^(y|yes)$')
}

function Set-RegValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        Write-Log "Set $Path\$Name = $Value" OK
    } catch {
        Write-Log "FAILED $Path\$Name : $($_.Exception.Message)" ERR
    }
}

function Read-ListFile {
    param([string]$Name)
    $p = Join-Path $Script:Root $Name
    if (Test-Path $p) {
        Get-Content $p | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') }
    } else { @() }
}

function Initialize-Templates {
    $files = @{
        'authorized-users.txt'  = "# One username per line. Copy from the competition README (ALL authorized users, admins included).`r`n"
        'authorized-admins.txt' = "# One username per line. ONLY users the README says are administrators.`r`n"
        'keep-services.txt'     = "# One SERVICE NAME per line that the README requires. The script will never disable these.`r`n# Example: W3SVC`r`n"
    }
    foreach ($f in $files.Keys) {
        $p = Join-Path $Script:Root $f
        if (-not (Test-Path $p)) { Set-Content -Path $p -Value $files[$f]; Write-Log "Created template $f - fill it in from the README." WARN }
    }
}

function Initialize-Config {
    $Script:Cfg.Rdp   = if ($Auto) { $RdpRequired.IsPresent }       else { Confirm-Action 'Does the README REQUIRE Remote Desktop (RDP)?' $RdpRequired.IsPresent }
    $Script:Cfg.Web   = if ($Auto) { $WebServerRequired.IsPresent } else { Confirm-Action 'Does the README REQUIRE a web/FTP server (IIS)?' $WebServerRequired.IsPresent }
    $Script:Cfg.Ssh   = if ($Auto) { $SshRequired.IsPresent }       else { Confirm-Action 'Does the README REQUIRE OpenSSH server?' $SshRequired.IsPresent }
    $Script:Cfg.Print = if ($Auto) { $PrintingRequired.IsPresent }  else { Confirm-Action 'Does the README REQUIRE printing (Print Spooler)?' $PrintingRequired.IsPresent }
    Write-Log ("Config: RDP={0} Web={1} SSH={2} Print={3}" -f $Script:Cfg.Rdp, $Script:Cfg.Web, $Script:Cfg.Ssh, $Script:Cfg.Print) INFO
}

function ConvertTo-PlainText {
    param([System.Security.SecureString]$Secure)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

# ----------------------------------------------------------------------------
# 1. Backup
# ----------------------------------------------------------------------------
function Invoke-Backup {
    Write-Log '== Backup / restore point ==' HEAD
    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction Stop
        Checkpoint-Computer -Description "CP-Before-Hardening-$Script:Stamp" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        Write-Log 'Restore point created.' OK
    } catch { Write-Log "Restore point not created (rate-limited or disabled): $($_.Exception.Message)" WARN }

    $b = Join-Path $Script:OutDir 'backup'
    New-Item -ItemType Directory -Path $b -Force | Out-Null
    secedit /export /cfg (Join-Path $b 'secpol-before.inf') /quiet | Out-Null
    auditpol /backup /file:(Join-Path $b 'auditpol-before.csv') | Out-Null
    netsh advfirewall export (Join-Path $b 'firewall-before.wfw') | Out-Null
    foreach ($k in 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa','HKLM\SOFTWARE\Policies','HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies','HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer') {
        $n = ($k -replace '[\\:]', '_') + '.reg'
        reg export $k (Join-Path $b $n) /y | Out-Null
    }
    Get-Service | Select-Object Name, DisplayName, Status, StartType | Export-Csv (Join-Path $b 'services-before.csv') -NoTypeInformation
    Get-LocalUser | Select-Object * | Export-Csv (Join-Path $b 'users-before.csv') -NoTypeInformation
    Write-Log "Backups saved to $b" OK
}

# ----------------------------------------------------------------------------
# 2. Users and groups
# ----------------------------------------------------------------------------
function Invoke-UserAudit {
    Write-Log '== Users and groups ==' HEAD
    $authUsers  = Read-ListFile 'authorized-users.txt'
    $authAdmins = Read-ListFile 'authorized-admins.txt'
    $authAll    = @($authUsers) + @($authAdmins) | Sort-Object -Unique
    $builtinSid = @('-500','-501','-503','-504')   # Administrator, Guest, DefaultAccount, WDAGUtility
    $me = $env:USERNAME

    if ($authAll.Count -eq 0) {
        Write-Log 'authorized-users.txt is empty. Listing only; fill it from the README and rerun for removals.' WARN
    }

    $users = Get-LocalUser
    $users | Select-Object Name, Enabled, PasswordRequired, PasswordNeverExpires, LastLogon, SID |
        Format-Table -AutoSize | Out-String | Tee-Object -FilePath (Join-Path $Script:RepDir 'users.txt') | Write-Host

    # Built-in Guest and Administrator
    foreach ($u in $users) {
        $sid = $u.SID.Value
        if ($sid -like '*-501' -and $u.Enabled) { Disable-LocalUser -SID $u.SID; Write-Log "Disabled built-in Guest ($($u.Name))" OK }
        if ($sid -like '*-500' -and $u.Enabled -and $u.Name -ne $me) {
            if (Confirm-Action "Disable built-in Administrator '$($u.Name)'?" $true) { Disable-LocalUser -SID $u.SID; Write-Log 'Disabled built-in Administrator' OK }
        }
    }

    # Unauthorized users
    foreach ($u in $users) {
        $isBuiltin = $builtinSid | Where-Object { $u.SID.Value -like "*$_" }
        if ($isBuiltin) { continue }
        if ($authAll.Count -gt 0 -and ($authAll -notcontains $u.Name)) {
            Write-Log "UNAUTHORIZED user: $($u.Name) (Enabled=$($u.Enabled))" WARN
            if ($u.Name -eq $me) { Write-Log 'That is the account running this script - skipping.' WARN; continue }
            if (Confirm-Action "  Remove user '$($u.Name)'?") {
                try { Remove-LocalUser -SID $u.SID -ErrorAction Stop; Write-Log "Removed $($u.Name)" OK } catch { Write-Log $_.Exception.Message ERR }
            } elseif ($u.Enabled -and (Confirm-Action "  Disable '$($u.Name)' instead?")) {
                Disable-LocalUser -SID $u.SID; Write-Log "Disabled $($u.Name)" OK
            }
        }
    }

    # Authorized users that don't exist
    foreach ($a in $authAll) {
        if (-not (Get-LocalUser -Name $a -ErrorAction SilentlyContinue)) {
            Write-Log "Authorized user '$a' does NOT exist (README may ask you to create them)." WARN
            if (Confirm-Action "  Create local user '$a' now?") {
                $pw = Read-Host "  Password for $a" -AsSecureString
                try { New-LocalUser -Name $a -Password $pw -PasswordNeverExpires:$false | Out-Null; Add-LocalGroupMember -Group 'Users' -Member $a; Write-Log "Created $a" OK } catch { Write-Log $_.Exception.Message ERR }
            }
        }
    }

    # Administrators group
    $adm = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
    foreach ($m in $adm) {
        $short = ($m.Name -split '\\')[-1]
        $local = Get-LocalUser -Name $short -ErrorAction SilentlyContinue
        if ($local -and $local.SID.Value -like '*-500') { continue }
        if ($authAdmins.Count -gt 0 -and ($authAdmins -notcontains $short)) {
            Write-Log "NOT an authorized admin: $($m.Name) [$($m.ObjectClass)]" WARN
            if ($short -eq $me) { Write-Log '  (current user) - skipping to avoid locking yourself out.' WARN; continue }
            if (Confirm-Action "  Remove '$($m.Name)' from Administrators?") {
                try { Remove-LocalGroupMember -Group 'Administrators' -Member $m.Name -ErrorAction Stop; Write-Log "Removed $($m.Name) from Administrators" OK } catch { Write-Log $_.Exception.Message ERR }
            }
        }
    }
    foreach ($a in $authAdmins) {
        $isMember = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Where-Object { ($_.Name -split '\\')[-1] -eq $a }
        if (-not $isMember -and (Get-LocalUser -Name $a -ErrorAction SilentlyContinue)) {
            if (Confirm-Action "Authorized admin '$a' is not in Administrators. Add them?") { Add-LocalGroupMember -Group 'Administrators' -Member $a; Write-Log "Added $a to Administrators" OK }
        }
    }

    # Other sensitive groups
    foreach ($g in 'Remote Desktop Users','Remote Management Users','Backup Operators','Power Users','Network Configuration Operators','Replicator','Distributed COM Users') {
        $members = Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue
        foreach ($m in $members) {
            Write-Log "Group '$g' contains: $($m.Name)" WARN
            if ($g -eq 'Remote Desktop Users' -and $Script:Cfg.Rdp -and ($authAll -contains ($m.Name -split '\\')[-1])) { continue }
            if (Confirm-Action "  Remove '$($m.Name)' from '$g'?") {
                try { Remove-LocalGroupMember -Group $g -Member $m.Name -ErrorAction Stop; Write-Log "Removed from $g" OK } catch { Write-Log $_.Exception.Message ERR }
            }
        }
    }

    # Account property fixes
    foreach ($u in (Get-LocalUser | Where-Object { $_.Enabled })) {
        if (-not $u.PasswordRequired) {
            Write-Log "$($u.Name): password NOT required" WARN
            net user $u.Name /passwordreq:yes | Out-Null
        }
        if ($u.PasswordNeverExpires -and $u.SID.Value -notlike '*-500') {
            Set-LocalUser -SID $u.SID -PasswordNeverExpires $false
            Write-Log "$($u.Name): cleared 'password never expires'" OK
        }
    }

    # Bulk password reset
    if ($authAll.Count -gt 0 -and (Confirm-Action 'Set a new strong password on all authorized accounts (except you)?')) {
        $p1 = Read-Host 'Enter new password (12+ chars, upper/lower/digit/symbol)' -AsSecureString
        $p2 = Read-Host 'Confirm password' -AsSecureString
        if ((ConvertTo-PlainText $p1) -ceq (ConvertTo-PlainText $p2)) {
            foreach ($a in $authAll) {
                if ($a -eq $me) { Write-Log "Skipping current user $a (change manually: Ctrl+Alt+Del)." WARN; continue }
                try { Set-LocalUser -Name $a -Password $p1 -ErrorAction Stop; Write-Log "Password set for $a" OK } catch { Write-Log "$a : $($_.Exception.Message)" ERR }
            }
        } else { Write-Log 'Passwords did not match. Skipped.' ERR }
    }
}

# ----------------------------------------------------------------------------
# 3. Password / lockout / local security policy
# ----------------------------------------------------------------------------
function Invoke-PasswordPolicy {
    Write-Log '== Password, lockout and local security policy ==' HEAD
    net accounts /minpwlen:12 /maxpwage:60 /minpwage:1 /uniquepw:24 /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 | Out-Null
    Write-Log 'net accounts: len 12, max age 60, min age 1, history 24, lockout 5/30/30' OK

    $remoteInteractive = if ($Script:Cfg.Rdp) { "SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555" } else { "SeRemoteInteractiveLogonRight = *S-1-5-32-544" }
    $inf = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 60
MinimumPasswordLength = 12
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
ClearTextPassword = 0
EnableGuestAccount = 0
LSAAnonymousNameLookup = 0
[Privilege Rights]
SeDenyNetworkLogonRight = *S-1-5-32-546
SeDenyInteractiveLogonRight = *S-1-5-32-546
SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546
SeDebugPrivilege = *S-1-5-32-544
SeRemoteShutdownPrivilege = *S-1-5-32-544
SeTakeOwnershipPrivilege = *S-1-5-32-544
SeCreateTokenPrivilege =
$remoteInteractive
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
    $infPath = Join-Path $Script:OutDir 'cp-secpol.inf'
    Set-Content -Path $infPath -Value $inf -Encoding Unicode
    secedit /configure /db (Join-Path $Script:OutDir 'cp.sdb') /cfg $infPath /areas SECURITYPOLICY USER_RIGHTS /quiet
    Write-Log "secedit applied (exit $LASTEXITCODE). Details: %windir%\security\logs\scesrv.log" OK
}

# ----------------------------------------------------------------------------
# 4. Registry hardening
# ----------------------------------------------------------------------------
function Invoke-RegistryHardening {
    Write-Log '== Registry hardening ==' HEAD
    $SYS  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $LSA  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $SRV  = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $WKS  = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    $NLG  = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    $TCP  = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    $EXP  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $WLG  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $POL  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
    $WRM  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM'

    $reg = @(
        # --- UAC / logon screen ---
        @($SYS,'EnableLUA',1), @($SYS,'ConsentPromptBehaviorAdmin',2), @($SYS,'ConsentPromptBehaviorUser',0),
        @($SYS,'PromptOnSecureDesktop',1), @($SYS,'EnableInstallerDetection',1), @($SYS,'EnableSecureUIAPaths',1),
        @($SYS,'EnableVirtualization',1), @($SYS,'FilterAdministratorToken',1), @($SYS,'LocalAccountTokenFilterPolicy',0),
        @($SYS,'DontDisplayLastUserName',1), @($SYS,'DontDisplayLockedUserId',3), @($SYS,'DisableCAD',0),
        @($SYS,'ShutdownWithoutLogon',0), @($SYS,'InactivityTimeoutSecs',900),
        @($SYS,'legalnoticecaption','Authorized Use Only','String'),
        @($SYS,'legalnoticetext','This system is for authorized users only. Activity may be monitored.','String'),
        @("$POL\System",'EnumerateLocalUsers',0), @("$POL\System",'EnableSmartScreen',1),
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI','EnumerateAdministrators',0),
        # --- Winlogon ---
        @($WLG,'AutoAdminLogon','0','String'), @($WLG,'CachedLogonsCount','4','String'),
        @($WLG,'ScreenSaverGracePeriod','0','String'),
        # --- LSA / credentials / NTLM ---
        @($LSA,'RestrictAnonymous',1), @($LSA,'RestrictAnonymousSAM',1), @($LSA,'EveryoneIncludesAnonymous',0),
        @($LSA,'LmCompatibilityLevel',5), @($LSA,'NoLMHash',1), @($LSA,'RunAsPPL',1),
        @($LSA,'LimitBlankPasswordUse',1), @($LSA,'DisableDomainCreds',1), @($LSA,'ForceGuest',0),
        @($LSA,'SCENoApplyLegacyAuditPolicy',1),
        @("$LSA\MSV1_0",'NTLMMinClientSec',537395200), @("$LSA\MSV1_0",'NTLMMinServerSec',537395200),
        @("$LSA\MSV1_0",'allownullsessionfallback',0),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest','UseLogonCredential',0),
        # --- SMB / netlogon ---
        @($SRV,'SMB1',0), @($SRV,'RestrictNullSessAccess',1), @($SRV,'RequireSecuritySignature',1),
        @($SRV,'EnableSecuritySignature',1), @($SRV,'AutoDisconnect',15),
        @($WKS,'RequireSecuritySignature',1), @($WKS,'EnableSecuritySignature',1), @($WKS,'EnablePlainTextPassword',0),
        @('HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10','Start',4),
        @($NLG,'RequireSignOrSeal',1), @($NLG,'SealSecureChannel',1), @($NLG,'SignSecureChannel',1),
        @($NLG,'DisablePasswordChange',0), @($NLG,'MaximumPasswordAge',30), @($NLG,'RequireStrongKey',1),
        # --- Network stack ---
        @($TCP,'DisableIPSourceRouting',2), @($TCP,'EnableICMPRedirect',0), @($TCP,'EnableDeadGWDetect',0),
        @($TCP,'PerformRouterDiscovery',0), @($TCP,'SynAttackProtect',1), @($TCP,'TcpMaxDataRetransmissions',3),
        @('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters','DisableIPSourceRouting',2),
        @('HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters','NoNameReleaseOnDemand',1),
        @("$POL NT\DNSClient",'EnableMulticast',0),            # LLMNR off
        # --- Autoplay / explorer ---
        @($EXP,'NoDriveTypeAutoRun',255), @($EXP,'NoAutorun',1),
        @("$POL\Explorer",'NoAutoplayfornonVolume',1),
        # --- Remote assistance / RDP policy ---
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance','fAllowToGetHelp',0),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance','fAllowFullControl',0),
        @("HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",'fAllowToGetHelp',0),
        @("HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",'fAllowUnsolicited',0),
        # --- Installer / kernel / DLL search ---
        @("$POL\Installer",'AlwaysInstallElevated',0), @('HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer','AlwaysInstallElevated',0),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager','ProtectionMode',1),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager','SafeDllSearchMode',1),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel','DisableExceptionChainValidation',0),
        # --- Printing (PrintNightmare family) ---
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint','RestrictDriverInstallationToAdministrators',1),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint','NoWarningNoElevationOnInstall',0),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers','RegisterSpoolerRemoteRpcEndPoint',2),
        # --- PowerShell / WinRM ---
        @("$POL\PowerShell\ScriptBlockLogging",'EnableScriptBlockLogging',1),
        @("$WRM\Client",'AllowBasic',0), @("$WRM\Client",'AllowUnencryptedTraffic',0), @("$WRM\Client",'AllowDigest',0),
        @("$WRM\Service",'AllowBasic',0), @("$WRM\Service",'AllowUnencryptedTraffic',0), @("$WRM\Service",'DisableRunAs',1),
        # --- Windows Update ---
        @("$POL\WindowsUpdate\AU",'NoAutoUpdate',0), @("$POL\WindowsUpdate\AU",'AUOptions',4),
        @("$POL\WindowsUpdate",'DisableWindowsUpdateAccess',0),
        # --- Edge ---
        @('HKLM:\SOFTWARE\Policies\Microsoft\Edge','SmartScreenEnabled',1),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Edge','PreventSmartScreenPromptOverride',1),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Edge','SSLErrorOverrideAllowed',0),
        # --- Current user (the account running the script) ---
        @('HKCU:\Control Panel\Desktop','ScreenSaveActive','1','String'),
        @('HKCU:\Control Panel\Desktop','ScreenSaverIsSecure','1','String'),
        @('HKCU:\Control Panel\Desktop','ScreenSaveTimeOut','600','String'),
        @('HKCU:\Control Panel\Desktop','SCRNSAVE.EXE','C:\Windows\System32\scrnsave.scr','String'),
        @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced','Hidden',1),
        @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced','HideFileExt',0),
        @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced','ShowSuperHidden',1)
    )

    # RDP: lock down or disable
    $ts  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdp = "$ts\WinStations\RDP-Tcp"
    if ($Script:Cfg.Rdp) {
        $reg += ,@($ts,'fDenyTSConnections',0)
        $reg += ,@($rdp,'UserAuthentication',1)
        $reg += ,@($rdp,'SecurityLayer',2)
        $reg += ,@($rdp,'MinEncryptionLevel',3)
        $reg += ,@('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','fEncryptRPCTraffic',1)
        Write-Log 'RDP required: enabled with NLA + high encryption.' INFO
    } else {
        $reg += ,@($ts,'fDenyTSConnections',1)
        Write-Log 'RDP not required: disabled.' INFO
    }

    foreach ($r in $reg) {
        if ($r.Count -ge 4) { Set-RegValue -Path $r[0] -Name $r[1] -Value $r[2] -Type $r[3] }
        else                { Set-RegValue -Path $r[0] -Name $r[1] -Value $r[2] }
    }

    # Remove stored autologon password
    Remove-ItemProperty -Path $WLG -Name 'DefaultPassword' -ErrorAction SilentlyContinue
    # Disable NetBIOS over TCP/IP on every interface
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue | ForEach-Object {
        Set-ItemProperty -Path $_.PSPath -Name 'NetbiosOptions' -Value 2 -ErrorAction SilentlyContinue
    }
    Write-Log 'NetBIOS over TCP/IP disabled on all interfaces.' OK
    # DEP always on
    bcdedit /set nx AlwaysOn | Out-Null
    Write-Log 'DEP set to AlwaysOn (reboot required).' OK
}

# ----------------------------------------------------------------------------
# 5. Services
# ----------------------------------------------------------------------------
function Invoke-Services {
    Write-Log '== Services ==' HEAD
    $keep = Read-ListFile 'keep-services.txt'
    $disable = @('RemoteRegistry','TlntSvr','SNMP','SNMPTRAP','SSDPSRV','upnphost','Fax','simptcp','SharedAccess','RemoteAccess',
                 'lltdsvc','icssvc','NetTcpPortSharing','p2psvc','p2pimsvc','PNRPsvc','PNRPAutoReg','XblAuthManager','XblGameSave',
                 'XboxNetApiSvc','XboxGipSvc','WMPNetworkSvc','MSiSCSI','RpcLocator','Browser','irmon','HomeGroupListener','HomeGroupProvider')
    if (-not $Script:Cfg.Rdp)   { $disable += 'TermService','UmRdpService','SessionEnv' }
    if (-not $Script:Cfg.Web)   { $disable += 'W3SVC','WAS','FTPSVC','IISADMIN','MSFTPSVC' }
    if (-not $Script:Cfg.Ssh)   { $disable += 'sshd','ssh-agent' }
    if (-not $Script:Cfg.Print) { $disable += 'Spooler' }

    foreach ($name in ($disable | Sort-Object -Unique)) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        if ($keep -contains $name) { Write-Log "Keeping $name (listed in keep-services.txt)" INFO; continue }
        try {
            if ($svc.Status -eq 'Running') { Stop-Service -Name $name -Force -ErrorAction Stop }
            Set-Service -Name $name -StartupType Disabled -ErrorAction Stop
            Write-Log "Disabled service $name ($($svc.DisplayName))" OK
        } catch { Write-Log "Could not disable $name : $($_.Exception.Message)" ERR }
    }

    if ((Get-Service WinRM -ErrorAction SilentlyContinue) -and ($keep -notcontains 'WinRM') -and (Confirm-Action 'Disable WinRM (PowerShell remoting)?' $true)) {
        Stop-Service WinRM -Force -ErrorAction SilentlyContinue; Set-Service WinRM -StartupType Disabled
        Write-Log 'Disabled WinRM' OK
    }

    # Make sure security services are on
    foreach ($name in 'mpssvc','EventLog','WinDefend','SecurityHealthService') {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc) {
            try { Set-Service -Name $name -StartupType Automatic -ErrorAction Stop } catch {}
            if ($svc.Status -ne 'Running') { Start-Service -Name $name -ErrorAction SilentlyContinue }
            Write-Log "Ensured $name is Automatic/Running" OK
        }
    }
    $wu = Get-Service wuauserv -ErrorAction SilentlyContinue
    if ($wu) { Set-Service wuauserv -StartupType Manual; Start-Service wuauserv -ErrorAction SilentlyContinue }
}

# ----------------------------------------------------------------------------
# 6. Windows features, SMB, shares, hosts file
# ----------------------------------------------------------------------------
function Invoke-FeaturesAndNetwork {
    Write-Log '== Windows features / SMB / shares ==' HEAD
    $features = @('SMB1Protocol','SMB1Protocol-Client','SMB1Protocol-Server','TelnetClient','TelnetServer','TFTP',
                  'MicrosoftWindowsPowerShellV2Root','MicrosoftWindowsPowerShellV2','SimpleTCP','WCF-TCP-PortSharing45')
    if (-not $Script:Cfg.Web) { $features += 'IIS-WebServerRole','IIS-FTPServer','IIS-WebServer' }
    foreach ($f in $features) {
        $state = Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction SilentlyContinue
        if ($state -and $state.State -eq 'Enabled') {
            try { Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction Stop | Out-Null; Write-Log "Disabled feature $f" OK }
            catch { Write-Log "Feature $f : $($_.Exception.Message)" ERR }
        }
    }
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -EnableSecuritySignature $true -RestrictNullSessAccess $true -Force -ErrorAction Stop
        Write-Log 'SMBv1 off, SMB signing required, null sessions restricted.' OK
    } catch { Write-Log "SMB config: $($_.Exception.Message)" ERR }

    # Shares
    Get-SmbShare | Select-Object Name, Path, Description, Special | Format-Table -AutoSize | Out-String |
        Tee-Object -FilePath (Join-Path $Script:RepDir 'shares.txt') | Write-Host
    foreach ($s in (Get-SmbShare | Where-Object { -not $_.Special })) {
        Write-Log "Non-default share: $($s.Name) -> $($s.Path)" WARN
        if (Confirm-Action "  Remove share '$($s.Name)'?") { Remove-SmbShare -Name $s.Name -Force; Write-Log "Removed share $($s.Name)" OK }
    }

    # Hosts file
    $hosts = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') }
    if ($hosts) {
        Write-Log 'Hosts file has active entries (check for malicious redirects):' WARN
        $hosts | ForEach-Object { Write-Log "  $_" WARN }
        if (Confirm-Action 'Reset hosts file to default (backup saved)?') {
            Copy-Item "$env:SystemRoot\System32\drivers\etc\hosts" (Join-Path $Script:OutDir 'hosts.bak') -Force
            Set-Content "$env:SystemRoot\System32\drivers\etc\hosts" "# Reset by CP-Win11-Harden`r`n127.0.0.1 localhost`r`n::1 localhost" -Encoding ASCII
            Write-Log 'Hosts file reset.' OK
        }
    }
}

# ----------------------------------------------------------------------------
# 7. Firewall
# ----------------------------------------------------------------------------
function Invoke-Firewall {
    Write-Log '== Windows Firewall ==' HEAD
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow `
        -NotifyOnListen True -AllowInboundRules True -LogAllowed False -LogBlocked True -LogMaxSizeKilobytes 16384 `
        -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
    Write-Log 'Firewall enabled on all profiles, inbound default = Block, blocked-packet logging on.' OK

    $groups = @('Remote Assistance','Windows Remote Management','Remote Service Management','Remote Event Log Management',
                'Remote Scheduled Tasks Management','Remote Volume Management','Remote Administration','Network Discovery',
                'Windows Management Instrumentation (WMI)','Windows Media Player Network Sharing Service','Wireless Portable Devices')
    if (-not $Script:Cfg.Rdp) { $groups += 'Remote Desktop' }
    foreach ($g in $groups) {
        $rules = Get-NetFirewallRule -DisplayGroup $g -ErrorAction SilentlyContinue
        if ($rules) { $rules | Disable-NetFirewallRule; Write-Log "Disabled firewall rule group: $g" OK }
    }

    $ports = @(
        @{ N = 'CP Block Telnet';  P = 'TCP'; L = '23' },
        @{ N = 'CP Block TFTP';    P = 'UDP'; L = '69' },
        @{ N = 'CP Block SNMP';    P = 'UDP'; L = '161,162' },
        @{ N = 'CP Block SSDP';    P = 'UDP'; L = '1900' }
    )
    if (-not $Script:Cfg.Rdp) { $ports += @{ N = 'CP Block RDP'; P = 'TCP'; L = '3389' } }
    foreach ($p in $ports) {
        if (-not (Get-NetFirewallRule -DisplayName $p.N -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $p.N -Direction Inbound -Action Block -Protocol $p.P -LocalPort ($p.L -split ',') -Profile Any | Out-Null
            Write-Log "Created block rule: $($p.N)" OK
        }
    }
}

# ----------------------------------------------------------------------------
# 8. Microsoft Defender
# ----------------------------------------------------------------------------
function Invoke-Defender {
    Write-Log '== Microsoft Defender ==' HEAD
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false `
            -DisableScriptScanning $false -DisableArchiveScanning $false -DisableEmailScanning $false `
            -DisableRemovableDriveScanning $false -DisableBlockAtFirstSeen $false -MAPSReporting Advanced `
            -SubmitSamplesConsent SendSafeSamples -PUAProtection Enabled -CloudBlockLevel High -CloudExtendedTimeout 50 `
            -EnableNetworkProtection Enabled -ErrorAction Stop
        Write-Log 'Defender preferences hardened.' OK
    } catch { Write-Log "Set-MpPreference: $($_.Exception.Message) (Tamper Protection or 3rd-party AV can block this)" ERR }

    $asr = @('BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550','D4F940AB-401B-4EFC-AADC-AD5F3C50688A','3B576869-A4EC-4529-8536-B80A7769E899',
             '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84','D3E037E1-3EB8-44C8-A917-57927947596D','5BEB7EFE-FD9A-4556-801D-275E5FFC04CC',
             '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B','C1DB55AB-C21A-4637-BB3F-A12568109D35','9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2',
             'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4')
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $asr -AttackSurfaceReductionRules_Actions ($asr | ForEach-Object { 'Enabled' }) -ErrorAction Stop
        Write-Log 'Attack Surface Reduction rules enabled.' OK
    } catch { Write-Log "ASR rules: $($_.Exception.Message)" ERR }

    try { Update-MpSignature -ErrorAction Stop; Write-Log 'Signatures updated.' OK } catch { Write-Log "Signature update failed (offline?): $($_.Exception.Message)" WARN }
    if (Confirm-Action 'Start a Defender quick scan in the background?' $true) {
        Start-Job -ScriptBlock { Start-MpScan -ScanType QuickScan } | Out-Null
        Write-Log 'Quick scan started (check Windows Security for results).' OK
    }
}

# ----------------------------------------------------------------------------
# 9. Audit policy
# ----------------------------------------------------------------------------
function Invoke-AuditPolicy {
    Write-Log '== Audit policy ==' HEAD
    auditpol /set /category:* /success:enable /failure:enable | Out-Null
    Write-Log 'All audit categories: success and failure enabled.' OK
    wevtutil sl Security /ms:209715200 | Out-Null
    wevtutil sl Application /ms:67108864 | Out-Null
    wevtutil sl System /ms:67108864 | Out-Null
    Write-Log 'Event log sizes increased (Security 200MB).' OK
}

# ----------------------------------------------------------------------------
# 10. Windows Update
# ----------------------------------------------------------------------------
function Invoke-Updates {
    Write-Log '== Windows Update ==' HEAD
    Set-Service wuauserv -StartupType Manual -ErrorAction SilentlyContinue
    Start-Service wuauserv -ErrorAction SilentlyContinue
    Start-Process -FilePath "$env:SystemRoot\System32\UsoClient.exe" -ArgumentList 'StartScan' -WindowStyle Hidden -ErrorAction SilentlyContinue
    Write-Log 'Update scan triggered. Verify and install in Settings > Windows Update.' OK
    if (Confirm-Action 'Open Windows Update settings now?' $true) { Start-Process 'ms-settings:windowsupdate' }
}

# ----------------------------------------------------------------------------
# 11. Reports (what to hunt manually)
# ----------------------------------------------------------------------------
function Invoke-Reports {
    Write-Log '== Generating reports ==' HEAD
    $r = $Script:RepDir

    Get-LocalGroup | ForEach-Object {
        $g = $_.Name
        Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Group = $g; Member = $_.Name; Type = $_.ObjectClass } }
    } | Export-Csv "$r\group-members.csv" -NoTypeInformation

    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [pscustomobject]@{ Local = "$($_.LocalAddress):$($_.LocalPort)"; PID = $_.OwningProcess; Process = $p.ProcessName; Path = $p.Path }
    } | Sort-Object Local | Export-Csv "$r\listening-ports.csv" -NoTypeInformation

    Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine | Export-Csv "$r\processes.csv" -NoTypeInformation

    Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' } |
        Select-Object Name, DisplayName, StartMode, PathName, StartName | Export-Csv "$r\running-services.csv" -NoTypeInformation

    Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
        [pscustomobject]@{ Task = $_.TaskName; Path = $_.TaskPath; State = $_.State; Run = (($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; ') }
    } | Export-Csv "$r\scheduled-tasks-nonMS.csv" -NoTypeInformation

    $runKeys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
               'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
               'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    $runKeys | ForEach-Object { if (Test-Path $_) { Get-ItemProperty $_ | Out-String } } | Out-File "$r\startup-registry.txt"
    Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup","$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue |
        Select-Object FullName, LastWriteTime | Out-File "$r\startup-folders.txt"

    $uninst = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    $apps = Get-ItemProperty $uninst -ErrorAction SilentlyContinue | Where-Object DisplayName |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName
    $apps | Export-Csv "$r\installed-programs.csv" -NoTypeInformation
    $bad = 'nmap|zenmap|wireshark|john|hashcat|hydra|cain|netcat|ncat|metasploit|keylog|ophcrack|aircrack|angry ip|crack|torrent|utorrent|bittorrent|limewire|tor browser|vuze|emule|frostwire|kali|burp|sqlmap|nikto|ettercap|responder|mimikatz|tightvnc|teamviewer|anydesk|logmein|vnc'
    $hits = $apps | Where-Object { $_.DisplayName -match $bad }
    $hits | Export-Csv "$r\SUSPECT-programs.csv" -NoTypeInformation
    if ($hits) { Write-Log "Possible prohibited software ($(@($hits).Count)) - see SUSPECT-programs.csv (CHECK README before removing)" WARN }

    Write-Log 'Searching user profiles for media / suspicious files (can take a minute)...' INFO
    $media = '*.mp3','*.mp4','*.wav','*.flac','*.avi','*.mkv','*.mov','*.m4a','*.wma','*.ogg','*.wmv','*.mpg','*.mpeg','*.aac'
    Get-ChildItem -Path 'C:\Users' -Recurse -File -Include $media -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\AppData\\' } | Select-Object FullName, Length, LastWriteTime | Export-Csv "$r\media-files.csv" -NoTypeInformation
    $susp = '*.torrent','*.vbs','*.bat','*.cmd','*.ps1','*.reg','*.hta','*.scr','*.pif','*password*.*','*passwd*.*','*creds*.*','*.pst','*.kdbx'
    Get-ChildItem -Path 'C:\Users','C:\' -Recurse -File -Include $susp -Depth 4 -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\(Windows|Program Files|Program Files \(x86\)|AppData|\$Recycle\.Bin|CP-Output)' } |
        Select-Object FullName, Length, LastWriteTime | Export-Csv "$r\suspicious-files.csv" -NoTypeInformation

    Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue |
        Select-Object DisplayName, Profile, DisplayGroup | Export-Csv "$r\firewall-inbound-allow.csv" -NoTypeInformation

    Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID, Description, InstalledOn | Export-Csv "$r\hotfixes.csv" -NoTypeInformation
    Get-MpComputerStatus -ErrorAction SilentlyContinue | Out-File "$r\defender-status.txt"
    auditpol /get /category:* | Out-File "$r\auditpol-after.txt"
    Write-Log "Reports written to $r" OK
}

# ----------------------------------------------------------------------------
# Manual checklist
# ----------------------------------------------------------------------------
function Show-ManualChecklist {
    Write-Log '== Still on YOU (the script cannot judge these) ==' HEAD
    @(
        'Read the competition README again and answer every Forensics Question first.',
        'Review reports\ folder: SUSPECT-programs.csv, media-files.csv, suspicious-files.csv, scheduled-tasks-nonMS.csv, listening-ports.csv.',
        'Update required applications (browser, Office, 7-zip, etc.) - uninstall prohibited ones only if the README allows.',
        'Browser settings: pop-up blocker, SmartScreen, no saved passwords, remove bad extensions, homepage.',
        'Check file/folder permissions and shared folders for sensitive files; look for credentials left in plain text.',
        'Service-specific config (IIS, FTP, SSH, SQL, etc.) per the README.',
        'Windows Features list (optionalfeatures.exe) and Apps & features for anything odd.',
        'Verify required services still work (the README is the source of truth) then REBOOT.'
    ) | ForEach-Object { Write-Log "[ ] $_" INFO }
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
function Invoke-FullRun {
    Invoke-Backup
    Invoke-UserAudit
    if (Confirm-Action 'Apply password/lockout/local security policy?' $true) { Invoke-PasswordPolicy }
    if (Confirm-Action 'Apply registry hardening?' $true)                    { Invoke-RegistryHardening }
    if (Confirm-Action 'Disable unneeded services?' $true)                   { Invoke-Services }
    if (Confirm-Action 'Disable risky features / SMB1 / check shares?' $true){ Invoke-FeaturesAndNetwork }
    if (Confirm-Action 'Configure firewall?' $true)                          { Invoke-Firewall }
    if (Confirm-Action 'Harden Defender?' $true)                             { Invoke-Defender }
    if (Confirm-Action 'Enable full auditing?' $true)                        { Invoke-AuditPolicy }
    if (Confirm-Action 'Trigger Windows Update?' $true)                      { Invoke-Updates }
    if (Confirm-Action 'Generate reports?' $true)                            { Invoke-Reports }
    Show-ManualChecklist
}

function Show-Menu {
    Write-Host ''
    Write-Host '  CyberPatriot Windows 11 Hardening Helper' -ForegroundColor Cyan
    Write-Host '  ----------------------------------------'
    Write-Host '  1  Full run (guided, recommended)'
    Write-Host '  2  Backup only'
    Write-Host '  3  Users and groups'
    Write-Host '  4  Password / lockout / local policy'
    Write-Host '  5  Registry hardening'
    Write-Host '  6  Services'
    Write-Host '  7  Features, SMB, shares, hosts file'
    Write-Host '  8  Firewall'
    Write-Host '  9  Defender'
    Write-Host '  10 Audit policy'
    Write-Host '  11 Windows Update'
    Write-Host '  12 Reports (hunt list)'
    Write-Host '  13 Manual checklist'
    Write-Host '  0  Exit'
}

Write-Log "CP-Win11-Harden started. Output: $Script:OutDir" HEAD
if ((Get-CimInstance Win32_OperatingSystem).Caption -notmatch 'Windows 11') {
    Write-Log 'Warning: this does not look like Windows 11. Most steps still work on Windows 10.' WARN
}
Initialize-Templates
Initialize-Config

if ($Auto) {
    Invoke-FullRun
} else {
    $exit = $false
    while (-not $exit) {
        Show-Menu
        switch (Read-Host '  Choose') {
            '1'  { Invoke-FullRun }
            '2'  { Invoke-Backup }
            '3'  { Invoke-UserAudit }
            '4'  { Invoke-PasswordPolicy }
            '5'  { Invoke-RegistryHardening }
            '6'  { Invoke-Services }
            '7'  { Invoke-FeaturesAndNetwork }
            '8'  { Invoke-Firewall }
            '9'  { Invoke-Defender }
            '10' { Invoke-AuditPolicy }
            '11' { Invoke-Updates }
            '12' { Invoke-Reports }
            '13' { Show-ManualChecklist }
            '0'  { $exit = $true }
            default { Write-Host 'Invalid choice.' -ForegroundColor Yellow }
        }
    }
}

Write-Log "Done. Log: $Script:LogFile  -  REBOOT to finish applying changes." HEAD
