<# 

usage:

Set-ExecutionPolicy Unrestricted
Copy-Item //tsclient/rackmount-ssl-enable/ssl-enable.ps1 .; ./ssl-enable.ps1

# disable fbwfmgr and reboot immediately
powershell.exe -executionpolicy bypass -noninteractive -noprofile -noninteractive -command "& $([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/TaylorMonacelli/rackmount-ssl-enable/master/ssl-enable.ps1'))) -reboot"

# dont disable/reboot, prompt to do so
powershell.exe -executionpolicy bypass -noninteractive -noprofile -noninteractive -command "& $([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/TaylorMonacelli/rackmount-ssl-enable/master/ssl-enable.ps1')))"

#>



[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)] [switch]$reboot = $false
)

$computername=$env:COMPUTERNAME

if(!(test-path ${env:SYSTEMDRIVE}/Apache/bin/openssl.exe)){
	Write-Error "Can't find c:/Apache/bin/openssl.exe, quitting prematurely"
	Exit 1
}

$res = Get-Command -ErrorAction SilentlyContinue ${env:SYSTEMDRIVE}/windows/system32/fbwfMgr.exe
if($?) {
	<# this machine has fbwfmgr onit #>
	$res1 = & ${env:SYSTEMDRIVE}/windows/system32/fbwfMgr.exe
	if($res1 | Select-String 'filter state:' | Select-Object -First 1 | Out-String |
	  Where-Object {$_ -like '*enabled*'}) {
		  if($reboot) {
			  Write-Warning "Turning off FBWF Write protect and rebooting immediately"
			  & ${env:SYSTEMDRIVE}/windows/system32/fbwfMgr.exe /disable
			  shutdown /f /t 1 /r /c "Rebooting after disabling write protect"
		  } else {
			  Write-Error "Write-protect is on, quitting prematurely.  Turn write protect off, reboot and retry."
			  Exit 1
		  }
	}
}

mkdir -force c:/Apache/conf/ssl >$null

c:/Apache/bin/openssl.exe `
  req `
  -config c:/Apache/conf/openssl.cnf `
  -out c:/Apache/conf/ssl/cert.crt.pem `
  -keyout c:/Apache/conf/ssl/cert.key.pem `
  -subj "/CN=US/ST=Washington/L=Seattle/O=myCompany Inc./CN=$computername/emailAddress=firstname.lastname@mycompany.com" `
  -nodes `
  -x509 `
  -newkey rsa:2048 `
  -days 365 `
  2>&1 | Where-Object {
	  <# filter empty newline #>
	  $_ -like "*\w*" `
	  -and $_ -notlike "WARNING: can't open config file: *:/openssl-*-win32/*/openssl.cnf" `
	  -and $_ -notlike "*writing new private key to*" `
	  -and $_ -notlike "*Generating a * bit RSA private key*"
  }

(Get-Content c:/Apache/conf/httpd.conf) |
  Where-Object {
	  $_ -notmatch 'Include conf/httpd-streambox-ssl.conf'
  } | Set-Content c:/Apache/conf/httpd.conf

Add-Content -Path c:/Apache/conf/httpd.conf -Value 'Include conf/httpd-streambox-ssl.conf'

(Get-Content c:/Apache/conf/httpd.conf) `
  -replace `
  '#LoadModule socache_shmcb_module modules/mod_socache_shmcb.so', `
  'LoadModule socache_shmcb_module modules/mod_socache_shmcb.so' |
  Set-Content c:/Apache/conf/httpd.conf

$sslconf = @'
Listen 443

SSLCipherSuite HIGH:MEDIUM:!MD5:!RC4
SSLProxyCipherSuite HIGH:MEDIUM:!MD5:!RC4

SSLHonorCipherOrder on 

SSLProtocol all -SSLv3
SSLProxyProtocol all -SSLv3

SSLPassPhraseDialog  builtin

SSLSessionCache        "shmcb:c:/Apache/logs/ssl_scache(512000)"
SSLSessionCacheTimeout  300

<VirtualHost _default_:443>

#   General setup for the virtual host
DocumentRoot "c:/Apache/htdocs"
ServerName www.example.com:443
ServerAdmin admin@example.com
ErrorLog "c:/Apache/logs/error.log"
TransferLog "c:/Apache/logs/access.log"

SSLEngine on

SSLCertificateFile conf/ssl/cert.crt.pem
SSLCertificateKeyFile conf/ssl/cert.key.pem

<FilesMatch "\.(cgi|shtml|phtml|php)$">
    SSLOptions +StdEnvVars
</FilesMatch>
<Directory "c:/Apache/cgi-bin">
    SSLOptions +StdEnvVars
</Directory>

BrowserMatch "MSIE [2-5]" \
         nokeepalive ssl-unclean-shutdown \
         downgrade-1.0 force-response-1.0

CustomLog "c:/Apache/logs/ssl_request.log" \
          "%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%r\" %b"

</VirtualHost>                                  
'@
Set-Content -Path c:/Apache/conf/httpd-streambox-ssl.conf -Value $sslconf

<# Stop apache service if it exists and its set to run automatically. This rules out sbt3-9400 #>
Get-WmiObject win32_service |
  Where-Object {
	  $_.Name -like 'Apache2.4' -and $_.StartMode -eq 'Auto'
  } | Stop-Service 2>&1 | Out-String |
	Where-Object {
		<# filter empty newline #>
		$_ -like "*\w*" -and $_ -notlike "*WARNING: Waiting for service * to finish *"
	}

<# Kill httpd.exe for sbt3-9400, its running as console app outside service #>
Get-Process | Where-Object { $_.Name -like 'httpd' } | Stop-Process -Force

<# Start apache service if it exists and set to run automatically. This
rules out sbt3-9400 #>
Get-WmiObject win32_service |
  Where-Object {
	  $_.Name -like 'Apache2.4' -and $_.StartMode -eq 'Auto'
  } | Start-Service 2>&1 | Out-String |
	Where-Object {
		<# filter empty newline #>
		$_ -like "*\w*" `
		  -and $_ -notlike "*WARNING: Waiting for service * to start *"
	}

<# Start apache from shortcut for 9400 #>
$glob = "${env:SYSTEMDRIVE}/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/Apache HTTP Server.lnk"
$httpd_link = Get-ChildItem $glob -ea 0 | Select-Object -Last 1 | Select-Object -exp fullname
if($httpd_link -ne $null)
{
	Invoke-Item "$httpd_link"
}
