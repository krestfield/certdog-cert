# ------------------------------------------------------------------------------------------------
# Krestfield Certdog Certificate Management Script
# ------------------------------------------------------------------------------------------------
# 
# Copyright (c) 2021, Krestfield Limited
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted 
# provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice, this list of conditions 
#     and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice, this list of conditions 
#     and the following disclaimer in the documentation and/or other materials provided with the distribution.
#   * Neither the name of Krestfield Limited nor the names of its contributors may be used to endorse or 
#     promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED 
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A 
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# ------------------------------------------------------------------------------------------------
#
# For an official supported, signed version of this script contact support@krestfield.com
#
# For more details on this script go here
#     https://krestfield.github.io/docs/certdog/cert_powershell.html
#
# This script requires the certdog application to issue certificates
#     More information: https://krestfield.github.io/docs/certdog/get_certdog.html
#
# Simple run options:
#
#   .\certdog-cert.ps1 -new
#
# This will prompt for all information including the certdog login as well as
# the dn, sans and whether to create a sheduled task etc.
# To provide the certdog login details without being prompted, run:
#
#   .\certdog-cert.ps1 -new -username [certdoguser] -password [certdogpassword]
#
# To run without any prompting:
#
#   .\certdog-cert.ps1 -new -username [certdoguser] -password [certdogpassword] -dn [Required DN] 
#                      -sans [SAN List] -saveCreds y 
#                      -createTask y -taskUsername [taskUsername] -taskPassword [taskPassword]
#
# Once the above has been performed the script saves the required information. Running:
#
#   .\certdog-cert.ps1 -renew
#
# Will check and process any renewals required when the -new switch was used
#
# If credentials are not saved, this can be run with the username and password options:
#
#   .\certdog-cert.ps1 -renew -username [certdoguser] -password [certdogpassword]
#
#
# To list what certificates are being monitored:
#
#   .\certdog-cert.ps1 -list
#
#
# To create a scheduled task that runs the .\certdog-cert.ps1 -renew script daily, run
#
#   .\certdog-cert.ps1 -taskonly
#
#
# To override the certdog URL as specified in the settings.json file, use -certdogUrl e.g.
#
#   .\certdog-cert.ps1 -new -certdogUrl https://certdog.org.com/certdog/api
#
#
# To ignore any SSL errors (if the certdog URL is not protected with a trusted cert), 
# use -ignoreSslErrors e.g.
#
#   .\certdog-cert.ps1 -new -ignoreSslErrors
# 
# ------------------------------------------------------------------------------------------------
Param (
    [switch]
    $new,
    [switch]
    $renew,
    [switch]
    $list,
    [switch]
    $taskonly,
    [switch]
    $setcreds,
    [switch]
    $ignoreSslErrors,
    [Parameter(Mandatory=$false)]
    $username,
    [Parameter(Mandatory=$false)]
    $password,
    [Parameter(Mandatory=$false)]
    $certdogUrl,
	[Parameter(Mandatory=$false)]
    $dn,
    [Parameter(Mandatory=$false)]
    $sans,
    [Parameter(Mandatory=$false)]
    $saveCreds,
    [Parameter(Mandatory=$false)]
    $createTask,
    [Parameter(Mandatory=$false)]
    $taskUsername,
	[Parameter(Mandatory=$false)]
    $taskPassword

)
 
$script:scriptName = "certdog-cert.ps1"
$script:managedCertsFilename = "managedcerts.json"

# By default we do not ignore SSL errors
$script:IgnoreTlsErrors = $false

# The list of managed certs, if any, that may be saved
$script:managedCerts = @()

$script:CertdogSecureUsername=$null
$script:CertdogSecurePassword=$null

$CREDS_REGISTRY_PATH = "HKLM:\Software\Krestfield\Certdog"

$script:loggedIn = $false

# -----------------------------------------------------------------------------
# When -ignoreSslErrors is called, this is set which ignores https TLS errors
# due to untrusted certificates etc.
# -----------------------------------------------------------------------------
Function IgnoreSSLErrors
{
    $script:IgnoreTlsErrors = $true

	if ("TrustAllCertsPolicy" -as [type]) {} 
	else 
	{
	# NOTE: This skips the SSL certificate check
	add-type @"
	using System.Net;
	using System.Security.Cryptography.X509Certificates;
	public class TrustAllCertsPolicy : ICertificatePolicy {
		public bool CheckValidationResult(
			ServicePoint srvPoint, X509Certificate certificate,
			WebRequest request, int certificateProblem) {
			return true;
		}
	}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy 
	}
}

# -----------------------------------------------------------------------------
# Logs in the user and retains the authorization token for use by other
# functions
# -----------------------------------------------------------------------------
Function login
{
    Param(
        [Parameter(Mandatory=$true)]
        $username,
        [Parameter(Mandatory=$true)]
        $password
    )
       
    $initialHeaders = @{
        'Content-Type' = 'application/json'
    }
    
    $body = [Ordered]@{
        'username' = "$username"
        'password' = "$password"
    } | ConvertTo-Json -Compress

    try 
    {
        $response = Invoke-RestMethod "$certdogUrl/login" -Method "POST" -Headers $initialHeaders -Body $body
        
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Content-Type", "application/json")
        $authToken = $response.token
        $headers.Add("Authorization", "Bearer $authToken")
        Set-Variable -Name "HEADERS" -Force -Value $headers -Visibility Private -Scope Global
	$script:loggedIn = $true
    }
    catch 
    {
	$script:loggedIn = $false
        Throw "Authentication to certdog at $certdogUrl failed`nError: $_" 
    }
}

# -----------------------------------------------------------------------------
# Logs out a user from this IP
# 
# -----------------------------------------------------------------------------
Function Logout
{
    $body = [Ordered]@{}
    
    Run-Rest-Command -endPoint "logouthere" -method "GET" -body $body -methodName "Logout-Here"
}

# -----------------------------------------------------------------------------
# Makes a generic REST call requiring the end point, body, method etc.
# Returns the response
# -----------------------------------------------------------------------------
Function Run-Rest-Command
{
    Param(
        [Parameter(Mandatory=$true)]
        $endPoint,
        [Parameter(Mandatory=$true)]
        $method,
        [Parameter(Mandatory=$true)]
        $body,
        [Parameter(Mandatory=$true)]
        $methodName
    )

    try {
		
        $headers = Get-Variable -Name "HEADERS" -ValueOnly -ErrorAction SilentlyContinue
        if (!$headers)
        {
            Write-Host "Please authenticate with Login -username [username] -password [password] (or just type Login to be prompted)"
            Return
        }

        $response = Invoke-RestMethod "$certdogUrl/$endPoint" -Headers $headers -Method $method -Body $body

        return $response
    }
    catch 
    {
        Write-Host "$methodName failed: $_" 
    
        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $responseBody = $reader.ReadToEnd();
        
        #Write-Host responseBody = $responseBody

        $output = $responseBody | ConvertFrom-Json
        $output | Format-List

        throw $output
    }
}

# -----------------------------------------------------------------------------
# Requests a cert with a CSR
# 
# -----------------------------------------------------------------------------
Function Request-CertP10
{
    [alias("request-csr")]
    Param(
        [Parameter(Mandatory=$true)]
        $caName,
        [Parameter(Mandatory=$false)]
        $csr,
        [Parameter(Mandatory=$false)]
        $teamName,
        [Parameter(Mandatory=$false)]
        $extraInfo,
        [Parameter(Mandatory=$false)]
        [string[]]$extraEmails
    )

	if ($script:loggedIn -eq $false)
	{
		Throw "Not logged in. Unable to request certificate from certdog"
	}

	if (!$csr)
    {
		Throw "Unable to request a certificate from certdog as no CSR data was provided"
    }
    
	try
	{
		$body = [Ordered]@{
			'caName' = "$caName"
			'csr' = "$csr"
			'teamName' = "$teamName"
			'extraInfo' = "$extraInfo"
			'extraEmails' = @($extraEmails)
		} | ConvertTo-Json -Compress
		$response = Run-Rest-Command -endPoint "certs/requestp10" -method "POST" -body $body -methodName "Request-CertP10"

		return $response
	}
	catch
	{
		Throw "Unable to obtain certificate from certdog. Error: $_"
	}
}


# ------------------------------------------------------------------------------------------------
# Generates a certificate request in the local machine store
#
#
# ------------------------------------------------------------------------------------------------
Function Generate-Csr
{
    Param(
        [Parameter(Mandatory=$true)]
        [string]
        $dn,
        [Parameter(Mandatory=$false)]
        $sans
    )

    try
	{
		# Temp filename for CSR and INF file
		$UID = [guid]::NewGuid()
		$settingsInfFile = "$($env:TEMP)\$($UID)-settings.inf";
		$csrFile = "$($env:TEMP)\$($UID)-csr.req"

		# Create the settings.inf
		$keySize = $global:Settings.csrKeyLength
		$hash = $global:Settings.csrHash
		$provider = $global:Settings.csrProvider
		$providerType = $global:Settings.csrProviderType
		$exportable = $global:Settings.exportable
		
		$settingsInf = "
[Version]
Signature=`"`$Windows NT`$
[NewRequest]
KeyLength = $keySize
Exportable = $exportable
MachineKeySet = TRUE
SMIME = FALSE
RequestType =  PKCS10
ProviderName = `"$provider`"
ProviderType =  $providerType
HashAlgorithm = $hash
;Variables
Subject = `"$dn`"
[Extensions]
	"
		# Add the SANs
		if ($sans -and $sans.count -gt 0) {
			$settingsInf += "2.5.29.17 = `"{text}`"
	"
			foreach ($sanItem In $sans) 
			{
				$settingsInf += "_continue_ = `"$sanItem`&`"
	"       }
		}

		# Save settings to file in temp
		Set-Content -Path $settingsInfFile -Value $settingsInf

		$resp = certreq -q -new $settingsInfFile $csrFile
		if ($LASTEXITCODE -ne 0)
		{
			Throw $resp
		}

		$csr = Get-Content $csrFile

		Remove-Item $csrFile -ErrorAction SilentlyContinue
		Remove-Item $settingsInfFile -ErrorAction SilentlyContinue

		return $csr
	}
	catch
	{
		Throw "There was an error whilst creating the CSR for the requested DN of $dn. Error: $_"
	}
}

# ------------------------------------------------------------------------------------------------
# Requests a certificate from certdog
#
# ------------------------------------------------------------------------------------------------
Function Request-Cert
{
    Param(
        [Parameter(Mandatory=$true)]
        [string]
        $username,
        [Parameter(Mandatory=$true)]
        [string]
        $password,
        [Parameter(Mandatory=$true)]
        [string]
        $caName,
        [Parameter(Mandatory=$true)]
        [string]
        $csr,
        [Parameter(Mandatory=$true)]
        [string]
        $teamName
    )

	if ($script:loggedIn -eq $false)
	{
		login -username $username -password $password
		$script:loggedIn = $true
	}
	
	$cert = Request-CertP10 -caName $caName -csr $csr -teamName $teamName

	#Logout
	
	return $cert.pemCert
}

# ------------------------------------------------------------------------------------------------
# Imports a certificate into the local machine store
#
# ------------------------------------------------------------------------------------------------
Function Import-Cert
{
	Param(
        [Parameter(Mandatory=$true)]
        [string]
        $certData
	)
	
	$tmpId = [guid]::NewGuid()
	$tmpFilename = "$($env:TEMP)\$($UID).cer";
	Set-Content -Path $tmpFilename -Value $certData

	try
	{		
		if (Test-Path $tmpFilename)
		{
			Get-ChildItem -Path $tmpFilename | Import-Certificate -CertStoreLocation cert:\LocalMachine\My > $null
			
			# Get Thumbprint
			$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($tmpFilename)
			
			# Store the Thumbprint in a global ready for use by any subsequent script
			$global:thumbprint = $cert.Thumbprint
					
			Remove-Item $tmpFilename -ErrorAction SilentlyContinue
			
			return $cert
		}
		else
		{
			Throw "Could not install certificate into local store, the certificate file at $tmpFilename could not be found." 
		}
	}
	catch
	{
		Throw "Importing of the certdog issued certificate failed. Error: $_"
	}
}

# ------------------------------------------------------------------------------------------------
# Given the DN returns the common name
#
# e.g. 
# Given: CN=test,O=Org,C=GB 
# will return: test
#
# ------------------------------------------------------------------------------------------------
Function Get-CommonNameFromDn
{
	Param(
        [Parameter(Mandatory=$true)]
        [string]
        $dn
	)
	
	$cn = $dn -replace "(CN=)(.*?),.*",'$2'
	$cn = $cn -replace "CN=",""
	
	return $cn
}

# ------------------------------------------------------------------------------------------------
# Gather any additional SANs
#
# Note that the common name is added automatically
#
# ------------------------------------------------------------------------------------------------
Function Get-Sans
{
	if ($sans)
	{
		$sanArray = $sans -split (',');
		return $sanArray
	}
	else 
	{
		$addMoreSans = Read-Host "`nDo you wish to add any subject alternative names to this certificate? (y/n)"
		if ($addMoreSans -eq "y")
		{
			$sansOk = $false
			do
			{
				Write-Host "`nEnter additional names in the form [Name Type]=[Name], seperated with a comma"
				Write-Host "Name Type can be: DNS, IPAddress or EMAIL"
				$addSans = Read-Host "e.g. DNS=test1.com,DNS=test2.com,EMAIL=user@home.com"
				$sanArray = @()
				
				Write-Host "`nAdditional Names:"
				Foreach ($sanItem In $addSans -split ",") 
				{
					Write-Host "   " $sanItem -ForegroundColor Yellow
					$sanArray = $sanArray + "$sanItem"
				}
				$allOk = Read-Host "`nAll ok? (y/n)"
				if ($allOk -eq "y")
				{
					$sansOk = $true
				}
			}
			while ($sansOk -ne $true)
		}
		else
		{
			$sanArray = @()
		}
		
		return $sanArray
	}
}

# ------------------------------------------------------------------------------------------------
# If the .\config dir is not present, creates it
# ------------------------------------------------------------------------------------------------
Function Check-ConfigDir
{
	$dirLoc = "$PSScriptRoot\config"
	if (!(Test-Path $dirLoc))
	{
		New-Item -ItemType directory -Path $dirLoc -Force > $null
	}	
}

# ------------------------------------------------------------------------------------------------
# Saves the certs to be managed
#
# ------------------------------------------------------------------------------------------------
Function Save-ManagedCerts
{
	Check-ConfigDir

	# Save the cert details
	$script:managedCerts | ConvertTo-Json -depth 100 | Out-File "$PSScriptRoot\config\$managedCertsFilename"
}

# ------------------------------------------------------------------------------------------------
# Loads the managed certs
#
# ------------------------------------------------------------------------------------------------
Function Load-ManagedCerts
{
	$managedCertsFilename = "$PSScriptRoot\config\$managedCertsFilename"
	if (Test-Path $managedCertsFilename)
	{
		[string[]]$script:managedCerts = Get-Content -Path $managedCertsFilename  | ConvertFrom-Json
	}
}

# ------------------------------------------------------------------------------------------------
# Saves the user credentials which means the renew option can be run 
# without requiring the credentials to be passed
#
# ------------------------------------------------------------------------------------------------
Function Save-Credentials
{	
	# If option not provided, prompt
	if (!$saveCreds)
	{	
		$saveCreds = Read-Host "Do you wish to save your credentials so they are not required when 'renew' is run? (y/n)"
	}

	if ($saveCreds -like "y")
	{		
		if (!$script:CertdogSecureUsername)
		{
			$user = Get-Username
			$pass = Get-Password
		}
		# Save the certdog credentials to the registry
		$secureUsername = $script:CertdogSecureUsername | ConvertFrom-SecureString
		$securePassword = $script:CertdogSecurePassword | ConvertFrom-SecureString

		if (!(Test-Path $CREDS_REGISTRY_PATH))
		{
			New-Item -Path $CREDS_REGISTRY_PATH -Force | Out-Null
		}
		New-ItemProperty -Path $CREDS_REGISTRY_PATH -Name "SecureUsername" -Value $secureUsername -PropertyType String -Force | Out-Null
		New-ItemProperty -Path $CREDS_REGISTRY_PATH -Name "SecurePassword" -Value $securePassword -PropertyType String -Force | Out-Null
		
		Write-Host "Credentials saved OK. They can only be accessed by the account running this script. Run '$script:scriptName -setcreds' to update"
	}
}

# ------------------------------------------------------------------------------------------------
# Loads the certdog secure credentials from the registry
#
# ------------------------------------------------------------------------------------------------
Function Load-Credentials
{
	# If username and password passed in, use those, otherwise get from the registry
	if ($username -and $password)
	{
		$script:CertdogSecureUsername = ConvertTo-SecureString -String $username -AsPlainText -Force		
		$script:CertdogSecurePassword = ConvertTo-SecureString -String $password -AsPlainText -Force				
	}
	else
	{
		# Load the certdog credentials from the registry
		try 
		{
			if (Test-Path $CREDS_REGISTRY_PATH)
			{
				Get-ItemProperty -Path $CREDS_REGISTRY_PATH | Select-Object -ExpandProperty "SecureUsername" -ErrorAction Stop | Out-Null
				$secureUsername = (Get-ItemProperty -Path $CREDS_REGISTRY_PATH -Name "SecureUsername").SecureUsername         
				$script:CertdogSecureUsername = $secureUsername | ConvertTo-SecureString
				if (!$script:CertdogSecureUsername)
				{
					Throw "Unable to obtain credentials from the store"
				}

				Get-ItemProperty -Path $CREDS_REGISTRY_PATH | Select-Object -ExpandProperty "SecurePassword" -ErrorAction Stop | Out-Null
				$SecurePassword = (Get-ItemProperty -Path $CREDS_REGISTRY_PATH -Name "SecurePassword").SecurePassword     
				$script:CertdogSecurePassword = $securePassword | ConvertTo-SecureString				
				if (!$script:CertdogSecurePassword)
				{
					Throw "Unable to obtain credentials from the store"
				}
			}
			else
			{
				Throw "No credentials could be found in the registry. Either run .\$script:scriptName -new to have them stored on this machine or provide to this script"
			}
		}
		catch 
		{
			Throw "Failed to load username or password from registry. $_"
		}
	}
}

# ------------------------------------------------------------------------------------------------
# Writes the message to a log file and optionally the event log
#
# ------------------------------------------------------------------------------------------------
Function Write-Event
{
	Param(
        [Parameter(Mandatory=$true)]
        $message,
		[Switch]
		$toEventLog,
		[Switch]
		$isError
	)
	
	$EventLogSource="certdog"
	$EventLogID=$global:Settings.eventLogId
	
	Add-Content $global:RenewLogFile "$message"
	
	if ($toEventLog)
	{
		if (![System.Diagnostics.EventLog]::SourceExists($EventLogSource))
		{
			New-EventLog –LogName Application –Source $EventLogSource
		}
		
		$entryType = "Information"
		if ($isError)
		{
			$entryType = "Error"
			$EventLogID=$global:Settings.errorLogId
		}
		Write-EventLog –LogName Application –Source $EventLogSource –EntryType $entryType –EventID $EventLogID –Message $message -Category 0
	}
	
	#Write-Host $message
}

# ------------------------------------------------------------------------------------------------
# Creates a scheduled task which will call this script with the -renew switch
# Task will run once a day between 1 and 3am
#
# ------------------------------------------------------------------------------------------------
Function Create-Task()
{
	try
	{
		# If option not provided, prompt
		if (!$createTask)
		{	
			$createTask = Read-Host "`nDo you want to create a task to automatically renew certificates? (y/n)"
		}

		if ($createTask -like "y")
		{		
			if (!$taskUsername)
			{
				Write-Host "`nThe script will use saved credentials to authenticate to certdog"
				Write-Host "Only the account that saved those credentials will have access to them"
				Write-Host "The task must run under this same account"
				$username = Read-Host "`nEnter the username of this account"	
				$securePassword = Read-Host -assecurestring "Enter the password"	
				$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword))
			}
			else 
			{
				$username = $taskUsername
				$password = $taskPassword	
			}
		
			$description = "Checks for expiry of Certdog certificates"
			$taskName = "Certdog Cert Expiry Check"
			
			$scriptLoc = "$PSScriptRoot\$script:scriptName"
			$arg = "-Command `"& '$scriptLoc' -renew`""
			if ($script:IgnoreTlsErrors)
			{
				$arg = "-Command `"& '$scriptLoc' -renew -ignoreSslErrors`""
			}
			$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $arg -WorkingDirectory $PSScriptRoot

			# Run every day a random time between 1am and 3am
			$trigger =  New-ScheduledTaskTrigger -Daily -DaysInterval 1 -At 1am -RandomDelay (New-TimeSpan -minutes 120)

			# Create the task (if not already present)
			$taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName}
			if($taskExists) 
			{
				Write-Host "`nDid not create a new task as a task already exists to monitor TLS certificates called $taskName"
			} 
			else 
			{        
				$newTask = Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskName -User $username -Password $password -Description $description -ErrorAction Stop | Out-Null
				Write-Host "`nTask: '"$taskName"' created OK"
			}
			Write-Host "If required, you can manually edit the timings of this task from the Task Scheduler"

			Write-Host "`nBye`n"
		}
		else
		{
			Write-Host "`nThis certificate will not auto-renew"
			Write-Host "`nYou can manually renew this certificate (and any others that are being monitored) by running"
			Write-Host "    $script:scriptName -renew" -ForegroundColor Gray
			Write-Host "`nSee: https://krestfield.github.io/docs/certdog/cert_powershell.html for more information"
			Write-Host "`nBye`n"
		}
	}
	catch 
	{
		Throw "Unable to create scheduled task. Error: $_"
	}
}

# ------------------------------------------------------------------------------------------------
# If a username has not been passed in, prompt for it
# Store this username in the CertdogSecureUsername secure string
#
# ------------------------------------------------------------------------------------------------
Function Get-Username()
{
	# If not passed in, prompt the operator
	if (!$username)
	{
		$username = Read-Host "`nEnter your certdog username"
	}
	
	# Store as a secure string
	$script:CertdogSecureUsername = ConvertTo-SecureString -String $username -AsPlainText -Force
	
	return $username
}

# ------------------------------------------------------------------------------------------------
# If a password has not been passed in, prompt for it
# Store this password in the CertdogSecurePassword secure string
#
# ------------------------------------------------------------------------------------------------
Function Get-Password()
{
	if (!$password)
	{
		$script:CertdogSecurePassword = Read-Host -assecurestring "Enter your certdog password"
		
		$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:CertdogSecurePassword))
	
		return $password
	}
	else
	{
		$script:CertdogSecurePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
		
		return $password
	}
}

# ------------------------------------------------------------------------------------------------
# Extracts the SANS from a certificate and returns an array
#
# ------------------------------------------------------------------------------------------------
Function getSansFromCert
{
    Param(
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $cert
    )

    try
	{
		# Get all SAN extensions
		$sanExt = $cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "subject alternative name"}
		if ($sanExt)
		{
			$sanString = $sanExt.Format(1) -replace "DNS Name", "DNS"	
			$sanString = $sanString -replace "IP Address", "IPAddress"   
			$sanString = $sanString -replace "RFC822 Name", "EMAIL" 			
			$sanString = $sanString -replace "`r`n", ";" 
			$sanArray = $sanString.split(";")

			return $sanArray
		}
	}
	catch 
	{
		Throw "There was an error obtaining the SANs from certificate cert.SubjectDN Error: $_"
	}		
}

# ------------------------------------------------------------------------------------------------
# Obtain the certs from managedcerts.json and check if it is expiring in $settings.renewalDays
# If so, renew the cert
#
# ------------------------------------------------------------------------------------------------
Function CheckFor-ExpiringCerts
{
	if ($script:managedCerts)
	{				
		$newCertThumbprints = @()
		foreach($certThumbprint in $script:managedCerts)
		{
			$currentCertificate = Get-ChildItem -Path CERT:LocalMachine/My | Where-Object -Property Thumbprint -EQ -Value $certThumbprint
			if (!$currentCertificate)
			{
				Write-Event -message "`nCould not find a certificate with thumbprint: $certThumbprint"
			}
			else
			{
				$certSubject = $currentCertificate.Subject
				$certThumbprint = $currentCertificate.Thumbprint
				$expiring = $currentCertificate.NotAfter
				Write-Event -message "Current Certificate - $certSubject Thumbprint: $certThumbprint Expiring $expiring"

				$renewalDays = $global:Settings.renewalDays
				if ($currentCertificate.NotAfter -le (get-date).AddDays($renewalDays))
				{
					Write-Event -message "Is expiring in less than $renewalDays days. Renewing now..."

					# Get certificate dn and common name
					$certDn = $currentCertificate.Subject
					
					$certSans = getSansFromCert $currentCertificate
					
					$csr = Generate-Csr -dn $certDn -sans $certSans
					
					# Need to convert from secure
					$username = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:CertdogSecureUsername))
					$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:CertdogSecurePassword))						
					$cert = Request-Cert -username $username -password $password -caName $global:Settings.certIssuerName -csr "$csr" -teamName $global:Settings.teamName
					Write-Event -message "Obtained new certificate from certdog OK"
					
					# Import the certificate
					$newCert = Import-Cert $cert
					$newCertThumbprint = $newCert.Thumbprint
					$newCertExpiry = $newCert.NotAfter
					Write-Event -message "New Certificate - Thumbprint: $newCertThumbprint Expiring: $newCertExpiry"

					# Store the new thumbprint to monitor
					$newCertThumbprints += $newCertThumbprint
				}
				else
				{
					Write-Event -message "Is not expiring (in the next $renewalDays days)"
					
					# No change so we store the same thumbprint as before
					$newCertThumbprints += $certThumbprint
				}
			}
		}
		
		# Save the new thumbprints
		$script:managedCerts = $newCertThumbprints
		Save-ManagedCerts
	}
	else
	{
		Write-Event -message "No certificates to monitor`n"
	}
}

# ------------------------------------------------------------------------------------------------
# Displays the startup header
#
# ------------------------------------------------------------------------------------------------
Function Show-Heading
{
	Write-Host "`n`nCertdog Certificate Manager Script" -ForegroundColor Gray
	Write-Host "----------------------------------`n" -ForegroundColor Green
}

# ------------------------------------------------------------------------------------------------
# Updates the Get New Certificate
#
# Prompts for input regarding DN, username and password then requests the cert
# and installs to the machine store.
#
# ------------------------------------------------------------------------------------------------
Function Get-NewCert
{
	Show-Heading
	
	if (!$dn)
	{
		$dn = Read-Host "Enter the DN (e.g. CN=name,O=org,C=GB)"
		if (!$dn)
		{
			Throw "A subject DN is required"
		}

	    Write-Host "`nCertificate DN will be: " -NoNewline
		Write-Host $dn -ForegroundColor Yellow
    	$continue = Read-Host "`nContinue? (y/n)"
	}
	else {
		$continue = "y"
	}
	
	if ($continue -eq "y")
	{	
		Load-ManagedCerts

		$sans = Get-Sans

		$username = Get-Username
		
		$password = Get-Password

		$caName = $global:Settings.certIssuerName

		# Generate the CSR
		Write-Host "`nGenerating certificate request..."
		$csr = Generate-Csr -dn $dn -sans $sans
		Write-Host "Request created OK"
		
		# Request and obtain the certificate
		Write-Host "`nRequesting certificate..."
		$cert = Request-Cert -username $username -password $password -caName $caName -csr "$csr" -teamName $global:Settings.teamName
		Write-Host "Obtained certificate OK"
		
		# Import the certificate
		Write-Host "`nImporting certificate..."
		$newCert = Import-Cert $cert
		
		# Add this to the list of managed certs
		$script:managedCerts += $newCert.Thumbprint
		
		Write-Host "`nCertificate has been issued and imported OK`n"
		
		Save-Credentials	
				
		Save-ManagedCerts
		
		# Create scheduled task
		Create-Task		
	}
}

# ------------------------------------------------------------------------------------------------
# Gets the renew log filename - creates the log directory if doesn't already exist
#
# ------------------------------------------------------------------------------------------------
Function Get-RenewLogFile
{
	$dateStamp = get-date -Format yyyyMMddTHHmmss
	$logDir = "$PSScriptRoot\logs"

	if (!(Test-Path $logDir))
	{
		New-Item -ItemType directory -Path $logDir -Force > $null
	}	
	$RenewLogFile = "$($logDir)\$($dateStamp)_certdogrenew.log"	

	return $RenewLogFile
}

# ------------------------------------------------------------------------------------------------
# Renews certs by loading the managedcerts.json file which contains 
# a list of the thumbprints being monitored
# For each cert if expiring in $settings.renewalDays (or sooner), renew the cert
#
# ------------------------------------------------------------------------------------------------
Function Renew-Cert
{
	$global:RenewLogFile = Get-RenewLogFile
	
	try
	{
		Write-Event -message "'$script:scriptName -renew' was started. Checking for expiring certs...";
		
		Load-ManagedCerts
		Load-Credentials
			
		# Check for expiring certs - 
		CheckFor-ExpiringCerts
		
		#Write-Host "`nCert Check Complete`n`nBye`n"
		
		$log = Get-Content -Raw $global:RenewLogFile
		Write-Host $log
		Write-Event -toEventLog -message $log
	}
	catch 
	{
		Write-Event -message "`nRenew Failed with the following error:`r`n $_"

		$log = Get-Content -Raw $global:RenewLogFile
		Write-Host $log
		Write-Event -toEventLog -message $log -isError
		Exit 2
	}
}

# ------------------------------------------------------------------------------------------------
# Lists the certs being monitored
#
# ------------------------------------------------------------------------------------------------
Function List-MonitoredCertificates
{
	Write-Host "`nThe following certificates are being monitored:"

	Load-ManagedCerts
	$count = 1
	foreach($certThumbprint in $script:managedCerts)
	{
		$currentCertificate = Get-ChildItem -Path CERT:LocalMachine/My | Where-Object -Property Thumbprint -EQ -Value $certThumbprint
		if (!$currentCertificate)
		{
			Write-Host "`nCould not find a certificate with thumbprint: $certThumbprint"
		}
		else
		{
			$certSubject = $currentCertificate.Subject
			$certIssuer = $currentCertificate.Issuer
			$certSerialNum = $currentCertificate.SerialNumber
			$certThumbprint = $currentCertificate.Thumbprint
			$expiring = $currentCertificate.NotAfter
			Write-Host "`n  $count. $certSubject" -ForegroundColor Green
			Write-Host "      Issuer: $certIssuer"
			Write-Host "      Serial Number: $certSerialNum"
			Write-Host "      Thumbprint: $certThumbprint"
			Write-Host "      Expiring: $expiring"
			$count = $count + 1
		}
	}
	if ($count -gt 1)
	{
		Write-Host "`nTo cease monitoring a certificate, delete its Thumbprint from $PSScriptRoot\config\managedcerts.json`n"
	}

}

# ------------------------------------------------------------------------------------------------
# Load settings from the settings.json file
#
# ------------------------------------------------------------------------------------------------
Function Load-Settings
{
	$settingsPath = "$PSScriptRoot\settings.json"
	if (Test-Path $settingsPath)
	{
		$global:Settings = Get-Content -Path $settingsPath | ConvertFrom-Json
	}
	else 
	{
		Write-Host "Settings could not be located. Searched for $settingsPath"
		Exit
	}
}

# ------------------------------------------------------------------------------------------------
# This script will read/write to the registry and import certificates to the machine store
# Admin rights are therefore required
#
# ------------------------------------------------------------------------------------------------
Function Exit-IfNotAdmin
{
	If (-NOT([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
	{
		Write-Host "`nAdministrator privileges are required. Please restart this script with elevated rights`n" -ForegroundColor Yellow
		
		Exit
	}	
}

Function Check-Params
{
	if ($createTask -like 'y')
	{
		if (!$taskUsername -or !$taskPassword)
		{
			throw "Values for '-taskUsername' and '-taskPassword' are required when '-createTask y' is set"
		}
	}
}

# -------------------------------------------------------------------------------------------
#
#
#
# -------------------------------------------------------------------------------------------
Exit-IfNotAdmin

try {	
	Check-Params

	Load-Settings

	#
	# If URL passed in we use that otherwise what is provided in settings.json
	#
	if (!$certdogUrl)
	{
		$certdogUrl = $global:Settings.certdogUrl
	}

	#
	# If using a non-trusted SSL certificate, provide the -ignoreSslErrors switch
	#
	if ($ignoreSslErrors)
	{
		IgnoreSSLErrors
	}

	if ($new)
	{
		# Run the initial process to create a new certificate
		Get-NewCert -username $username -password $password
	}
	elseif ($renew)
	{
		# Run the renewal check and auto-renew process
		Renew-Cert
	}
	elseif ($list)
	{
		# List the monitored URLs
		List-MonitoredCertificates
	}
	elseif ($taskonly)
	{
		# Only create the scheduled task
		Create-Task
	}
	elseif ($setcreds)
	{
		# Only update or save credentials
		Save-Credentials
	}
	else {
		Write-Host "Nothing to do. Call either -new, -renew, -list, -taskonly or -setcreds"
	}
}
catch {
	Write-Host $_	
}

# -------------------------------------------------------------------------------------------
# 
# -------------------------------------------------------------------------------------------