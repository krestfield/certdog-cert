# Certdog Cert Script

This script generates a local CSR , requests a certificate from certdog and imports into the Local Machine store  

It can create a scheduled task to then monitor and auto-renew storing the authentication details in the Windows Credential Store    

  

Certdog can interface to your Microsoft CAs, PrimeKey EJBCAs or use its own internal CAs, providing a simple UI or a REST API (as is used by this script) to automate the issuance of certificates

  

This example is much like a traditional, Microsoft auto-enrolment model, but enables the use of other CAs, and can be used where auto-enrolment may not be possible (non-domain joined servers) or where you wish to avoid group-policy changes. You also have the ability to easily view and search your issued certificates    




Full details on this script can be found [here](https://krestfield.github.io/docs/certdog/cert_powershell.html)  

Get the signed version of this script from [here](https://krestfield.s3.eu-west-2.amazonaws.com/certdog/certdog-cert.zip)  



More info on certdog: https://krestfield.com/certdog

All the documentation: https://krestfield.github.io/docs/certdog/certdog.html



## Pre-requisites

An instance of certdog is required. See [here](https://krestfield.github.io/docs/certdog/get_certdog.html) for more details on how to get certdog



  

## Running

Open a PowerShell window as Administrator



 Simple run options:

```powershell
.\certdog-cert.ps1 -new
```

This will prompt for all information including the certdog login as well as the binding and certificate details. See the sample output below for more details



To provide the certdog authentication details (and not be prompted for username/password), run:

```powershell
.\certdog-cert.ps1 -new -username [certdoguser] -password [certdogpassword]
```

  

To provide all required information (removing all prompting):

```powershell
.\certdog-cert.ps1 -new -username [certdoguser] -password [password] -sans [SAN List] -dn [Required DN] -saveCreds y -createTask y -taskUsername [taskUsername] -taskPassword [taskPassword]
```

For example, to generate a certificate with a DN of ``CN=test.com,O=Org,C=GB``, Subject Alternative Names of ``EMAIL=user@domain.com`` and ``DNS=server2.com`` saving the certdog username and password and creating a task which is run under user ``domain\user1`` with password ``password``:

```powershell
.\certdog-cert.ps1 -new -username certdoguser -password password -sans "EMAIL=user@domain.com,DNS=server2.com" -dn "CN=test.com,O=Org,C=GB" -saveCreds y -createTask y -taskUsername "domain\user1" -taskPassword "password"
```

​    

  

 Once the above has been performed the script saves the required information. Running:

```powershell
.\certdog-cert.ps1 -renew
```

Will check and process any renewals required  


As above, this can be run with the username and password options:

```powershell
.\certdog-cert.ps1 -renew -username [certdoguser] -password [certdogpassword]
```

 

 To list what certificates are being monitored:

```powershell
.\certdog-cert.ps1 -list
```

   

 To create a scheduled task that runs the ``.\certdog-cert.ps1 -renew`` script daily, run

```powershell
.\certdog-cert.ps1 -taskonly
```

  

To override the certdog URL as specified in the ``settings.json`` file, use ``-certdogUrl`` e.g.

```powershell
.\certdog-cert.ps1 -new -certdogUrl https://certdog.org.com/certdog/api
```

​     

To ignore any SSL errors (if the certdog URL is not protected with a trusted cert), use ``-ignoreSslErrors`` e.g.

```powershell
.\certdog-cert.ps1 -new -ignoreSslErrors
```



### Settings (settings.json)

Settings are stored within the ``settings.json`` file. Sample contents:

```json
{
	"certdogUrl" : "https://certdog.net/certdog/api",
	"certIssuerName" : "Certdog TLS",
	"renewalDays" : 30,
	"csrKeyLength" : 2048,
	"csrHash" : "sha256",
	"csrProvider" : "Microsoft RSA SChannel Cryptographic Provider",
	"csrProviderType" : 12,
	"exportable" : "FALSE",
	"eventLogId" : 5280,
	"errorLogId" : 5281
}
```

* certdogUrl

The URL of the certdog installation's api. If using the Docker image use https://127/0/0/1/certdog/api

* certIssuer

The name of the certificate issuer as configured in certdog (e.g. Certdog TLS)

* renewalDays

When the script is run with the *-renew* option this value will be used when deciding whether to renew certificates or not

If a certificate is expiring in *renewalDays* (or fewer) the renewal process will initiate

* csrKeyLength

When a new CSR is generated (when creating a new or renewing a current certificate), this key length will be used

* csrHash

The hash used to generate the CSR

* csrProvider

This is the Microsoft provider that will be used to generate the CSR

* csrProviderType

This depends on the csrProvider selected and must match. See [here](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.cspparameters.providertype?view=net-5.0) for more information

* exportable

If TRUE then it will be permitted for the private key of the issued certificate to be exported (e.g. as a password protected PFX/PKCS#12 file)

* eventLogId

This is the Event Log ID that will be assigned to entries the script adds. If monitoring events, you may need to note this value. It can also be updated here

* errorLogId

This is the Event Log ID that will be assigned to entries the script adds when errors occur. If monitoring error events, you may need to note this value. It can also be updated here



