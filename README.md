#  Applicationgateway Azure Script (for api a& spa .net core)


This is a useful powershell script i made to automatically compare DNS A-records from Cloudflare, add rules and re-direct rules to the Azure appgateway if new sites are added

## Installation

Just copy paste the .ps1



## Usage

Please change the credentials to your own application gateway.
Note the script is expecting you have already configured HTTPS settings and your back-end pool
```powershell


$azureAplicationId = ""
$azureTenantId = ""
$azurePassword = ConvertTo-SecureString "" -AsPlainText -Force
$psCred = New-Object System.Management.Automation.PSCredential($azureAplicationId , $azurePassword)
$subscription = ""

```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
Dont know