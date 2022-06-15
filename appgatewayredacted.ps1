#Establlish TLS 1.2 min
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#main display
$text = @"
_____                                           _                   
/  __ \                                         | |                  
| /  \/ ___  _ __ ___  _ __   __ _ _ __  _   _  | | ___   __ _  ___  
| |    / _ \| '_ ` _ \| '_ \ / _` | '_ \| | | | | |/ _ \ / _` |/ _ \ 
| \__/\ (_) | | | | | | |_) | (_| | | | | |_| | | | (_) | (_| | (_) |
 \____/\___/|_| |_| |_| .__/ \__,_|_| |_|\__, | |_|\___/ \__, |\___/ 
                      | |                 __/ |           __/ |      
                      |_|                |___/           |___/       
                          Application Gateway
                                v1.0
    ~[Automaticly monitor and apply new configuration changes if required!]~ 
"@

cls
write-host $text -ForegroundColor White -BackgroundColor  Blue

#Check dependency

Write-host "Application Gateway MonitorChecking some things first..." -ForegroundColor Yellow
$Installation = test-Path -Path C:\powershell\appgateway.txt -ErrorAction SilentlyContinue

if ($Installation -eq $false) {
    $InstalledModules = (Get-InstalledModule).name
    if ($InstalledModules.contains("Az.Network")) {
        write-host "Az.Network module already installed!" -BackgroundColor Green
    }
    else {
        write-warning "Did not detect module Az.Network, which is required for this to work!`nAttempting to install now!"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Install-Module -Name Az.Network -RequiredVersion 3.0.0 -Verbose
        $InstalledModules = (Get-InstalledModule).name
        if ($InstalledModules.contains("Az.Network")) {
            write-host "Succesfully installed Az.Network!" -BackgroundColor Green
        }
        else {
            throw "Error, could not install AZ.network! which is required for this to continue!"
        }
    }
    $InstalledModules = (Get-InstalledModule).name
    if ($InstalledModules.contains("Az.Accounts")) {
        write-host "Az.Accounts module already installed!" -BackgroundColor Green
    }
    else {
        write-warning "Did not detect module Az.Accounts, which is required for this to work!`nAttempting to install now!"
        
        Install-Module -Name Az.Accounts -RequiredVersion 2.2.3 -Verbose
        $InstalledModules = (Get-InstalledModule).name
        if ($InstalledModules.contains("Az.Accounts")) {
            write-host "Succesfully installed Az.Accounts!" -BackgroundColor Green
        }
        else {
            throw "Error, could not install AZ.Accounts! which is required for this to continue!"
        }

    }
    write-host "Leaving behind log of installation!" | Out-File -FilePath C:\powershell\appgateway.txt -Force -Append -ErrorAction SilentlyContinue
}

write-host "`nAll Good!" -ForegroundColor Green

#Connect to Azure using Service Prinicpal
sleep 1;
write-host "`nConnecting Azure..." -BackgroundColor Yellow
$azureAplicationId = ""
$azureTenantId = ""
$azurePassword = ConvertTo-SecureString "" -AsPlainText -Force
$psCred = New-Object System.Management.Automation.PSCredential($azureAplicationId , $azurePassword)
$subscription = ""
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $azureAplicationId, $azurePassword
try {
    $ConnectToAZ = Connect-AzAccount -ServicePrincipal -TenantId $azureTenantId -Credential $Credential
}
catch {
    throw "Unable to connect to azure, please investigate!"
}
#null check
if ($null -eq $ConnectToAZ) {
    throw "Unable to connect to azure, please investigate!"
}
else {
    write-host "Connected to SnagR Azure HK subscription!" -BackgroundColor Green
}

#Main connection to Azure Application gateway, please change variable below
$AppGWName = ""
$RG = ""
$IP = (Invoke-WebRequest ifconfig.me/ip).Content.Trim() #Gets IP where Agent is located on , ideally this should be the APP gateawy public ip

#error clearing
if ($error.count -gt 0) { $error.clear() }
#Main exec
write-host "Fetching details for application gateway" $AppGWName "in resource group" $RG -ForegroundColor Yellow
$AppGw = Get-AzApplicationGateway -Name "$AppGWName" -ResourceGroupName "$RG"

#Check Success
if ($error.count -gt 0) {
    write-host "`n`n`nDetected and issue fetching specific resource details for " $AppGWName "in resource group" $RG -BackgroundColor red
    throw "Unable to continue"
}
else {
    write-host "Fetched the details!`n`n" -BackgroundColor Green
}

#Explanation & naming convention
#Assumption: 2 listeners for each site (80, and 443), then, 1 rule associated to each listener
#For example: 2 listeners for applicationgateway.yourdomain.io : 1: port 80, associated rule purpose: port 80 -> 443 (send traffic to 443 rule). 
#2: port 443, associated rule purpose: send traffic to backend pool and configure with HTTP settings

#Why not use multi-site wildcard? Because it's a pain in the butt and cant get it to work without doing extensive research on rewrites etc so we'll have to go this way.

#Listener naming convention: 
#SPA: Listener-x.yourdomain.io-80(or 443)
#API: Listener-api-x.yourdomain.io-80(or 443)

#Rule naming convention: 
#SPA: Rule-x.yourdomain.io-80(or 443)
#API: Rule-api-x.yourdomain.io-80(or 443)

$AppGWListeners = ($AppGw.HttpListeners).name 
$AppGWRules = ($AppGw.RequestRoutingRules).name 

#Now fetch source of truth comparison (operating from the assumption that only v5 yourcompany infrastructure is using the application gateway, please contact redacted(or whomever is replacing him) or redacted if that is not the case, already have code ready for a situation like that in purger script (will detect each domain on iis))
#Get yourcompany sites pointing to this machine (assumption: all IIS sites are up to date and DNS is single source of truth)

$cloudflaresites = @()
[System.Collections.ArrayList]$cloudflaresites = $cloudflaresites
$DNSlist = @{
    "REMOVEDFORSECURITYREASONS"   = "REMOVEDFORSECURITYREASONS"; #.com
    "12312"   = "REMOVEDFORSECURITYREASONS"; #.com.hk
    "1352341"   = "REMOVEDFORSECURITYREASONS"; #.com.za
    "12301938"       = "REMOVEDFORSECURITYREASONS"; #.ae
    "123123141"    = "REMOVEDFORSECURITYREASONS"; #.co.il
    "123213123"   = "REMOVEDFORSECURITYREASONS"; #.com.za
    "1234"   = "REMOVEDFORSECURITYREASONS"; #.com.za
    "534"   = "REMOVEDFORSECURITYREASONS"; #.com.za
    "13231"    = "REMOVEDFORSECURITYREASONS"; #.com.za
    "123123"    = "REMOVEDFORSECURITYREASONS"; #.com.za
    "213141"       = "REMOVEDFORSECURITYREASONS"; #.de
    "091283"       = "REMOVEDFORSECURITYREASONS"; #.it
    "425353"       = "REMOVEDFORSECURITYREASONS"; #.nl
}

write-host "Connecting to Cloudflare..." -foregroundcolor yellow
$CloudFlarePassword = ""
$CloudflareUserName = ""
write-host "Fetching type A DNS records for yourdomain.io pointing to this machine ("$ip")"
$apiuri = -join ("https://api.cloudflare.com/client/v4/zones/", $DNSlist."yourdomain.io", "/dns_records?type=A&content=", $ip, "&per_page=100&order=type&direction=desc&match=all")
$CloudFlareFetch = Invoke-RestMethod -Method Get -Uri $apiuri -Headers @{
    "X-Auth-Email" = "$CloudflareUserName"
    "X-Auth-Key"   = "$CloudFlarePassword"
    "Content-Type" = "application/json" 
}   

#errorCheck
if ($null -eq $CloudFlareFetch) {
    write-warning "Did not fetch any results! Are there no DNS records pointing to this IP?"
    throw "Cannot continue without any DNS records!"
}
else {
    write-host "Success!`nFetched a total of"  $CloudFlareFetch.result.count "A records!`n`n`n" -BackgroundColor Green
}

#Put records in aray and compare the records with the appgateway current rules and listeners
$CloudFlareRecords = $CloudFlareFetch.result.name 
foreach ($ARecord in $CloudFlareRecords) {
    [void]$cloudflaresites.add($ARecord)   
}
#Main comparison
$RuleTobeCreated = @()
[System.Collections.ArrayList]$RuleTobeCreated = $RuleTobeCreated
#Check Appgateway rules
#Rule naming convention: 
#SPA: Rule-x.yourdomain.io-80(or 443)
#API: Rule-api-x.yourdomain.io-80(or 443)
write-host "Fetched CloudFlare Records, now checking if RULES exist for those records (expecting 1 port 80 rule and 1 port 443 rule) " -ForegroundColor Yellow
sleep 1;
foreach ($x in $CloudFlareRecords) {
    $X80 = -join ("Rule-", $x, "-80")
    write-host "Detecting if" $x80 "exists or not"
    if ($AppGWRules.contains("$x80")) {}else {
        $X80RoutingRule = -join ($x80,"-RoutingRule")
        $TestRoutingRule = $AppGWRules.contains("$X80RoutingRule")
        if ($TestRoutingRule -eq $false){
            write-host "WARNING: Did NOT detect" $X80 "in current" $AppGWName "rule set configuration, adding" $X80 "to rule set to be created" -ForegroundColor Blue -BackgroundColor White
            [void]$RuleTobeCreated.add($x80)    
        }
    }
    $X443 = -join ("Rule-", $x, "-443")
    write-host "Detecting if" $x443 "exists or not"
    if ($AppGWRules.contains("$x443")) {}else {
        write-host "WARNING: Did NOT detect" $X443 "in current" $AppGWName "rule set configuration, adding" $X443 "to rule set to be created" -ForegroundColor Blue -BackgroundColor White
        [void]$RuleTobeCreated.add($X443)
    }
}


#Check Appgateway Listeners
#Listener naming convention: 
#SPA: Listener-x.yourdomain.io-80(or 443)
#API: Listener-api-x.yourdomain.io-80(or 443)
write-host "`n`n`n***************************************`nNow checking if LISTENERS exist for those records (expecting 1 port 80 rule and 1 port 443 rule) " -ForegroundColor Yellow
$ListenerTobeCreated = @()
[System.Collections.ArrayList]$ListenerTobeCreated = $ListenerTobeCreated

sleep 1;
foreach ($x in $CloudFlareRecords) {
    $X80 = -join ("Listener-", $x, "-80")
    write-host "Detecting if" $x80 "exists or not"
    if ($AppGWListeners.contains("$x80")) {}else {
        write-host "WARNING: Did NOT detect" $X80 "in current" $AppGWName "LISTENER configuration, adding" $X80 "to listener to be created" -ForegroundColor Blue -BackgroundColor White
        [void]$ListenerTobeCreated.add($x80)
    }
    $X443 = -join ("Listener-", $x, "-443")
    write-host "Detecting if" $X443 "exists or not"
    if ($AppGWListeners.contains("$X443")) {}else {
        write-host "WARNING: Did NOT detect" $X443 "in current" $AppGWName "LISTENER configuration, adding" $X443 "to listener to be created" -ForegroundColor Blue -BackgroundColor White
        [void]$ListenerTobeCreated.add($X443)
    }

}


#Main creation part (listeners must be created first so rules can be associated with it.)
$AppGw = Get-AzApplicationGateway -Name $AppGWName -ResourceGroupName $RG
$Cert = Get-AzApplicationGatewaySslCertificate -Name "yourcompany" -ApplicationGateway $AppGW
#create SSL listener

#Listeners
if ($null -eq $ListenerTobeCreated -or $ListenerTobeCreated.count -eq 0) {
    write-host "There are" $ListenerTobeCreated.count "total listeners to be created, therefor not required and skipping this part" -ForegroundColor Green
}
else {
    $FEC = Get-AzApplicationGatewayFrontendIPConfig -Name $ipName -ApplicationGateway $appgw
    foreach ($X in $ListenerTobeCreated) {

        $TotalDashes = $x.ToCharArray() | Group-Object -NoElement | Sort-Object Count -Descending; $TotalDashes = $TotalDashes | where-object { $_.Name -like "*-*" } 
        $tempname = $x
        if ($TotalDashes.Count -eq 1) {
            $tempname = $tempname.split('.')[0]; $tempname = $tempname.split('-'); $tempname = $tempname[1];
        }
        if ($TotalDashes.Count -gt 1) {
            $tempname = $tempname.split('.')[0]; $tempname = $tempname.split('-'); $tempname = $tempname[1];
        
        }
        $ApiDetect = $tempname
        
        if ($ApiDetect -eq "api") {
            $xsplit = $x.split('-')[3];
            $Hostname = $x.split('-')[2]; $Hostname = -join ("api-", $Hostname)
        }
        else {
            $xsplit = $x.split('-')[2];
            $Hostname = $x.split('-')[1];
        }

        Switch -Wildcard ($xsplit) {
            '80' { $PortName = "port_80" }
            '443' { $PortName = "port_443" }
        }
        $listenerName = $x

        write-host "Attempting to create Listener" $x "with port:" $PortName -ForegroundColor Yellow

        #port 80
        if ($portName -eq "port_80") {
            #provision port
            Add-AzApplicationGatewayFrontendPort -ApplicationGateway $appgw -Name $portName -Port $xsplit -ErrorAction SilentlyContinue
            $port = Get-AzApplicationGatewayFrontendPort -ApplicationGateway $appgw -Name $portName
            #create listener
            $AppGw = Get-AzApplicationGateway -Name $AppGWName -ResourceGroupName $RG
            $Create = Add-AzApplicationGatewayHttpListener -ApplicationGateway $AppGw -Name $listenerName -Protocol "Http" -FrontendIpConfiguration $FEC -FrontendPort $Port -HostName $Hostname
        }
        #port 443
        if ($portName -eq "port_443") {
            #provision port
            Add-AzApplicationGatewayFrontendPort -ApplicationGateway $appgw -Name $portName -Port $xsplit -ErrorAction SilentlyContinue
            $port = Get-AzApplicationGatewayFrontendPort -ApplicationGateway $appgw -Name $portName
            #create listener
            $AppGw = Get-AzApplicationGateway -Name $AppGWName -ResourceGroupName $RG
            $Create = Add-AzApplicationGatewayHttpListener -ApplicationGateway $appgw -Name $listenerName -Protocol "Https" -FrontendIpConfiguration $FEC -FrontendPort $port -SslCertificate $cert -HostName $Hostname
        }
        #apply configuration
        write-host "Applying configuration..." -ForegroundColor Yellow
        $Apply = Set-AzApplicationGateway -ApplicationGateway $appGw
        #validate success
        $UpdateCheck = (Get-AzApplicationGatewayHttpListener -ApplicationGateway $appgw).Name
        if ($UpdateCheck.contains($listenerName)) {
            write-host $listenerName "has been added to application gateway" $appgw "sucesfully!`n" -BackgroundColor Black -ForegroundColor Green
                
        }
        else {
            write-host "`nWarning, attempted to create and apply listener" $listenerName "to application gateway: " $appgw "but was unable to succeed`nDetails: Created the listener with success but during validation check was unable to detect success! (fetch did not contain new listener)`n`n" -BackgroundColor Red
            throw "Created the listener with success but during validation check was unable to detect success! (fetch did not contain new listener)"
        }
    }
}

#Rules
#Rule naming convention: 
#SPA: Rule-x.yourdomain.io-80(or 443)
#API: Rule-api-x.yourdomain.io-80(or 443)


if ($null -eq $RuleTobeCreated -or $RuleTobeCreated.count -eq 0) {
    write-host "There are" $RuleTobeCreated.count "total rules to be created, therefor not required and skipping this part" -ForegroundColor Green
}
else {
    write-host "`n`n************************************************************`nThere are" $RuleTobeCreated.count "total rules to be created, attempting to create this now for appgateway" $AppGWName -ForegroundColor Yellow
    sleep 1;
    $FEC = Get-AzApplicationGatewayFrontendIPConfig -Name $ipName -ApplicationGateway $appgw
    foreach ($X in $RuleTobeCreated) {
        $TotalDashes = $x.ToCharArray() | Group-Object -NoElement | Sort-Object Count -Descending; $TotalDashes = $TotalDashes | where-object { $_.Name -like "*-*" } 
        $tempname = $x
        if ($TotalDashes.Count -eq 1) {
            $tempname = $tempname.split('.')[0]; $tempname = $tempname.split('-'); $tempname = $tempname[1];
        }
        if ($TotalDashes.Count -gt 1) {
            $tempname = $tempname.split('.')[0]; $tempname = $tempname.split('-'); $tempname = $tempname[1];
        
        }
        $ApiDetect = $tempname
        if ($ApiDetect -eq "api") {
            $xsplit = $x.split('-')[3];
            $Hostname = $x.split('-')[2]; $Hostname = -join ("api-", $Hostname)
        }
        else {
            $xsplit = $x.split('-')[2];
            $Hostname = $x.split('-')[1];
        }


        Switch -Wildcard ($xsplit) {
            '80' { $PortName = "port_80" }
            '443' { $PortName = "port_443" }
        }


        #Bind to correct listener
        $Listener = $x
        $Listener = $Listener.split('-'); 
        $tempname = "Listener"
        foreach ($l in $Listener) {
            if ($l -ne "Rule") {
                $tempname = -join ($tempname, "-", $l)
            }
        }
        $listener = $tempname 
        #Check if that listener exists or not
        $CheckListener = (Get-AzApplicationGatewayHttpListener -ApplicationGateway $appgw).Name
        if ($CheckListener.contains($listener)) {
            write-host "Creating rule" $x "for listener" $Listener
        }
        else {
            write-host "Was unable to detect what listener to bind to. `nDetails: $x , $listener" -BackgroundColor Red
            throw "Please investigate"
        }
        if ($FinalListener.count -gt 0) { $FinalListener.clear }
        

        #Create Rule: port 80 should go to target listener 443. Rule 443 should go to back end pool (ensuring all traffic to VM is ONLY https)
        if ($PortName -eq "port_80"){
            <#
            $AppGW = Get-AzApplicationGateway -Name "$AppGWName" -ResourceGroupName "$rg"
            #BackEndPool
            $BackendPool = Get-AzApplicationGatewayBackendAddressPool -Name "myBackendPool" -ApplicationGateway $AppGw
            #BackEnd HTTP Settings
            $Settings = Get-AzApplicationGatewayBackendHttpSetting -Name "myHTTPSetting" -ApplicationGateway $AppGw 
            #Final Listener
            $FinalListener = Get-AzApplicationGatewayHttpListener -Name $Listener -ApplicationGateway $appgw
            #Create port 80 rule (redirect to 443 listener)
            $CreateRule =           Add-AzApplicationGatewayRedirectConfiguration -ApplicationGateway $AppGw -IncludePath $false -IncludeQueryString $false -Name $x -RedirectType Permanent -TargetListener $FinalListener
            $redirectConfig =       Get-AzApplicationGatewayRedirectConfiguration -Name $x -ApplicationGateway $appgw
            $CreateRoutingRule =    Add-AzApplicationGatewayRequestRoutingRule -ApplicationGateway $AppGw -name $x -RuleType Basic -HttpListener $FinalListener -RedirectConfiguration $redirectConfig
            write-host "Applying rule configuration $x..." -ForegroundColor Yellow
            $Apply = Set-AzApplicationGateway -ApplicationGateway $appGw
            #>


            $80listener = $listener
            $443Listener =  $443Listener = $listener.split('.')[0]; $443Listener = -join ($443Listener,".yourdomain.io-443")
            $AppGW = Get-AzApplicationGateway -Name "$AppGWName" -ResourceGroupName "$rg"


            #FirstRule
            $80listener = Get-AzApplicationGatewayHttpListener -Name "$80listener" -ApplicationGateway $appgw
            $443Listener = Get-AzApplicationGatewayHttpListener -Name "$443Listener"  -ApplicationGateway $appgw
            $XRequestRoutingRule = -join ($X,"-RoutingRule")
            Add-AzApplicationGatewayRedirectConfiguration  -ApplicationGateway $appgw  -Name "$XRequestRoutingRule"  -RedirectType Permanent -TargetListener $443Listener  -IncludePath $true  -IncludeQueryString $true
            Set-AzApplicationGateway -ApplicationGateway $appgw

            #SecondRule
            $AppGW = Get-AzApplicationGateway -Name "$AppGWName" -ResourceGroupName "$rg"
            $redirectConfig = Get-AzApplicationGatewayRedirectConfiguration -Name "$x" -ApplicationGateway $appgw   
            Add-AzApplicationGatewayRequestRoutingRule -ApplicationGateway $appgw -Name "$x" -RuleType Basic -HttpListener $80listener -RedirectConfiguration $redirectConfig
            Set-AzApplicationGateway -ApplicationGateway $appgw



            #Validate Success
            $CurrentRedirect = (Get-AzApplicationGatewayRedirectConfiguration -ApplicationGateway $AppGW).Name
            if ($CurrentRedirect.contains($x)){write-host $x "Created!" -ForegroundColor Green}else {write-host "Did not detect succesful configuration change for" $X -BackgroundColor red}

 

        }else{ #443 to backend
        $FinalListener = Get-AzApplicationGatewayHttpListener -Name $Listener -ApplicationGateway $appgw
        #BackEndPool
        $BackendPool = Get-AzApplicationGatewayBackendAddressPool -Name "myBackendPool" -ApplicationGateway $AppGw
        #BackEnd HTTP Settings
        $Settings = Get-AzApplicationGatewayBackendHttpSetting -Name "myHTTPSetting" -ApplicationGateway $AppGw 
        #Create port 443 rule (redirect to back end VM)
        $CreateRule = Add-AzApplicationGatewayRequestRoutingRule -ApplicationGateway $AppGw -Name "$x" -RuleType Basic  -BackendHttpSettings $Settings -HttpListener $FinalListener -BackendAddressPool $BackendPool
        $Apply = Set-AzApplicationGateway -ApplicationGateway $appGw
        }
        #apply configuration
        write-host "Applying rule configuration $x..." -ForegroundColor Yellow
        $Apply = Set-AzApplicationGateway -ApplicationGateway $appGw
    
        #Validate Success
        $CurrentRules = (Get-AzApplicationGatewayRequestRoutingRule -ApplicationGateway $AppGW).Name
        if ($CurrentRules.contains($x)){write-host $x "Created!" -ForegroundColor Green}else {write-host "Did not detect succesful configuration change for" $X -BackgroundColor red}
    }
}
