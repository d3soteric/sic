<#
.SYNOPSIS
    PowerShell Script for Interrogating the Office 365 Graph for Over-Shared Items

.DESCRIPTION
    Example URL for finding proper value for parameters below
    https://office365<orgDomain>-my.sharepoint.com/personal/<user>_<officeDomain>_<tld>/...

.PARAMETER inFile
    Location of new line-delimited file of usernames to search for available files from


.PARAMETER officeDomain
    This parameter defines the domain for the office account of the organization being accessed
    This could potentially be the same as the orgDomain.  Inspecting the URL when visiting OneDrive
    in a browser will disclose this value  

.PARAMETER orgDomain
    This parameter is the organization name and may be the same as officeDomain.  
    Inspecting the URL when visiting OneDrive in a browser will disclose this value  

.Parameter tld
    This parameter is needed to specify the top-level domain which appears in OneDrive URLs.  
    e.g. com, org, eu, ca, us, biz...etc.

.Parameter proxy
    This parameter is a switch for turning the proxy settings on or off (default)
#>

### Read Variables
param (
    [Parameter(Mandatory=$true)][string]$inFile,
    [Parameter(Mandatory=$true)][string]$officeDomain,
    [Parameter(Mandatory=$true)][string]$orgDomain,
    [Parameter(Mandatory=$true)][string]$tld,
    [Parameter(Mandatory=$false)][switch]$proxy
    )

###########################
### Gather Auth. Tokens ###
###########################

###Variables for Session Tracking and Gathering Credentials

function Get-Cred{
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$cred = Get-Credential
$encodedUser = [uri]::EscapeDataString($Cred.UserName)
$encodedPass = [uri]::EscapeDataString($Cred.GetNetworkCredential().Password)
Get-First $encodedUser
}

function Set-Proxy{
# Enable Proxy
    if ($proxy -eq $true) {
        $proxyString = "http://192.168.1.30:8888"
        $proxyUri = new-object System.Uri($proxyString)
        [System.Net.WebRequest]::DefaultWebProxy = new-object System.Net.WebProxy ($proxyUri, $true)
        ###Trust Self-signed Certificates
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
    else{

    }
}

function Get-First{
    $theURL = "https://portal.office.com/onedrive?msafed=0&wsucxt=2&username=${encodedUser}"
    $userAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:50.0) Gecko/20100101 Firefox/60.1"
    $webRequest1 = Invoke-WebRequest -MaximumRedirection 2 -WebSession $session -ContentType $accept -userAgent $userAgent -Method GET -Uri $theURL
    Parse-BodyFirst $webRequest1 $userAgent $theURL $accept
    
}

function Parse-BodyFirst{
    # Parse the response received above
    ## Parse ctx, canary, hpgrequestid and sFt (flow token) out of the response
    $canary = Select-String "(?<=`"canary`":`").+(?=`",`"correlationId)" -InputObject $webRequest1 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    $sCtx = Select-String "(?<=`"sCtx`":`").+(?=`",`"iProductIcon)" -InputObject $webRequest1 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    $hpgrequestid = Select-String "(?<=`"sessionId`":`").+(?=`",`"locale)" -InputObject $webRequest1 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    $flowToken= Select-String "(?<=`"sFT`":`").+(?=`",`"sFTName)" -InputObject $webRequest1 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    ## Some Encoding for Later
    $encodedCanary = [uri]::EscapeDataString($canary)
    Get-Second $userAgent $encodedCanary $sCtx $hpgrequestid $flowToken
    }

function Get-Second{
    # Set Vars and Make the 2nd web request
    ## This request sends the encoded password entered earlier in POST body to get AUTH cookies
    ## The two cookies we care about in particular are the ESTSAUTH and ESTSAUTHPERSISTENT cookies
    $theURL = "https://login.microsoftonline.com/common/login"
    $contentType = "application/x-www-form-urlencoded"
    $encodedUser = [uri]::EscapeDataString($Cred.UserName)
    $encodedPass = [uri]::EscapeDataString($Cred.GetNetworkCredential().Password)
    $body = "login=${encodedUser}&loginfmt=${encodedUser}&passwd=${encodedPass}&canary=${encodedCanary}&ctx=${sCtx}&hpgrequestid=${hpgrequestid}&flowToken=${flowToken}"
    $webRequest2 = Invoke-WebRequest -MaximumRedirection 0 -WebSession $session -Method POST -Uri $theURL -userAgent $userAgent -ContentType $contentType -Body $body | Select-Object -ExpandProperty Content
    Parse-BodySecond $webRequest2 $sCtx $hpgrequestid $flowToken $encodedCanary $userAgent $contentType
    }

function Parse-BodySecond{
    # Parse the response received above
    ## take updated canary out of the response
    $canary = Select-String "(?<=`"canary`":`").+(?=`",`"correlationId)" -InputObject $webRequest2 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    ## Parse updated sCtx out of the response
    $sCtx = Select-String "(?<=`"sCtx`":`").+(?=`",`"sCanaryTokenName`":`"canary`")" -InputObject $webRequest2 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    ## Parse updated sessionID (hpgrequestid) out of the response
    $hpgrequestid = Select-String "(?<=`"sessionId`":`").+(?=`",`"locale)" -InputObject $webRequest2 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    ## Parse updated flowToken -- now only called sFt -- out of the response
    $flowToken = Select-String "(?<=`"sFT`":`").+(?=`",`"sFTName)" -InputObject $webRequest2 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    ## Some encoding for Later
    $encodedCanary = [uri]::EscapeDataString($canary)
    Get-Third $userAgent $encodedCanary $sCtx $hpgrequestid $flowToken
}

function Get-Third{
    # Set Vars and Make 3rd web request
    ## This request sends the data parsed from the last response of request 1
    ## We need to update our ESTS* cookies
    $theURL = "https://login.microsoftonline.com/kmsi"
    $body = "ctx=${sCtx}&hpgrequestid=${hpgrequestid}&flowToken=${flowToken}&canary=${encodedCanary}&DontShowAgain=true"
    $webRequest3 = Invoke-WebRequest -MaximumRedirection 0 -WebSession $session -Method POST -Uri $theURL -userAgent $userAgent -ContentType $contentType -Body $body | Select-Object -ExpandProperty Content
    Parse-BodyThird $webRequest3 $userAgent $contentType
}

function Parse-BodyThird{
    ###Parse "code","id_token", "state" and "session_state"  out of the response
    $code = Select-String "(?<=name=`"code`" value=`").+(?=`" /><input type=`"hidden`" name=`"id_token`")" -InputObject $webRequest3 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    $idToken = Select-String "(?<=name=`"id_token`" value=`").+(?=`" /><input type=`"hidden`" name=`"state`")" -InputObject $webRequest3 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    $state = Select-String "(?<=<input type=`"hidden`" name=`"state`" value=`").+(?=`" /><input type=`"hidden`" name=`"session_state`")" -InputObject $webRequest3 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    $sessionState = Select-String "(?<=<input type=`"hidden`" name=`"session_state`" value=`").+(?=`" /><noscript><p>Script is disabled.)" -InputObject $webRequest3 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    Get-Fourth $code $idToken $state $sessionState $userAgent $contentType
}

function Get-Fourth{
    $theURL = "https://portal.office.com/landing"
    $body = "code=${code}&id_token=${idToken}&state=${state}&session_state=${sessionState}"
    $webRequest4 = Invoke-WebRequest -MaximumRedirection 6 -WebSession $session -Method POST -Uri $theURL -userAgent $userAgent -ContentType $contentType -Body $body | Select-Object -ExpandProperty Content
    Parse-BodyFourth $webRequest4 $userAgent $contentType
}

function Parse-BodyFourth{
    #need the apicanary from body, needs to be passed as header in the 5th
    #also need to update sCtx and sFt.
    $apiCanary = Select-String "(?<=`"apiCanary`":`").+(?=`",`"canary`":)" -InputObject $webRequest4 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    $ctx = Select-String "(?<=ctx\=).+(?=`",`"iPawnIcon`":)" -InputObject $webRequest4 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    $flowToken = Select-String "(?<=`"sFT`":`").+(?=`",`"sFTName)" -InputObject $webRequest4 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    $hpgrequestid = Select-String "(?<=`"sessionId`":`").+(?=`",`"locale)" -InputObject $webRequest4 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    Get-Fifth $apiCanary $ctx $flowToken $userAgent $hpgrequestid
}

function Get-Fifth{
    # begin auth (triggers an SMS message)
    $contentType = "application/json; charset=utf-8"
    $theURL = "https://login.microsoftonline.com/common/SAS/BeginAuth"
    $authMethodID = "OneWaySMS"
    $method = "BeginAuth"
    $body = "{`"AuthMethodID`":`"${authMethodID}`",`"Method`":`"${method}`",`"ctx`":`"${ctx}`",`"flowToken`":`"${flowToken}`"}"
    $webRequest5 = Invoke-WebRequest -WebSession $session -Method POST -Uri $theURL -userAgent $userAgent -ContentType $contentType -Headers @{"canary"="${apicanary}"} -Body $body | Select-Object -ExpandProperty Content
    Parse-BodyFifth $webRequest5 $contentType $authMethodID $apiCanary $hpgrequestid
}

function Parse-BodyFifth{
    $flowToken = Select-String "(?<=:false,`"FlowToken`":`").+(?=`",`"Ctx`")" -InputObject $webRequest5 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    $sessionId = Select-String "(?<=`",`"SessionId`":`").+(?=`",`"CorrelationId`")" -InputObject $webRequest5 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    Get-Sixth $flowToken $sessionId $authMethodID $apiCanary $hpgrequestid
}

function Get-Sixth{
    #parse the sms token and send the final auth request
    $theURL = "https://login.microsoftonline.com/common/SAS/EndAuth"
    $method = "EndAuth"
    $smsToken = Read-Host -Prompt "Enter your SMS token here" 
    $body = "{`"Method`":`"${method}`",`"SessionId`":`"${sessionId}`",`"flowToken`":`"${flowToken}`",`"ctx`":`"${ctx}`",`"AuthMethodID`":`"${authMethodID}`",`"AdditionalAuthData`":`"${smsToken}`",`"PollCount`":`"1`"}"
    $webRequest6 = Invoke-WebRequest -WebSession $session -Method POST -Uri $theURL -userAgent $userAgent -ContentType $contentType -Body $body | Select-Object -ExpandProperty Content
    Parse-Sixth $webRequest6 $authMethodID $userAgent $apiCanary $smsToken $hpgrequestid
}

function Parse-Sixth{
    $canary = [uri]::EscapeDataString($apiCanary)
    $flowToken = Select-String "(?<=:false,`"FlowToken`":`").+(?=`",`"Ctx`")" -InputObject $webRequest6 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    $ctx = Select-String "(?<=`",`"Ctx`":`").+(?=`",`"SessionId`")" -InputObject $webRequest6 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    Get-Seventh  $authMethodID $canary $flowToken $ctx $smsToken $hpgrequestid $userAgent
}

function Get-Seventh{
    $contentType = "application/x-www-form-urlencoded"
    $theURL = "https://login.microsoftonline.com/common/SAS/ProcessAuth"
    $encodedUser = [uri]::EscapeDataString($Cred.UserName)
    $body = "request=${ctx}&mfaAuthMethod=${AuthMethodID}&canary=${canary}&otc=${smsToken}&rememberMFA=false&login=${encodedUser}&flowToken=${flowToken}&hpgrequestid=${hpgrequestid}"
    $webRequest7 = Invoke-WebRequest -WebSession $session -Method POST -Uri $theURL -userAgent $userAgent -ContentType $contentType -Body $body | Select-Object -ExpandProperty Content
    Parse-Seventh $webRequest7 $contentType $userAgent
}

Function Parse-Seventh{
    ###Parse "code","id_token" and "session_state"  out of the response
    $destURL = Select-String "(?<=</title></head><body><form method=`"POST`" name=`"hiddenform`" action=`").+(?=`"><input type=`"hidden`" name=`"code`")" -InputObject $webRequest7 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    $code = Select-String "(?<=name=`"code`" value=`").+(?=`" /><input type=`"hidden`" name=`"id_token`")" -InputObject $webRequest7 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    $idToken = Select-String "(?<=name=`"id_token`" value=`").+(?=`" /><input type=`"hidden`" name=`"session_state`")" -InputObject $webRequest7 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    $sessionState = Select-String "(?<=<input type=`"hidden`" name=`"session_state`" value=`").+(?=`" /><input type=`"hidden`" name=`"correlation_id`")" -InputObject $webRequest7 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    Get-Eighth $code $idToken $sessionState $contentType $userAgent $destURL
}

function Get-Eighth{
    $encodedUser = [uri]::EscapeDataString($Cred.UserName)
    $body = "code=${code}&id_token=${idToken}&session_state=${sessionState}"
    $webRequest8 = Invoke-WebRequest -WebSession $session -Method POST -Uri $destURL -userAgent $userAgent -ContentType $contentType -Body $body
    Parse-Eighth $webRequest8 $userAgent $contentType 
}

function Parse-Eighth{
    $absoluteURL = Select-String "(?<=`"siteAbsoluteUrl`":`").+(?=`",`"siteId`":`")" -InputObject $webRequest8 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    $absoluteURLObject = [uri]$absoluteURL
    $relativeURL = $absoluteURLObject.LocalPath
    $hostURL = $absoluteURLObject.Host
    Get-Ninth $absoluteURLObject $relativeURL $hostURL $userAgent
}

function Get-Ninth{
    Get-Content .\users.txt | ForEach-Object{
        $user = $_
        $personal = $absoluteURLObject.segments[1]
        $userURL = $absoluteURLObject.segments[2]
        $userURL = $userURL -split '(_)'
        $userURL = $userURL[1,2,3,4] -join ''
        $userURL = "${personal}${user}${userURL}"        
        $encodedRelativeURL = [uri]::EscapeDataString($userURL)
        $encodedRelativeURL = $encodedRelativeURL.replace("_","%5f")
        $finalURL = "https://${hostURL}/${userURL}/_api/web/GetList(@listUrl)/RenderListDataAsStream?@listUrl=%27%2F${encodedRelativeURL}%2FDocuments%27&View=&RootFolder=%2F${encodedRelativeURL}%2FDocuments%2FShared%20with%20Everyone"
        $contentType = "application/json;odata=verbose"
        $Body = 
@"
{"parameters":{"__metadata":{"type":"SP.RenderListDataParameters"},"ViewXml":"<View ><Query><OrderBy><FieldRef Name=\"LinkFilename\" Ascending=\"true\"></FieldRef></OrderBy></Query><ViewFields><FieldRef Name=\"FSObjType\"/><FieldRef Name=\"LinkFilename\"/><FieldRef Name=\"Modified\"/><FieldRef Name=\"Editor\"/><FieldRef Name=\"FileSizeDisplay\"/><FieldRef Name=\"SharedWith\"/><FieldRef Name=\"_ip_UnifiedCompliancePolicyUIAction\"/><FieldRef Name=\"ItemChildCount\"/><FieldRef Name=\"FolderChildCount\"/><FieldRef Name=\"SMTotalFileCount\"/><FieldRef Name=\"SMTotalSize\"/></ViewFields><RowLimit Paged=\"TRUE\">100</RowLimit></View>","AllowMultipleValueFilterForTaxonomyFields":true}}
"@
        try{
        $webRequest9 = Invoke-WebRequest -WebSession $session -Method POST -Uri $finalURL -userAgent $userAgent -ContentType $contentType -Body $body | Select-Object -ExpandProperty content
        Parse-Results $webRequest9 $user
        } 
        catch{
            $err_message=("`r`nFYI, some exception occurred that prevented access to " + $user + "`'s Shared with Everyone Folder.`r`nMaybe the folder doesn't exist?`r`n")
            Set-failure $err_message
        }
    }
}

function Parse-Results{
    $parse = Select-String "(?<=FileLeafRef`"`:\s`").+(?=`",)" -InputObject $webRequest9 -AllMatches | foreach {$_.Matches} | Select-Object -ExpandProperty value
    $parse_obj = New-Object psobject
    $parse_obj | Add-Member NoteProperty name ($user)
    $parse_obj | Add-Member NoteProperty result ($parse)
    if ($parse_obj.result -eq $null){
        echo ($user + "`'s `"Shared with Everyone`" Folder Appears Empty to You")
    }
    else{
        Write-Output $parse_obj | Format-Table -Wrap
    }
}

function Set-Failure{
    ###Error Handling
    Write-Host -ForegroundColor:Red $err_message
}
Set-Proxy
Get-Cred