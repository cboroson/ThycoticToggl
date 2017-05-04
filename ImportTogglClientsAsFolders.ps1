#######################################################
###                                                 ###
###  Filename: ImportTogglClientsAsFolders.ps1      ###
###  Author:   Craig Boroson                        ###
###  Version:  1.0                                  ###
###  Date:     May 1, 2017                          ###
###  Purpose:  Collect data from the Toggl website  ###
###            related to customer names.           ###
###            Create new customer folders if       ###
###            they don't already exist.            ###
###                                                 ###
#######################################################

Import-Module C:\Scripts\ImportTogglClientsAsFolders\Function-Write-Log.psm1
Import-Module C:\Scripts\ImportTogglClientsAsFolders\Function-Credentials.psm1

$date = get-date -Format MM-dd-yyyy
$logfile = "c:\scripts\ImportTogglClientsAsFolders\Logs\ImportTogglClientsAsFolders_$Date.log"

# Note: The key below is associated to Tara Boroson's Toggl account
#       It will need to be changed if this Toggl account is removed or disabled.
$pass = "api_token"
$username = get-credentials -username $pass -path "c:\scripts\ImportTogglClientsAsFolders"
$pair = "$($username):$($pass)"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)
$basicAuthValue = "Basic $base64"
$TogglHeaders = @{ Authorization = $basicAuthValue }
$contentType = "application/json"
$workspace_id = "656157" # Note: this is HA's unique workspace identifier

# Thycotic logon info
$adminUsername = 'apiUser'
$adminPassword = get-credentials -username $adminUsername -path "c:\scripts\ImportTogglClientsAsFolders"
$adminDomain = 'local'
$uri = "https://hainc.secretservercloud.com"
$api = "$uri/api/v1" 


function Get-Token ($adminUserName, $adminPassword, $adminDomain, $api){
    try
    {  
        $creds = @{
           username = $adminUserName
           password = $adminPassword
           domain = $adminDomain
           grant_type = "password"
       }
       
        $token = ""
        write-log -Path $logfile -Level Info "Authenticating to Thycotic Secret Server"
        $response = Invoke-RestMethod "$uri/oauth2/token" -Method Post -Body $creds -ContentType "application/json"
    
        if($response -and $response.access_token)
        {
            write-log -Path $logfile -Level Info "Authenticatication Successful"
            $token = $response.access_token;
            return $token;
        }
        else
        {
            write-log -Path $logfile -Level Error "ERROR: Failed to authenticate."
            return
        }      
    }
    catch [System.Net.WebException]
    {
        write-log -Path $logfile -Level Error "----- Exception -----"
        write-log -Path $logfile -Level Error  $_.Exception
        write-log -Path $logfile -Level Error  $_.Exception.Response.StatusCode
        write-log -Path $logfile -Level Error  $_.Exception.Response.StatusDescription
        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd()
    
        write-log -Path $logfile -Level Error $responseBody 
    }
}


function add_folder ($foldername, $parentID) {

    #Get Folder Stub
    $folderStub = Invoke-RestMethod $api"/Folders/stub" -Method GET -Headers $headers -ContentType "application/json"

    $folderStub.FolderName = $foldername
    $folderStub.FolderTypeId = 1
    $folderStub.InheritPermissions = $true
    $folderStub.InheritSecretPolicy = $true
    $folderStub.ParentFolderId = $parentID
    $folderstub.SecretPolicyiD = -1

    $folderArgs = $folderStub | ConvertTo-Json -Compress

    $folderAddResult = Invoke-RestMethod $api"/folders" -Method POST -Body $folderArgs -Headers $headers -ContentType "application/json"
    $folderId = $folderAddResult.id 

    if($folderId -gt 1)
    {
        write-log -Path $logfile -Level Info "Successfully added folder for $foldername"
        write-log -Path $logfile -Level Info $($folderAddResult | ConvertTo-Json)
    }
    else
    {
        write-log -Path $logfile -Level Error "ERROR: Failed to add folder $foldername"
        return
    }    
}

# Toggl Authorization
#####################
Invoke-RestMethod -Uri https://www.toggl.com/api/v8/me -Headers $TogglHeaders -ContentType $contentType

# Thycotic Authorization
########################
$token = Get-Token -adminUserName $adminUsername -adminPassword $adminPassword -api $api
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", "Bearer $token")

# All Customers
###############
# This is the complete list of HA Customers.  The client name is used to cross reference across the Toggl
# queries and collect various types of hours for each customer.
$uriReport = "https://toggl.com/api/v8/workspaces/$workspace_id/clients"
$AllClients = Invoke-RestMethod -Uri $uriReport -Headers $TogglHeaders -ContentType $contentType

# All Folders
#############
# These are complete lists of Thycotic folders
$NetworkFolders = Invoke-RestMethod $api"/folders/lookup?take=5000&filter.parentFolderId=26" -Method Get -Headers $headers -ContentType "application/json"
$StorageFolders = Invoke-RestMethod $api"/folders/lookup?take=5000&filter.parentFolderId=27" -Method Get -Headers $headers -ContentType "application/json"

If ($NetworkFolders -eq $null -or $StorageFolders -eq $null) {
    Write-Log -Path $logfile -Level Error "Failed to retrieve list of folders from Thycotic.  Aborting script."
    Exit
}


# Create any folder that doesn't already exist
foreach ($client in $AllClients.name) {

    # Look in Network subfolder
    if ($client -in $NetworkFolders.records.value) {
        write-log -Path $logfile -Level Info "Network folder already exists for $client"
    }
    else {
        Write-Log -Path $logfile -Level Info "Creating Network folder for $client..."
        add_folder -foldername $client -parentID 26 
    }


    # Look in Storage subfolder
    if ($client -in $StorageFolders.records.value) {
        write-log -Path $logfile -Level Info "Storage folder already exists for $client"
    }
    else {
        Write-Log -Path $logfile -Level Info "Creating Storage folder for $client" 
        add_folder -foldername $client -parentID 27 
    }

}


