#######################################################
###                                                 ###
###  Filename: Function-Credentials.psm1            ###
###  Author:   Craig Boroson                        ###
###  Version:  1.0                                  ###
###  Date:     April 4, 2017                        ###
###  Purpose:  Save encrypted credentials to files  ###
###            Retrieve encrypted credentials       ###
###            from files.                          ###
###                                                 ###
#######################################################


function set-credentials ( $path, $username, $password ) {

    $credpath = "$path\$username.xml"
    New-Object System.Management.Automation.PSCredential($username, (ConvertTo-SecureString -AsPlainText -Force $password)) | Export-CliXml $credpath

    Return "Password saved for $username"

}


function get-credentials ( $path, $username ) {

    $credpath = "$path\$username.xml"
    if (Test-Path $credpath) {
        try {
            $cred = import-clixml -path $credpath -ErrorAction SilentlyContinue
            $password = $cred.GetNetworkCredential().password
        }
        catch { 
            $password = "Error retrieving password for $username"
        }
    }    
    else {
        $password = "Password not found for $username"
    }

    Return $password
}