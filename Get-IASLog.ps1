<#
.Synopsis
   Helps to read the IAS log file
.DESCRIPTION
   Helps to read the IAS log file accordingly with the link: https://technet.microsoft.com/en-us/library/cc771748(v=ws.10).aspx
   The function requires two parameters:
        - IASLogFilePath, mandatory, with the location of the IAS log file
        - IASUserName, optional, with a string to do a wildcard search for username
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-IASLog
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        $IASLogFilePath,

        # Param2 help description
        [string]
        $IASUSerName
    )

    Begin
    {
        $IASLogs = Import-Csv $IASLogFilePath -Header ComputerName, ServiceName, Record-Date, Record-Time, Packet-Type, User-Name, Fully-Qualified-Distinguished-Name, Called-Station-ID, Calling-Station-ID, Callback-Number, Framed-IP-Address, NAS-Identifier, NAS-IP-Address, NAS-Port, Client-Vendor, Client-IP-Address, Client-Friendly-Name, Event-Timestamp, Port-Limit, NAS-Port-Type, Connect-Info, Framed-Protocol, Service-Type, Authentication-Type, Policy-Name, Reason-Code, Class, Session-Timeout, Idle-Timeout, Termination-Action, EAP-Friendly-Name, Acct-Status-Type, Acct-Delay-Time, Acct-Input-Octets, Acct-Output-Octets, Acct-Session-Id, Acct-Authentic, Acct-Session-Time, Acct-Input-Packets, Acct-Output-Packets, Acct-Terminate-Cause, Acct-Multi-Ssn-ID, Acct-Link-Count, Acct-Interim-Interval, Tunnel-Type, Tunnel-Medium-Type, Tunnel-Client-Endpt, Tunnel-Server-Endpt, Acct-Tunnel-Conn, Tunnel-Pvt-Group-ID, Tunnel-Assignment-ID, Tunnel-Preference, MS-Acct-Auth-Type, MS-Acct-EAP-Type, MS-RAS-Version, MS-RAS-Vendor, MS-CHAP-Error, MS-CHAP-Domain, MS-MPPE-Encryption-Types, MS-MPPE-Encryption-Policy, Proxy-Policy-Name, Provider-Type, Provider-Name, Remote-Server-Address, MS-RAS-Client-Name, MS-RAS-Client-Version
        $newIASLogs = New-Object System.Collections.Generic.List[System.Object]
    }
    Process
    {
        foreach ($IASLog in $IASLogs) {
            if ($IASUSerName) {
                if (!($IASLog."User-Name" -like "*$IASUSerName*")){
                    continue
                }
            }
            
            switch ($IASLog."Packet-Type") {
                "1" { $IASLog."Packet-Type" = "Access-Request" }
                "2" { $IASLog."Packet-Type" = "Access-Accept" }
                "3" { $IASLog."Packet-Type" = "Access-Reject" }
                "4" { $IASLog."Packet-Type" = "Accounting-Request" }
            }
            switch ($IASLog."Authentication-Type") {
                "1" { $IASLog."Authentication-Type" = "PAP"}
                "2" { $IASLog."Authentication-Type" = "CHAP"}
                "3" { $IASLog."Authentication-Type" = "MS-CHAP"}
                "4" { $IASLog."Authentication-Type" = "MS-CHAP v2"}
                "5" { $IASLog."Authentication-Type" = "EAP"}
                "7" { $IASLog."Authentication-Type" = "None"}
                "8" { $IASLog."Authentication-Type" = "Custom"}
            }
            switch ($IASLog."Reason-Code") {
                "0"  { $IASLog."Reason-Code" = "IAS_SUCCESS"}
                "1"  { $IASLog."Reason-Code" = "IAS_INTERNAL_ERROR"}
                "2"  { $IASLog."Reason-Code" = "IAS_ACCESS_DENIED"}
                "3"  { $IASLog."Reason-Code" = "IAS_MALFORMED_REQUEST"}
                "4"  { $IASLog."Reason-Code" = "IAS_GLOBAL_CATALOG_UNAVAILABLE"}
                "5"  { $IASLog."Reason-Code" = "IAS_DOMAIN_UNAVAILABLE"}
                "6"  { $IASLog."Reason-Code" = "IAS_SERVER_UNAVAILABLE"}
                "7"  { $IASLog."Reason-Code" = "IAS_NO_SUCH_DOMAIN"}
                "8"  { $IASLog."Reason-Code" = "IAS_NO_SUCH_USER"}
                "16" { $IASLog."Reason-Code" = "IAS_AUTH_FAILURE"}
                "17" { $IASLog."Reason-Code" = "IAS_CHANGE_PASSWORD_FAILURE"}
                "18" { $IASLog."Reason-Code" = "IAS_UNSUPPORTED_AUTH_TYPE"}
                "32" { $IASLog."Reason-Code" = "IAS_LOCAL_USERS_ONLY"}
                "33" { $IASLog."Reason-Code" = "IAS_PASSWORD_MUST_CHANGE"}
                "34" { $IASLog."Reason-Code" = "IAS_ACCOUNT_DISABLED"}
                "35" { $IASLog."Reason-Code" = "IAS_ACCOUNT_EXPIRED"}
                "36" { $IASLog."Reason-Code" = "IAS_ACCOUNT_LOCKED_OUT"}
                "37" { $IASLog."Reason-Code" = "IAS_INVALID_LOGON_HOURS"}
                "38" { $IASLog."Reason-Code" = "IAS_ACCOUNT_RESTRICTION"}
                "48" { $IASLog."Reason-Code" = "IAS_NO_POLICY_MATCH"}
                "64" { $IASLog."Reason-Code" = "IAS_DIALIN_LOCKED_OUT"}
                "65" { $IASLog."Reason-Code" = "IAS_DIALIN_DISABLED"}
                "66" { $IASLog."Reason-Code" = "IAS_INVALID_AUTH_TYPE"}
                "67" { $IASLog."Reason-Code" = "IAS_INVALID_CALLING_STATION"}
                "68" { $IASLog."Reason-Code" = "IAS_INVALID_DIALIN_HOURS"}
                "69" { $IASLog."Reason-Code" = "IAS_INVALID_CALLED_STATION"}
                "70" { $IASLog."Reason-Code" = "IAS_INVALID_PORT_TYPE"}
                "71" { $IASLog."Reason-Code" = "IAS_INVALID_RESTRICTION"}
                "80" { $IASLog."Reason-Code" = "IAS_NO_RECORD"}
                "96" { $IASLog."Reason-Code" = "IAS_SESSION_TIMEOUT"}
                "97" { $IASLog."Reason-Code" = "IAS_UNEXPECTED_REQUEST"}
            }

            $newIASLogs.Add($IASLog)
        }
    }
    End
    {
        $newIASLogs | Out-GridView -Title "IAS Logs for file in $IASLogFilePath"
    }
}



