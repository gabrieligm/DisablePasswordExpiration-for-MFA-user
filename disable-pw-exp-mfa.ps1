
Connect-AzureAd 
Connect-MsolService 

$Result=@() 
$users = Get-MsolUser -All
$users | ForEach-Object {
$user = $_
if ($user.StrongAuthenticationRequirements.State -ne $null){
$mfaStatus = $user.StrongAuthenticationRequirements.State
}else{
$mfaStatus = "Disabled" }
   

If ($user.UserType -eq "Member") {

        If ($mfaStatus -eq "Enforced") {
                Set-AzureADUser -ObjectId $user.UserPrincipalName -PasswordPolicies DisablePasswordExpiration 
       }
        Else {
                Set-AzureADUser -ObjectId $user.UserPrincipalName -PasswordPolicies none 
        }
        

        $Result += New-Object PSObject -property @{ 
        UserName = $user.DisplayName
        UserPrincipalName = $user.UserPrincipalName
        MFAStatus = $mfaStatus
        UserType = $user.UserType
        Policy= (Get-AzureADUser -ObjectId $user.UserPrincipalName).PasswordPolicies
        DayToExpire= (([datetime]::FromFileTime((Get-ADUser -Filter {EmailAddress -eq $user.UserPrincipalName} -Properties "msDS-UserPasswordExpiryTimeComputed")."msDS-UserPasswordExpiryTimeComputed"))-(Get-Date)).Days
        }

}
}

$Result | Select UserName,UserPrincipalName,MFAStatus,Usertype, Policy, DayToExpire
