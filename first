#Declare Variables
$LIST = klist
$TimeMatches=@()
$Regex = '\d\/(\d{1}|\d{2})\/(\d){4} \d.*\d'
$TicketCount = 0
$DateTimeFormat = 'M/d/yyyy H:mm:ss'
$TimeCounter = 0
$SuspiciousTicket = @()

#Attempts to match all times in klist and dumps them into a psobject for collection
foreach($Line in $LIST | Select-String  -Pattern '(Start Time)|(End Time)') {
  $Line -match $Regex
  $StartDateTime = [DateTime]::ParseExact($Matches[0],$DateTimeFormat,$null)
  $TimeMatches += $StartDateTime
  $TicketCount++
}
#Iterates through all times of all Tickets to detect tickets with expiration times greater than 10 hours
$result = for($TicketCount -gt 0; $TimeCounter -lt $TicketCount; $TimeCounter+=2){
  $TimeDifference = New-TimeSpan $TimeMatches[$TimeCounter] $TimeMatches[$TimeCounter+1]
  if($TimeDifference.TotalHours -gt 10){
    #Creates object to store ticket and device properties to be sent over UDP or any other protocol the user would like.
'This alert has detected a suspicious ticket on an endpoint. It works by checking if the expiration time of a ticket is greater than 10-hours. This typically indicates the presence of a golden ticket or silver ticket.';
      }else {'No suspicious TGT'}
} $result | Out-File $env:TEMP\tgt.txt
