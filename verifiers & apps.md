# Verifiers, wallets & apps

Both the [VCI Directory](https://github.com/the-commons-project/vci-directory/) 
and [SMART Health Cards specification](https://spec.smarthealth.cards/) are licensed under the [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). 
This means that virtually anyone can create an application that consumes, creates and verifies SMART Health Cards. 

The following table is not authoritative, but attempts to document the capabilities of commonly available apps capable of producing, consuming or verifying SMART Health Cards. 

|| QR code support | .smart-health-card support | API support | reads vaccinations | reads labs | time-delay to sync VCI issuer directory | verification business logic | links
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
SMART Health Card Verifier | yes (read only)        | no   | no | yes| no | daily | no
NYS Excelsior Pass Scanner | yes (read only)        | no?  | no | yes| yes? | ~~not at all~~ ? | yes? | [iOS](https://apps.apple.com/us/app/nys-excelsior-pass-scanner/id1552709177), [android](https://play.google.com/store/apps/details?id=gov.ny.its.healthpassport.verify), [developer](https://epass.ny.gov/privacy-scanner)
CommonPass                 | yes (read and produce) | yes  | yes? | yes | no? | periodic/manual | no (wallet) | [iOS](https://apps.apple.com/us/app/commonpass/id1548682047), android?, [developer](https://commonpass.org/)
CommonHealth               | (yes, read and produce)|      |||||| [android](https://play.google.com/store/apps/details?id=org.thecommonsproject.android.phr), [developer](https://www.commonhealth.org/)
CLEAR Health Pass          | yes (read only)        | ?    | ? | yes | yes | ? | yes? | [iOS](https://apps.apple.com/us/app/clear-fast-touchless-access/id1436333504), [android](https://play.google.com/store/apps/details?id=com.clearme.clearapp), [developer](https://www.clearme.com/healthpass)
New MITRE verifier web app | ?                      | ?    |?|?|?|? | yes?
Apple Health               | yes (read and produce) | yes  | yes | yes | yes | not at all (wallet) | no (wallet) | [developer](https://support.apple.com/en-us/HT212752)
