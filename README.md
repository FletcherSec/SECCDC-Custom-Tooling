Subsist.ps1 -> A modular windows persistence framework
 - Utilizes the below files for dll injection persistence mechanisms:
   - SvcHealthMonLSA.c
   - SvcHealthMonLSA.def
   - SvcHealthMonTimeProv.c

WLcredRotator.ps1 -> takes in a wordlist in the format {username}:{password} and securely rotates credentials via memory loading (credentials should be hidden from all logs)

restartServicesPS.ps1 -> a powershell script which checks if specified services are running and starts them if they are not.  Intended as a payload to be used restart killed services via persistence mechanisms.

loginit.ps1 -> initiates a plethora of windows logs useful for attack triaging and forensics, installs and enables sysmon.

GPO Policy/Import-GPOPolicies.ps1 -> Modular GPO importer to apply specified logically grouped policies inside `gpo_policies/`.  Can change and add to `gpo_policies/` to better fit use case.

toolInstaller.ps1 -> list of tools whose installation should be automated.  Ideally should have a commented list incase manual installation is necessary.
