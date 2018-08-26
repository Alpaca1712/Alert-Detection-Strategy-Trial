# Goal
Detect attempts by potentially malicious activity in the Security Account Manager (SAM) to discover the presence of a possible Credential Dumping Instance.

# Categorization
These attempts are categorized as [Credential Access](https://attack.mitre.org/wiki/Technique/T1003).

# Strategy Abstract
The strategy will function as follows: 

* Leverage the Sysmon Logs to Monitor activity on the SAM
* Look for any potential malicious activity on the SAM
* Alerts of Anomolies occuring to the team.

# Technical Context
[System Monitor (Sysmon)](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows Event log. 

A SAM is a database file that holds account informatoin for local users. It holds your credentials as hashes which authenticate local users.

Extracting the data from the [Security Account Manager (SAM)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc756748(v=ws.10)) is as simple as some Windows Registry [(Reg)](https://attack.mitre.org/wiki/Software/S0075) commands.

These are some Reg commands than can be used to extract the SAM data locally:

```
>>> reg save HKLM\sam sam
```
OR
```
>>> reg save HKLM\system system
```
An attacker can then use Creddump7 to process the SAM data and recieve the hashes.



# Blind Spots and Assumptions

This strategy relies on the following assumptions: 
* System Monitoring tools are opperating correctly on the system.
* Process execution events are being recorded.
* Logs from endpoint detection tooling are reported.
* Attacker toolkits will extract the data in the SAM to process it locally.

A blind spot will occur if any of the assumptions are violated. For instance, the following would not trip the alert: 
* System Monitoring tools are tampered with or disabled.
* Obfuscation occurs in the monitoring of Sysmon Logs which defeats our regex.

# False Positives
There are several instances where false positives for this ADS could occur:
* The user utilizes scritpts that contain credit dumping funcitonality.


# Priority
The priority is set to medium-low under all conditions.

# Validation
Validation can occur for this ADS by using a hash dumper such as mimikatz to collect, store, and utilized the hash collected from the SAM to autheticate them on any machine. 

# Response
In the event that this alert fires, the following response procedures are recommended: 

* Look at management tooling to identify if the SAM was accessed.
  * If an unknown user  is attempting to access the SAM maliciously.
* Look at the process that triggered this alert. Walk the process chain.
  * What process triggered this alert?
  * What was the user the process ran as?
  * Are there any unusual discrepancies in this chain?
* Look at the process that triggered this alert. Inspect the binary.
  * Is this a shell process?
  * Is the process digitally signed?
  * Is the parent process digitally signed?
  * How prevalent is this binary?
* Does this appear to be user-generated in nature?
  * Is this running in a long-running shell?
  * Are there other indicators this was manually typed by a user?
  * If the activity may have been user-generated, reach out to the user via our chat client and ask them to clarify their behavior.
* If the user is unaware of this behavior, escalate to a security incident.
* If the process behavior seems unusual, or if the SAM was not utilized in the alerted instance, escalate to a security incident. 

# Additional Resources
* [mimikatz Documentation](https://github.com/gentilkiwi/mimikatz/blob/master/README.md)
  * Credential Dumper Capable of obtaining Plaintext Windows Credentials
  
* [MimiPenguin Documentation](https://github.com/huntergregal/mimipenguin)
  * Similar to Mimikatz, but built mostly for Linux environments.
