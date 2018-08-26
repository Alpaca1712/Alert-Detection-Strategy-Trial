# Alert-Detection-Strategy-Trial
Specter-Ops ADS Exercise
<br>
# Scenario:
A client has asked you to help them gain as much value as possible out of
their centralization of Windows Event Logs and Sysmon Event Logs. Design
and document an ADS to address a Technique of your choosing from the
[MITRE ATT&CK Framework](https://attack.mitre.org/wiki/Windows_Technique_Matrix)

# Thoughts on this exercise.
  The technique that was used in this scenario was Credential Dumping, and building an Alert Detection Strategy for this meant leveraging Sysmon tools to correspond with real time detection methods and create alerts for anomolies. Utilizing tools like mimikatz, H1N1, and even using Windows Registry commands an attacker can gather local user hashes, and can authenticate themselves as that local user. 
    That would potentially make an outsider attack look like an insider threat by utilizing those credentials. Researching the possible attack vectors, proactive monitoring is crucial for the ADS to be succesful, and be utilized to its fullest. This exercise has made me learn about attack vectors I previously was not aware of. 
