Fix-SystemHealth
An interactive PowerShell script that checks a Windows 10/11 PC's security posture and drivers, then fixes the safe things, asking before every change.

It detects the hardware at runtime (CPU vendor, motherboard, BIOS, drivers), so the same script works on any machine.

What it does
Step	Action	Changes system?
0	Create a System Restore point	Yes (asks)
1	OS support status, TPM, Secure Boot, BitLocker, VBS	No
2	Enable Defender Network Protection + PUA blocking	Yes (asks)
3	Remove legacy PowerShell 2.0 engine	Yes (asks)
4	Install pending driver updates from Windows Update	Yes (asks)
5	Upgrade selected packages via winget	Yes (asks)
6	List devices with errors; offer Intel DSA / AMD chipset drivers	Yes (asks)
7	Report old BIOS, old third-party drivers, local account hygiene	No
Deliberately not automated: BIOS flashing, OS upgrades, uninstalling drivers.

Usage
From an elevated PowerShell:

Set-ExecutionPolicy -Scope Process Bypass -Force
.\Fix-SystemHealth.ps1
Parameters
Parameter	Default	Description
-Yes	off	Answer yes to every prompt (non-interactive)
-OldDriverYears	3	Flag third-party drivers older than this
-WingetIds	VC++ 2015+ x64/x86	Package IDs to upgrade; @() for none, '*' for all
-LogPath	Desktop	Where the transcript log is written
.\Fix-SystemHealth.ps1 -OldDriverYears 2 -WingetIds '*'
Requirements
Windows 10 or 11, PowerShell 5.1+
Administrator rights
winget (App Installer) for steps 5–6
Notes
The log file contains your machine's hardware and driver inventory, so review it before you share it.
Use at your own risk. A restore point is offered first so changes can be rolled back.
