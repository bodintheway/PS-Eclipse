# PS-Eclipse ![image](https://github.com/user-attachments/assets/28a5becf-d25d-422c-a10d-d5d94c0ac268)



Scenario : You are a SOC Analyst for an MSSP (Managed Security Service Provider) company called TryNotHackMe .

A customer sent an email asking for an analyst to investigate the events that occurred on Keegan's machine on Monday, May 16th, 2022 . The client noted that the machine is operational, but some files have a weird file extension. The client is worried that there was a ransomware attempt on Keegan's device. 

Your manager has tasked you to check the events in Splunk to determine what occurred in Keegan's device. 


### A suspicious binary was downloaded to the endpoint. What was the name of the binary?


First thing i did was to do index=* to see what we are working with
![image](https://github.com/user-attachments/assets/e1b5c88b-d822-4329-9554-5461370b1ecb)


I clicked into the `Image` field to view all the executable paths being recorded. This field typically contains the full path to the executable that was launched on the endpoint.
![image](https://github.com/user-attachments/assets/64bdab34-ede0-49c6-8cdd-b149d924d23f)


### What is the address the binary was downloaded from? Add http:// to your answer & defang the URL.

To identify the address from which the suspicious binary `OUTSTANDING_GUTTER.exe` was downloaded, I started by investigating the **command line activity** related to the process, especially looking for PowerShell commands.

### Steps:

1. **Checked the command line logs** in Splunk for PowerShell or other command executions involving the binary:

```spl
index=* (image="*powershell.exe" OR image="*cmd.exe")
| search message="*OUTSTANDING_GUTTER.exe*"
| table _time user image message
| sort -_time
![image](https://github.com/user-attachments/assets/c3d11204-20a0-4c12-87f8-6aea1e359fe3)
```
![image](https://github.com/user-attachments/assets/69a03c45-180b-4f39-af77-0914b4371e25)
![image](https://github.com/user-attachments/assets/2804ef67-8c4e-41af-ad84-5cdbbee08de6)

hxxp[://]886e-181-215-214-32[.]ngrok[.]io

### What Windows executable was used to download the suspicious binary? Enter full path.

we already know this
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe


### What command was executed to configure the suspicious binary to run with elevated privileges?



Looking through the decoded PowerShell, we can see that a task was scheduled with the /RU “SYSTEM” switch which will create a scheduled task and run it as SYSTEM.
![image](https://github.com/user-attachments/assets/1a16c4c7-3180-461e-b6bb-96792438c69f)

What permissions will the suspicious binary run as? What was the command to run the binary with elevated privileges? (Format: User + ; + CommandLine)

To find out what permissions the suspicious binary ran under and how it was executed with elevated privileges, I analyzed the process execution logs in Splunk.

- The binary `OUTSTANDING_GUTTER.exe` was running as **`NT AUTHORITY\SYSTEM`**, which is the highest system privilege on Windows.
- I found a command line where the binary was launched via the Windows Task Scheduler using `schtasks.exe`.
- The exact command was:

"C:\Windows\system32\schtasks.exe" /Run /TN OUTSTANDING_GUTTER.exe

yaml
Copy
Edit

- This command runs the scheduled task named `OUTSTANDING_GUTTER.exe` with SYSTEM privileges, effectively giving the binary elevated execution rights.

---

### Final Answer Format:

NT AUTHORITY\SYSTEM;"C:\Windows\system32\schtasks.exe" /Run /TN OUTSTANDING_GUTTER.exe

### The suspicious binary connected to a remote server. What address did it connect to? Add http:// to your answer & defang the URL.

To identify the remote server that `OUTSTANDING_GUTTER.exe` connected to, I filtered DNS query logs in Splunk with:
"OUTSTANDING_GUTTER.exe" TaskCategory="Dns query (rule: DnsQuery)"

![image](https://github.com/user-attachments/assets/38882229-cee2-48f9-a4c1-c5fcf346cb2b)


A PowerShell script was downloaded to the same location as the suspicious binary. What was the name of the file?


![image](https://github.com/user-attachments/assets/b7f20c71-d8d6-4bfd-aa50-73b39b23d40f)


The malicious script was flagged as malicious. What do you think was the actual name of the malicious script?
just check the hash in virus total for example
![image](https://github.com/user-attachments/assets/ec6235a5-803b-49ec-881e-cb880bf12372)
![image](https://github.com/user-attachments/assets/c2f4bd14-92aa-4c4d-b261-117ec207070f)


### A ransomware note was saved to disk, which can serve as an IOC. What is the full path to which the ransom note was saved?

this jsut search blacksun since we know the name and search thru the logs
![image](https://github.com/user-attachments/assets/e67ee142-a4f1-435a-9a25-0c64e3e789ad)
![image](https://github.com/user-attachments/assets/7017ebf3-d99a-4c32-a71b-d6b513b5b5f4)


### The script saved an image file to disk to replace the user's desktop wallpaper, which can also serve as an IOC. What is the full path of the image?

![image](https://github.com/user-attachments/assets/baf48982-8131-43fa-bc5a-39dac46e6cc5)

C:\Users\Public\Pictures\blacksun.jpg









