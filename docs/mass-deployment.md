# Mass deployment

The local kite-collector dashboard includes **Mass deployment**. It generates a
single short-lived Ansible package for Windows, Linux, and macOS targets:

1. Open the dashboard and select **Mass deployment**.
2. Press **Discover computers**. One click combines TCP scanning, SSH banners,
   Bonjour/mDNS, NetBIOS, SSDP, and WS-Discovery. Kite shows the detected local
   IP and queries only its local `/24` after explicit confirmation.
3. Select the compatible computers already discovered in **Machines**. Kite
   derives their operating system and architecture automatically. Additional
   hosts or IP addresses can still be entered as `hostname,os,arch`.
4. Press **Generate deployment package**. Kite automatically requests one
   single-use, two-hour PKI credential per computer and downloads the ZIP. The
   operator never copies or types enrollment credentials.
5. Move the ZIP to a Linux control computer that can reach the targets, unzip
   it, and run `./deploy.sh`.

For a version-pinned, rolling deployment to hundreds of domain-joined Windows
computers, use the [Ansible fleet deployment](../deploy/ansible/README.md).

## Prepare Windows computers without copying files

The same command can be run on any number of Windows 7/8/10/11 and Windows
Server 2008 R2 or newer computers. On each one, open **Command Prompt (CMD) as
Administrator** and paste:

```cmd
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f & sc.exe config WinRM start= auto & sc.exe start WinRM & winrm quickconfig -quiet & netsh advfirewall firewall add rule name="Kite WinRM HTTP 5985" dir=in action=allow protocol=TCP localport=5985 profile=any remoteip=localsubnet & netstat -ano | findstr ":5985"
```

This command only enables the WinRM management channel; it does not install or
enroll Kite and contains no token, credential, or computer-specific value. The
`LocalAccountTokenFilterPolicy` value lets a local administrator account manage
the computer remotely; without it, deployment fails with `REMOTE_UAC_FILTERED`.
The firewall rule accepts connections only from the local subnet. A line
containing `:5985` should appear when it succeeds. The generated ZIP carries the
same command in `bootstrap/windows/WINDOWS-COMMAND.txt`, plus
`Enable-KiteWinRM.ps1` and `GPO-SETUP.md` for rolling it out through Group
Policy or Intune instead of visiting each computer.

After running it on the selected computers, generate one ZIP and run
`./deploy.sh` once from Linux. The deployment installs and enrolls every
computer using its unique token from the ZIP. For each Windows target,
`deploy.sh` suggests `COMPUTER-NAME\Administrator`; press Enter to accept it or
type another administrative account, so packages with hundreds of computers
need no per-host editing.

## Credentials

The script prompts for AD/WinRM and SSH credentials at runtime; infrastructure
passwords are not written to the package. Windows targets require WinRM, while
Linux and macOS targets require SSH and privilege escalation. The enrollment
credentials are confidential and are contained in the generated ZIP, so delete
the ZIP after deployment or when they expire. The collector release, PKI
endpoint, and unique per-computer agent codes are supplied by the controller
and are not operator inputs.

## Operating-system detection

Operating-system detection uses high-confidence evidence such as WinRM or an
SSH banner that identifies the distribution. If the network or firewall offers
no conclusive signal, Kite leaves the OS unselected rather than risk deploying
to a router, printer, or another non-computer device. When a host advertises
OpenSSH but cannot be distinguished as Linux or macOS, the package performs
that check after connecting, detects `amd64`/`arm64`, and saves the result in
`detected-platforms.csv`.

Windows 7 and 32-bit computers automatically get the isolated legacy collector;
see [legacy/windows7/README.md](../legacy/windows7/README.md).
