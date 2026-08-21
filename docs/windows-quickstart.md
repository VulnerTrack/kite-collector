# Installing Kite Collector on Windows

This guide explains how to install Kite Collector on Windows and connect it to
VulnerTrack.

## 1. Download Kite Collector

1. Go to the [Kite Collector releases page](https://github.com/VulnerTrack/kite-collector/releases).
2. Open the release marked as **Latest**.
3. Under **Assets**, download
   `kite-collector_windows_amd64_bin.exe`.
4. Wait for the download to finish.

> Download the `.exe` file directly. You do not need to download or extract
> the `.tar.gz` archive.

## 2. Start the installation

> **Administrator access is required.** The installer must be run as an
> administrator so it can register and start the Kite Collector Windows
> service.

1. Open the Windows **Downloads** folder.
2. Right-click `kite-collector_windows_amd64_bin.exe` and select
   **Run as administrator**.
3. When the User Account Control window appears, click **Yes**.
4. In the **Vulnertrack Kite Collector Setup** window, click **Install**.
5. Wait until the **Installation complete!** message appears.

## 3. Open the portal

1. When the installation is complete, click **Launch Portal**.
2. Kite Collector will open the portal in your default browser.

If the browser does not open automatically, go to:

```text
http://127.0.0.1:9090/kite-login
```

## 4. Sign in

1. In the portal, click **Sign in**.
2. Sign in with your VulnerTrack account.
3. If the browser asks for permission to continue, approve the request.

## 5. Select an organization

1. Select the organization you want to associate with the computer.
2. Confirm your selection.
3. Wait while Kite Collector completes the enrollment.

## 6. Open the dashboard

When enrollment is complete, the Kite Collector dashboard will open. From the
dashboard, you can confirm that the computer is connected and view:

- Operating system information.
- Installed software and license status.
- Hardware and computer configuration.
- Findings detected by Kite Collector.

Installation and enrollment are now complete.

## If Windows blocks the file

If the **Windows protected your PC** message appears:

1. Click **More info**.
2. Confirm that the downloaded file is the Kite Collector executable.
3. Click **Run anyway**.

For advanced options or automated deployments, see the
[complete installation documentation](window_install.md).
