# LicenseFix v1.0.0 (preview)

Windows 10/11 and Microsoft Office license diagnostics and **reviewable, confirmed cleanup of residual activation settings**.

> **Preview:** Not yet tested on Windows. Test `Scan` in a disposable VM before using `Repair` on a real PC. Do not use this tool to disguise license state or alter SPP timestamps. A green result from a third-party scanner does not establish legal license ownership.

## Quick start (after files are published)

Open Windows PowerShell 5.1+:

```powershell
irm https://raw.githubusercontent.com/orderthangtinstore-creator/licensefix/main/launch.ps1 | iex
```

The launcher downloads `LicenseFix.ps1` and verifies its SHA-256 before executing. **The first-stage launcher itself is unpinned**, so for high-assurance use inspect the script and pin the GitHub commit.

On an elevated PowerShell console, use the menu:
- `1`: scan (read-only)
- `2`: show remediation plan
- `3`: backup + selectively remove verified residual Registry values, after typing `SUA`
- `4`: export JSON scan report
- `5`: `sfc /verifyonly`

The program **does not** automatically delete license keys, tamper with SPP `data.dat`/`tokens.dat`, change timestamps, or rewrite activation history.

## Components

- `LicenseFix.ps1` – diagnostics and scoped remediation.
- `launch.ps1` – online bootstrap with pinned SHA-256 of the second-stage script.
- `START_HERE.cmd` – local launcher.
- `CHECKLIST_19.md` – relationship to the 19 checks in License Info.
- `deploy/cloudflare-worker.js` – optional Cloudflare Worker for a short domain.
- `DEPLOY.md` – online deployment and update guidance.

Independent community utility. Not affiliated with Microsoft or [License Info](https://github.com/tiennnict/license.info.vn); that upstream project is licensed Apache-2.0. No code from the upstream repo is embedded here. No warranty is made regarding activation status.
