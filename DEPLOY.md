# Deploy LicenseFix Online

Repo: https://github.com/orderthangtinstore-creator/licensefix

## PowerShell launcher

Open Windows PowerShell 5.1+ as Administrator, inspect the source, then run:

```powershell
irm https://raw.githubusercontent.com/orderthangtinstore-creator/licensefix/main/launch.ps1 | iex
```

The bootstrapper fetches `LicenseFix.ps1`, checks the SHA-256 of the downloaded bytes against the pinned value inside `launch.ps1`, and only then executes. It does **not** validate the downloaded launcher itself: an authenticated, commit-pinned URL is safer for managed computers.

## Updating the core

1. Work in a branch; review changes and test on a Windows VM.
2. Keep both `.ps1` files as LF in Git. Keep `launch.ps1` ASCII without a BOM so `irm ... | iex` works in Windows PowerShell 5.1.
3. Compute SHA-256 from the exact Git blob or downloaded raw `LicenseFix.ps1`, including its UTF-8 BOM. A Windows working copy with CRLF can have a different hash.
4. Update `$lfExpectedSHA256` in `launch.ps1` and run the repository CI checks.
5. Verify the live short-domain launcher and raw GitHub bytes, then try the read-only Scan first.

Current SHA-256 of `LicenseFix.ps1` in this GitHub release:

`9FD3A207534FFDCB9B83E40B910C9377CD4C57911EDFB95ABA927DCF95F331D9`

## Optional Cloudflare domain

Deploy `deploy/cloudflare-worker.js` as a Cloudflare Worker. Attach a **Custom Domain** such as `fix.thangtin.com` (only if you own and control that hostname), ensure DNS and HTTPS are correct, and test:

```powershell
irm https://fix.thangtin.com
```

It should return PowerShell source, not HTML, 404, or a JavaScript page. After manually reviewing the result, you may run the one-liner with `| iex`. Domain is not configured by uploading to GitHub.

## Notes

- The repository is public. Never commit genuine product keys, personal records, credentials, or Windows license-store backups.
- Read-only inventory and menu regression checks ran on Windows PowerShell 5.1. Registry/hosts repairs and real key installation remain untested and require VM validation before production use.
- The original draft ZIP from earlier messages may have a different core script/hash. Use GitHub `main` as the source of truth for the online launcher.
