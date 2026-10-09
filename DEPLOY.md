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
2. Compute the SHA-256 of **the actual published UTF-8 bytes** of `LicenseFix.ps1` (not a local file with different newline endings).
3. Update `$lfExpectedSHA256` in `launch.ps1` to that digest in the same release.
4. Verify the raw GitHub content and try the read-only Scan first.
5. Avoid editing production branches without revision review.

Current SHA-256 of `LicenseFix.ps1` in this GitHub release:

`783FAC6EDF3108758A74F4897E5F0D94AA6E11D7BD0E63C02C8D40836EC19977`

## Optional Cloudflare domain

Deploy `deploy/cloudflare-worker.js` as a Cloudflare Worker. Attach a **Custom Domain** such as `fix.thangtin.com` (only if you own and control that hostname), ensure DNS and HTTPS are correct, and test:

```powershell
irm https://fix.thangtin.com
```

It should return PowerShell source, not HTML, 404, or a JavaScript page. After manually reviewing the result, you may run the one-liner with `| iex`. Domain is not configured by uploading to GitHub.

## Notes

- The repository is public. Never commit genuine product keys, personal records, credentials, or Windows license-store backups.
- No known Windows run has been completed for this preview; testing is required before production repairs.
- The original draft ZIP from earlier messages may have a different core script/hash. Use GitHub `main` as the source of truth for the online launcher.
