# Third-party notice

The Windows `DigitalProductId` decoding feature in `LicenseFix.ps1` was implemented after reviewing `ConvertFrom-DigitalProductId` in [tiennnict/license.info.vn](https://github.com/tiennnict/license.info.vn/blob/eac90d133bc1f4209d72992a837c89a2cc903839/WinLicCheck.ps1). The implementation is adapted for LicenseFix and was modified to show full keys only after a separate confirmation. The source project is licensed under Apache License 2.0; its license text is copied in [license-info-vn-APACHE-2.0.txt](license-info-vn-APACHE-2.0.txt).

LicenseFix does not adopt the source project's conclusions about a decoded Registry key. A decoded value can be a generic installation key or an old value and does not establish ownership of a license.
