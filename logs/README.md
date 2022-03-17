# VCI Directory Snapshot

This folder contains directory log, snapshot and audit files updated daily from the GitHub action [audit scripts](https://github.com/the-commons-project/vci-directory/blob/main/.github/workflows/vci-directory-audit.yaml):

* `audit-index.csv`: contains the IDs and timestamps for the git commits for the files in this folder. It can be used to retrieve specific versions of the directory log, snapshot and audit files.

* `daily_audit.json`: this file contains the daily audit of the VCI directory, including misc information about the directory entries and a list of issuers with audit errors.

* `daily_log.json`: contains the daily log of the VCI directory including, for each issuer: keys, TLS details, revocation lists (if any), errors and warnings.

* `daily_log_snapshot.json`: contains the daily snapshot of VCI non-erroneous issuers' keys and revocation lists.

* `vci_snapshot.json`: contains the evolving snapshot of the VCI non-erroneous issuers' keys and revocation lists.

* `vci_snapshot.sig`: contains the signature on the `vci_snapshot.json` file.

The audit script first retrieves all the keys and revocation lists from issuers, and logs TLS details, errors, and warning into `daily_log.json`. The `daily_audit.json` file is created using the current and previous version of `daily_log.json`, to report daily changes to the directory data and various other information. The `daily_log_snapshot.json` file is created from `daily_log.json` by filtering-out erroneous issuers, and by keeping only the keys and revocation lists. Finally, the `vci_snapshot.json` file is updated using the `daily_log_snapshot.json` content, replacing matching issuers data, while keeping non-matched older ones for archival purposes. The `vci_snapshot.json` is then signed, and the resulting signature is stored in `vci_snapshot.sig`.

The `vci_snapshot.json` provides the daily view of the VCI directory which can be used by validation apps to verify SMART Health Cards in an offline manner. Each entry is timestamped, so applications might chose to reject older keys (e.g., for issuers that have been offline for a long-time, which SHCs might still be in circulation). The snapshot signature can be verified using
```
openssl dgst -sha512 -verify  <(openssl x509 -in ../vci_snapshot.crt  -pubkey -noout) -signature vci_snapshot.sig vci_snapshot.json
```
