# vci-directory-auditor

Audit tool for the [VCI directory](https://github.com/the-commons-project/vci-directory/). Scripts in this project create snapshot (including issuer keys and revocation information) of the VCI directory, along with an audit log.

## Setup

Make sure [node.js](https://nodejs.org/) and [npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) are installed on your system; the latest Long-Term Support (LTS) version is recommended for both. [OpenSSL](https://www.openssl.org/) is also needed to validate TLS connections.

1. Get the source, for example using `git`
```
git clone -b main https://github.com/the-commons-project/vci-directory.git
cd vci-directory/scripts/vci-directory-auditor
```

2. Build the `npm` package
```
npm install
npm run build
```

## Usage

```
npm run audit -- <options>
```
where `<options>` are:
- `-o, --outlog <outlog>`: output directory log storing directory issuer keys, TLS details, CRLs, and errors/warnings
- `-s, --outsnapshot <outsnapshot>`: output snapshot file storing directory issuer keys for non-erroneous issuers
- `-p, --previous <previous>`: directory log file from a previous audit, for comparison with current one
- `-a, --auditlog <auditlog>`: output audit file on the directory
- `-d, --dirpath <dirpath>`: path of the directory to audit, uses "../../vci-issuers.json" by default
- `-v, --verbose`: verbose mode


For example, to audit the VCI directory stored in this repository, run:
```
npm run audit -- -d ../../vci-issuers.json
```

To create a directory snapshot `snapshot.json` (including issuer keys (and CRLs, if any)), a full directory log `today.json` (including issuer keys (and CRLs, if any), TLS config, and errors), and an audit log `audit.json` comparing it with a previous directory log `yesterday.json`, run:
```
npm run audit -- -d ../../vci-issuers.json -o today.json -s snapshot.json -p yesterday.json -a audit.json
```
## Checks

The tool does the following:
 - Parse the specified issuer directory. For each issuer:
   - Download and validate its JWK set
   - Check its default TLS connection configuration (see below)
   - If a CRL is specified in the JWK set, download and validate it
 - Output a directory log with the issuer JWK sets (and CRLs, if any), TLS configuration, and any detected errors
 - Output a directory snapshot with the issuer JWK sets (and CRLs, if any) for issuers without errors. This could be downloaded by SMART Health Card verifiers for offline validation
 - Audit the directory (optionally comparing to a previous log of the directory), and report:
   - The number of issuers
   - The number of added and deleted issuers
   - Issuer errors
   - Duplicated KIDs, issuer names, iss URLs

### TLS validation

This tool tests conformance with [IETF BCP 195](https://www.rfc-editor.org/info/bcp195), consisting of:
  - [RFC 7525](https://www.rfc-editor.org/info/rfc7525): Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)
  - [RFC 8996](https://www.rfc-editor.org/info/rfc8996): Deprecating TLS 1.0 and TLS 1.1

OpenSSL's `s_client` tool is used to connect to a specified server, testing the various aspects of the TLS connections. The following table summarizes the validated items.

|Section         |Rule|Command|Error if|Warn if|Note|
|----------------|--------------------|-------|--------|-------|----|
|3.1: TLS version|MUST support TLS 1.2    |openssl s_client -connect <server>:443 -tls1_2|fails||
|                |MUST NOT support TLS 1.0, 1.1 (and SSL)|openssl s_client -connect <server>:443 -no_tls1_2 -no_tls1_3|succeeds||From RFC 8996|
|3.2: Strict TLS |MUST support the HTTP Strict Transport Security (HSTS) header|curl -s -D- <server> \| grep -i Strict|no match||
|3.3: Compression|SHOULD disable TLS-level compression|openssl s_client ... \|  grep ""Compression: NONE"""||no match|
|3.4: TLS Session Resumption|*TODO*||||
|3.5: TLS Renegotiation|*TODO*||||
|3.6: Server Name Indication|*TODO*||||
|4.1: General Guideline|MUST NOT negotiate the cipher suites with NULL encryption. MUST NOT negotiate RC4 cipher suites. MUST NOT negotiate cipher suites offering less than 112 bits of security, including so-called "export-level" encryption (which provide 40 or 56 bits of security).|openssl s_client -connect \<server\>:443 -cipher NULL,EXPORT,LOW,3DES -tls1_2|succeeds||
||SHOULD NOT negotiate cipher suites that use algorithms offering less than 128 bits of security|*TODO*|||
||SHOULD NOT negotiate cipher suites based on RSA key transport, a.k.a. "static RSA"|*TODO*|||
||MUST support and prefer to negotiate cipher suites offering forward secrecy, such as those in DHE and ECDHE families|*TODO*|||
|4.2. Recommended Cipher Suites|The following cipher suites are RECOMMENDED:<br/> - TLS_DHE_RSA_WITH_AES_128_GCM_SHA256<br/> - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256<br/> - TLS_DHE_RSA_WITH_AES_256_GCM_SHA384<br/> - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384|*TODO*|||
|4.2.1. Implementation Details|SHOULD include TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as the first proposal to any server.  Servers MUST prefer this cipher suite over weaker cipher suites whenever it is proposed, even if it is not the first proposal|*TODO*|||
||Clients and servers SHOULD include the "Supported Elliptic Curves" extension and SHOULD support the NIST P-256 (secp256r1) curve|openssl s_client -connect \<server\>:443 -curves prime256v1 \| grep "Server Temp Key: ECDH, P-256, 256 bits"||no match|openssl doesn't have curve "secp256r1". Curve "prime256v1" uses ECDHE, curve "secp256k1" uses DHE. "|
|4.3: Public Key Length|DH key lengths of at least 2048 bits are RECOMMENDED|openssl s_client ... \| grep "Server public key is "||if "xxxx bits" is < 2048|
||Curves of less than 192 bits SHOULD NOT be used|*TODO*|||
||When using RSA, servers SHOULD authenticate using certificates with at least a 2048-bit modulus for the public key|*TODO*|||
||The use of the SHA-256 hash algorithm is RECOMMENDED|*TODO*|||
|4.4: Modular Exponential vs. Elliptic Curve DH Cipher Suites|*TODO*||||
|4.5: Truncated HMAC|MUST NOT use the Truncated HMAC extension||||
|6.1: Host Name Validation|||||
