# vci-directory-auditor

Audit tool for the [VCI directory](https://github.com/the-commons-project/vci-directory/).

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
- `-d, --dirpath <dirpath>`: path of the directory to audit
- `-o, --outpath <outpath>`: output path for the directory with keys
- `-l, --outlogpath <outlogpath>`: 'output path for the directory log

For example, to audit the VCI directory stored in this repository, run:
```
npm run audit -- -d ../../vci-issuers.json
```

## Checks

The tool does the following:
 - Store a copy of the directory with the issuer JWK sets
