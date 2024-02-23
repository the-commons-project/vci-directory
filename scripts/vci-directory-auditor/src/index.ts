// Audit script for the VCI issuers directory

import { Command } from 'commander';
import got from 'got';
import fs from 'fs';
import * as jose from 'jose';
import path from 'path';
import date from 'date-and-time';
import Url from 'url-parse';
import { AuditLog, CRL, DirectoryLog, IssuerKey, IssuerKids, IssuerLogInfo, TlsDetails, TrustedIssuers } from './interfaces';
import { auditTlsDetails, getDefaultTlsDetails } from './bcp195';
import * as forge from 'node-forge';

interface KeySet {
    keys : IssuerKey[]
}

interface Options {
    outlog: string;
    outsnapshot: string;
    previous: string;
    auditlog: string;
    dirpath: string;
    notls: boolean,
    verbose: boolean;
}

//
// program options
//
const program = new Command();
program.option('-o, --outlog <outlog>', 'output directory log storing directory issuer keys, TLS details, CRLs, and errors/warnings');
program.option('-s, --outsnapshot <outsnapshot>', 'output snapshot file storing directory issuer keys for non-erroneous issuers');
program.option('-p, --previous <previous>', 'directory log file from a previous audit, for comparison with current one');
program.option('-a, --auditlog <auditlog>', 'output audit file on the directory');
program.option('-d, --dirpath <dirpath>', 'path of the directory to audit');
program.option('-n, --notls', 'do not run the TLS audit (using OpenSSL)');
program.option('-v, --verbose', 'verbose mode');
program.parse(process.argv);
const currentTime = new Date();

// process options
const options = program.opts() as Options;
if (!options.dirpath) {
    options.dirpath = "../../vci-issuers.json";
}
const outputUTC = true;
if (!options.outlog) {
    options.outlog = path.join('logs', `directory_log_${date.format(currentTime, 'YYYY-MM-DD-HHmmss', outputUTC)}.json`);
}
if (!options.outsnapshot) {
    options.outsnapshot = path.join('logs', `directory_snapshot_${date.format(currentTime, 'YYYY-MM-DD-HHmmss', outputUTC)}.json`);
}
if (!options.auditlog) {
    options.auditlog = path.join('logs', `audit_log_${date.format(currentTime, 'YYYY-MM-DD-HHmmss', outputUTC)}.json`);
}

function validateX5cChain(x5c: string[]): boolean {
    if (!x5c || x5c.length === 0) {
        console.error('No x5c field provided.');
        return false;
    }

    try {
        const certificates = x5c.map(cert => forge.pki.certificateFromAsn1(forge.asn1.fromDer(forge.util.decode64(cert))));

        // Simplified validation: verify that each certificate is signed by the next one in the chain
        for (let i = 0; i < certificates.length - 1; i++) {
            const childCert = certificates[i];
            const parentCert = certificates[i + 1];

            // Verify child certificate is signed by parent
            const childCertVerified = parentCert.verify(childCert);
            if (!childCertVerified) {
                console.error(`Certificate chain validation failed at index ${i}.`);
                return false;
            }
        }

        // TODO: Add more comprehensive checks, e.g., against a list of trusted CAs, certificate validity periods, and revocation lists.
        return true;
    } catch (error) {
        console.error('Error validating x5c certificate chain:', error);
        return false;
    }
}


// check if a key is a valid SHC key
async function isSHCKey(key: IssuerKey) {
    const jwk = key as jose.JWK;
    if (!jwk.kid || !jwk.crv || !jwk.kty || !jwk.use || !jwk.crv || !jwk.alg || !jwk.use || !jwk.x || !jwk.y) {
        return false; // missing fields
    }
    if (jwk.kid !== await jose.calculateJwkThumbprint(jwk, 'sha256')) {
        return false; // invalid kid
    }
    if (jwk.alg.toLowerCase() !== "es256" || jwk.use.toLowerCase() !== "sig" || jwk.crv.toLowerCase() !== "p-256") {
        return false; // wrong key type
    }

        // If the key has an 'x5c' field, validate the certificate chain
    if (key.x5c && key.x5c.length > 0) {
        // Validate the x5c certificate chain
        const isX5cValid = validateX5cChain(key.x5c);
        if (!isX5cValid) {
            console.error(`x5c certificate chain validation failed for key ID: ${key.kid}`);
            return false; // x5c certificate chain is invalid
        }
    }

    // everything is ok
    return true;
}

// download the specified directory
async function fetchDirectory(directoryPath: string, verbose: boolean = false) : Promise<DirectoryLog> {
    const issuers = JSON.parse(fs.readFileSync(directoryPath).toString('utf-8')) as TrustedIssuers;
    console.log(`Retrieving ${issuers.participating_issuers.length} issuers`);

    const issuerLogInfoArray: IssuerLogInfo[] = [];
    for (const issuer of issuers.participating_issuers) {
        const jwkURL = issuer.iss + '/.well-known/jwks.json';
        const issuerLogInfo: IssuerLogInfo = {
            issuer: issuer,
            keys: [],
            tlsDetails: undefined,
            crls: [],
            errors: [],
            warnings: []
        }
        const requestedOrigin = 'https://example.org'; // request bogus origin to test CORS response
        try {
            if (verbose) console.log("fetching jwks at " + jwkURL);
            const response = await got(jwkURL, { headers: { Origin: requestedOrigin }, timeout:5000 });
            if (!response) {
                throw "Can't reach JWK set URL: " + jwkURL;
            }
            const acaoHeader = response.headers['access-control-allow-origin'];
            if (!acaoHeader) {
                issuerLogInfo.warnings?.push("Issuer key endpoint does not contain a CORS 'access-control-allow-origin' header");
            } else if (acaoHeader !== '*' && acaoHeader !== requestedOrigin) {
                issuerLogInfo.warnings?.push(`Issuer key endpoint's CORS 'access-control-allow-origin' header ${acaoHeader} does not match the requested origin`);
            }
            const keySet = JSON.parse(response.body) as KeySet;
            if (!keySet) {
                issuerLogInfo.errors?.push("Failed to parse JSON KeySet schema");
            }

            // check each key; at least one must be a SHC key (some issuers might have non-SHC keys in their JWK set;
            // not best practice, but possible). All valid keys will be logged, but only valid SHC keys will appear in
            // the snapshot
            let hasSHCKey = false;
            let hasNonSHCKey = false;
            issuerLogInfo.keys = [];
            for await (const key of keySet.keys) { // using for loop because filter doesn't support async predicates
                try {
                    if (await isSHCKey(key)) {
                        hasSHCKey = true;
                    } else {
                        hasNonSHCKey = true;
                    }
                    issuerLogInfo.keys.push(key);
                }
                catch (err) {
                    issuerLogInfo.errors?.push("Error parsing key", (err as Error).toString());
                }
            }
            if (!hasSHCKey) {
                issuerLogInfo.errors?.push("No valid SHC key in issuer key set");
            }
            if (hasNonSHCKey) {
                issuerLogInfo.warnings?.push("Issuer key set contains non-valid keys for SHC issuance");
            }

        } catch (err) {
            issuerLogInfo.errors?.push((err as Error).toString());
        }
        // audit TLS configuration, if enabled
        if (!options.notls) {
            try {
                const tlsResult = getDefaultTlsDetails(new Url(issuer.iss).hostname);
                if (tlsResult) {
                    // we report TLS issues (OpenSSL error or TLS config issues) as warnings
                    if (typeof tlsResult === "string") {
                        issuerLogInfo.warnings?.push(tlsResult);
                    } else {
                        issuerLogInfo.tlsDetails = <TlsDetails>(tlsResult);
                        auditTlsDetails(issuerLogInfo.tlsDetails).map(a => issuerLogInfo.warnings?.push(a));
                    }
                }
            } catch (err) {
                // report TLS issues as warnings
                issuerLogInfo.warnings?.push((err as Error).toString());
            }
        }
        for (const key of issuerLogInfo.keys) {
            // the issuer has a card revocation list (CRL); fetch it
            if (key.crlVersion !== undefined) {
                try {
                    if (key.crlVersion <= 0) {
                        throw "Invalid crlVersion: " + key.crlVersion;
                    }
                    const crlURL = `${issuer.iss}/.well-known/crl/${key.kid}.json`;
                    if (verbose) console.log("fetching CRL at " + crlURL);
                    const response = await got(crlURL, { timeout:5000 });
                    if (!response) {
                        throw "Can't reach CRL at " + crlURL;
                    }
                    const crl = JSON.parse(response.body) as CRL;
                    if (!crl) {
                        throw "Can't parse CRL at " + crlURL;
                    }
                    if (!crl.rids || crl.rids.length == 0) {
                        issuerLogInfo.warnings?.push("Empty CRL at " + crlURL);
                    }
                    // check for rid duplicates
                    const ridsWithoutTimestamps: string[] = crl.rids.map(rid => rid.split('.')[0]);
                    if (Array.from(new Set(ridsWithoutTimestamps)).length !== ridsWithoutTimestamps.length) {
                        issuerLogInfo.warnings?.push("Duplicate rid values in CRL at " + crlURL);
                    }
                    issuerLogInfo.crls?.push(crl);
                } catch (err) {
                    issuerLogInfo.errors?.push((err as Error).toString());
                }
            }
        }
        issuerLogInfoArray.push(issuerLogInfo);
        process.stdout.write("."); // print progress marker (without newline, unlike console.log)
    }
    console.log("done"); // also puts a newline after the progress markers

    const directoryLog: DirectoryLog = {
        directory: "https://raw.githubusercontent.com/the-commons-project/vci-directory/main/vci-issuers.json",
        time: date.format(currentTime, 'YYYY-MM-DDTHH:mm:ss', outputUTC).concat('Z'),
        issuerInfo: issuerLogInfoArray
    }

    return directoryLog;
}

// get duplicates in a string array
function getDuplicates(array: string[]) : string[] {
    const set = new Set(array);
    const duplicates = array.filter(item => {
        if (set.has(item)) {
            set.delete(item);
        } else {
            return item;
        }
    });
    return Array.from(new Set(duplicates));
}

// audit the directory, optionally comparing it to a previously obtained directory
function audit(currentLog: DirectoryLog, previousLog: DirectoryLog | undefined) : AuditLog {
    // get the issuers from a directory log
    const getIssuers = (dir: DirectoryLog) => dir.issuerInfo.map(info => info.issuer.iss);
    const currentIss = getIssuers(currentLog);
    const auditLog: AuditLog = {
        directory: currentLog.directory,
        auditTime: currentLog.time,
        issuerCount: currentLog.issuerInfo.length,
        issuersWithErrors: currentLog.issuerInfo.filter(info => info.errors != undefined && info.errors.length > 0),
        issuerWithCRLCount: currentLog.issuerInfo.filter(info => info.crls != undefined && info.crls.length > 0).length,
        duplicatedKids: getDuplicates(currentLog.issuerInfo.flatMap(info => info.keys.map(key => key.kid))),
        duplicatedIss: getDuplicates(currentIss),
        duplicatedNames: getDuplicates(currentLog.issuerInfo.map(info => info.issuer.name))
    }
    if (previousLog) {
        auditLog.previousAuditTime = previousLog?.time;
        const initialCount = 0;
        const previousIss = getIssuers(previousLog);
        auditLog.newIssuerCount = currentIss.reduce((acc, current) => acc + (previousIss.includes(current) ? 0 : 1), initialCount);
        auditLog.deletedIssuerCount = previousIss.reduce((acc, current) => acc + (currentIss.includes(current) ? 0 : 1), initialCount);
        const getIssuerKids = (dir: DirectoryLog) => dir.issuerInfo.map(info => { return { iss: info.issuer.iss, kids: info.keys.map(key => key.kid)}});
        const currentIssKids: IssuerKids[] = getIssuerKids(currentLog);
        const previousIssKids: IssuerKids[] = getIssuerKids(previousLog);
        auditLog.removedKids = [];
        previousIssKids.forEach(pik => {
            currentIssKids.forEach(cik => {
                if (pik.iss === cik.iss) {
                    const removedKids: string[] = [];
                    pik.kids.forEach(kid => {
                        if (!cik.kids.includes(kid)) {
                            removedKids.push(kid);
                        }
                    })
                    if (removedKids.length > 0) {
                        auditLog.removedKids?.push({iss: pik.iss, kids: removedKids});
                    }
                }
            })
        });
    }
    
    return auditLog;
}

async function directoryLogToSnapshot(log: DirectoryLog) : Promise<DirectoryLog> {
    const snapshot: DirectoryLog = {
        directory: log.directory,
        time: log.time,
        issuerInfo: []
    };
    // copy non-erroneous issuers, keeping only SHC keys and CRLs
    for await (const ii of log.issuerInfo) { // using for loop because filter doesn't support async predicates
        if (ii.errors && ii.errors.length > 0) {
            continue; // skip issuers with errors
        }
        const issuer: IssuerLogInfo =
        {
            issuer: ii.issuer,
            keys: []
        }
        for await (const key of ii.keys) {
            if (await isSHCKey(key)) {
                issuer.keys.push(key); // only keep SHC keys
            }
        }
        if (ii.crls && ii.crls.length > 0) {
            issuer.crls = ii.crls;
        }
        snapshot.issuerInfo.push(issuer);
    }

    return snapshot;
}


// main
void (async () => {
    console.log(`Auditing ${options.dirpath}`);
    try {
        // download a fresh copy of the directory (with keys)
        const directoryLog = await fetchDirectory(options.dirpath, options.verbose);
        fs.writeFileSync(options.outlog, JSON.stringify(directoryLog, null, 4));
        console.log(`Directory log written to ${options.outlog}`);

        if (directoryLog) {
            // save a snapshot of issuers (without errors) with keys and CRLs
            const directorySnapshot = await directoryLogToSnapshot(directoryLog);
            fs.writeFileSync(options.outsnapshot, JSON.stringify(directorySnapshot, null, 4));
            console.log(`Directory snapshot written to ${options.outsnapshot}`);
        }
        if (!directoryLog) {
            throw "No directory available; aborting";
        }

        // the audit script optionally compares the directory with a previous version to highlight changes
        let previousDirectoryLog: DirectoryLog | undefined = undefined;
        if (options.previous) {
            let errMsg = `Can't read ${options.previous}`;
            try {
                previousDirectoryLog = JSON.parse(fs.readFileSync(options.previous).toString('utf-8')) as DirectoryLog;
            } catch (e) {
                errMsg += (". " + (e as Error).message);
            }
            if (!previousDirectoryLog) {
                console.log(errMsg);
            }
        }

        // audit the directory, optionally comparing with a previous version
        const auditLog = audit(directoryLog, previousDirectoryLog);
        fs.writeFileSync(options.auditlog, JSON.stringify(auditLog, null, 4));
        console.log(`Audit log written to ${options.auditlog}`);
    } catch (err) {
        console.log(err);
    }
})();