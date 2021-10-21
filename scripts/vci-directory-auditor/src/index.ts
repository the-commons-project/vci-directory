// Audit script for the VCI issuers directory

import { Command } from 'commander';
import { JWK } from "node-jose";
import got from 'got';
import fs from 'fs';
import path from 'path';
import date from 'date-and-time';
import Url from 'url-parse';

const VCI_ISSUERS_DIR_URL = "https://raw.githubusercontent.com/the-commons-project/vci-directory/main/vci-issuers.json";
const DEFAULT_LOG_LOCATION = "logs"

//
// interfaces
//

// issuer info in the directory
interface TrustedIssuer {
    iss: string,
    name: string
}

// directory structure
interface TrustedIssuers {
    participating_issuers: TrustedIssuer[]
}

// issuer log info
interface IssuerInfoWithKeys {
    // the issuer info
    issuer: TrustedIssuer,
    // the issuer's JWK set
    keys: JWK.Key[],
}

interface IssuerLogInfo extends IssuerInfoWithKeys {
    // errors while retrieving the issuer JWK set, if any
    errors?: string[]
} 

// Key identifiers (KID) of one issuer
interface IssuerKids {
    iss: string,
    kids: string[]
}

// a snapshot of the directory, including keys
interface DirectorySnapshot {
    // directory URL
    directory: string,
    // snapshot time
    time: string,
    // directory issuers
    issuerInfo: IssuerInfoWithKeys[]
}

// a snapshot of the directory, including keys
interface DirectoryLog {
    // directory URL
    directory: string,
    // snapshot time
    time: string,
    // directory issuers
    issuerInfo: IssuerLogInfo[]
}


interface KeySet {
    keys : JWK.Key[]
}

interface Options {
    dirpath: string;
    outpath: string;
    outlogpath: string;
}

//
// program options
//
const program = new Command();
program.requiredOption('-d, --dirpath <dirpath>', 'path of the directory to audit');
program.option('-o, --outpath <outpath>', 'output path for the directory with keys');
program.option('-l, --outlogpath <outlogpath>', 'output path for the directory log');
program.parse(process.argv);
const currentTime = new Date();

// process options
const options = program.opts() as Options;
if (!options.outpath) {
    options.outpath = path.join(DEFAULT_LOG_LOCATION, `directory_snapshot_${date.format(currentTime, 'YYYY-MM-DD-HHmmss')}.json`);
}
if (!options.outlogpath) {
    options.outlogpath = path.join(DEFAULT_LOG_LOCATION, `directory_log_${date.format(currentTime, 'YYYY-MM-DD-HHmmss')}.json`);
}

// download the issuer keys
async function fetchDirectoryKeys(issuers: TrustedIssuers) : Promise<DirectoryLog> {

    const issuerLogInfo = issuers.participating_issuers.map(async (issuer): Promise<IssuerLogInfo> => {
        const jwkURL = issuer.iss + '/.well-known/jwks.json';
        const issuerLogInfo: IssuerLogInfo = {
            issuer: issuer,
            keys: [],
            errors: []
        }
        try {
            const response = await got(jwkURL, { timeout:10000 });
            if (!response) {
                throw "Can't reach JWK URL";
            }
            const keySet = JSON.parse(response.body) as KeySet;
            if (!keySet) {
                throw "Failed to parse JSON KeySet schema";
            }
            issuerLogInfo.keys = keySet.keys;
        } catch (err) {
            issuerLogInfo.errors?.push((err as Error).toString());
        }
        return issuerLogInfo;        
    });

    const directoryLog: DirectorySnapshot = {
        directory: VCI_ISSUERS_DIR_URL,
        time: date.format(currentTime, 'YYYY-MM-DD HH:mm:ss'),
        issuerInfo: []    
    }
    try {
        directoryLog.issuerInfo = await Promise.all(issuerLogInfo);
    } catch(err) {
        Promise.reject(err);
    }

    return directoryLog;
}

function directoryLogToSnapshot(log: DirectoryLog) : DirectorySnapshot {
    const snapshot: DirectorySnapshot = {
        directory: log.directory,
        time: log.time,
        // don't list iss with errors, and remove errors param from IssuerLogInfo for the directory snapshot
        issuerInfo: log.issuerInfo.filter(ii => ii.errors ? true : false).map(ii => {
            return {
                issuer: ii.issuer,
                keys: ii.keys
            }
        })
    }
    return snapshot;
}

// main
void (async () => {
    console.log(`Auditing ${options.dirpath}`);

    try {
        const directory = JSON.parse(fs.readFileSync(options.dirpath).toString('utf-8')) as TrustedIssuers;
        const directoryLog = await fetchDirectoryKeys(directory);
        fs.writeFileSync(options.outpath, JSON.stringify(directoryLog, null, 4));
        // convert to snapshot
        const directorySnapshot = directoryLogToSnapshot(directoryLog);
        fs.writeFileSync(options.outpath, JSON.stringify(directorySnapshot, null, 4));
    } catch (e) {
        console.log((e as Error).message);
        return;
    }

})();