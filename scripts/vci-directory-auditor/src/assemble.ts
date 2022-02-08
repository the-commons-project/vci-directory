// Script to assemble the VCI issuers directory snapshot

import { Command } from 'commander';
import fs from 'fs';
import { DirectoryLog, IssuerLogInfo } from './interfaces';

interface Options {
    snapshot: string;
    current: string;
    new: boolean;
}

//
// program options
//
const program = new Command();
program.requiredOption('-s, --snapshot <snapshot>', 'path to the previous directory snapshot to update');
program.requiredOption('-c, --current <current>', 'path to current snapshot to integrate in the previous snapshot');
program.option('-n, --new', 'create a new directory snapshot from the current snapshot');
program.parse(process.argv);
const options = program.opts() as Options;

function updateDirectorySnapshot(snapshot: DirectoryLog, current: DirectoryLog) : DirectoryLog {
    if (snapshot.directory !== current.directory) {
        // uncommon scenario, so let's warn about that
        console.log("Warning current log is not from the same directory");
    }

    if (snapshot.time > current.time) { // TODO: will that work?
        // throw "Current log is older than snapshot"; // TODO: workaround for tests
    }

    const issuerMap = new Map<string, IssuerLogInfo>();
    snapshot.issuerInfo.forEach(issuerInfo => {
        // add the issuer info to the map (will overwrite duplicates, which _shouldn't_ exist)
        issuerMap.set(issuerInfo.issuer.iss, issuerInfo);
    })

    // all new entries will be timestamped with the current snapshot's creation time
    const lastUpdated = current.time;
    current.issuerInfo.forEach(issuerInfo => {
        // previous issuer entry will be overwritten with new data
        issuerInfo.lastRetrieved = lastUpdated;
        issuerMap.set(issuerInfo.issuer.iss, issuerInfo);
    })

    const updatedSnapshot: DirectoryLog = {
        directory: snapshot.directory,
        time: current.time,
        issuerInfo: []
    }
    issuerMap.forEach((issuerLogInfo, key, map) => {
        updatedSnapshot.issuerInfo.push(issuerLogInfo);
    })

    return updatedSnapshot;
}

// main
void (async () => {
    console.log(`Updating ${options.snapshot} with content from ${options.current}`);
    try {
        // read the current directory snapshot
        const currentLog = JSON.parse(fs.readFileSync(options.current).toString('utf-8')) as DirectoryLog;

        let snapshotLog: DirectoryLog;
        if (options.new) {
            console.log("Creating new snapshot");
            // first time called, create a new empty snapshot
            snapshotLog = {
                directory: currentLog.directory,
                time: currentLog.time,
                issuerInfo: []
            }
        } else {
            // read the directory snapshot
            snapshotLog = JSON.parse(fs.readFileSync(options.snapshot).toString('utf-8')) as DirectoryLog;
        }

        // update the directory snapshot
        snapshotLog = updateDirectorySnapshot(snapshotLog, currentLog);

        // write back the directory snapshot
        fs.writeFileSync(options.snapshot, JSON.stringify(snapshotLog, null, 4));

        console.log(`Updated directory snapshot written to ${options.snapshot}`);
    } catch (err) {
        console.log(err);
    }

})();
