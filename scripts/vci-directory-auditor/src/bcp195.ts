// Test conformance with IETF BCP 195 (https://www.rfc-editor.org/info/bcp195), consisting of:
//  - RFC 7525: Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)
//  - RFC 8996: Deprecating TLS 1.0 and TLS 1.1

import execa from 'execa';
import { TlsDetails } from './interfaces';

// min key sizes rfc7525, section 4.3
const MIN_EC_KEY_SIZE = 192;
const MIN_RSA_KEY_SIZE = 2048;
const MIN_DH_KEY_SIZE = 2048;

const TLS_ERROR_PREFIX = "TLS error: ";

function isOpensslAvailable(): boolean {
    try {
        const result = execa.commandSync("openssl version");
        return (result.exitCode == 0);
    } catch (err) {
        return false;
    }
}

const openssl = (args: string[]): execa.ExecaSyncReturnValue<string> => {
    let result: execa.ExecaSyncReturnValue<string>;
    try {
        result = execa.sync('openssl', args, {timeout: 2000}); // TODO: make timeout configurable
    }
    catch(err) {
        result = (err as execa.ExecaSyncReturnValue<string>);
        if (!result) {
            console.log(err);
        }
    }
    return result;
}

// Connect to the specified server and return its default TLS connection details
export function getDefaultTlsDetails(server: string): TlsDetails | undefined {
    if (!isOpensslAvailable()) {
        console.log("OpenSSL not available");
        return undefined;
    }
    const result = openssl(['s_client', '-connect', `${server}:443`]);
    if (!result || result.failed) {
        console.log(result ? result.stderr : "openssl failed");
        return undefined;
    }

    let version = result.stdout.match(new RegExp('^    Protocol  : (.*)$', 'm'))?.[1];
    let cipher = result.stdout.match(new RegExp('^    Cipher    : (.*)$', 'm'))?.[1];
    if (!version || !cipher) {
        // with some config, the previous lines are not written; parse a different line
        const match = result.stdout.match(new RegExp('^New, (.*), Cipher is (.*)$', 'm'));
        version = match?.[1];
        cipher = match?.[2];
    }

    let kexAlg = result.stdout.match(new RegExp('^Server Temp Key: (.*)$', 'm'))?.[1];
    let authAlg = result.stdout.match(new RegExp('^Peer signature type: (.*)$', 'm'))?.[1];
    if (!kexAlg || !authAlg) {
        // some old ciphers don't print out the above statements, let's see if we can populate
        // them from the OpenSSL cipher
        if (cipher?.startsWith("AES")) {
            // this is an OpenSSL name for static RSA kex and RSA auth
            // see https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/include/openssl/tls1.h
            kexAlg = "RSA";
            authAlg = "RSA";
        }
    }
    const pubKeySize = result.stdout.match(new RegExp('^Server public key is ([0-9]*) bit', 'm'))?.[1];
    const compression = result.stdout.match(new RegExp('^Compression: (.*)$', 'm'))?.[1];
    const tlsDetails = {
        version: version,
        cipher: cipher,
        kexAlg: kexAlg,
        authAlg: authAlg,
        pubKeySize: pubKeySize,
        compression: compression
    }
    return tlsDetails;
}

export function auditTlsDetails(details: TlsDetails): string[] {

    if (!details.version) {
        return [TLS_ERROR_PREFIX + "Unspecified TLS version; can't audit the TLS details"];
    }

    // any TLS 1.3 configuration is ok
    if (details.version === "TLSv1.3") {
        return [];
    }

    // old SSL/TLS versions are insecure
    if (details.version !== "TLSv1.2") {
        return [TLS_ERROR_PREFIX + `Insecure TLS version: ${details.version}`];
    }

    // audit the TLS 1.2 configuation
    const errors:string[] = [];

    // rfc7525, section 4.4: MUST support and prefer "DHE" and "ECDHE"
    if (details.cipher?.startsWith("DHE")) {
        // check min key length
        if (details.kexAlg) {
            const kexKeySize = details.kexAlg.match(new RegExp('^DH, (.*) bits$'))?.[1];
            if (!kexKeySize || parseInt(kexKeySize) < MIN_DH_KEY_SIZE) {
                errors.push(TLS_ERROR_PREFIX + `DHE key too small ( < ${MIN_DH_KEY_SIZE}) or can't determine size: ${kexKeySize}`);
            }
        }
    } else if (details.cipher?.startsWith("ECDHE")) {
        if (details.kexAlg) {
            const kexKeySize = details.kexAlg.match(new RegExp('^.*, (.*) bits$'))?.[1];
            if (!kexKeySize || parseInt(kexKeySize) < MIN_EC_KEY_SIZE) {
                errors.push(TLS_ERROR_PREFIX + `ECDHE key too small ( < ${MIN_EC_KEY_SIZE} bits) or can't determine size: ${kexKeySize}`);
            }
        }
    } else if (details.cipher?.startsWith("AES") || details.kexAlg?.startsWith("RSA")) {
        // this is an OpenSSL name for static RSA kex and RSA auth
        // see https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/include/openssl/tls1.h
        errors.push(TLS_ERROR_PREFIX + `Static RSA SHOULD NOT be used, MUST prefer ECDHE and DHE`);
    } else {
        errors.push(TLS_ERROR_PREFIX + `Unrecognized cipher, MUST prefer ECDHE and DHE`);
    }

    // check signature alg
    let authKeySize:number = -1;
    if (details.pubKeySize) {
        authKeySize = parseInt(details.pubKeySize);
    }
    if (details.authAlg == "ECDSA") {
        if (authKeySize < 0) {
            errors.push(TLS_ERROR_PREFIX + `Can't determine authentication public key size: ${details.pubKeySize}`);
        } else if (authKeySize < MIN_EC_KEY_SIZE) {
            errors.push(TLS_ERROR_PREFIX + `ECDSA key too small ( < ${MIN_EC_KEY_SIZE} bits ): ${authKeySize}`);
        }
    } else if (details.authAlg?.startsWith("RSA")) {
        // could be "RSA", "RSA-PSS"
        if (authKeySize < 0) {
            errors.push(TLS_ERROR_PREFIX + `Can't determine authentication public key size: ${details.pubKeySize}`);
        } else if (authKeySize < MIN_RSA_KEY_SIZE) {
            errors.push(TLS_ERROR_PREFIX + `RSA key too small ( < ${MIN_RSA_KEY_SIZE} bits ): ${authKeySize}`);
        }
    } else {
        errors.push(TLS_ERROR_PREFIX + `Unrecognized authentication algorithm: ${details.authAlg}`);
    }

    // check compression
    if (details.compression && details.compression !== "NONE") {
        errors.push(TLS_ERROR_PREFIX + `Uses compression: ${details.compression}`);
    }

    return errors;
}
