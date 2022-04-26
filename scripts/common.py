from asyncio.locks import BoundedSemaphore
import csv
import json
from collections import namedtuple
from typing import Any, List, Tuple, Set, Dict
import asyncio
import httpx
from enum import Enum, auto
from jwcrypto import jwk as _jwk
IssuerEntry = namedtuple('IssuerEntry', 'name iss website canonical_iss')
IssuerEntryChange = namedtuple('IssuerEntryChange', 'old new')

## Reduce SSL context security level due to SSL / TLS error with some domains
## https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_security_level.html
httpx._config.DEFAULT_CIPHERS = httpx._config.DEFAULT_CIPHERS + ':@SECLEVEL=1'

class IssException(BaseException):
    pass

class IssueLevel(Enum):
    WARNING = auto()
    ERROR = auto()

    def __str__(self):
        return f'{self.name}'

    def __repr__(self):
        return f'{self.name}'


class IssueType(Enum):

    ISS_ENDS_WITH_TRAILING_SLASH = (auto(), IssueLevel.ERROR)
    FETCH_EXCEPTION = (auto(), IssueLevel.ERROR)
    KEYS_PROPERTY_MISSING = (auto(), IssueLevel.ERROR)
    KEYS_PROPERTY_EMPTY = (auto(), IssueLevel.ERROR)
    KEY_IS_INVALID = (auto(), IssueLevel.ERROR)
    KID_IS_MISSING = (auto(), IssueLevel.ERROR)
    KEY_CONTAINS_PRIVATE_MATERIAL = (auto(), IssueLevel.ERROR)
    KID_IS_INCORRECT = (auto(), IssueLevel.ERROR)
    KEY_USE_IS_INCORRECT = (auto(), IssueLevel.WARNING)
    KEY_ALG_IS_INCORRECT = (auto(), IssueLevel.WARNING)
    WEBSITE_DOES_NOT_RESOLVE = (auto(), IssueLevel.ERROR)
    CANONICAL_ISS_SELF_REFERENCE = (auto(), IssueLevel.ERROR)
    CANONICAL_ISS_REFERENCE_INVALID = (auto(), IssueLevel.ERROR)
    CANONICAL_ISS_MULTIHOP_REFERENCE = (auto(), IssueLevel.ERROR)
    ## TODO - convert CORS issues to ERROR in the future
    CORS_HEADER_MISSING = (auto(), IssueLevel.WARNING)
    CORS_HEADER_INCORRECT = (auto(), IssueLevel.WARNING)

    def __init__(self, id, level):
        self.id = id
        self.level = level

    def __str__(self):
        return f'{self.name}: {self.level}'

    def __repr__(self):
        return f'{self.name}: {self.level}'

class VCIDirectoryDiffs():

    def __init__(self, additions: List[IssuerEntry], deletions: List[IssuerEntry], changes: List[IssuerEntryChange]):
        self.additions = additions
        self.deletions = deletions
        self.changes = changes

    def __repr__(self):
        return f'additons={self.additions}\ndeletions={self.deletions}\nchanges={self.changes}'


Issue = namedtuple('Issue', 'description type')
ValidationResult = namedtuple('ValidationResult', 'issuer_entry is_valid issues')

DEFAULT_NAME_INDEX = 0
DEFAULT_NAME_HEADER = 'name'
DEFAULT_ISS_INDEX = 1
DEFAULT_ISS_HEADER = 'iss'
DEFAULT_ENCODING = 'utf-8'

NAME_KEY = 'name'
ISS_KEY = 'iss'
WEBSITE_KEY = 'website'
CANONICAL_ISS_KEY = 'canonical_iss'
PARTICIPATING_ISSUERS_KEY = 'participating_issuers'

USER_AGENT = "VCIDirectoryValidator/1.0.0"

EXPECTED_KEY_USE = 'sig'
EXPECTED_KEY_ALG = 'ES256'
EXPECTED_KEY_CRV = 'P-256'

MAX_FETCH_RETRY_COUNT=5
FETCH_RETRY_COUNT_DELAY=2
FETCH_REQUEST_ORIGIN = 'https://example.org'
CORS_ACAO_HEADER = 'access-control-allow-origin'
CORS_ACAO_HEADER_ALL = '*'

def read_issuer_entries_from_tsv_file(
    input_file: str,
    name_index: int = DEFAULT_NAME_INDEX,
    name_header: str = DEFAULT_NAME_HEADER,
    iss_index: int = DEFAULT_ISS_INDEX,
    iss_header: str = DEFAULT_ISS_HEADER,
    encoding: str = DEFAULT_ENCODING
) -> List[IssuerEntry]:
    with open(input_file, 'r', newline='', encoding=encoding) as tsvfile:
        reader = csv.reader(tsvfile, delimiter='\t')
        entries = {}
        for row in reader:
            name = row[name_index].strip()
            iss = row[iss_index].strip()
            if name != name_header and iss != iss_header:
                entry = IssuerEntry(name, iss, None, None)
                entries[iss] = entry
        return list(entries.values())

def read_issuer_entries_from_json_file(
    input_file: str
) -> List[IssuerEntry]:
    with open(input_file, 'r') as json_file:
        input_dict = json.load(json_file)
        entries = {}
        for entry_dict in input_dict[PARTICIPATING_ISSUERS_KEY]:
            name = entry_dict[NAME_KEY].strip()
            iss = entry_dict[ISS_KEY].strip()
            website = entry_dict[WEBSITE_KEY].strip() if entry_dict.get(WEBSITE_KEY) else None
            canonical_iss = entry_dict[CANONICAL_ISS_KEY].strip() if entry_dict.get(CANONICAL_ISS_KEY) else None
            entry = IssuerEntry(
                name=name,
                iss=iss,
                website=website,
                canonical_iss=canonical_iss
            )
            entries[iss] = entry

        return list(entries.values())

def issuer_entry_to_dict(issuer_entry: IssuerEntry) -> dict:
    d = {ISS_KEY: issuer_entry.iss, NAME_KEY: issuer_entry.name}
    if issuer_entry.website:
        d[WEBSITE_KEY] = issuer_entry.website
    if issuer_entry.canonical_iss:
        d[CANONICAL_ISS_KEY] = issuer_entry.canonical_iss

    return d

def write_issuer_entries_to_json_file(
    output_file: str,
    entries: List[IssuerEntry]
):
    entry_dicts = [issuer_entry_to_dict(entry) for entry in entries]
    output_dict = {
        PARTICIPATING_ISSUERS_KEY: entry_dicts
    }
    with open(output_file, 'w') as json_file:
        json.dump(output_dict, json_file, indent=2)

def validate_key(jwk_dict) -> Tuple[bool, List[Issue]]:
    '''
    Validates a JWK represented by jwk_dict
    '''
    try:
        kid = jwk_dict['kid']
    except:
        issues = [
            Issue('kid is missing', IssueType.KID_IS_MISSING)
        ]
        return [False, issues]
    try:
        jwk = _jwk.JWK(**jwk_dict)
    except:
        issues = [
            Issue(f'Key with kid={kid} is invalid', IssueType.KEY_IS_INVALID)
        ]
        return [False, issues]

    if jwk.has_private:
        issues = [
            Issue(f'Key with kid={kid} contains private key material', IssueType.KEY_CONTAINS_PRIVATE_MATERIAL)
        ]
        return [False, issues]

    is_valid = True
    issues = []
    ## check that use matches expected use
    if kid != jwk.thumbprint():
        is_valid = False
        issues = [
            Issue(f'Key with kid={kid} has an incorrect kid value. It should be {jwk.thumbprint()}', IssueType.KID_IS_INCORRECT)
        ]
        return [False, issues]

    if jwk_dict.get('use') != EXPECTED_KEY_USE:
        is_valid = False
        issues.append(
            Issue(f'Key with kid={kid} has an incorrect key use. It should be \"{EXPECTED_KEY_USE}\"', IssueType.KEY_USE_IS_INCORRECT)
        )

    if jwk_dict.get('alg') != EXPECTED_KEY_ALG:
        is_valid = False
        issues.append(
            Issue(f'Key with kid={kid} has an incorrect key alg. It should be \"{EXPECTED_KEY_ALG}\"', IssueType.KEY_ALG_IS_INCORRECT)
        )

    return [is_valid, issues]


def validate_keyset(jwks_dict) -> Tuple[bool, List[Issue]]:
    '''
    Validates a JWKS represented by jwks_dict
        Ensures that at least one key is fully valid for signing and that NO keys contains errors (warnings are ok)
    '''
    try:
        keys = jwks_dict['keys']
    except:
        issues = [
            Issue(f'\"keys\" property missing from jwks.json', IssueType.KEYS_PROPERTY_MISSING)
        ]
        return [False, issues]

    if len(keys) == 0:
        issues = [
            Issue(f'jwks.json contains no keys', IssueType.KEYS_PROPERTY_EMPTY)
        ]
        return [False, issues]

    at_least_one_valid_keyset = False
    keyset_issues = []
    for key in keys:
        (is_valid, issues) = validate_key(key)
        at_least_one_valid_keyset = at_least_one_valid_keyset or is_valid
        keyset_issues.extend(issues)

    # Issuers may host other keys in their keyset unrelated to SHC issuance.
    # In that case we have no expectation of what those kids should look like
    if at_least_one_valid_keyset:
        return [True, []]
    else:
        return [False, keyset_issues]

def validate_response_headers(
    response_headers: any,
) -> List[Issue]:
    '''
    Validates response headers from the jwks.json fetch
        Ensures that CORS headers are configured properly
    '''
    acao_header = response_headers.get(CORS_ACAO_HEADER)
    if acao_header == None or len(acao_header) == 0:
        issues = [
            Issue(f'{CORS_ACAO_HEADER} header is missing', IssueType.CORS_HEADER_MISSING)
        ]
        return issues
    elif acao_header == CORS_ACAO_HEADER_ALL or acao_header == FETCH_REQUEST_ORIGIN:
        return []
    else:
        issues = [
            Issue(f'{CORS_ACAO_HEADER} header is incorrect. Expected {CORS_ACAO_HEADER_ALL} or {FETCH_REQUEST_ORIGIN}, but got {acao_header}', IssueType.CORS_HEADER_INCORRECT)
        ]
        return issues

async def fetch_jwks(
    jwks_url: str,
    retry_count: int = 0
) -> Any:

    try:
        async with httpx.AsyncClient() as client:
            headers = {
                'User-Agent': USER_AGENT,
                'Origin': FETCH_REQUEST_ORIGIN
            }
            res = await client.get(jwks_url, headers=headers, follow_redirects=True)
            res.raise_for_status()
            return (res.json(), res.headers)
    except BaseException as ex:
        if retry_count < MAX_FETCH_RETRY_COUNT:
            ## Add exponential backoff, starting with 1s
            delay_seconds = pow(FETCH_RETRY_COUNT_DELAY, retry_count)
            await asyncio.sleep(delay_seconds)
            return await fetch_jwks(
                jwks_url,
                retry_count = retry_count + 1
            )
        else:
            raise ex

async def validate_website(
    website_url: str,
    retry_count: int = 0
) -> Tuple[bool, List[Issue]]:
    try:
        async with httpx.AsyncClient() as client:
            headers = {'User-Agent': USER_AGENT}
            res = await client.get(website_url, headers=headers, follow_redirects=True)
            res.raise_for_status()
    except BaseException as ex:
        if retry_count < MAX_FETCH_RETRY_COUNT:
            ## Add exponential backoff, starting with 1s
            delay_seconds = pow(FETCH_RETRY_COUNT_DELAY, retry_count)
            await asyncio.sleep(delay_seconds)
            return await validate_website(
                website_url,
                retry_count = retry_count + 1
            )
        else:
            raise ex

async def validate_issuer(
    issuer_entry: IssuerEntry,
    skip_keyset_check: bool = False
) -> Tuple[bool, List[Issue]]:
    iss = issuer_entry.iss
    if iss.endswith('/'):
        issues = [
            Issue(f'{iss} ends with a trailing slash', IssueType.ISS_ENDS_WITH_TRAILING_SLASH)
        ]
        return (False, issues)
    else:
        jwks_url = f'{iss}/.well-known/jwks.json'

    if skip_keyset_check:
        return (True, [])

    try:
        (jwks, response_headers) = await fetch_jwks(jwks_url)
        headers_issues = validate_response_headers(response_headers)
        header_errors = [issue for issue in headers_issues if issue.type.level == IssueLevel.ERROR]
        headers_are_valid = len(header_errors) == 0
        (keyset_is_valid, keyset_issues) = validate_keyset(jwks)
        is_valid = headers_are_valid and keyset_is_valid
        issues = headers_issues + keyset_issues
        return (is_valid, issues)
    except BaseException as ex:
        issues = [
            Issue(f'An exception occurred when fetching {jwks_url}: {ex}', IssueType.FETCH_EXCEPTION)
        ]
        return (False, issues)

async def validate_entry(
    issuer_entry: IssuerEntry,
    entry_map: Dict[str, IssuerEntry],
    semaphore: BoundedSemaphore
) -> ValidationResult:
    async with semaphore:
        print('.', end='', flush=True)
        (iss_is_valid, iss_issues) = await validate_issuer(issuer_entry, skip_keyset_check=issuer_entry.canonical_iss is not None)

        website_is_valid = True
        website_issues = []
        if issuer_entry.website:
            try:
                await validate_website(issuer_entry.website)
            except BaseException as e:
                website_is_valid = False
                website_issues.append(
                    Issue(f'An exception occurred when fetching {issuer_entry.website}', IssueType.WEBSITE_DOES_NOT_RESOLVE)
                )

        canonical_iss_is_valid = True
        canonical_iss_issues = []
        if issuer_entry.canonical_iss:
            ## check that canonical_iss does not reference itself
            if issuer_entry.iss == issuer_entry.canonical_iss:
                canonical_iss_is_valid = False
                canonical_iss_issues.append(
                    Issue('canonical_iss references iss in this entry', IssueType.CANONICAL_ISS_SELF_REFERENCE)
                )

            ## check that canonical_iss is included in the list
            elif issuer_entry.canonical_iss not in entry_map:
                canonical_iss_is_valid = False
                canonical_iss_issues.append(
                    Issue(f'canonical_iss {issuer_entry.canonical_iss} not found in the directory', IssueType.CANONICAL_ISS_REFERENCE_INVALID)
                )
            else:
                ## check that canonical_iss does not refer to another entry that has canonical_iss defined
                canonical_entry = entry_map[issuer_entry.canonical_iss]
                if canonical_entry.canonical_iss:
                    canonical_iss_is_valid = False
                    canonical_iss_issues.append(
                        Issue(f'canonical_iss {issuer_entry.canonical_iss} refers to an entry with a canonical_iss value', IssueType.CANONICAL_ISS_MULTIHOP_REFERENCE)
                    )

        is_valid = iss_is_valid and website_is_valid and canonical_iss_is_valid
        issues = iss_issues + website_issues + canonical_iss_issues
        return ValidationResult(
            issuer_entry,
            is_valid,
            issues
        )

async def validate_all_entries(
    entries: List[IssuerEntry],
    full_issuer_list: List[IssuerEntry]
) -> List[ValidationResult]:
    full_issuer_entry_map = {entry.iss: entry for entry in full_issuer_list}
    asyncio_semaphore = asyncio.BoundedSemaphore(50)
    aws = [validate_entry(issuer_entry, full_issuer_entry_map, asyncio_semaphore) for issuer_entry in entries]
    return await asyncio.gather(
        *aws
    )

def validate_entries(
    entries_to_validate: List[IssuerEntry],
    full_issuer_list: List[IssuerEntry]
) -> List[ValidationResult]:
    results = asyncio.run(validate_all_entries(entries_to_validate, full_issuer_list))
    print('')
    return results

def duplicate_entries(
    entries: List[IssuerEntry]
) -> List[IssuerEntry]:
    seen_set = set()
    duplicate_set = set()
    for entry in entries:
        if entry.iss in seen_set:
            duplicate_set.add(entry.iss)
        else:
            seen_set.add(entry.iss)

    duplicate_list = [entry for entry in entries if entry.iss in duplicate_set]
    duplicate_list.sort(key=lambda x: x.iss)
    return duplicate_list

def analyze_results(
    validation_results: List[ValidationResult],
    show_errors_and_warnings: bool,
    show_warnings: bool,
    cors_issue_is_error: bool = False
) -> bool:

    is_valid = True
    for result in validation_results:

        ## Remove this once CORS issues are marked errors
        if cors_issue_is_error:
            for issue in result.issues:
                if issue.type == IssueType.CORS_HEADER_MISSING or issue.type == IssueType.CORS_HEADER_INCORRECT:
                    is_valid = False
                    print(f'{result.issuer_entry.iss}: {issue.description}')

        errors = [issue for issue in result.issues if issue.type.level == IssueLevel.ERROR]
        assert(result.is_valid == (len(errors) == 0))
        if not result.is_valid:
            is_valid = False
            if show_errors_and_warnings:
                print(f'{result.issuer_entry.iss} is INVALID')
                for error in errors:
                    print(f'{result.issuer_entry.iss}: {error.description}')

        if show_errors_and_warnings and show_warnings:
            warnings = [issue for issue in result.issues if issue.type.level == IssueLevel.WARNING]
            for warning in warnings:
                print(f'{result.issuer_entry.iss} warning: {warning}')

    return is_valid

def is_different(entry1: IssuerEntry, entry2: IssuerEntry) -> bool:
    return entry1.name != entry2.name or entry1.website != entry2.website or entry1.canonical_iss != entry2.canonical_iss

def compute_diffs(curent_entries: List[IssuerEntry], new_entries: List[IssuerEntry]) -> VCIDirectoryDiffs:
    current_entry_map = { entry.iss:entry for entry in curent_entries }
    new_entry_map = { entry.iss:entry for entry in new_entries }

    ## for all, the primary key is the iss values
    ## additions are items with keys that are contained in new_entries but not curent_entries
    ## deletions are items with keys that are contained in curent_entries but not new_entries
    ## changes are items with keys in both, but they are not the same
    additions = []
    for entry in new_entries:
        if entry.iss not in current_entry_map:
            additions.append(entry)

    deletions = []
    for entry in curent_entries:
        if entry.iss not in new_entry_map:
            deletions.append(entry)

    changes = []
    for entry in new_entries:
        if entry.iss in current_entry_map and is_different(entry, current_entry_map[entry.iss]):
            change = IssuerEntryChange(
                old=current_entry_map[entry.iss],
                new=entry
            )
            changes.append(change)

    return VCIDirectoryDiffs(
        additions,
        deletions,
        changes
    )
