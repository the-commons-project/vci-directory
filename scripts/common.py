import csv
import json
from collections import namedtuple
from typing import List, Tuple
import asyncio
import httpx
from enum import Enum, auto
from jwcrypto import jwk as _jwk
IssuerEntry = namedtuple('IssuerEntry', 'name iss')

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
    KID_IS_INCORRECT = (auto(), IssueLevel.WARNING)
    KEY_USE_IS_INCORRECT = (auto(), IssueLevel.WARNING)
    KEY_ALG_IS_INCORRECT = (auto(), IssueLevel.WARNING)

    def __init__(self, id, level):
        self.id = id
        self.level = level

    def __str__(self):
        return f'{self.name}: {self.level}'

    def __repr__(self):
        return f'{self.name}: {self.level}'


Issue = namedtuple('Issue', 'description type')
ValidationResult = namedtuple('ValidationResult', 'issuer_entry is_valid issues')

DEFAULT_NAME_INDEX = 0
DEFAULT_NAME_HEADER = 'name'
DEFAULT_ISS_INDEX = 1
DEFAULT_ISS_HEADER = 'iss'
DEFAULT_ENCODING = 'utf-8'

NAME_KEY = 'name'
ISS_KEY = 'iss'
PARTICIPATING_ISSUERS_KEY = 'participating_issuers'

EXPECTED_KEY_USE = 'sig'
EXPECTED_KEY_ALG = 'ES256'
EXPECTED_KEY_CRV = 'P-256'

def read_issuer_entries_from_tsv_file(
    input_file: str,
    name_index: int = DEFAULT_NAME_INDEX,
    name_header: str = DEFAULT_NAME_HEADER,
    iss_index: int = DEFAULT_ISS_INDEX,
    iss_header: str = DEFAULT_ISS_HEADER,
    encoding: str = DEFAULT_ENCODING
) -> list[IssuerEntry]:
    with open(input_file, 'r', newline='', encoding=encoding) as tsvfile:
        reader = csv.reader(tsvfile, delimiter='\t')
        entries = {}
        for row in reader:
            name = row[name_index]
            iss = row[iss_index]
            if name != name_header and iss != iss_header:
                entry = IssuerEntry(name, iss)
                entries[iss] = entry
        return list(entries.values())

def read_issuer_entries_from_json_file(
    input_file: str
) -> list[IssuerEntry]:
    with open(input_file, 'r') as json_file:
        input_dict = json.load(json_file)
        entries = {}
        for entry_dict in input_dict[PARTICIPATING_ISSUERS_KEY]:
            name = entry_dict[NAME_KEY]
            iss = entry_dict[ISS_KEY]
            entry = IssuerEntry(name, iss)
            entries[iss] = entry

        return list(entries.values())

def write_issuer_entries_to_json_file(
    output_file: str,
    entries: list[IssuerEntry]
):
    entry_dicts = [{ISS_KEY: entry.iss, NAME_KEY: entry.name} for entry in entries]
    output_dict = {
        PARTICIPATING_ISSUERS_KEY: entry_dicts
    }
    with open(output_file, 'w') as json_file:
        json.dump(output_dict, json_file, indent=2)

def validate_key(jwk_dict) -> Tuple[bool, list[Issue]]:
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
        issues.append(
            Issue(f'Key with kid={kid} has an incorrect kid value. It should be {jwk.thumbprint()}', IssueType.KID_IS_INCORRECT)
        )

    if jwk.use != EXPECTED_KEY_USE:
        is_valid = False
        issues.append(
            Issue(f'Key with kid={kid} has an incorrect key use. It should be \"{EXPECTED_KEY_USE}\"', IssueType.KEY_USE_IS_INCORRECT)
        )

    if jwk.alg != EXPECTED_KEY_ALG:
        is_valid = False
        issues.append(
            Issue(f'Key with kid={kid} has an incorrect key alg. It should be \"{EXPECTED_KEY_ALG}\"', IssueType.KEY_ALG_IS_INCORRECT)
        )

    return [is_valid, issues]


def validate_keyset(jwks_dict) -> Tuple[bool, list[Issue]]:
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

    errors = [issue for issue in keyset_issues if issue.type.level == IssueLevel.ERROR]
    keyset_is_valid = at_least_one_valid_keyset and len(errors) == 0

    return [keyset_is_valid, keyset_issues]

async def validate_issuer(issuer_entry):

    iss = issuer_entry.iss
    if iss.endswith('/'):
        issues = [
            Issue(f'{iss} ends with a trailing slash', IssueType.ISS_ENDS_WITH_TRAILING_SLASH)
        ]
        return ValidationResult(issuer_entry, False, issues) 
    else:
        jwks_url = f'{iss}/.well-known/jwks.json'
    
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(jwks_url)
            res.raise_for_status()
            jwks = res.json()
            (is_valid, issues) = validate_keyset(jwks)
            return ValidationResult(issuer_entry, is_valid, issues)
    except BaseException as ex:
        issues = [
            Issue(f'An exception occurred when fetching {jwks_url}: {ex}', IssueType.FETCH_EXCEPTION)
        ]
        return ValidationResult(issuer_entry, False, issues) 

async def validate_all_entries(entries):
    aws = [validate_issuer(issuer_entry) for issuer_entry in entries]
    return await asyncio.gather(
        *aws
    )

def validate_entries(
    entries: list[IssuerEntry]
) -> list[ValidationResult]:
    results = asyncio.run(validate_all_entries(entries))
    return results

def analyze_results(
    validation_results: list[ValidationResult],
    show_errors_and_warnings: bool,
    show_warnings: bool
) -> bool:

    is_valid = True
    for result in validation_results:

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
