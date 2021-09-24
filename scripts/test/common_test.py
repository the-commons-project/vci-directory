import os
import unittest
import json
from common import (
    read_issuer_entries_from_tsv_file, IssuerEntry, validate_entries, ValidationResult,
    validate_key, IssueType, validate_keyset, Issue, duplicate_entries, read_issuer_entries_from_json_file,
    analyze_results
)

FIXTURE_DIRECTORY = f'{os.path.dirname(__file__)}/fixtures'

class ReadIssuerEntriesFromTSVFileTestCase(unittest.TestCase):

    def test1(self):
        actual = read_issuer_entries_from_tsv_file(
            f'{FIXTURE_DIRECTORY}/example1.tsv',
            encoding='ISO-8859-1'
        )

        expected = [
            IssuerEntry('State of California', 'https://myvaccinerecord.cdph.ca.gov/creds', None, None),
            IssuerEntry('State of Louisiana', 'https://healthcardcert.lawallet.com', None, None),
        ]

        self.assertEqual(actual, expected)

    def test2(self):
        actual = read_issuer_entries_from_tsv_file(
            f'{FIXTURE_DIRECTORY}/example2.tsv',
            encoding='ISO-8859-1'
        )

        expected = [
            IssuerEntry('Example Issuer', 'https://example.com/issuer', None, None),
        ]

        self.assertEqual(actual, expected)

    def test_duplicate_issuer_names(self):
        actual = read_issuer_entries_from_tsv_file(
            f'{FIXTURE_DIRECTORY}/duplicate_issuer_names.tsv',
            encoding='ISO-8859-1'
        )

        expected = [
            IssuerEntry('Example Issuer', 'https://example.com/issuer', None, None),
            IssuerEntry('Example Issuer', 'https://example.com/issuer2', None, None),
        ]

        self.assertEqual(actual, expected)

    def test_duplicate_iss_values(self):
        actual = read_issuer_entries_from_tsv_file(
            f'{FIXTURE_DIRECTORY}/duplicate_iss_values.tsv',
            encoding='ISO-8859-1'
        )

        ## ensure that last value seen in file is preserved
        expected = [
            IssuerEntry('Example Issuer 2', 'https://example.com/issuer', None, None),
        ]

        self.assertEqual(actual, expected)

    def test_no_entries(self):
        actual = read_issuer_entries_from_tsv_file(
            f'{FIXTURE_DIRECTORY}/no_entries.tsv',
            encoding='ISO-8859-1'
        )

        expected = []

        self.assertEqual(actual, expected)

    def test_empty_file(self):
        actual = read_issuer_entries_from_tsv_file(
            f'{FIXTURE_DIRECTORY}/empty_file.tsv',
            encoding='ISO-8859-1'
        )

        expected = []

        self.assertEqual(actual, expected)

class ValidateKeyTestCase(unittest.TestCase):

    def test_valid_sig_key(self):
        jwk_json = """
        {
            "kty": "EC",
            "use": "sig",
            "alg": "ES256",
            "kid": "54M7LspsUfvbirxoLfGeTQp8oCVducfvt0DEU8W4Wcc",
            "crv": "P-256",
            "x": "SM85B9i8alfba9WcWehUYY5WTn6lnRQ9ivlOGrIELzY",
            "y": "I9Agmt_PyqNv3LLkcCBA3iNmi9dieDNrXHnQdplNvHI"
        }
        """

        jwk = json.loads(jwk_json)

        (actual_is_valid, actual_issues) = validate_key(jwk)
        actual_issue_types = [issue.type for issue in actual_issues]

        expected_is_valid = True
        expected_issue_types = []
        self.assertEqual(actual_is_valid, expected_is_valid)
        self.assertEqual(actual_issue_types, expected_issue_types)

    def test_malformed_key(self):
        jwk_json = """
        {
            "kty": "EC",
            "use": "sig",
            "alg": "ES256",
            "kid": "54M7LspsUfvbirxoLfGeTQp8oCVducfvt0DEU8W4Wcc",
            "crv": "P-256",
            "x": "SM85B9i8alfba9WcWehUYY5WTn6lnRQ9ivlOGrIELzY"
        }
        """

        jwk = json.loads(jwk_json)

        (actual_is_valid, actual_issues) = validate_key(jwk)
        actual_issue_types = [issue.type for issue in actual_issues]

        expected_is_valid = False
        expected_issue_types = [
            IssueType.KEY_IS_INVALID
        ]
        self.assertEqual(actual_is_valid, expected_is_valid)
        self.assertEqual(actual_issue_types, expected_issue_types)

    def test_kid_missing(self):
        jwk_json = """
        {
            "kty": "EC",
            "use": "sig",
            "alg": "ES256",
            "crv": "P-256",
            "x": "SM85B9i8alfba9WcWehUYY5WTn6lnRQ9ivlOGrIELzY",
            "y": "I9Agmt_PyqNv3LLkcCBA3iNmi9dieDNrXHnQdplNvHI"
        }
        """

        jwk = json.loads(jwk_json)

        (actual_is_valid, actual_issues) = validate_key(jwk)
        actual_issue_types = [issue.type for issue in actual_issues]

        expected_is_valid = False
        expected_issue_types = [
            IssueType.KID_IS_MISSING
        ]
        self.assertEqual(actual_is_valid, expected_is_valid)
        self.assertEqual(actual_issue_types, expected_issue_types)

    def test_invalid_kid(self):
        jwk_json = """
        {
            "kty": "EC",
            "use": "sig",
            "alg": "ES256",
            "kid": "54M7LspsUfvGeTQp8oCVducfvt0DEU8W4Wcc",
            "crv": "P-256",
            "x": "SM85B9i8alfba9WcWehUYY5WTn6lnRQ9ivlOGrIELzY",
            "y": "I9Agmt_PyqNv3LLkcCBA3iNmi9dieDNrXHnQdplNvHI"
        }
        """

        jwk = json.loads(jwk_json)

        (actual_is_valid, actual_issues) = validate_key(jwk)
        actual_issue_types = [issue.type for issue in actual_issues]

        expected_is_valid = False
        expected_issue_types = [
            IssueType.KID_IS_INCORRECT
        ]
        self.assertEqual(actual_is_valid, expected_is_valid)
        self.assertEqual(actual_issue_types, expected_issue_types)

    def test_valid_enc_key(self):
        jwk_json = """
        {
            "kty": "EC",
            "use": "enc",
            "alg": "ECDH-ES",
            "kid": "UoGD6QXSfg5glPtfg9sgKQzmUkUtCYb9Df2oidXXkeA",
            "crv": "P-256",
            "x": "ULq4jmu0kzCgJRSUuR2hvKGJfXZmX0ckGIRpYYdvbQw",
            "y": "wNv2WCwH3if340DrtfpO9netZt_Cr9Po4FcYkNWFxf0"
        }
        """

        jwk = json.loads(jwk_json)

        (actual_is_valid, actual_issues) = validate_key(jwk)
        actual_issue_types = [issue.type for issue in actual_issues]

        expected_is_valid = False
        expected_issue_types = [
            IssueType.KEY_USE_IS_INCORRECT,
            IssueType.KEY_ALG_IS_INCORRECT
        ]

        self.assertEqual(actual_is_valid, expected_is_valid)
        self.assertEqual(actual_issue_types, expected_issue_types)

    def test_contains_private_key_material(self):
        jwk_json = """
        {
            "kty": "EC",
            "use": "sig",
            "alg": "ES256",
            "kid": "54M7LspsUfvbirxoLfGeTQp8oCVducfvt0DEU8W4Wcc",
            "crv": "P-256",
            "x": "SM85B9i8alfba9WcWehUYY5WTn6lnRQ9ivlOGrIELzY",
            "y": "I9Agmt_PyqNv3LLkcCBA3iNmi9dieDNrXHnQdplNvHI",
            "d": "kmCdd0MVkSDEWlhesvOMEkx99hSA5ZFcvpaqCvEUI9o"
        }
        """

        jwk = json.loads(jwk_json)

        (actual_is_valid, actual_issues) = validate_key(jwk)
        actual_issue_types = [issue.type for issue in actual_issues]

        expected_is_valid = False
        expected_issue_types = [
            IssueType.KEY_CONTAINS_PRIVATE_MATERIAL
        ]

        self.assertEqual(actual_is_valid, expected_is_valid)
        self.assertEqual(actual_issue_types, expected_issue_types)

class ValidateKeysetTestCase(unittest.TestCase):

    def test_keys_prop_missing(self):
        jwks_json = """
        {
            "test": "value"
        }
        """

        jwks = json.loads(jwks_json)
        (actual_is_valid, actual_issues) = validate_keyset(jwks)
        actual_issue_types = [issue.type for issue in actual_issues]

        expected_is_valid = False
        expected_issue_types = [
            IssueType.KEYS_PROPERTY_MISSING
        ]

        self.assertEqual(actual_is_valid, expected_is_valid)
        self.assertEqual(actual_issue_types, expected_issue_types)

    def test_empty_keys_prop(self):
        jwks_json = """
        {
            "keys": []
        }
        """

        jwks = json.loads(jwks_json)
        (actual_is_valid, actual_issues) = validate_keyset(jwks)
        actual_issue_types = [issue.type for issue in actual_issues]

        expected_is_valid = False
        expected_issue_types = [
            IssueType.KEYS_PROPERTY_EMPTY
        ]

        self.assertEqual(actual_is_valid, expected_is_valid)
        self.assertEqual(actual_issue_types, expected_issue_types)

    def test_valid_keyset_1_sig(self):

        jwks_json = """
        {
            "keys": [
                {
                    "kty": "EC",
                    "use": "sig",
                    "alg": "ES256",
                    "kid": "54M7LspsUfvbirxoLfGeTQp8oCVducfvt0DEU8W4Wcc",
                    "crv": "P-256",
                    "x": "SM85B9i8alfba9WcWehUYY5WTn6lnRQ9ivlOGrIELzY",
                    "y": "I9Agmt_PyqNv3LLkcCBA3iNmi9dieDNrXHnQdplNvHI"
                }
            ]
        }
        """

        jwks = json.loads(jwks_json)
        (actual_is_valid, actual_issues) = validate_keyset(jwks)
        actual_issue_types = [issue.type for issue in actual_issues]

        expected_is_valid = True
        expected_issue_types = []

        self.assertEqual(actual_is_valid, expected_is_valid)
        self.assertEqual(actual_issue_types, expected_issue_types)

    def test_valid_keyset_2_sig(self):

        jwks_json = """
        {
            "keys": [
                {
                    "kty": "EC",
                    "use": "sig",
                    "alg": "ES256",
                    "kid": "54M7LspsUfvbirxoLfGeTQp8oCVducfvt0DEU8W4Wcc",
                    "crv": "P-256",
                    "x": "SM85B9i8alfba9WcWehUYY5WTn6lnRQ9ivlOGrIELzY",
                    "y": "I9Agmt_PyqNv3LLkcCBA3iNmi9dieDNrXHnQdplNvHI"
                },
                {
                    "kty": "EC",
                    "use": "sig",
                    "alg": "ES256",
                    "kid": "5iNYX3Im0lBD4B3tZTQRkDw1BsJROIrcnYOsb6qjAHM",
                    "crv": "P-256",
                    "x": "4Tisi9KVtl3YRZailW14pHCVGSBnkR8EXd1RUQ36egc",
                    "y": "hx8z_yr_yVaor-lZsVPeGKC8RT1Vk4iX-gxjZKF8MK0"
                }
            ]
        }
        """

        jwks = json.loads(jwks_json)
        (actual_is_valid, actual_issues) = validate_keyset(jwks)
        actual_issue_types = [issue.type for issue in actual_issues]

        expected_is_valid = True
        expected_issue_types = []

        self.assertEqual(actual_is_valid, expected_is_valid)
        self.assertEqual(actual_issue_types, expected_issue_types)

    def test_valid_keyset_1_sig_1_only(self):

        jwks_json = """
        {
            "keys": [
                {
                    "kty": "EC",
                    "use": "sig",
                    "alg": "ES256",
                    "kid": "54M7LspsUfvbirxoLfGeTQp8oCVducfvt0DEU8W4Wcc",
                    "crv": "P-256",
                    "x": "SM85B9i8alfba9WcWehUYY5WTn6lnRQ9ivlOGrIELzY",
                    "y": "I9Agmt_PyqNv3LLkcCBA3iNmi9dieDNrXHnQdplNvHI"
                },
                {
                    "kty": "EC",
                    "use": "enc",
                    "alg": "ECDH-ES",
                    "kid": "UoGD6QXSfg5glPtfg9sgKQzmUkUtCYb9Df2oidXXkeA",
                    "crv": "P-256",
                    "x": "ULq4jmu0kzCgJRSUuR2hvKGJfXZmX0ckGIRpYYdvbQw",
                    "y": "wNv2WCwH3if340DrtfpO9netZt_Cr9Po4FcYkNWFxf0"
                }
            ]
        }
        """

        jwks = json.loads(jwks_json)
        (actual_is_valid, actual_issues) = validate_keyset(jwks)

        expected_is_valid = True
        expected_issues = [
            Issue('Key with kid=UoGD6QXSfg5glPtfg9sgKQzmUkUtCYb9Df2oidXXkeA has an incorrect key use. It should be \"sig\"', IssueType.KEY_USE_IS_INCORRECT),
            Issue('Key with kid=UoGD6QXSfg5glPtfg9sgKQzmUkUtCYb9Df2oidXXkeA has an incorrect key alg. It should be \"ES256\"', IssueType.KEY_ALG_IS_INCORRECT),
        ]

        self.assertEqual(actual_is_valid, expected_is_valid)
        self.assertEqual(actual_issues, expected_issues)

    def test_invalid_keyset_1_key_invalid(self):

        jwks_json = """
        {
            "keys": [
                {
                    "kty": "EC",
                    "use": "sig",
                    "alg": "ES256",
                    "kid": "54M7LspsUfvbirxoLfGeTQp8oCVducfvt0DEU8W4Wcc",
                    "crv": "P-256",
                    "x": "SM85B9i8alfba9WcWehUYY5WTn6lnRQ9ivlOGrIELzY",
                    "y": "I9Agmt_PyqNv3LLkcCBA3iNmi9dieDNrXHnQdplNvHI"
                },
                {
                    "kty": "EC",
                    "use": "sig",
                    "alg": "ES256",
                    "kid": "5iNYX3Im0lBD4B3tZTQRkDw1BsJROIrcnYOsb6qjAHM",
                    "crv": "P-256",
                    "x": "4Tisi9KVtl3YRZailW14pHCVGSBnkR8EXd1RUQ36egc",
                    "y": "hx8z_yr_yVaor-lZsVPeGKC8RT1Vk4iX-gxjZKF8MK0",
                    "d": "0OaOfIFXiSLKfYVM01_4DjhleNafW4JjjMc50Ge0GRk"
                }
            ]
        }
        """

        jwks = json.loads(jwks_json)
        (actual_is_valid, actual_issues) = validate_keyset(jwks)

        expected_is_valid = False
        expected_issues = [
            Issue('Key with kid=5iNYX3Im0lBD4B3tZTQRkDw1BsJROIrcnYOsb6qjAHM contains private key material', IssueType.KEY_CONTAINS_PRIVATE_MATERIAL),
        ]

        self.assertEqual(actual_is_valid, expected_is_valid)
        self.assertEqual(actual_issues, expected_issues)

    def test_invalid_keyset_kid_missing(self):

        jwks_json = """
        {
            "keys": [
                {
                    "kty": "EC",
                    "use": "sig",
                    "alg": "ES256",
                    "kid": "54M7LspsUfvbirxoLfGeTQp8oCVducfvt0DEU8W4Wcc",
                    "crv": "P-256",
                    "x": "SM85B9i8alfba9WcWehUYY5WTn6lnRQ9ivlOGrIELzY",
                    "y": "I9Agmt_PyqNv3LLkcCBA3iNmi9dieDNrXHnQdplNvHI"
                },
                {
                    "kty": "EC",
                    "use": "sig",
                    "alg": "ES256",
                    "crv": "P-256",
                    "x": "4Tisi9KVtl3YRZailW14pHCVGSBnkR8EXd1RUQ36egc",
                    "y": "hx8z_yr_yVaor-lZsVPeGKC8RT1Vk4iX-gxjZKF8MK0"
                }
            ]
        }
        """

        jwks = json.loads(jwks_json)
        (actual_is_valid, actual_issues) = validate_keyset(jwks)

        expected_is_valid = False
        expected_issues = [
            Issue('kid is missing', IssueType.KID_IS_MISSING)
        ]

        self.assertEqual(actual_is_valid, expected_is_valid)
        self.assertEqual(actual_issues, expected_issues)

class ValidateEntriesTestCase(unittest.TestCase):

    maxDiff = None

    def test_validate_entries1(self):
        entries = [
            IssuerEntry('SHC Example Issuer 1', 'https://spec.smarthealth.cards/examples/issuer', 'https://smarthealth.cards/', None),
            IssuerEntry('SHC Example Issuer 2', 'https://spec.smarthealth.cards/examples/issuer', 'https://spec.smarthealth.cards/', None),
            IssuerEntry('SHC Example Issuer 3', 'https://spec.smarthealth.cards/examples/issuer', None, None),
            IssuerEntry('SHC Example Issuer 4', 'https://spec.smarthealth.cards/examples/issuer', None, None),
            IssuerEntry('SHC Example Issuer 5', 'https://spec.smarthealth.cards/examples/issuer', None, None),
            IssuerEntry('SHC Example Issuer 6', 'https://spec.smarthealth.cards/examples/issuer', None, None),
            IssuerEntry('SHC Example Issuer 7', 'https://spec.smarthealth.cards/examples/issuer', None, None),
            IssuerEntry('SHC Example Issuer 8', 'https://spec.smarthealth.cards/examples/issuer', None, None),
            IssuerEntry('SHC Example Issuer 9', 'https://spec.smarthealth.cards/examples/issuer', None, None),
            IssuerEntry('SHC Example Issuer 10', 'https://spec.smarthealth.cards/examples/issuer', None, None)
        ]

        actual = validate_entries(entries)

        expected = [ValidationResult(entry, True, []) for entry in entries]

        self.assertEqual(actual, expected)

    def test_valid_and_invalid_entry(self):
        entries = [
            IssuerEntry('SHC Example Issuer', 'https://spec.smarthealth.cards/examples/issuer', None, None),
            IssuerEntry('Invalid issuer 1', 'https://spec.smarthealth.cards/examples/iss', None, None),
            IssuerEntry('Invalid issuer 2', 'https://spec.smarthealth.cards/examples/issuer/', None, None),
        ]

        actual = validate_entries(entries)
        self.assertEqual(actual[0].issuer_entry, entries[0])
        self.assertEqual(actual[0].is_valid, True)
        self.assertEqual(actual[0].issues, [])

        self.assertEqual(actual[1].issuer_entry, entries[1])
        self.assertEqual(actual[1].is_valid, False)
        self.assertEqual(actual[1].issues[0].type, IssueType.FETCH_EXCEPTION)

        self.assertEqual(actual[2].issuer_entry, entries[2])
        self.assertEqual(actual[2].is_valid, False)
        self.assertEqual(actual[2].issues[0].type, IssueType.ISS_ENDS_WITH_TRAILING_SLASH)

    def test_invalid_website_entry(self):
        entries = [
            IssuerEntry('SHC Example Issuer', 'https://spec.smarthealth.cards/examples/issuer', 'https://spec.smarthealth.cards/unknown', None),
        ]

        actual = validate_entries(entries)
        self.assertEqual(actual[0].issuer_entry, entries[0])
        self.assertEqual(actual[0].is_valid, False)
        self.assertEqual(actual[0].issues[0].type, IssueType.WEBSITE_DOES_NOT_RESOLVE)

    def test_valid_canonical_iss(self):
        entries = [
            IssuerEntry('State of California', 'https://myvaccinerecord.cdph.ca.gov/creds', None, None),
            IssuerEntry('State of Louisiana', 'https://healthcardcert.lawallet.com', None, None),
            IssuerEntry('SHC Example Issuer', 'https://spec.smarthealth.cards/examples/issuer', None, 'https://myvaccinerecord.cdph.ca.gov/creds'),
        ]

        actual = validate_entries(entries)

        expected = [ValidationResult(entry, True, []) for entry in entries]

        self.assertEqual(actual, expected)

    def test_invalid_canonical_iss_self_reference(self):
        entries = [
            IssuerEntry('State of California', 'https://myvaccinerecord.cdph.ca.gov/creds', None, None),
            IssuerEntry('State of Louisiana', 'https://healthcardcert.lawallet.com', None, None),
            IssuerEntry('SHC Example Issuer', 'https://spec.smarthealth.cards/examples/issuer', None, 'https://spec.smarthealth.cards/examples/issuer'),
        ]

        actual = validate_entries(entries)
        self.assertEqual(actual[0].issuer_entry, entries[0])
        self.assertEqual(actual[0].is_valid, True)
        self.assertEqual(actual[0].issues, [])

        self.assertEqual(actual[1].issuer_entry, entries[1])
        self.assertEqual(actual[1].is_valid, True)
        self.assertEqual(actual[1].issues, [])

        self.assertEqual(actual[2].issuer_entry, entries[2])
        self.assertEqual(actual[2].is_valid, False)
        self.assertEqual(actual[2].issues[0].type, IssueType.CANONICAL_ISS_SELF_REFERENCE)

    def test_invalid_canonical_iss_reference_invalid(self):
        entries = [
            IssuerEntry('State of California', 'https://myvaccinerecord.cdph.ca.gov/creds', None, None),
            IssuerEntry('State of Louisiana', 'https://healthcardcert.lawallet.com', None, None),
            IssuerEntry('SHC Example Issuer', 'https://spec.smarthealth.cards/examples/issuer', None, 'https://spec.smarthealth.cards/examples/issuer1'),
        ]

        actual = validate_entries(entries)
        self.assertEqual(actual[0].issuer_entry, entries[0])
        self.assertEqual(actual[0].is_valid, True)
        self.assertEqual(actual[0].issues, [])

        self.assertEqual(actual[1].issuer_entry, entries[1])
        self.assertEqual(actual[1].is_valid, True)
        self.assertEqual(actual[1].issues, [])

        self.assertEqual(actual[2].issuer_entry, entries[2])
        self.assertEqual(actual[2].is_valid, False)
        self.assertEqual(actual[2].issues[0].type, IssueType.CANONICAL_ISS_REFERENCE_INVALID)

    def test_invalid_canonical_iss_multihop_reference(self):
        entries = [
            IssuerEntry('State of California', 'https://myvaccinerecord.cdph.ca.gov/creds', None, None),
            IssuerEntry('State of Louisiana', 'https://healthcardcert.lawallet.com', None, 'https://myvaccinerecord.cdph.ca.gov/creds'),
            IssuerEntry('SHC Example Issuer', 'https://spec.smarthealth.cards/examples/issuer', None, 'https://healthcardcert.lawallet.com'),
        ]

        actual = validate_entries(entries)
        self.assertEqual(actual[0].issuer_entry, entries[0])
        self.assertEqual(actual[0].is_valid, True)
        self.assertEqual(actual[0].issues, [])

        self.assertEqual(actual[1].issuer_entry, entries[1])
        self.assertEqual(actual[1].is_valid, True)
        self.assertEqual(actual[1].issues, [])

        self.assertEqual(actual[2].issuer_entry, entries[2])
        self.assertEqual(actual[2].is_valid, False)
        self.assertEqual(actual[2].issues[0].type, IssueType.CANONICAL_ISS_MULTIHOP_REFERENCE)

class DuplicateEntriesTestCase(unittest.TestCase):

    def test_duplicate_entries1(self):
        entries = [
            IssuerEntry('SHC Example Issuer 1', 'https://spec.smarthealth.cards/examples/issuer1', None, None),
            IssuerEntry('SHC Example Issuer 2', 'https://spec.smarthealth.cards/examples/issuer2', None, None),
            IssuerEntry('SHC Example Issuer 3', 'https://spec.smarthealth.cards/examples/issuer3', None, None),
            IssuerEntry('SHC Example Issuer 4', 'https://spec.smarthealth.cards/examples/issuer4', None, None),
            IssuerEntry('SHC Example Issuer 5', 'https://spec.smarthealth.cards/examples/issuer4', None, None),
            IssuerEntry('SHC Example Issuer 6', 'https://spec.smarthealth.cards/examples/issuer6', None, None),
            IssuerEntry('SHC Example Issuer 7', 'https://spec.smarthealth.cards/examples/issuer7', None, None),
            IssuerEntry('SHC Example Issuer 8', 'https://spec.smarthealth.cards/examples/issuer2', None, None),
            IssuerEntry('SHC Example Issuer 9', 'https://spec.smarthealth.cards/examples/issuer9', None, None),
            IssuerEntry('SHC Example Issuer 10', 'https://spec.smarthealth.cards/examples/issuer10', None, None)
        ]

        actual = duplicate_entries(entries)
        expected = [
            IssuerEntry('SHC Example Issuer 2', 'https://spec.smarthealth.cards/examples/issuer2', None, None),
            IssuerEntry('SHC Example Issuer 8', 'https://spec.smarthealth.cards/examples/issuer2', None, None),
            IssuerEntry('SHC Example Issuer 4', 'https://spec.smarthealth.cards/examples/issuer4', None, None),
            IssuerEntry('SHC Example Issuer 5', 'https://spec.smarthealth.cards/examples/issuer4', None, None)
        ]

        self.assertEqual(actual, expected)

    def test_no_duplicates(self):
        entries = [
            IssuerEntry('SHC Example Issuer 1', 'https://spec.smarthealth.cards/examples/issuer1', None, None),
            IssuerEntry('SHC Example Issuer 2', 'https://spec.smarthealth.cards/examples/issuer2', None, None),
            IssuerEntry('SHC Example Issuer 3', 'https://spec.smarthealth.cards/examples/issuer3', None, None),
            IssuerEntry('SHC Example Issuer 4', 'https://spec.smarthealth.cards/examples/issuer4', None, None),
        ]

        actual = duplicate_entries(entries)
        expected = []
        self.assertEqual(actual, expected)

class ValidateEntriesTest(unittest.TestCase):
    
    def validate_entries_test(self):
        entries_from_json = read_issuer_entries_from_json_file(f'{FIXTURE_DIRECTORY}/sample_directory.json')

        expected = [
            IssuerEntry('State of California', 'https://myvaccinerecord.cdph.ca.gov/creds', 'https://myvaccinerecord.cdph.ca.gov/', None),
            IssuerEntry('State of Louisiana', 'https://healthcardcert.lawallet.com', None, None),
            IssuerEntry('SHC Example Issuer', 'https://spec.smarthealth.cards/examples/issuer', None, 'https://healthcardcert.lawallet.com')
        ]

        self.assertEqual(entries_from_json, expected)

        validation_results = validate_entries(entries_from_json)
        valid = analyze_results(validation_results, False, False)
        self.assertTrue(valid)


