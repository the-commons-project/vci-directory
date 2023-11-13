import os
import unittest
import json
from common import (
    read_issuer_entries_from_tsv_file, IssuerEntry, validate_entries, ValidationResult,
    validate_key, IssueType, validate_keyset, Issue, duplicate_entries, read_issuer_entries_from_json_file,
    analyze_results, compute_diffs, IssuerEntryChange, validate_entry, validate_all_entries
)
import asyncio
import respx
from httpx import Response

FIXTURE_DIRECTORY = f'{os.path.dirname(__file__)}/fixtures'

class ReadIssuerEntriesFromTSVFileTestCase(unittest.TestCase):

    def test1(self):
        actual = read_issuer_entries_from_tsv_file(
            f'{FIXTURE_DIRECTORY}/example1.tsv',
            encoding='ISO-8859-1'
        )

        expected = [
            IssuerEntry('State of Colorado', 'https://smarthealthcard.iisregistry.net/colorado/issuer', None, None),
            IssuerEntry('State of Louisiana', 'https://api.myirmobile.com/la/issuer', None, None),
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

        self.assertTrue(actual_is_valid)
        self.assertEqual(len(actual_issues), 0)

    def test_invalid_keyset_wrong_key_use_wrong_alg(self):

        jwks_json = """
        {
            "keys": [
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

        self.assertFalse(actual_is_valid)
        self.assertEqual(len(actual_issues), 2)

        invalid_key_use = actual_issues[0]
        self.assertEqual(invalid_key_use.type, IssueType.KEY_USE_IS_INCORRECT)

        invalid_key_use = actual_issues[1]
        self.assertEqual(invalid_key_use.type, IssueType.KEY_ALG_IS_INCORRECT)

    def test_invalid_keyset_wrong_kid(self):

        jwks_json = """
        {
            "keys": [
                {
                    "kty": "EC",
                    "use": "sig",
                    "alg": "ES256",
                    "kid": "notanexpectedKid",
                    "crv": "P-256",
                    "x": "SM85B9i8alfba9WcWehUYY5WTn6lnRQ9ivlOGrIELzY",
                    "y": "I9Agmt_PyqNv3LLkcCBA3iNmi9dieDNrXHnQdplNvHI"
                }
            ]
        }
        """

        jwks = json.loads(jwks_json)
        (actual_is_valid, actual_issues) = validate_keyset(jwks)

        self.assertFalse(actual_is_valid)
        self.assertEqual(len(actual_issues), 1)

        wrong_kid = actual_issues[0]
        self.assertEqual(wrong_kid.type, IssueType.KID_IS_INCORRECT)

    def test_invalid_keyset_wrong_kid(self):

        jwks_json = """
        {
            "keys": [
                {
                    "kty": "EC",
                    "use": "sig",
                    "alg": "ES256",
                    "crv": "P-256",
                    "x": "SM85B9i8alfba9WcWehUYY5WTn6lnRQ9ivlOGrIELzY",
                    "y": "I9Agmt_PyqNv3LLkcCBA3iNmi9dieDNrXHnQdplNvHI"
                }
            ]
        }
        """

        jwks = json.loads(jwks_json)
        (actual_is_valid, actual_issues) = validate_keyset(jwks)

        self.assertFalse(actual_is_valid)
        self.assertEqual(len(actual_issues), 1)

        missing_kid = actual_issues[0]
        self.assertEqual(missing_kid.type, IssueType.KID_IS_MISSING)

    def test_keyset_1_key_valid_1_key_invalid(self):

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

        self.assertTrue(actual_is_valid)
        self.assertEqual(len(actual_issues), 0)

    def test_keyset_1_key_valid_1_key_kid_missing(self):

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

        self.assertTrue(actual_is_valid)
        self.assertEqual(len(actual_issues), 0)

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

        actual = validate_entries(entries, entries)

        expected = [ValidationResult(entry, True, []) for entry in entries]

        self.assertEqual(actual, expected)

    def test_valid_and_invalid_entry(self):
        entries = [
            IssuerEntry('SHC Example Issuer', 'https://spec.smarthealth.cards/examples/issuer', None, None),
            IssuerEntry('Invalid issuer 1', 'https://spec.smarthealth.cards/examples/iss', None, None),
            IssuerEntry('Invalid issuer 2', 'https://spec.smarthealth.cards/examples/issuer/', None, None),
        ]

        actual = validate_entries(entries, entries)
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

        actual = validate_entries(entries, entries)
        self.assertEqual(actual[0].issuer_entry, entries[0])
        self.assertEqual(actual[0].is_valid, False)
        self.assertEqual(actual[0].issues[0].type, IssueType.WEBSITE_DOES_NOT_RESOLVE)

    def test_valid_canonical_iss(self):
        entries = [
            IssuerEntry('State of Colorado', 'https://smarthealthcard.iisregistry.net/colorado/issuer', None, None),
            IssuerEntry('State of Louisiana', 'https://api.myirmobile.com/la/issuer', None, None),
            IssuerEntry('SHC Example Issuer', 'https://spec.smarthealth.cards/examples/issuer', None, 'https://smarthealthcard.iisregistry.net/colorado/issuer'),
        ]

        actual = validate_entries(entries, entries)

        expected = [ValidationResult(entry, True, []) for entry in entries]

        self.assertEqual(actual, expected)

    def test_invalid_canonical_iss_self_reference(self):
        entries = [
            IssuerEntry('State of Colorado', 'https://smarthealthcard.iisregistry.net/colorado/issuer', None, None),
            IssuerEntry('State of Louisiana', 'https://api.myirmobile.com/la/issuer', None, None),
            IssuerEntry('SHC Example Issuer', 'https://spec.smarthealth.cards/examples/issuer', None, 'https://spec.smarthealth.cards/examples/issuer'),
        ]

        actual = validate_entries(entries, entries)
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
            IssuerEntry('State of Colorado', 'https://smarthealthcard.iisregistry.net/colorado/issuer', None, None),
            IssuerEntry('State of Louisiana', 'https://api.myirmobile.com/la/issuer', None, None),
            IssuerEntry('SHC Example Issuer', 'https://spec.smarthealth.cards/examples/issuer', None, 'https://spec.smarthealth.cards/examples/issuer1'),
        ]

        actual = validate_entries(entries, entries)
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
            IssuerEntry('State of Colorado', 'https://smarthealthcard.iisregistry.net/colorado/issuer', None, None),
            IssuerEntry('State of Louisiana', 'https://api.myirmobile.com/la/issuer', None, None),
            IssuerEntry('SHC Example Issuer', 'https://spec.smarthealth.cards/examples/issuer', None, 'https://api.myirmobile.com/la/issueeeer'),
        ]

        actual = validate_entries(entries, entries)
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

    '''
    This is testing the validate_entries function, which is a wrapper that concurrently performs validation on each item in the list.
    It currently returns List[ValidationResult] (one for each input entry) and is not checking for duplicates
    (this happens before we call validate_entries in validate_entries.py).
    '''

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

class ValidateEntriesIntegrationTestCase(unittest.TestCase):

    def test_validate_entries_integration(self):
        entries_from_json = read_issuer_entries_from_json_file(f'{FIXTURE_DIRECTORY}/sample_directory.json')

        expected = [
            IssuerEntry('State of Colorado', 'https://smarthealthcard.iisregistry.net/colorado/issuer', None, None),
            IssuerEntry('State of Louisiana', 'https://api.myirmobile.com/la/issuer', None, None),
            IssuerEntry('SHC Example Issuer', 'https://spec.smarthealth.cards/examples/issuer', None, 'https://api.myirmobile.com/la/issuer')
        ]

        self.assertEqual(entries_from_json, expected)

        validation_results = validate_entries(entries_from_json, entries_from_json)
        valid = analyze_results(validation_results, True, True)
        self.assertTrue(valid)

class ComputeDiffsTestCase(unittest.TestCase):

    def test_diffs_empty(self):
        curent_entries = []
        new_entries = []

        diffs = compute_diffs(curent_entries, new_entries)

        self.assertEqual(diffs.additions, [])
        self.assertEqual(diffs.deletions, [])
        self.assertEqual(diffs.changes, [])

    def test_diffs_same(self):
        curent_entries = [
            IssuerEntry('SHC Example Issuer 1', 'https://spec.smarthealth.cards/examples/issuer1', None, None),
            IssuerEntry('SHC Example Issuer 2', 'https://spec.smarthealth.cards/examples/issuer2', None, None),
            IssuerEntry('SHC Example Issuer 3', 'https://spec.smarthealth.cards/examples/issuer3', None, None),
        ]
        new_entries = [
            IssuerEntry('SHC Example Issuer 1', 'https://spec.smarthealth.cards/examples/issuer1', None, None),
            IssuerEntry('SHC Example Issuer 2', 'https://spec.smarthealth.cards/examples/issuer2', None, None),
            IssuerEntry('SHC Example Issuer 3', 'https://spec.smarthealth.cards/examples/issuer3', None, None),
        ]

        diffs = compute_diffs(curent_entries, new_entries)

        self.assertEqual(diffs.additions, [])
        self.assertEqual(diffs.deletions, [])
        self.assertEqual(diffs.changes, [])

    def test_diffs_additions(self):
        curent_entries = [
            IssuerEntry('SHC Example Issuer 1', 'https://spec.smarthealth.cards/examples/issuer1', None, None),
            IssuerEntry('SHC Example Issuer 2', 'https://spec.smarthealth.cards/examples/issuer2', None, None),
            IssuerEntry('SHC Example Issuer 3', 'https://spec.smarthealth.cards/examples/issuer3', None, None),
        ]
        new_entries = [
            IssuerEntry('SHC Example Issuer 1', 'https://spec.smarthealth.cards/examples/issuer1', None, None),
            IssuerEntry('SHC Example Issuer 2', 'https://spec.smarthealth.cards/examples/issuer2', None, None),
            IssuerEntry('SHC Example Issuer 3', 'https://spec.smarthealth.cards/examples/issuer3', None, None),
            IssuerEntry('SHC Example Issuer 4', 'https://spec.smarthealth.cards/examples/issuer4', None, None),
            IssuerEntry('SHC Example Issuer 5', 'https://spec.smarthealth.cards/examples/issuer5', None, None),
        ]

        diffs = compute_diffs(curent_entries, new_entries)

        self.assertEqual(
            diffs.additions,
            [
                IssuerEntry('SHC Example Issuer 4', 'https://spec.smarthealth.cards/examples/issuer4', None, None),
                IssuerEntry('SHC Example Issuer 5', 'https://spec.smarthealth.cards/examples/issuer5', None, None),
            ]
        )
        self.assertEqual(diffs.deletions, [])
        self.assertEqual(diffs.changes, [])

    def test_diffs_deletions(self):
        curent_entries = [
            IssuerEntry('SHC Example Issuer 1', 'https://spec.smarthealth.cards/examples/issuer1', None, None),
            IssuerEntry('SHC Example Issuer 2', 'https://spec.smarthealth.cards/examples/issuer2', None, None),
            IssuerEntry('SHC Example Issuer 3', 'https://spec.smarthealth.cards/examples/issuer3', None, None),
            IssuerEntry('SHC Example Issuer 4', 'https://spec.smarthealth.cards/examples/issuer4', None, None),
            IssuerEntry('SHC Example Issuer 5', 'https://spec.smarthealth.cards/examples/issuer5', None, None),
        ]
        new_entries = [
            IssuerEntry('SHC Example Issuer 1', 'https://spec.smarthealth.cards/examples/issuer1', None, None),
            IssuerEntry('SHC Example Issuer 2', 'https://spec.smarthealth.cards/examples/issuer2', None, None),
            IssuerEntry('SHC Example Issuer 3', 'https://spec.smarthealth.cards/examples/issuer3', None, None),
        ]

        diffs = compute_diffs(curent_entries, new_entries)

        self.assertEqual(diffs.additions, [])
        self.assertEqual(
            diffs.deletions,
            [
                IssuerEntry('SHC Example Issuer 4', 'https://spec.smarthealth.cards/examples/issuer4', None, None),
                IssuerEntry('SHC Example Issuer 5', 'https://spec.smarthealth.cards/examples/issuer5', None, None),
            ]
        )
        self.assertEqual(diffs.changes, [])

    def test_diffs_changes(self):
        curent_entries = [
            IssuerEntry('SHC Example Issuer 1', 'https://spec.smarthealth.cards/examples/issuer1', None, None),
            IssuerEntry('SHC Example Issuer 2', 'https://spec.smarthealth.cards/examples/issuer2', None, None),
            IssuerEntry('SHC Example Issuer 3', 'https://spec.smarthealth.cards/examples/issuer3', None, None),
        ]
        new_entries = [
            IssuerEntry('SHC Example Issuer 1', 'https://spec.smarthealth.cards/examples/issuer1', None, None),
            IssuerEntry('SHC Example Issuer 2', 'https://spec.smarthealth.cards/examples/issuer2', None, None),
            IssuerEntry('SHC Example Issuer 3a', 'https://spec.smarthealth.cards/examples/issuer3', None, None),
        ]

        diffs = compute_diffs(curent_entries, new_entries)

        self.assertEqual(diffs.additions, [])
        self.assertEqual(diffs.deletions, [])
        self.assertEqual(
            diffs.changes,
            [
                IssuerEntryChange(
                    IssuerEntry('SHC Example Issuer 3', 'https://spec.smarthealth.cards/examples/issuer3', None, None),
                    IssuerEntry('SHC Example Issuer 3a', 'https://spec.smarthealth.cards/examples/issuer3', None, None),
                )
            ]
        )

class ValidateIssuerEntryTestCase(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.semaphore = asyncio.BoundedSemaphore(1)
        with open(f'{FIXTURE_DIRECTORY}/example_iss_jwks.json') as f:
            self.example_valid_iss_jwks = json.load(f)

        self.example_valid_jwks_response = Response(200, json=self.example_valid_iss_jwks, headers={"access-control-allow-origin": "*"})
        self.example_not_found_response = Response(404)

    @respx.mock
    async def test_valid_iss(self):
        entry = IssuerEntry('SHC Example Issuer 1', 'https://spec.smarthealth.cards/examples/issuer1', None, None)
        entry_map = {entry.iss: entry}
        route = respx.get('https://spec.smarthealth.cards/examples/issuer1/.well-known/jwks.json').mock(return_value=self.example_valid_jwks_response)
        validation_result = await validate_entry(entry, entry_map, self.semaphore)

        self.assertTrue(route.called)
        self.assertIsNotNone(validation_result)
        self.assertTrue(validation_result.is_valid)
        self.assertEqual(len(validation_result.issues), 0)
        self.assertEqual(validation_result.issuer_entry, entry)

    @respx.mock
    async def test_invalid_iss_keyset(self):
        entry = IssuerEntry('SHC Example Issuer 1', 'https://spec.smarthealth.cards/examples/issuer1', None, None)
        entry_map = {entry.iss: entry}
        route = respx.get('https://spec.smarthealth.cards/examples/issuer1/.well-known/jwks.json').mock(return_value=self.example_not_found_response)
        validation_result = await validate_entry(entry, entry_map, self.semaphore)

        self.assertTrue(route.called)
        self.assertIsNotNone(validation_result)
        self.assertFalse(validation_result.is_valid)
        self.assertTrue(len(validation_result.issues) > 0)
        self.assertEqual(validation_result.issuer_entry, entry)

    @respx.mock
    async def test_canonical_iss_skips_iss_keyset_checks(self):
        entry = IssuerEntry('SHC Example Issuer', 'https://spec.smarthealth.cards/examples/issuer', None, canonical_iss='https://spec.smarthealth.cards/examples/issuer1')
        canonical_entry = IssuerEntry('SHC Example Issuer 1', 'https://spec.smarthealth.cards/examples/issuer1', None, None)

        entry_map = {entry.iss: entry, canonical_entry.iss: canonical_entry}
        route = respx.get('https://spec.smarthealth.cards/examples/issuer/.well-known/jwks.json').mock(return_value=self.example_not_found_response)
        validation_result = await validate_entry(entry, entry_map, self.semaphore)
        # If a canonical_entry iss is defined, we have no expectation of behavior for the iss value, so we should skip validation
        self.assertFalse(route.called)
        self.assertIsNotNone(validation_result)
        self.assertTrue(validation_result.is_valid)
        self.assertEqual(len(validation_result.issues), 0)
        self.assertEqual(validation_result.issuer_entry, entry)

    @respx.mock
    async def test_canonical_iss_must_be_in_full_issuer_list(self):
        entry = IssuerEntry('SHC Example Issuer', 'https://spec.smarthealth.cards/examples/issuer', None, canonical_iss='https://spec.smarthealth.cards/examples/issuer1')

        entry_map = {entry.iss: entry}
        route = respx.get('https://spec.smarthealth.cards/examples/issuer/.well-known/jwks.json').mock(return_value=self.example_not_found_response)
        validation_result = await validate_entry(entry, entry_map, self.semaphore)
        # If a canonical_entry iss is defined, we have no expectation of behavior for the iss value, so we should skip validation
        self.assertFalse(route.called)
        self.assertIsNotNone(validation_result)
        self.assertFalse(validation_result.is_valid)
        self.assertEqual(len(validation_result.issues), 1)
        issue = validation_result.issues[0]
        self.assertEqual(issue.type, IssueType.CANONICAL_ISS_REFERENCE_INVALID)

    @respx.mock
    async def test_canonical_iss_cannot_self_reference(self):
        entry = IssuerEntry('SHC Example Issuer', 'https://spec.smarthealth.cards/examples/issuer', None, canonical_iss='https://spec.smarthealth.cards/examples/issuer')

        entry_map = {entry.iss: entry}
        route = respx.get('https://spec.smarthealth.cards/examples/issuer/.well-known/jwks.json').mock(return_value=self.example_not_found_response)
        validation_result = await validate_entry(entry, entry_map, self.semaphore)
        # If a canonical_entry iss is defined, we have no expectation of behavior for the iss value, so we should skip validation
        self.assertFalse(route.called)
        self.assertIsNotNone(validation_result)
        self.assertFalse(validation_result.is_valid)
        self.assertEqual(len(validation_result.issues), 1)
        issue = validation_result.issues[0]
        self.assertEqual(issue.type, IssueType.CANONICAL_ISS_SELF_REFERENCE)

    @respx.mock
    async def test_canonical_iss_entry_cannot_have_itself_canonical_iss(self):
        entry = IssuerEntry('SHC Example Issuer', 'https://spec.smarthealth.cards/examples/issuer', None, canonical_iss='https://spec.smarthealth.cards/examples/issuer1')
        canonical_entry = IssuerEntry('SHC Example Issuer 1', 'https://spec.smarthealth.cards/examples/issuer1', None, canonical_iss='https://spec.smarthealth.cards/examples/issuer2')

        entry_map = {entry.iss: entry, canonical_entry.iss: canonical_entry}
        route = respx.get('https://spec.smarthealth.cards/examples/issuer/.well-known/jwks.json').mock(return_value=self.example_not_found_response)
        validation_result = await validate_entry(entry, entry_map, self.semaphore)
        # If a canonical_entry iss is defined, we have no expectation of behavior for the iss value, so we should skip validation
        self.assertFalse(route.called)
        self.assertIsNotNone(validation_result)
        self.assertFalse(validation_result.is_valid)
        self.assertEqual(len(validation_result.issues), 1)
        issue = validation_result.issues[0]
        self.assertEqual(issue.type, IssueType.CANONICAL_ISS_MULTIHOP_REFERENCE)


class ValidateAllEntriesTestCase(unittest.IsolatedAsyncioTestCase):

    @respx.mock
    async def test_adding_entry_with_canonical(self):
        entry = IssuerEntry('SHC Example Issuer 1', 'https://spec.smarthealth.cards/examples/issuer', None, canonical_iss='https://spec.smarthealth.cards/examples/issuer1')
        canonical_entry = IssuerEntry('SHC Example Issuer 1', 'https://spec.smarthealth.cards/examples/issuer1', None, None)

        route = respx.get('https://spec.smarthealth.cards/examples/issuer/.well-known/jwks.json').mock(return_value=Response(404))
        validation_results = await validate_all_entries([entry], [entry, canonical_entry])

        self.assertFalse(route.called)
        self.assertIsNotNone(validation_results)
        self.assertEqual(len(validation_results), 1)
        result = validation_results[0]
        self.assertTrue(result.is_valid)

class ValidateJSONsyntax(unittest.TestCase):
    # no schema is provided error will be related to syntax errors only
    def test_validate_vci_issuer_json(self):
        with open('../vci-issuers.json') as json_file:
            data = json.load(json_file)
            self.assertTrue(data)

    def test_validate_vci_metadata_json(self):
        with open('../vci-issuers-metadata.json') as json_file:
            data = json.load(json_file)
            self.assertTrue(data)
