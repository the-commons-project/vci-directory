import argparse
import common
import csv
import sys


def main():

    parser = argparse.ArgumentParser(description='Validates entries in a JSON file')
    parser.add_argument('input_file', help='JSON file')

    args = parser.parse_args()
    entries_from_json = common.read_issuer_entries_from_json_file(args.input_file)

    validation_results = common.validate_entries(entries_from_json, entries_from_json)

    invalid_cors_entries = []

    for result in validation_results:
        for issue in result.issues:
            if issue.type == common.IssueType.CORS_HEADER_MISSING or issue.type == common.IssueType.CORS_HEADER_INCORRECT:
                invalid_cors_entries.append(result.issuer_entry)

    if len(invalid_cors_entries) > 0:
        writer = csv.DictWriter(
            sys.stdout,
            fieldnames=common.IssuerEntry._fields,
            delimiter='\t'
        )
        writer.writeheader()
        writer.writerows([entry._asdict() for entry in invalid_cors_entries])


if __name__ == "__main__":
    main()
