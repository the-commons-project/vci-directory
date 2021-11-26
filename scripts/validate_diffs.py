import argparse
import common


def main():

    parser = argparse.ArgumentParser(description='Validates different entries')
    parser.add_argument('head_input_file', help='JSON file')
    parser.add_argument('base_input_file', help='JSON file')
    parser.add_argument('--show-warnings', action='store_true', help='print warnings to the console')

    args = parser.parse_args()
    head_entries_from_json = common.read_issuer_entries_from_json_file(args.head_input_file)
    base_entries_from_json = common.read_issuer_entries_from_json_file(args.base_input_file)

    ## ensure no duplicate iss values
    duplicate_entries = common.duplicate_entries(head_entries_from_json)
    if len(duplicate_entries) > 1:
        print('Found duplicate entries')
        for entry in duplicate_entries:
            print(entry)
        exit(1)

    ## only validate new entries
    
    diffs = common.compute_diffs(base_entries_from_json, head_entries_from_json)
    additions = diffs.additions

    if len(additions) == 0:
        print('No new entries have been added')
        exit(0)

    print(f'Validating {len(additions)} new entries')
    for addition in additions:
        print(addition)

    validation_results = common.validate_entries(additions)
    valid = common.analyze_results(validation_results, True, args.show_warnings, cors_issue_is_error=True)

    if valid:
        print('All entries are valid')
        exit(0)
    else:
        print('One or more entries are invalid')
        exit(1)

if __name__ == "__main__":
    main()