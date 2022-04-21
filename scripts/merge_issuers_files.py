import argparse
import common


def main():

    parser = argparse.ArgumentParser(description='Merges 2 JSON issuer files')
    parser.add_argument('input_file_1', help='Initial JSON file')
    parser.add_argument('input_file_2', help='JSON file to merge into the initial file')
    parser.add_argument('output_file', help='JSON file')

    args = parser.parse_args()
    entries_from_json_2 = common.read_issuer_entries_from_json_file(args.input_file_2)

    ## validate entries_from_json_2
    validation_results = common.validate_entries(entries_from_json_2, entries_from_json_2)
    is_valid = common.analyze_results(validation_results, False, False)
    if not is_valid:
        print('One or more entries are invalid')
        exit(1)

    entries_from_json_2_dict = { entry.iss:entry for entry in entries_from_json_2}

    entries_from_json_1 = common.read_issuer_entries_from_json_file(args.input_file_1)
    entries_from_json_1_dict = { entry.iss:entry for entry in entries_from_json_1}

    merged_entry_dict = entries_from_json_1_dict.copy()
    merged_entry_dict.update(entries_from_json_2_dict)

    merged_entries = list(merged_entry_dict.values())
    common.write_issuer_entries_to_json_file(args.output_file, merged_entries)

if __name__ == "__main__":
    main()
