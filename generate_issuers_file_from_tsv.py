import argparse
import common

name_index = 0
name_header = 'name'
iss_index = 1
iss_header = 'iss'

def main():

    parser = argparse.ArgumentParser(description='Converts a tab delimited file into a compatible JSON file')
    parser.add_argument('input_file', help='TSV file')
    parser.add_argument('output_file', help='JSON file')

    args = parser.parse_args()

    entries_from_tsv = common.read_issuer_entries_from_tsv_file(args.input_file, encoding='ISO-8859-1')
    common.write_issuer_entries_to_json_file(args.output_file, entries_from_tsv)

    entries_from_json = common.read_issuer_entries_from_json_file(args.output_file)

    if set(entries_from_tsv) != set(entries_from_json):
        raise Exception('Input and output are not equivalent')
        
if __name__ == "__main__":
    main()

