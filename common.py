import csv
import json
from collections import namedtuple
IssuerEntry = namedtuple('IssuerEntry', 'name iss')


default_name_index = 0
default_name_header = 'name'
default_iss_index = 1
default_iss_header = 'iss'
default_encoding = 'utf-8'

name_key = 'name'
iss_key = 'iss'
participating_issuers_key = 'participating_issuers'

def read_issuer_entries_from_tsv_file(
    input_file, 
    name_index=default_name_index,
    name_header=default_name_header,
    iss_index=default_iss_index,
    iss_header=default_iss_index,
    encoding=default_encoding
):
    with open(input_file, 'r', newline='', encoding=encoding) as tsvfile:
        reader = csv.reader(tsvfile, delimiter='\t')
        entries = []
        for row in reader:
            name = row[name_index]
            iss = row[iss_index]
            if name != name_header and iss != iss_header:
                entry = IssuerEntry(name, iss)
                entries.append(entry)
        return entries

def read_issuer_entries_from_json_file(
    input_file
):
    with open(input_file, 'r') as json_file:
        d = json.load(json_file)
        entries = []
        for entry_dict in d[participating_issuers_key]:
            name = entry_dict[name_key]
            iss = entry_dict[iss_key]
            entry = IssuerEntry(name, iss)
            entries.append(entry)

        return entries

def write_issuer_entries_to_json_file(
    output_file,
    entries
):
    entry_dicts = [{iss_key: entry.iss, name_key: entry.name} for entry in entries]
    output_dict = {
        participating_issuers_key: entry_dicts
    }
    with open(output_file, 'w') as json_file:
        json.dump(output_dict, json_file, indent=4)

