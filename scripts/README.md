# Adding entries to `vci-issuers.json`

## Initial Setup
All the scripts are Python-based and the easiest (and tested) way to run them is to create a virtual environemnt. Run the following commands from the `scripts` directory to initialize your virtual environment:

```
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

To deactivate your virutal environment, run the following:
```
deactivate
```

To reenable your virtual envirionment, run the following:
```
source venv/bin/activate
```
## Generating an new VCI Issuers file

First, you will need to generate a file containing issuers that you would like to be added (see example.json). This can be done by either hand crafting one **OR** by starting with a tab separated value file (see example.tsv) and using the `generate_issuers_file_from_tsv.py` script. Example usage for `generate_issuers_file_from_tsv.py` would be something like:

```
python generate_issuers_file_from_tsv.py examples/example.tsv examples/example.json
```

## Validating the new VCI Issuers file

Before you merging additions into the main `vci-issuers.json` file, you should validate that the new issuer entries are valid. The `validate_entries.py` script is provided to ensure that properly formatted keys are hosted at the proper location relative to the `iss` value for each issuer entry. Example usage for `validate_entries.py` would be something like:

```
python validate_entries.py examples/example.json
```

## Merging in new VCI Issuer entries into `vci-issuers.json`

Once the new issuers file has been validated, you can use the `merge_issuers_files.py` script to merge the new file into `vci-issuers.json`. Example usage for `validate_entries.py` would be something like:

```
python merge_issuers_files.py ../vci-issuers.json examples/example.json ../vci-issuers.json
```

## Submit a pull request

Once the `vci-issuers.json` file has been updated, submit a pull request with the changes.


test
