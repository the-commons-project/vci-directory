import json

def update_readme(json_path, md_path):
    try:
        # Load the JSON data
        with open(json_path, 'r') as json_file:
            issuers_data = json.load(json_file)

        # Start the markdown content
        markdown_content = "# VCI Issuers\n\n"
        markdown_content += "This document lists the Vaccine Credential Initiative (VCI) issuers with their names and issuer identifiers.\n\n"
        markdown_content += "| Name | Issuer (iss) |\n"
        markdown_content += "| ---- | ------------- |\n"

        # Parse the JSON data and generate markdown table
        for issuer in issuers_data.values():
            for entry in issuer:
                name = entry.get('name', 'N/A')
                iss = entry.get('iss', 'N/A')
                markdown_content += f"| {name} | {iss} |\n"

        # Write the markdown content to the README
        with open(md_path, 'w') as md_file:
            md_file.write(markdown_content)
        print(f"Updated {md_path} successfully.")

    except Exception as e:
        print(f"An error occurred: {e}")

# Paths to the JSON and Markdown files
json_path = 'vci-directory/vci-issuers.json'
md_path = 'vci-directory/VCI-Issuers.md'

# Call the function to update the README
update_readme(json_path, md_path)
