# VCI Directory

This repository provides a public directory of institutions issuing COVID-19 SMART Health Cards. The directory, represented in the [vci-issuers.json file](https://raw.githubusercontent.com/the-commons-project/vci-directory/main/vci-issuers.json), is a simple listing of issuer name, website and iss values that can be used for purposes of verification and display.

## Requirements for issuers
At this time, entries in the directory are authorized administrators of the vaccine and holders of immunization and lab result records, including:

- State registries and state-backed issuers
- Health systems supported by VCI-member EMR platform providers
- Retail pharmacy chains

Issuers present in the directory have asserted their conformance to the SMART Health Card specification and the VCI FHIR profile IG, and implementations were confirmed to be conformant by the VCI team at the time of submission. See the [terms for participation in the directory](https://github.com/the-commons-project/vci-directory/blob/main/VCI%20Directory%20Agreement.pdf).

## Verifiers
If you are a developer of a verifier application or service, you may use this list as a resource to:

- Identify trusted issuers per the above requirements.
- Look up and display proper issuer names.

The VCI Directory is licensed via [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). There are no additional terms or conditions for verifiers, but we do ask that you respect the VCI Verifier Code of Conduct, found at https://vci.org/about, including:

- Verifier applications shall not store SMART Health Cards or any data included within a SMART Health Card presented to it.
- Verifier applications shall check the SMART Health Card against a list of trusted issuers.
- Verifier applications shall comply with all applicable laws and comply with the California Consumer Privacy Act.

## Holder and Wallet Applications
If you are a developer of a holder application or service, such as a Personal Health Record or digital wallet, you may use this list as a resource to:

- Identify trusted issuers per the above requirements.
- Look up and display proper issuer names.

The VCI Directory is licensed via [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). There are no additional terms or conditions for verifiers, but we do ask that you follow [SMART Health Card Design Guidelines for display and presentation](https://github.com/smart-on-fhir/health-cards-designs).

## Limitations

The VCI Directory is not meant to be a substitute for a robust trust framework:

- The list of issuers may not be comprehensive.
- Holder and verifier applications are not bound to terms related to data use and best practices.
