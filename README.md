# VCI Directory

This repository provides a public directory of institutions issuing [SMART Health Cards](https://smarthealth.cards) for COVID-19 vaccination and laboratory diagnostic testing records. The directory, represented in the [vci-issuers.json file](https://raw.githubusercontent.com/the-commons-project/vci-directory/main/vci-issuers.json), is a simple listing of issuer name, issuer URL (`iss`), and issuer website that can be used for purposes of verification and display.

[VCI™](https://vci.org) is a voluntary coalition of public and private organizations committed to empowering individuals access to a trustworthy and verifiable copy of their vaccination records in digital or paper form using open, interoperable standards. 

The scope of VCI is to harmonize the standards and produce the implementation guides needed to support the issuance of verifiable health credentials - signed clinical data bound to an individual identity. VCI does this by leading the development and implementation of the open-source SMART Health Card Framework and specifications.

## Requirements for issuers
### Types of Issuers
Today, the types of issuers permitted in VCI Directory are limited to the following:

- clinical health systems and hospitals providing patient care
- national and regional pharmacy chains
- national and regional laboratory diagnostics providers
- national and regional health insurance payors
- government and governmental agencies. 

Participation is currently limited to these issuers because it’s easier for verifiers to understand who these issuers are and how they work, to understand where data originate and are held, and to audit if issues arise. VCI have published [expanded rationale for these decisions on VCI.org](https://vci.org/updates/october-25th-2021).

### Technical Requirements
SMART Health Cards issuers must follow the [SMART Health Cards Framework Specification](https://spec.smarthealth.cards). Each production implementation must fully comply with the open standards and specifications noted therein, including:

- SMART Health Cards must pass the FHIR Validator and conform with the [VCI SMART Health Cards FHIR Implementation Guide](https://build.fhir.org/ig/dvci/vaccine-credential-ig/branches/main/conformance.html#validation).
- SMART Health Cards must pass the [developer validator tools](https://github.com/smart-on-fhir/health-cards-dev-tools) or [validator portal](https://demo-portals.smarthealth.cards/VerifierPortal.html) without errors for all targeted representations (QR, SMART on FHIR API, and file).

Issuers must provide SHCs using their own unique Issuer URL (`iss`). Issuers who use a technology platform that is shared with, or common to, other issuers, will maintain their own unique ISS separate and apart from any other issuer's `iss`. Issuers will not permit other parties to issue SHCs using their `iss` without Issuer’s authorization.

Issuers must publish their public keys as defined by the [SMART Health Cards Framework](https://spec.smarthealth.cards):

- `iss` must use the “https” scheme and must not include a trailing “/”.
- The JSON Web Key Set must be available at <<`iss`>> + /.well-known/jwks.json.
- [Cross-Origin Resource Sharing](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin) must be enabled.
- Using TLS version 1.2 following the IETF [BCP 195](https://www.rfc-editor.org/info/bcp195) recommendations or TLS version 1.3 (with any configuration).

Issuers must follow best practices for key management as defined by the [SMART Health Cards Framework](https://spec.smarthealth.cards): 

- Credentials must use a different `iss` for test data and production to ensure strong key boundaries. 
- Issuers must maintain an openly accessible, up-to-date jwks.json file at least as long as we have record-keeping obligations for represented SHCs.

### Getting Listed
Request and complete the registration and attestation form (link to be made public soon).

The Commons Project reviews each submission, verifies information contained in the submission, and performs technical validation. In the event that a submission requires subjective evaluation, the [VCI Steering Committee](https://vci.org/about) may be consulted for resolution.

## Verifiers
If you are a developer of a verifier application or service, you may use this list as a resource to:

- Identify trusted issuers per the above requirements.
- Look up and display proper issuer names.

The VCI Directory is licensed via [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). There are no additional terms or conditions for verifiers, but we do ask that you respect the VCI Verifier Code of Conduct, found at https://vci.org/about, including:

- Verifier applications shall not store SMART Health Cards or any data included within a SMART Health Card presented to it for any purpose beyond reasonable use.
- Verifier applications shall check the SMART Health Card against a list of trusted issuers.
- Verifier applications shall comply with all applicable laws and comply with the California Consumer Privacy Act.

## Holder and Wallet Applications
If you are a developer of a holder application or service, such as a Personal Health Record or digital wallet, you may use this list as a resource to:

- Identify trusted issuers per the above requirements.
- Look up and display proper issuer names.

The VCI Directory is licensed via [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). There are no additional terms or conditions for holder and wallet applications, but we do ask that you follow [SMART Health Card Design Guidelines for display and presentation](https://github.com/smart-on-fhir/health-cards-designs).

## Technical Features
The VCI creates a daily snapshot of the directory, listing the issuers along with the keys retrieved from their listed `iss` endpoint. This can be used by Verifiers as an alternative mechanism to validate SMART Health Cards, without needing to connect to the directory and Issuer endpoints in real-time.

The VCI runs frequent auditing scripts on the directory, to ensure ongoing availability and security compliance of the Issuer endpoints: audit validates proper endpoint TLS configuration, JWK set correctness, and detects name and key identifier collisions
