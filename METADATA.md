# Issuer Metadata

## Metadata Representation

[vci-issuer-metadata.json](vci-issuers-metadata.json) represents metadata about an Issuer that may be useful to applications and websites.

| Attribute | Meaning |
|-----------|---------|
| `canonical_iss` | The matches the `iss` or `canonical_iss` of the issuer in `vci-issuers.json` |
| `website` | A website where the consumer can get their SMART Health Card or learn where they can get their SMART Health Card |
| `help_line` | A phone number a consumer can call for assistance |
| `issuer_type` | The type of issuer (see below for details) |
| `locations` | A list of locations (see below for details) that the issuer is associated with |

## Issuer Type Representation

The type of institution an issuer represents may be important for verifiers and holders. This value set captures the currently permitted and participating [issuer types in the VCI Directory](https://github.com/the-commons-project/vci-directory#types-of-issuers): clinical health systems and hospitals providing patient care, pharmacies, laboratory diagnostics providers, health insurance payors, and government and governmental agencies.

A simple hierarchy provides an easier means to segregate government and non-governmental issuers for those who find that valuable.

| Attribute | Meaning |
|-----------|---------|
| `organizational.health_system` | A clinical health system or hospital providing patient care |
| `organizational.pharmacy` | A national or regional pharmacy chain |
| `organizational.laboratory` | A national or regional laboratory diagnostics provider |
| `organizational.insurer` | A national or regional health insurance payor |
| `governmental.nation` | A nation or national governmental agency issuing for a nation |
| `governmental.state_province_territory` | A state, province, territory or governmental agency issuing for a state, province, or territory |
| `governmental.city_county` | A city, county or governmental agency issuing for a city |
| `governmental.agency` | A governmental agency |

## Location Representation

In order to best represent the reality of a SHC issuer issuing SHCs in multiple locations, an issuer can be associated to multiple country-state locations.

This location representation is heavily inspired by the [FHIR `Address` type][fhir-address-type].

| Attribute | Meaning |
|-----------|---------|
| `state` | The state, province, territory, or other administrative division within a country associated with the issuer |
| `country` | The country associated with the issuer expressed as ISO 3166 2 or 3 letter code |

Each location within the list of `locations` should be independently-defined. For
example, if an issuer has operations in the states of New York and New Jersey, each of its
`locations` should include both state and country:


```json
locations: [
  { "state": "NY", "country": "US" },
  { "state": "NJ", "country": "US" }
]
```

[example-metadata.json](example-metadata.json) shows basic example representing what an entry in the metadata file would look like.

[fhir-address-type]:https://www.hl7.org/fhir/datatypes.html#Address
