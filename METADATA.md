# Issuer Metadata

## Metadata Representation

[vci-issuer-metadata.json](vci-issuers-metadata.json) represents metadata about an Issuer that may be useful to applications and websites.

| Attribute | Meaning |
|-----------|---------|
| `canonical_iss` | The matches the `iss` or `canonical_iss` of the issuer in `vci-issuers.json` |
| `website` | A website where the consumer can get their SMART Health Card or learn where they can get their SMART Health Card |
| `help_line` | A phone number a consumer can call for assistance |
| `issuer_type` | The type of issuer |
| `locations` | A list of locations (see below for details) that the issuer is associated with |

## Location Representation

In order to best represent the reality of a SHC issuer issuing SHCs in multiple
locations, an issuer can be associated to multiple country-state locations.

This location representation is heavily inspired by the [FHIR `Address` type][fhir-address-type].

| Attribute | Meaning |
|-----------|---------|
| `state` | Which state, province, territory, or other administrative division within a country the issuer represents |
| `country` | The country the issuer represents as ISO 3166 2 or 3 letter code |

Each location within the list of `locations` should be independently-defined. For
example, if an issuer operations in the states of New York and New Jersey, its
`locations` should be represented by (country should not be omitted):


```json
locations: [
  { "state": "NY", "country": "US" },
  { "state": "NJ", "country": "US" }
]
```

[example-metadata.json](example-metadata.json) shows basic example representing what an entry in the metadata file would look like.

[fhir-address-type]:https://www.hl7.org/fhir/datatypes.html#Address
