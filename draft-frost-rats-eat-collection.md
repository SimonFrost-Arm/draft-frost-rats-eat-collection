---
title: "Entity Attestation Token (EAT) Collection Type"
abbrev: "EAT Collection"
category: std

docname: draft-frost-rats-eat-collection-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Remote ATtestation ProcedureS"
keyword:
- EAT
- collection container
venue:
  group: "Remote ATtestation ProcedureS"
  type: "Working Group"
  mail: "rats@ietf.org"

author:
  -
    fullname: Simon Frost
    organization: Arm
    email: Simon.Frost@arm.com

contributor:
- name: Thomas Fossati
  org: Arm Limited
  email: thomas.fossati@arm.com

normative:
  I-D.ietf-rats-eat: eat
  IANA.cbor-tags:
  RFC8610: cddl
  RFC9165: cddlplus

informative:
  I-D.ietf-rats-uccs:
  I-D.ietf-rats-architecture: rats-architecture
  RFC8392:
  STD96:
    -: cose
    =: RFC9052
  RFC7519:
  RFC7515:
  Arm-CCA:
    author:
      org: "Arm Ltd"
    title: "Confidential Compute Architecture"
    target: https://www.arm.com/architecture/security-features/arm-confidential-compute-architecture
    date: 2022

entity:
  SELF: "RFCthis"

--- abstract

The default top-level definitions for an EAT {{I-D.ietf-rats-eat}} assume a hierarchy involving a leading signer within the Attester. Some token use cases do not match that model. This specification defines an extension to EAT allowing the top-level of the token to consist of a collection of otherwise defined tokens.

--- middle

# Introduction

An Attestation Token conforming to EAT {{I-D.ietf-rats-eat}} has a default top level definition for a token to be constructed principally as a claim set within a CBOR Web Token (CWT) {{RFC8392}} with the associated COSE envelope {{-cose}} providing at least integrity and authentication. An equivalent JSON encoding for a JWT {{RFC7519}} in a JWS envelope {{RFC7515}} is supported as an alternative at the top-level definition. The top level token can be augmented with related claims in a Detached EAT Bundle.

For the use case of transmitting a claim set through a secure channel, the top-level definition can be extended to use an Unprotected CWT Claim Set (UCCS) {{I-D.ietf-rats-uccs}}.

This document outlines an additional top-level extension for which neither of the above top level definitions match exactly: the attestation token consists of a collection of objects, each with their own integrity and some internally defined relationship through which the integrity of the whole collection can be determined. i.e. there is no top-level signer for the set. The objects may all share the same logical hierarchy in a device or have a hierarchy which is internally defined within the object set.

# Terminology and Requirements Language

Readers are also expected to be familiar with the terminology from {{-eat}} and {{-rats-architecture}}.

In this document, the structure of data is specified in CDDL {{-cddl}} {{-cddlplus}}.

{::boilerplate bcp14-tagged}

# Design Considerations / Use Cases

Take a device with an attestation system consisting of a platform claim set and a workload claim set, each controlled by different components and with an underlying hardware Root of Trust. The two claim sets are delivered together to make up the overall attestation token. Depending upon the implementation and deployment use case, the signing system can either be entirely centric to the platform RoT or can have separate signers for the two claim sets. In either case, a cryptographic binding is established between the two parts of the token.

A specific manifestation of such a device is one incorporating the Arm Confidential Compute Architecture (CCA) attestation token {{Arm-CCA}}. In trying to prepare the attestation token using EAT, there were no issues constructing the claim sets or incorporating them into individual CWTs where appropriate. However, in trying to design an 'envelope structure' to convey the two parts as a single report it was found that maintaining EAT compatibility would require very different shaped compound tokens for different models, for example one based on a submod arrangement and another based on a Detached EAT Bundle, though with different ‘leading’ objects. This would create extra code and explanation in areas where keeping things simple is desirable. There was an alternative approach considered, which stays close to existing thinking on EAT, which would be to create the wrapper from the UCCS EAT extension containing only submods for the respective components. This however stretches the current use case for UCCS beyond its existing description. The RATS WG approach of separating UCCS from the core EAT specification to be an extension also encourages proposing this further extension.

To support the CCA use case, it is also relevant to consider current attestation technologies which are based on certificate chains (e.g. SPDM, DICE, several key attestation systems). Here also are multiple objects with their own integrity and an internally defined relationship. If attempting to move such a technology to the EAT world, the same challenges apply.

# Token Collection

The proposed extension for the top-level definition is to add a 'Token Collection' type. The contents of the type are a map of CWTs (JWTs). The Detached EAT Bundle top-level entry for EAT is included for completeness, and the UCCS extension can also be embraced, though the use cases for these have not been explored. The identification of collection members and the intra collection integrity mechanism is considered usage specific. A verifier will be expected to extract each of the members of the collection and check their validity both individually and as a set. In addition to entries which have their own integrity, it is also
supported to include an unsigned Claims Set, provided that the integrity for that Claims Set is provided
within another entry that uses one of the signed forms.

A map was chosen rather than an unbounded array to give the opportunity to add identifying map tags to each entry. The interpretation of the tags will be usage specific, but may correspond to registered identities of specific token types. To assist a verifier correlate the expected contents a profile entry can be added as the ‘profile-label’ identity in the map.

See {{cddl}} for a CDDL description of the proposed extension.

While most of the use cases for collections are for scenarios where there will be at least two entries in a collection, the CDDL allows for >= 1 entries in a collection to allow for the scenario where only one entry is currently available even though the normal set is larger.

## Binder Definition
This specification includes a proposal for a Collection Binder claim (see {{fig-binder}}). This claim would be
included within any collection entry as a definiton of the integrity mechanism that binds that collection
entry to another collection entry. A verifier can use the information within this claim to drive inter
collection entry integrity checking. This claim would not be mandatory within a collection entry as a
verifier may implement the integrity checking based upon information in the profile alone.

~~~ cddl
{::include cddl/collection-binder.cddl}
~~~
{: #fig-binder title="EAT collection binder" }

The attributes within the binder claim are:

+ `binder-function`: the identity of the binding cryptographic function, usually a hash function, applied
to the values identified by the binder-source-label array.
+ `binder-source-label`: an array defining the set of claims providing the binding information within the
collection entry. It is assumed that the values corresponding to this (ordered) list will be concatenated
and have the binder-function applied to produce a binder value. If the array is empty, the entire source
collection entry is used as input to the binder-function. This latter condition would normally be applied
to a collection entry consisting of a Claim Set.
+ `destination-collection-entry`: this defines the collection entry that will hold (receive) the binding
for this (source) collection entry.
+ `destination-claim`: this defines the claim label within destination-collection-entry which will store
the binder value.

A verifier can check the binding between two collection entries by computing the binder value for one
entry and comparing the result stored within the value of the destination claim (in the destination
collection entry).

# Security Considerations

A verifier for an attestation token must apply a verification process for the full set of entries contained within the Token Collection.
This process will be custom to the relevant profile for the Token Collection and take into account any individual verification per entry and/or verification for the objects considered collectively, including the intra token integrity scheme.
As there is no overall signature for the Collection, protection against malicious modification must be contained within the entries.
It is expected that there exists a cryptographic binding between entries, this can for example be one to many or one to one in a (chain) series.
Depending upon the use case and associated threat model, the freshness of entries may need extra consideration.

# IANA Considerations

In the registry {{IANA.cbor-tags}}, IANA is requested to allocate the tag in {{tbl-eat-collection}} from the FCFS space, with the present document as the specification reference.

| Tag | Data Item | Semantics |
|---|---|---|
| TBD399 | map | EAT Collection {{&SELF}} |
{: #tbl-eat-collection align="left" title="EAT Collection"}

--- back


# CDDL

~~~ cddl
$$EAT-CBOR-Tagged-Token /= Tagged-Collection
$$EAT-CBOR-Untagged-Token /= TL-Collection

Tagged-Collection =  #6.TBD399(TL-Collection)

TL-Collection = {
    ? eat-collection-identifier,
    + all-collection-types
}

eat-collection-identifier = (
    profile-label => general-uri / general-oid
)

all-collection-types = (
    cwt-collection-entries //
    jwt-collection-entries //
    claim-set-collection-entries //
    detatched-eat-bundle-collection-entries
)

cwt-collection-entries = (
    collection-entry-label => CWT-Messages
)

jwt-collection-entries = (
    collection-entry-label => JWT-Messages
)

claim-set-collection-entries = (
    collection-entry-label => JC<json-wrapped-claims-set,
                                 cbor-wrapped-claims-set>
)

detatched-eat-bundle-collection-entries = (
    collection-entry-label => BUNDLE-Messages
)

collection-entry-label = JC<text, int>

; The Collection Binder is a formal declaration of the inter entry
; binding mechanism. It would be included within the body of one or
; more of the collection entries.
Tagged-Collection-Binder =  #6.TBD99(Collection-Binder)
Collection-Binder = [
    binder-function,
    [*binder-source-label],
    destination-collection-entry,
    destination-claim
]
; binder function is normally the name/id of a hash algorithm
binder-function = JC<text,int>

; by definition, the binder-function is applied to a concatenation
; of the ordered list of source claims
; If the array is empty, the function is applied to the whole
; contents of the token
binder-source-label = Claim-Label

destination-collection-entry = collection-entry-label

destination-claim = Claim-Label


~~~

--- back

# Acknowledgments
{:numbered="false"}

Thomas Fossati proposed the inclusion of the Binder definiton and collaborated
on the CDDL. Yogesh Deshpande provided insightful comments and review for this
proposal.
