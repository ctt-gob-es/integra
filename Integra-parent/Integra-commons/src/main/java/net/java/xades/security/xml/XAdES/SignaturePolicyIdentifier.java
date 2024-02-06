// Copyright (C) 2012-13 MINHAP, Gobierno de España
// This program is licensed and may be used, modified and redistributed under the terms
// of the European Public License (EUPL), either version 1.1 or (at your
// option) any later version as soon as they are approved by the European Commission.
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and
// more details.
// You should have received a copy of the EUPL1.1 license
// along with this program; if not, you may find it at
// https://eupl.eu/1.1/es/

/*
 * This file is part of the jXAdES library. 
 * jXAdES is an open implementation for the Java platform of the XAdES standard for advanced XML digital signature. 
 * This library can be consulted and downloaded from http://universitatjaumei.jira.com/browse/JXADES.
 * 
 */
package net.java.xades.security.xml.XAdES;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

/**
 *
7.2.3 The SignaturePolicyIdentifier element
The signature policy is a set of rules for the creation and validation of an electronic signature, under which the signature
can be determined to be valid. A given legal/contractual context MAY recognize a particular signature policy as
meeting its requirements.
The signature policy needs to be available in human readable form so that it can be assessed to meet the requirements of
the legal and contractual context in which it is being applied.
To facilitate the automatic processing of an electronic signature the parts of the signature policy which specify the
electronic rules for the creation and validation of the electronic signature also need to be in a computer processable
form.
If no signature policy is identified then the signature may be assumed to have been generated/verified without any
policy constraints, and hence may be given no specific legal or contractual significance through the context of a
signature policy.
The present document specifies two unambiguous ways for identifying the signature policy that a signature follows:
- The electronic signature can contain an explicit and unambiguous identifier of a signature policy together with
a hash value of the signature policy, so it can be verified that the policy selected by the signer is the one being
used by the verifier. An explicit signature policy has a globally unique reference, which, in this way, is bound
to an electronic signature by the signer as part of the signature calculation. In these cases, for a given explicit
signature policy there shall be one definitive form that has a unique binary encoded value. Finally, a signature
policy identified in this way MAY be qualified by additional information.
- Alternatively, the electronic signature can avoid the inclusion of the aforementioned identifier and hash value.
This will be possible when the signature policy can be unambiguously derived from the semantics of the type
of data object(s) being signed, and some other information, e.g. national laws or private contractual
agreements, that mention that a given signature policy MUST be used for this type of data content. In such
cases, the signature will contain a specific empty element indicating that this implied way to identify the
signature policy is used instead the identifier and hash value.
The signature policy identifier is a signed property qualifying the signature.
At most one SignaturePolicyIdentifier element MAY be present in the signature.
Below follows the Schema definition for this type.
<xsd:element name="SignaturePolicyIdentifier" type="SignaturePolicyIdentifierType"/>
<xsd:complexType name="SignaturePolicyIdentifierType">
<xsd:choice>
<xsd:element name="SignaturePolicyId" type="SignaturePolicyIdType"/>
<xsd:element name="SignaturePolicyImplied"/>
</xsd:choice>
</xsd:complexType>
<xsd:complexType name="SignaturePolicyIdType">
<xsd:sequence>
<xsd:element name="SigPolicyId" type="ObjectIdentifierType"/>
<xsd:element ref="ds:Transforms" minOccurs="0"/>
<xsd:element name="SigPolicyHash" type="DigestAlgAndValueType"/>
<xsd:element name="SigPolicyQualifiers"
type="SigPolicyQualifiersListType" minOccurs="0"/>
</xsd:sequence>
</xsd:complexType>
<xsd:complexType name="SigPolicyQualifiersListType">
<xsd:sequence>
<xsd:element name="SigPolicyQualifier" type="AnyType"
maxOccurs="unbounded"/>
</xsd:sequence>
</xsd:complexType>
The SignaturePolicyId element will appear when the signature policy is identified using the first alternative. The
SigPolicyId element contains an identifier that uniquely identifies a specific version of the signature policy. The
SigPolicyHash element contains the identifier of the hash algorithm and the hash value of the signature policy. The
SigPolicyQualifier element can contain additional information qualifying the signature policy identifier. The
optional ds:Transforms element can contain the transformations performed on the signature policy document
before computing its hash. The processing model for these transformations is described in [3].
Alternatively, the SignaturePolicyImplied element will appear when the second alternative is used. This empty
element indicates that the data object(s) being signed and other external data imply the signature policy.
7.2.3.1 Signature Policy qualifiers
Two qualifiers for the signature policy have been identified so far:
- a URL where a copy of the signature policy MAY be obtained;
- a user notice that should be displayed when the signature is verified.
Below follows the Schema definition for these two elements.
<xsd:element name="SPURI" type="xsd:anyURI"/>
<xsd:element name="SPUserNotice" type="SPUserNoticeType"/>
<xsd:complexType name="SPUserNoticeType">
<xsd:sequence>
<xsd:element name="NoticeRef" type="NoticeReferenceType"
minOccurs="0"/>
<xsd:element name="ExplicitText" type="xsd:string"
minOccurs="0"/>
</xsd:sequence>
</xsd:complexType>
<xsd:complexType name="NoticeReferenceType">
<xsd:sequence>
<xsd:element name="Organization" type="xsd:string"/>
<xsd:element name="NoticeNumbers" type="IntegerListType"/>
</xsd:sequence>
</xsd:complexType>
<xsd:complexType name="IntegerListType">
<xsd:sequence>
<xsd:element name="int" type="xsd:integer" minOccurs="0"
maxOccurs="unbounded"/>
</xsd:sequence>
</xsd:complexType>
The SPUserNotice element is intended for being displayed whenever the signature is validated. The
ExplicitText element contains the text of the notice to be displayed. Other notices could come from the
organization issuing the signature policy. The NoticeRef element names an organization and identifies by numbers
(NoticeNumbers element) a group of textual statements prepared by that organization, so that the application could
get the explicit notices from a notices file.
 *
 **/

/**
 *
 * @author miro
 */
public interface SignaturePolicyIdentifier {

    public boolean isImplied();

    public void setImplied(boolean implied);

    public String getIdentifier();

    public void setIdentifier(String identifier) throws IOException, NoSuchAlgorithmException;

    public String getHashBase64();

    public void setHashBase64(String hashBase64);

    public String getDescription();

    public void setDescription(String description);

    public String getQualifier();

    public void setQualifier(String qualifier);
}
