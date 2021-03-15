package net.java.xades.security.xml.XAdES;

import java.util.ArrayList;

/**
 * 5.2.6 The SignerRoleV2 qualifying property
<p>Semantics</p>
<p>The SignerRoleV2 qualifying property shall be a signed qualifying property that qualifies the signer.</p>
<p>The SignerRoleV2 qualifying property shall encapsulate signer attributes (e.g. role). This qualifying property may
encapsulate the following types of attributes:</p>
<ul>
<li>attributes claimed by the signer;</li>
<li>attributes certified in attribute certificates issued by an Attribute Authority; or/and</li>
<li>assertions signed by a third party.</li>
</ul>
<p>Syntax</p>
<p>The SignerRoleV2 qualifying property shall be defined as in XML Schema file "XAdES01903v132-201601.xsd",
whose location is detailed in clause C.1, and is copied below for information.</p>
<code>
    <!-- targetNamespace="http://uri.etsi.org/01903/v1.3.2#" -->
    <xsd:element name="SignerRoleV2" type="SignerRoleV2Type"/>
    <xsd:complexType name="SignerRoleV2Type">
        <xsd:sequence>
            <xsd:element ref="ClaimedRoles" minOccurs="0"/>
            <xsd:element ref="CertifiedRolesV2" minOccurs="0"/>
            <xsd:element ref="SignedAssertions" minOccurs="0"/>
        </xsd:sequence>
    </xsd:complexType>
    <xsd:element name="ClaimedRoles" type="ClaimedRolesListType"/>
    <xsd:element name="CertifiedRolesV2" type="CertifiedRolesListTypeV2"/>
    <xsd:element name="SignedAssertions" type="SignedAssertionsListType"/>
    <xsd:complexType name="ClaimedRolesListType">
        <xsd:sequence>
            <xsd:element name="ClaimedRole" type="AnyType" maxOccurs="unbounded"/>
        </xsd:sequence>
    </xsd:complexType>
    <xsd:complexType name="CertifiedRolesListTypeV2">
        <xsd:sequence>
            <xsd:element name="CertifiedRole" type="CertifiedRoleTypeV2" maxOccurs="unbounded"/>
        </xsd:sequence>
    </xsd:complexType>
    <xsd:complexType name="CertifiedRoleTypeV2">
        <xsd:choice>
            <xsd:element ref="X509AttributeCertificate"/>
            <xsd:element ref="OtherAttributeCertificate"/>
        </xsd:choice>
    </xsd:complexType>
    <xsd:element name="X509AttributeCertificate" type="EncapsulatedPKIDataType"/>
    <xsd:element name="OtherAttributeCertificate" type="AnyType"/>
    <xsd:complexType name="SignedAssertionsListType">
        <xsd:sequence>
            <xsd:element ref="SignedAssertion" maxOccurs="unbounded"/>
        </xsd:sequence>
    </xsd:complexType>
    <xsd:element name="SignedAssertion" type="AnyType"/>
</code>
<p>The ClaimedRoles element shall contain a non-empty sequence of roles claimed by the signer but which are not
certified.</p>
<p>Additional content types may be defined on a domain application basis and be part of this element.</p>
<p>NOTE 1: The namespaces given to the corresponding XML schemas allow their unambiguous identification in the
case these attributes are expressed in XML syntax (e.g. SAML assertions [i.9] of different versions).</p>
<p>The CertifiedRolesV2 element shall contain a non-empty sequence of certified attributes, which shall be one of
the following:</p>
<ul>
    <li>the base-64 encoding of DER-encoded X509 attribute certificates conformant to Recommendation
ITU-T X.509 [4] issued to the signer, within the X509AttributeCertificate element; or</li>
    <li>attribute certificates (issued, in consequence, by Attribute Authorities) in different syntax than the one
specified in Recommendation ITU-T X.509 [4], within the OtherAttributeCertificate element. The
definition of specific OtherAttributeCertificate is outside of the scope of the present document.</li>
</ul>
<p>The SignedAssertions element shall contain a non-empty sequence of assertions signed by a third party.</p>
<p>NOTE 2: A signed assertion is stronger than a claimed attribute, since a third party asserts with a signature that the
attribute of the signer is valid. However, it is less restrictive than an attribute certificate.</p>
<p>The definition of specific content types for SignedAssertions is outside of the scope of the present document.</p>
<p>NOTE 3: A possible content can be a signed SAML [i.9] assertion.
Empty SignerRoleV2 qualifying properties shall not be generated.</p>
 *
 *
 * @author miro
 */
public interface SignerRoleV2
{
	public ArrayList<String> getClaimedRoles();
	public void setClaimedRoles(ArrayList<String> claimedRole);
	public void addClaimedRole(String role);
		
	public ArrayList<String> getCertifiedRolesV2();
	public void setCertifiedRolesV2(ArrayList<String> certifiedRole);
	public void addCertifiedRoleV2(String role);
	
	public ArrayList<String> getSignedAssertions();
	public void setSignedAssertions(ArrayList<String> signedAssertions);	
}
