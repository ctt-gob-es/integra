package net.java.xades.security.xml.XAdES;

/**
 * ETSI EN 319 132-1 V1.1.1 (2016-04)
 * 
 * 5.2.10 The SignaturePolicyStore qualifying property
 * <p>Semantics</p>
 * <p>The SignaturePolicyStore qualifying property shall be an unsigned qualifying property qualifying the signature.</p>
 * <p>The SignaturePolicyStore qualifying property shall contain either:</p>
 * <ul>
 * <li>the signature policy document which is referenced in the SignaturePolicyIdentifier qualifying
 * property so that the signature policy document can be used for offline and long-term validation; or</li>
 * <li>a URI referencing a local store where the signature policy document can be retrieved.</li>
 * </ul>
 * <p>Syntax</p>
 * <p>The SignaturePolicyStore shall be defined as in XML Schema file "XAdES01903v141-201601.xsd", whose 
 * location is detailed in clause C.2, and is copied below for information.</p>
 * <code>
 * 		<!-- targetNamespace="http://uri.etsi.org/01903/v1.4.1#" -->
 * 		<xsd:element name="SignaturePolicyStore" type="SignaturePolicyStoreType"/>
 * 		<xsd:complexType name="SignaturePolicyStoreType">
 * 			<xsd:sequence>
 * 				<xsd:element ref="SPDocSpecification"/>
 * 				<xsd:choice>
 * 					<xsd:element name="SignaturePolicyDocument" type="xsd:base64Binary"/>
 * 					<xsd:element name="SigPolDocLocalURI" type="xsd:anyURI"/>
 * 				</xsd:choice>
 * 			</xsd:sequence>
 * 			<xsd:attribute name="Id" type="xsd:ID" use="optional"/>
 * 		</xsd:complexType>
 * </code>
 * <p>The SignaturePolicyDocument element shall contain the base-64 encoded signature policy.</p>
 * <p>The SigPolDocLocalURI element shall have as value the URI referencing a local store where the present document
 * can be retrieved.</p>
 * <p>NOTE 1: Contrary to the SPURI, the SigPolDocLocalURI points to a local file.
 * The SPDocSpecification element shall identify the technical specification that defines the syntax used for
 * producing the signature policy document.</p>
 * <p>NOTE 2: It is the responsibility of the entity incorporating the signature policy to the signature-policy-store to make
 * sure that the correct document is securely stored.</p>
 * <p>NOTE 3: Being an unsigned qualifying property, it is not protected by the digital signature. If the
 * SignaturePolicyIdentifier qualifying property is incorporated into the signature and contains the
 * SigPolicyHash element with the digest value of the signature policy document, any alteration of the
 * signature policy document present within SignaturePolicyStore or within a local store, would be
 * detected by the failure of the digests comparison.</p>
 */
public interface SignaturePolicyStore  
{
    String getSPDocSpecification();
    
    void setSignaturePolicyDocument(String policyDocument);
    String getSignaturePolicyDocument();
    
    void setSigPolDocLocalURI(String uri);
    String getSigPolDocLocalURI();
}
