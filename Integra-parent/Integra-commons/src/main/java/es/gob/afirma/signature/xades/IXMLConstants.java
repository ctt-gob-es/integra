// Copyright (C) 2020 MINHAP, Gobierno de España
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
// http://joinup.ec.europa.eu/software/page/eupl/licence-eupl

/**
 * <b>File:</b><p>es.gob.afirma.signature.xades.IXMLConstants.java.</p>
 * <b>Description:</b><p>Interface that defines constants related to XML signature elements.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>17/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.1, 16/04/2020.
 */
package es.gob.afirma.signature.xades;

/**
 * <p>Interface that defines constants related to XML signature elements.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 16/04/2020.
 */
public interface IXMLConstants {

	/**
	 * Constant attribute that identifies the data type for XML documents.
	 */
	int DATA_TYPE_XML = 1;

	/**
	 * Constant attribute that identifies the data type for binary documents.
	 */
	int DATA_TYPE_BINARY = 2;

	/**
	 * Constant attribute that identifies the data type for binary documents encoded on Base 64.
	 */
	int DATA_TYPE_BINARY_BASE64 = 3;

	/**
	 * Constant attribute that represents base64 encoding name.
	 */
	String ENCODING_BASE64 = "base64";

	/**
	 * Constant attribute that represents URI used in reference of OBJECT type.
	 */
	String OBJECT_URI = "http://www.w3.org/2000/09/xmldsig#Object";

	/**
	 * Constant attribute that represents signature node name (ds:signature).
	 */
	String DS_SIGNATURE_NODE_NAME = IXMLConstants.DS_PREFIX + ":Signature";

	/**
	 * Constant attribute that represents <code>ROOT_COSIGNATURES</code> tag name.
	 */
	String ROOT_COSIGNATURES_TAG = "ROOT_COSIGNATURES";

	/**
	 * Constant attribute that represents tag name used in Manifest objects (&lt;ds:Manifest&gt;).
	 */
	String MANIFEST_TAG_NAME = "ds:Manifest";

	/**
	 * Constant attribute that represents <code>CONTENT</code> tag name.
	 */
	String CONTENT_TAG = "CONTENT";

	/**
	 * Constant attribute that represents <code>AFIRMA</code> tag name.
	 */
	String AFIRMA_TAG = "AFIRMA";

	/**
	 * Constant attribute that represents <code><asic:XAdESSignatures</code> tag name.
	 */
	String ASICS_TAG = "asic:XAdESSignatures";

	/**
	 * Constant attribute that represents URI used in reference of counter-signatures.
	 */
	String COUNTER_SIGN_URI = "http://uri.etsi.org/01903#CountersignedSignature";

	/**
	 * Constant attribute that represents <code>ds</code> namespace prefix.
	 */
	String DS_PREFIX = "ds";

	/**
	 * Constant attribute that represents <code>dss</code> namespace prefix.
	 */
	String DSS_PREFIX = "dss";

	/**
	 * Constant attribute that represents <code>dst</code> namespace prefix.
	 */
	String DST_PREFIX = "dst";

	/**
	 * Constant attribute that represents <code>xades</code> namespace prefix.
	 */
	String XADES_PREFIX = "xades";

	/**
	 * Constant attribute that represents <code>xadesv141</code> namespace prefix.
	 */
	String XADESV141_PREFIX = "xadesv141";

	/**
	 * Constant attribute that represents the URI used for XAdES 1.3.2.
	 */
	String XADES_1_3_2_NAMESPACE = "http://uri.etsi.org/01903/v1.3.2#";

	/**
	 * Constant attribute that represents the URI used for XAdES 1.4.1.
	 */
	String XADES_1_4_1_NAMESPACE = "http://uri.etsi.org/01903/v1.4.1#";

	/**
	 * Constant attribute that represents the URI used for OASIS time-stamp.
	 */
	String TIMESTAMP_NAMESPACE = "urn:oasis:names:tc:dss:1.0:profiles:TimeStamp:schema#";

	/**
	 * Constant attribute that represents the URI used for OASIS DSS.
	 */
	String DSS_NAMESPACE = "urn:oasis:names:tc:dss:1.0:core:schema";

	/**
	 * Constant attribute that identifies <code>Signature</code> element.
	 */
	String ELEMENT_SIGNATURE = "Signature";

	/**
	 * Constant attribute that identifies <code>SignatureValue</code> element.
	 */
	String ELEMENT_SIGNATURE_VALUE = "SignatureValue";

	/**
	 * Constant attribute that identifies <code>Transforms</code> element.
	 */
	String ELEMENT_TRANSFORMS = "Transforms";
	
	/**
	 * Constant attribute that identifies <code>XPath</code> element.
	 */
	String ELEMENT_XPATH = "XPath";

	/**
	 * Constant attribute that identifies <code>idAplicacion</code> element.
	 */
	String ELEMENT_ID_APLICACION = "idAplicacion";

	/**
	 * Constant attribute that identifies <code>Transform</code> element.
	 */
	String ELEMENT_TRANSFORM = "Transform";

	/**
	 * Constant attribute that identifies <code>QualifyingProperties</code> element.
	 */
	String ELEMENT_QUALIFIYING_PROPERTIES = "QualifyingProperties";

	/**
	 * Constant attribute that represents the string to identify the <i>QualifyingPropertiesReference</i> element in a XML signature.
	 */
	String ELEMENT_QUALIFYING_PROPERTIES_REFERENCE = "QualifyingPropertiesReference";

	/**
	 * Constant attribute that identifies <code>UnsignedProperties</code> element.
	 */
	String ELEMENT_UNSIGNED_PROPERTIES = "UnsignedProperties";

	/**
	 * Constant attribute that identifies <code>UnsignedSignatureProperties</code> element.
	 */
	String ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES = "UnsignedSignatureProperties";

	/**
	 * Constant attribute that identifies <code>CounterSignature</code> element.
	 */
	String ELEMENT_COUNTER_SIGNATURE = "CounterSignature";

	/**
	 * Constant attribute that identifies <code>XMLTimeStamp</code> element.
	 */
	String ELEMENT_XML_TIMESTAMP = "XMLTimeStamp";

	/**
	 * Constant attribute that identifies <code>EncapsulatedTimeStamp</code> element.
	 */
	String ELEMENT_ENCAPSULATED_TIMESTAMP = "EncapsulatedTimeStamp";

	/**
	 * Constant attribute that identifies <code>CanonicalizationMethod</code> element.
	 */
	String ELEMENT_CANONICALIZATION_METHOD = "CanonicalizationMethod";

	/**
	 * Constant attribute that identifies <code>SignatureTimeStamp</code> element.
	 */
	String ELEMENT_SIGNATURE_TIMESTAMP = "SignatureTimeStamp";

	/**
	 * Constant attribute that identifies <code>Object</code> element.
	 */
	String ELEMENT_OBJECT = "Object";

	/**
	 * Constant attribute that identifies <code>KeyInfo</code> element.
	 */
	String ELEMENT_KEY_INFO = "KeyInfo";

	/**
	 * Constant attribute that identifies <code>Timestamp</code> element.
	 */
	String ELEMENT_TIMESTAMP = "Timestamp";

	/**
	 * Constant attribute that identifies <code>RFC3161TimeStampToken</code> element.
	 */
	String ELEMENT_RFC3161_TIMESTAMPTOKEN = "RFC3161TimeStampToken";

	/**
	 * Constant attribute that identifies <code>PreviousTimestamp</code> element.
	 */
	String ELEMENT_PREVIOUS_TIMESTAMP = "PreviousTimestamp";

	/**
	 * Constant attribute that identifies <code>X509Certificate</code> element.
	 */
	String ELEMENT_X509CERTIFICATE = "X509Certificate";

	/**
	 * Constant attribute that identifies <code>CreationTime</code> element.
	 */
	String ELEMENT_CREATION_TIME = "CreationTime";

	/**
	 * Constant attribute that identifies <code>TstInfo</code> element.
	 */
	String ELEMENT_TST_INFO = "TstInfo";

	/**
	 * Constant attribute that identifies <code>Reference</code> element.
	 */
	String ELEMENT_REFERENCE = "Reference";

	/**
	 * Constant attribute that identifies <code>SignedInfo</code> element.
	 */
	String ELEMENT_SIGNED_INFO = "SignedInfo";

	/**
	 * Constant attribute that identifies <code>DigestMethod</code> element.
	 */
	String ELEMENT_DIGEST_METHOD = "DigestMethod";

	/**
	 * Constant attribute that identifies <code>DigestValue</code> element.
	 */
	String ELEMENT_DIGEST_VALUE = "DigestValue";

	/**
	 * Constant attribute that identifies <code>SignatureMethod</code> element.
	 */
	String ELEMENT_SIGNATURE_METHOD = "SignatureMethod";

	/**
	 * Constant attribute that identifies <code>SignaturePolicyIdentifier</code> element.
	 */
	String ELEMENT_SIGNATURE_POLICY_IDENTIFIER = "SignaturePolicyIdentifier";

	/**
	 * Constant attribute that identifies <code>SignaturePolicyId</code> element.
	 */
	String ELEMENT_SIGNATURE_POLICY_ID = "SignaturePolicyId";

	/**
	 * Constant attribute that represents the string to identify the <i>SigningCertificate</i> element in a XML signature.
	 */
	String ELEMENT_SIGNING_CERTIFICATE = "SigningCertificate";

	/**
	 * Constant attribute that represents the string to identify the <i>SigningTime</i> element in a XML signature.
	 */
	String ELEMENT_SIGNING_TIME = "SigningTime";

	/**
	 * Constant attribute that represents the string to identify the <i>SignedDataObjectProperties</i> element in a XML signature.
	 */
	String ELEMENT_SIGNED_DATA_OBJECT_PROPERTIES = "SignedDataObjectProperties";

	/**
	 * Constant attribute that represents the string to identify the <i>DataObjectFormat</i> element in a XML signature.
	 */
	String ELEMENT_DATA_OBJECT_FORMAT = "DataObjectFormat";

	/**
	 * Constant attribute that represents the string to identify the <i>MimeType</i> element in a XML signature.
	 */
	String ELEMENT_MIME_TYPE = "MimeType";

	/**
	 * Constant attribute that represents the string to identify the <i>TimeStampValidationData</i> element in a XML signature.
	 */
	String ELEMENT_TIME_STAMP_VALIDATION_DATA = "TimeStampValidationData";

	/**
	 * Constant attribute that represents the string to identify the <i>AttributeCertificateRefs</i> element in a XML signature.
	 */
	String ELEMENT_ATTRIBUTE_CERTIFICATE_REFS = "AttributeCertificateRefs";

	/**
	 * Constant attribute that represents the string to identify the <i>AttributeRevocationRefs</i> element in a XML signature.
	 */
	String ELEMENT_ATTRIBUTE_REVOCATION_REFS = "AttributeRevocationRefs";

	/**
	 * Constant attribute that identifies <code>SigPolicyId</code> element.
	 */
	String ELEMENT_SIG_POLICY_ID = "SigPolicyId";

	/**
	 * Constant attribute that identifies <code>SigPolicyHash</code> element.
	 */
	String ELEMENT_SIG_POLICY_HASH = "SigPolicyHash";

	/**
	 * Constant attribute that identifies <code>Identifier</code> element.
	 */
	String ELEMENT_IDENTIFIER = "Identifier";

	/**
	 * Constant attribute that identifies <code>SignedSignatureProperties</code> element.
	 */
	String ELEMENT_SIGNED_SIGNATURE_PROPERTIES = "SignedSignatureProperties";

	/**
	 * Constant attribute that identifies <code>SignedProperties</code> element.
	 */
	String ELEMENT_SIGNED_PROPERTIES = "SignedProperties";

	/**
	 * Constant attribute that identifies <code>CompleteRevocationRefs</code> element.
	 */
	String ELEMENT_COMPLETE_REVOCATION_REFS = "CompleteRevocationRefs";

	/**
	 * Constant attribute that identifies <code>CompleteCertificateRefs</code> element.
	 */
	String ELEMENT_COMPLETE_CERTIFICATE_REFS = "CompleteCertificateRefs";

	/**
	 * Constant attribute that identifies <code>RefsOnlyTimeStamp</code> element.
	 */
	String ELEMENT_REFS_ONLY_TIMESTAMP = "RefsOnlyTimeStamp";

	/**
	 * Constant attribute that identifies <code>SigAndRefsTimeStamp</code> element.
	 */
	String ELEMENT_SIG_AND_REFS_TIMESTAMP = "SigAndRefsTimeStamp";

	/**
	 * Constant attribute that identifies <code>RevocationValues</code> element.
	 */
	String ELEMENT_REVOCATION_VALUES = "RevocationValues";

	/**
	 * Constant attribute that identifies <code>Document</code> element.
	 */
	String ELEMENT_DOCUMENT = "Document";

	/**
	 * Constant attribute that identifies <code>Base64Data</code> element.
	 */
	String ELEMENT_BASE64_DATA = "Base64Data";

	/**
	 * Constant attribute that identifies <code>Base64XML</code> element.
	 */
	String ELEMENT_BASE64_XML = "Base64XML";

	/**
	 * Constant attribute that identifies <code>InlineXML</code> element.
	 */
	String ELEMENT_INLINE_XML = "InlineXML";

	/**
	 * Constant attribute that identifies <code>EscapedXML</code> element.
	 */
	String ELEMENT_ESCAPED_XML = "EscapedXML";

	/**
	 * Constant attribute that identifies <code>DocumentHash</code> element.
	 */
	String ELEMENT_DOCUMENT_HASH = "DocumentHash";

	/**
	 * Constant attribute that identifies <code>TransformedData</code> element.
	 */
	String ELEMENT_TRANSFORMED_DATA = "TransformedData";

	/**
	 * Constant attribute that identifies <code>DocumentHashTransformedData</code> element.
	 */
	String ELEMENT_DOCUMENT_HASH_TRANSFORMED_DATA = "DocumentHashTransformedData";

	/**
	 * Constant attribute that identifies <code>AnyType</code> element.
	 */
	String ELEMENT_ANY_TYPE = "AnyType";

	/**
	 * Constant attribute that identifies <code>CertificateValues</code> element.
	 */
	String ELEMENT_CERTIFICATE_VALUES = "CertificateValues";

	/**
	 * Constant attribute that identifies <code>ArchiveTimeStamp</code> element.
	 */
	String ELEMENT_ARCHIVE_TIMESTAMP = "ArchiveTimeStamp";

	/**
	 * Constant attribute that identifies <code>InputDocuments</code> element.
	 */
	String ELEMENT_INPUT_DOCUMENTS = "InputDocuments";

	/**
	 * Constant attribute that identifies <code>RenewTimestamp</code> element.
	 */
	String ELEMENT_RENEW_TIMESTAMP = "RenewTimestamp";

	/**
	 * Constant attribute that identifies <code>Id</code> attribute.
	 */
	String ATTRIBUTE_ID = "Id";

	/**
	 * Constant attribute that identifies <code>Encoding</code> attribute.
	 */
	String ATTRIBUTE_ENCODING = "Encoding";

	/**
	 * Constant attribute that identifies <code>Algorithm</code> attribute.
	 */
	String ATTRIBUTE_ALGORITHM = "Algorithm";

	/**
	 * Constant attribute that identifies <code>Type</code> attribute.
	 */
	String ATTRIBUTE_TYPE = "Type";

	/**
	 * Constant attribute that identifies <code>URI</code> attribute.
	 */
	String ATTRIBUTE_URI = "URI";

	/**
	 * Constant attribute that identifies <code>MimeType</code> attribute.
	 */
	String ATTRIBUTE_MIME_TYPE = "MimeType";

	/**
	 * Constant attribute that identifies <code>http://uri.etsi.org/02918/v1.2.1#</code> attribute.
	 */
	String ASIC_NS = "http://uri.etsi.org/02918/v1.2.1#";

	/**
	 * Constant attribute that identifies <code>asic</code> attribute.
	 */
	String ASIC_NS_PREFIX = "asic";

	/**
	 * Constant attribute that identifies <code>Target</code> attribute.
	 */
	String ATTRIBUTE_TARGET = "Target";

	/**
	 * Constant attribute that identifies <code>SignatureProductionPlace</code> element.
	 */
	String ELEMENT_SIGNATURE_PRODUCTION_PLACE = "SignatureProductionPlace";

	/**
	 * Constant attribute that identifies <code>SignerRole</code> element.
	 */
	String ELEMENT_SIGNER_ROLE = "SignerRole";

	/**
	 * Constant attribute that identifies <code>Cert</code> element.
	 */
	String ELEMENT_CERT = "Cert";

	/**
	 * Constant attribute that identifies <code>CertDigest</code> element.
	 */
	String ELEMENT_CERT_DIGEST = "CertDigest";

	/**
	 * Constant attribute that identifies <code>X509Data</code> element.
	 */
	String ELEMENT_X509_DATA = "X509Data";

	/**
	 * Constant attribute that identifies <code>X509Certificate</code> element.
	 */
	String ELEMENT_X509_CERTIFICATE = "X509Certificate";

	/**
	 * Constant attribute that identifies <code>SerialNumber</code> element.
	 */
	String ELEMENT_SERIAL_NUMBER = "SerialNumber";
	
	/**
	 * Constant attribute that identifies <code>ObjectReference</code> attribute.
	 */
	String ATTRIBUTE_OBJECT_REFERENCE = "ObjectReference";
	
	/**
	 * Constant element that identifies <code>XAdESSignatures</code> element.
	 */
	String ELEMENT_XADES_SIGNATURE = "XAdESSignatures";

	/**
	 * Constant element that identifies <code>Description</code> element.
	 */
	String ELEMENT_DESCRIPTION = "Description";

	/**
	 * Constant element that identifies <code>Encoding</code> element.
	 */
	String ELEMENT_ENCODING = "Encoding";

	/**
	 * Constant element that identifies <code>ObjectIdentifier</code> element.
	 */
	String ELEMENT_OBJECT_IDENTIFIER = "ObjectIdentifier";

	/**
	 * Constant element that identifies <code>Identifier</code> attribute.
	 */
	String ATTRIBUTE_IDENTIFIER = "Identifier";

	/**
	 * Constant element that identifies <code>DocumentationReferences</code> element.
	 */
	String ELEMENT_DOCUMENTATION_REFERENCES = "DocumentationReferences";

}
