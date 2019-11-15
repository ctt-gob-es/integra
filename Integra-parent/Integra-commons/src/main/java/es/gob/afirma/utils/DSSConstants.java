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
// http://joinup.ec.europa.eu/software/page/eupl/licence-eupl

/**
 * <b>File:</b><p>es.gob.afirma.utils.DSSContants.java</p>
 * <b>Description:</b><p>Class that represents constants used in the DSS XML type.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @author Gobierno de España.
 * @version 1.1, 15/11/2019.
 */
package es.gob.afirma.utils;

/**
 * <p>Class that represents constants used in the DSS XML type.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 15/11/2019.
 */
public final class DSSConstants {

    /**
     * Constructor method for the class DSSContants.java.
     */
    private DSSConstants() {
    }

    /**
     * Attribute that represents 'dss' prefix.
     */
    public static final String PREFIX = "dss";

    /**
     * Attribute that represents the name space for oasis core.
     */
    public static final String OASIS_CORE_1_0_NS = "urn:oasis:names:tc:dss:1.0:core:schema";

    /**
     * <p>Class represents constants that contains XPaths of tag of @Firma DSS services' XML request .</p>
     * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
     * @version 1.0, 17/03/2011.
     */
    public final class DSSTagsRequest {

	/**
	 * Constructor method for the class DSSContants.java.
	 */
	private DSSTagsRequest() {
	}

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:OptionalInputs</code>.
	 */
	private static final String OPTIONAL_INPUT = "dss:OptionalInputs";

	/**
	 * Constant attribute that represents the XPath for 'requestId'(a signRequest attribute).
	 */
	public static final String SIGNREQUEST_ATR_REQUEST_ID = "@RequestID";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:InputDocuments</code>.
	 */
	public static final String INPUT_DOCUMENT = "dss:InputDocuments";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:Document</code>.
	 */
	public static final String DOCUMENT = INPUT_DOCUMENT + "/dss:Document";

	/**
	 * Constant attribute that represents the XPath for the attribute 'id' of tag <code>dss:Document</code>.
	 */
	public static final String DOCUMENT_ATR_ID = DOCUMENT + "@ID";

	/**
	 * Constant attribute that represents the XPath for the attribute 'id' of tag <code>dss:Document@ID</code>.
	 */
	public static final String DOCUMENT_ATR_ID_LAST = "@ID";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:Base64Data</code>.
	 */
	public static final String BASE64DATA = DOCUMENT + "/dss:Base64Data";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:Document/dss:Base64Data</code>.
	 */
	public static final String BASE64DATA_LAST = "dss:Base64Data";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:Base64XML</code>.
	 */
	public static final String BASE64XML = DOCUMENT + "/dss:Base64XML";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:Document/dss:Base64XML</code>.
	 */
	public static final String BASE64XML_LAST = "dss:Base64XML";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:DocumentHash</code>.
	 */
	public static final String DOCUMENTHASH = INPUT_DOCUMENT + "/dss:DocumentHash";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:DocumentHash</code>.
	 */
	public static final String DOCUMENTHASH_METHOD = DOCUMENTHASH + "/ds:DigestMethod";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:DocumentHash</code>.
	 */
	public static final String DOCUMENTHASH_VALUE = DOCUMENTHASH + "/ds:DigestValue";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:InlineXML</code>.
	 */
	public static final String INLINEXML = DOCUMENT + "/dss:InlineXML";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:EscapedXML</code>.
	 */
	public static final String ESCAPEDXML = DOCUMENT + "/dss:EscapedXML";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:TransformedData</code>.
	 */
	public static final String TRANSFORMEDDATA = INPUT_DOCUMENT + "/dss:TransformedData";

	/**
	 * Constant attribute that represents the XPath for the attribute 'Algorithm' of tag <code>dss:DocumentHash/ds:DigestMethod</code>.
	 */
	public static final String DIGEST_METHOD_ATR_ALGORITHM = INPUT_DOCUMENT + "/dss:DocumentHash/ds:DigestMethod@Algorithm";

	/**
	 * Constant attribute that represents the XPath for the tag <code>ds:DigestMethod</code>.
	 */
	public static final String DIGEST_METHOD = INPUT_DOCUMENT + "/dss:DocumentHash/ds:DigestMethod";

	/**
	 * Constant attribute that represents the XPath for the tag <code>ds:DigestMethod</code>.
	 */
	public static final String DOCUMENT_HASH_TRANSFORM_ATR_ALGORITHM = INPUT_DOCUMENT + "/dss:DocumentHash/ds:Transforms/ds:Transform@Algorithm";

	/**
	 * Constant attribute that represents the XPath for the tag <code>ds:DigestMethod</code>.
	 */
	public static final String TRANSFORMED_DATA_BASE64DATA = TRANSFORMEDDATA + "/dss:Base64Data";

	/**
	 * Constant attribute that represents the XPath for the tag <code>ds:DigestMethod</code>.
	 */
	public static final String TRANSFORMED_DATA_TRANSFORM_ATR_ALGORITHM = TRANSFORMEDDATA + "/ds:Transforms/ds:Transform@Algorithm";

	/**
	 * Constant attribute that represents the XPath for the tag <code>ds:DigestValue</code>.
	 */
	public static final String DIGEST_VALUE = INPUT_DOCUMENT + "/dss:DocumentHash/ds:DigestValue";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:Other</code>.
	 */
	public static final String DOCUMENT_OTHER = INPUT_DOCUMENT + "/dss:Other";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:InputDocuments/dss:Other/dss:SignatureObject</code>.
	 */
	public static final String INPUTDOC_SIGNATURE_SIGNATUREOBJECT = DOCUMENT_OTHER + "/dss:SignatureObject";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:InputDocuments/dss:Other/dss:SignatureObject</code>.
	 */
	public static final String INPUTDOC_SIGNATURE_SIGNATUREOBJECT_LAST = "dss:Other/dss:SignatureObject";

	/**
	 * Constant attribute that represents the XPath for the tag <code>afxp:DocumentArchiveId</code>.
	 */
	public static final String DOCUMENT_ARCHIVE_ID = DOCUMENT_OTHER + "/afxp:DocumentArchiveId";

	/**
	 * Constant attribute that represents the XPath for the attribute 'id' of tag <code>afxp:DocumentArchiveId</code>.
	 */
	public static final String DOCUMENT_ARCHIVE_ID_ATR_ID = DOCUMENT_OTHER + "/afxp:DocumentArchiveId@ID";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:InputDocuments/dss:Other/cmism:getContentStream/cmism:repositoryId</code>.
	 */
	public static final String INPUTDOC_GETCONTENTSTREAM_REPOID = DOCUMENT_OTHER + "/cmism:getContentStream/cmism:repositoryId";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:InputDocuments/dss:Other/cmism:getContentStream/cmism:objectId</code>.
	 */
	public static final String INPUTDOC_GETCONTENTSTREAM_OBJECTID = DOCUMENT_OTHER + "/cmism:getContentStream/cmism:objectId";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:InputDocuments/dss:Other/dss:SignatureObject/dss:Other/cmism:getContentStream/cmism:repositoryId</code>.
	 */
	public static final String INPUTDOC_SIGNATURE_GETCONTENTSTREAM_REPOID = INPUTDOC_SIGNATURE_SIGNATUREOBJECT + "/dss:Other/cmism:getContentStream/cmism:repositoryId";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:InputDocuments/dss:Other/dss:SignatureObject/dss:Other/cmism:getContentStream/cmism:objectId</code>.
	 */
	public static final String INPUTDOC_SIGNATURE_GETCONTENTSTREAM_OBJECTID = INPUTDOC_SIGNATURE_SIGNATUREOBJECT + "/dss:Other/cmism:getContentStream/cmism:objectId";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:InputDocuments/dss:Other/dss:SignatureObject/dss:Other/cmism:getContentStream/cmism:objectId</code>.
	 */
	public static final String INPUTDOC_SIGNATURE_SIGNATURE = INPUTDOC_SIGNATURE_SIGNATUREOBJECT + "/ds:Signature";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:InputDocuments/dss:Other/dss:SignatureObject/dss:Other/cmism:getContentStream/cmism:objectId</code>.
	 */
	public static final String INPUTDOC_SIGNATURE_BASE64SIGNATURE = INPUTDOC_SIGNATURE_SIGNATUREOBJECT + "/dss:Base64Signature";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:InputDocuments/dss:Other/dss:SignatureObject/dss:Other/cmism:getContentStream/cmism:objectId</code>.
	 */
	public static final String INPUTDOC_SIGNATURE_BASE64SIGNATURE_LAST = "dss:Other/dss:SignatureObject/dss:Base64Signature";

	/**
	 * Constant attribute that represents the XPath for the attribute 'WhichDocument' of tag <code>dss:SignaturePtr</code>.
	 */
	public static final String INPUTDOC_SIGNATURE_SIGNATURE_PTR_ATR_WHICH = INPUTDOC_SIGNATURE_SIGNATUREOBJECT + "/dss:SignaturePtr@WhichDocument";

	/**
	 * Constant attribute that represents the XPath for the attribute 'WhichDocument' of tag <code>dss:SignaturePtr</code>.
	 */
	public static final String INPUTDOC_SIGNATURE_SIGNATURE_PTR_ATR_WHICH_LAST = "dss:Other/dss:SignatureObject/dss:SignaturePtr@WhichDocument";

	/**
	 * Constant attribute that represents the XPath for the tag <code>ClaimedIdentity/dss:Name</code>.
	 */
	public static final String CLAIMED_IDENTITY = OPTIONAL_INPUT + "/dss:ClaimedIdentity/dss:Name";

	/**
	 * Constant attribute that represents the XPath for the tag <code>ClaimedIdentity/dss:idAplicacion</code>.
	 */
	public static final String CLAIMED_IDENTITY_TSA = OPTIONAL_INPUT + "/dss:ClaimedIdentity/dss:idAplicacion";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:KeySelector/ds:KeyInfo/ds:KeyName</code>.
	 */
	public static final String KEY_SELECTOR = OPTIONAL_INPUT + "/dss:KeySelector/ds:KeyInfo/ds:KeyName";

	/**
	 * Constant attribute that represents the XPath for the tag <code>afxp:ReferenceId</code>.
	 */
	public static final String AFXP_REFERENCEID = OPTIONAL_INPUT + "/afxp:ReferenceId";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:SignatureType</code>.
	 */
	public static final String SIGNATURE_TYPE = OPTIONAL_INPUT + "/dss:SignatureType";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:SignatureForm</code>.
	 */
	public static final String SIGNATURE_FORM = OPTIONAL_INPUT + "/ades:SignatureForm";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:HashAlgorithm</code>.
	 */
	public static final String HASH_ALGORITHM = OPTIONAL_INPUT + "/afxp:HashAlgorithm";

	/**
	 * Constant attribute that represents the XPath for the tag <code>afxp:AdditionalDocumentInfo</code>.
	 */
	private static final String ADDITIONAL_DOCUMENT_INFO = OPTIONAL_INPUT + "/afxp:AdditionalDocumentInfo";

	/**
	 * Constant attribute that represents the XPath for the tag <code>afxp:AdditionalDocumentInfo/afxp:DocumentName</code>.
	 */
	public static final String ADDITIONAL_DOCUMENT_NAME = ADDITIONAL_DOCUMENT_INFO + "/afxp:DocumentName";

	/**
	 * Constant attribute that represents the XPath for the tag <code>afxp:AdditionalDocumentInfo/afxp:DocumentType</code>.
	 */
	public static final String ADDITIONAL_DOCUMENT_TYPE = ADDITIONAL_DOCUMENT_INFO + "/afxp:DocumentType";

	/**
	 * Constant attribute that represents the XPath for the attribute 'WhichDocument' of tag <code>afxp:AdditionalDocumentInfo</code>.
	 */
	public static final String ADDITIONAL_DOCUMENT_ATR_WHICH = ADDITIONAL_DOCUMENT_INFO + "@WhichDocument";

	/**
	 * Constant attribute that represents the XPath for the tag <code>afxp:XMLSignatureMode</code>.
	 */
	public static final String XML_SIGNATURE_MODE = OPTIONAL_INPUT + "/afxp:XMLSignatureMode";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:IncludeEContent</code>.
	 */
	public static final String INCLUDE_E_CONTENT = OPTIONAL_INPUT + "/dss:IncludeEContent";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:SignatureType</code>.
	 */
	public static final String SIGNATURE_POLICY_IDENTIFIER = OPTIONAL_INPUT + "/sigpol:SignaturePolicyIdentifier";

	/**
	 * Constant attribute that represents the XPath for the tag <code>afxp:IgnoreGracePeriod </code>.
	 */
	public static final String IGNORE_GRACE_PERIOD = OPTIONAL_INPUT + "/afxp:IgnoreGracePeriod";

	/**
	 * Constant attribute that represents the XPath for the tag <code>xss:ParallelSignature </code>.
	 */
	public static final String PARALLEL_SIGNATURE = OPTIONAL_INPUT + "/xss:ParallelSignature";

	/**
	 * Constant attribute that represents the XPath for the tag <code>xss:CounterSignature </code>.
	 */
	public static final String COUNTER_SIGNATURE = OPTIONAL_INPUT + "/xss:CounterSignature";

	/**
	 * Constant attribute that represents the XPath for the attribute 'WhichDocument' of tag <code>xss:CounterSignature</code>.
	 */
	public static final String COUNTER_SIGNATURE_ATR_WHICH = OPTIONAL_INPUT + "/xss:CounterSignature@WhichDocument";

	/**
	 * Constant attribute that represents the XPath for the tag <code>xss:CounterSignature </code>.
	 */
	public static final String SIGPOL_SIGNATURE_POLICY_IDENTIFIER = OPTIONAL_INPUT + "/sigpol:GenerateUnderSignaturePolicy/sigpol:SignaturePolicyIdentifier";

	/**
	 * Constant attribute that represents the XPath for the tag <code>xss:CounterSignature </code>.
	 */
	public static final String ARCHIVE_IDENTIFIER = "/arch:ArchiveIdentifier";
	
	/**
	 * Constant attribute that represents the XPath for the tag <code>afxp:CertificateValidationLevel</code>.
	 */
	public static final String CERTIFICATE_VALIDATION_LEVEL = OPTIONAL_INPUT + "/afxp:CertificateValidationLevel";

	/********************	VERIFYREQUEST	********************************/

	/**
	 * Constant attribute that represents the XPath for the tag <code>vr:ReturnVerificationReport/vr:ReportOptions</code>.
	 */
	private static final String REPORT_OPTIONS = OPTIONAL_INPUT + "/vr:ReturnVerificationReport/vr:ReportOptions";

	/**
	 * Constant attribute that represents the XPath for the tag <code>vr:IncludeCertificateValues</code>.
	 */
	public static final String INCLUDE_CERTIFICATE = REPORT_OPTIONS + "/vr:IncludeCertificateValues";

	/**
	 * Constant attribute that represents the XPath for the tag <code>vr:IncludeRevocationValues</code>.
	 */
	public static final String INCLUDE_REVOCATION = REPORT_OPTIONS + "/vr:IncludeRevocationValues";

	/**
	 * Constant attribute that represents the XPath for the tag <code>vr:ReportDetailLevel</code>.
	 */
	public static final String REPORT_DETAIL_LEVEL = REPORT_OPTIONS + "/vr:ReportDetailLevel";

	/**
	 * Constant attribute that represents the XPath for the tag <code>/vr:ReturnVerificationReport/vr:CheckOptions/vr:CheckCertificateStatus</code>.
	 */
	public static final String CHECK_CERTIFICATE_STATUS = OPTIONAL_INPUT + "/vr:ReturnVerificationReport/vr:CheckOptions/vr:CheckCertificateStatus";

	/**
	 * Constant attribute that represents the XPath for the tag <code>/vr:ReturnVerificationReport/vr:CheckOptions/vr:VerifyManifest</code>.
	 */
	public static final String VERIFIY_MANIFEST = OPTIONAL_INPUT + "/vr:ReturnVerificationReport/vr:CheckOptions/vr:VerifyManifest";

	/**
	 * Constant attribute that represents the XPath for the tag <code>afxp:ReturnReadableCertificateInfo</code>.
	 */
	public static final String RETURN_READABLE_CERT_INFO = OPTIONAL_INPUT + "/afxp:ReturnReadableCertificateInfo";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:ReturnProcessingDetails</code>.
	 */
	public static final String RETURN_PROCESSING_DETAILS = OPTIONAL_INPUT + "/dss:ReturnProcessingDetails";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:ReturnUpdatedSignature</code>.
	 */
	private static final String RETURN_UPDATED_SIGNATURE = OPTIONAL_INPUT + "/dss:ReturnUpdatedSignature";

	/**
	 * Constant attribute that represents the XPath for the attribute 'Type' of tag <code>dss:ReturnUpdatedSignature</code>.
	 */
	public static final String RETURN_UPDATED_SIGNATURE_ATR_TYPE = RETURN_UPDATED_SIGNATURE + "@Type";

	/**
	 * Constant attribute that represents the XPath for the tag <code>afxp:TargetSigner</code>.
	 */
	public static final String TARGET_SIGNER = OPTIONAL_INPUT + "/afxp:TargetSigner";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:SignatureObject</code>.
	 */
	public static final String SIGNATURE_OBJECT = "dss:SignatureObject";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:SignaturePtr</code>.
	 */
	public static final String SIGNATURE_PTR = SIGNATURE_OBJECT + "/dss:SignaturePtr";

	/**
	 * Constant attribute that represents the XPath for the attribute 'WhichDocument' of tag <code>dss:SignaturePtr</code>.
	 */
	public static final String SIGNATURE_PTR_ATR_WHICH = SIGNATURE_OBJECT + "/dss:SignaturePtr@WhichDocument";

	/**
	 * Constant attribute that represents the XPath for the tag <code>ds:Signature</code>.
	 */
	public static final String SIGNATURE_DS = SIGNATURE_OBJECT + "/ds:Signature";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:Base64Signature</code>.
	 */
	public static final String SIGNATURE_BASE64 = SIGNATURE_OBJECT + "/dss:Base64Signature";

	/**
	 * Constant attribute that represents the XPath for the attribute 'Type' of tag <code>dss:Base64Signature</code>.
	 */
	public static final String SIGNATURE_BASE64_ATR_TYPE = SIGNATURE_BASE64 + "@Type";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:SignatureObject/dss:Other/cmism:getContentStream/cmism:repositoryId</code>.
	 */
	public static final String SIGNATURE_OTHER_GETCONTENTSTREAM_REPOID = SIGNATURE_OBJECT + "/dss:Other/cmism:getContentStream/cmism:repositoryId";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:SignatureObject/dss:Other/cmism:getContentStream/cmism:objectId</code>.
	 */
	public static final String SIGNATURE_OTHER_GETCONTENTSTREAM_OBJECTID = SIGNATURE_OBJECT + "/dss:Other/cmism:getContentStream/cmism:objectId";

	/**
	 * Constant attribute that represents the XPath for the tag <code>afxp:SignatureArchiveId</code>.
	 */
	public static final String SIGNATURE_ARCHIVE_ID = SIGNATURE_OBJECT + "/dss:Other/afxp:SignatureArchiveId";

	/**
	 * Constant attribute that represents the XPath for the attribute 'ID' of tag <code>afxp:SignatureArchiveId</code>.
	 */
	public static final String SIGNATURE_ARCHIVE_ID_ATR_ID = SIGNATURE_OBJECT + "/dss:Other/afxp:SignatureArchiveId@ID";

	/**
	 * Constant attribute that represents the XPath for the attribute that returns 'SignatureTimestamp' values.
	 */
	public static final String ADDICIONAL_REPORT_OPT_SIGNATURE_TIMESTAMP = OPTIONAL_INPUT + "/afxp:AdditionalReportOption/afxp:IncludeProperties/afxp:IncludeProperty@Type";

	/**
	 * Constant attribute that represents the XPath for the tag <code>ds:X509Certificate</code>.
	 */
	public static final String X509_CERTIFICATE = SIGNATURE_OBJECT + "/dss:Other/ds:X509Data/ds:X509Certificate";

	/**
	 * Constant attribute that represents the XPath for the tag <code>cmism:getContentStream/cmism:repositoryId</code>.
	 */
	public static final String X509_DATA_GETCONTENTSTREAM_REPOID = SIGNATURE_OBJECT + "/dss:Other/ds:X509Data/cmism:getContentStream/cmism:repositoryId";

	/**
	 * Constant attribute that represents the XPath for the tag <code>cmism:getContentStream/cmism:objectId</code>.
	 */
	public static final String X509_DATA_GETCONTENTSTREAM_OBJECTID = SIGNATURE_OBJECT + "/dss:Other/ds:X509Data/cmism:getContentStream/cmism:objectId";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:RFC3161TimeStampToken</code>.
	 */
	public static final String TIMESTAMP_RFC3161_TIMESTAMPTOKEN = SIGNATURE_OBJECT + "/dss:Timestamp/dss:RFC3161TimeStampToken";

	/**
	 * Constant attribute that represents the XPath for the tag <code>ds:Signature</code>.
	 */
	public static final String TIMESTAMP_XML_TIMESTAMPTOKEN = SIGNATURE_OBJECT + "/dss:Timestamp";

	/**
	 * Constant attribute that represents the XPath for the tag <code>ds:Signature</code>.
	 */
	public static final String TIMESTAMP_PREVIOUS_RFC3161_TIMESTAMPTOKEN = "/dst:RenewTimestamp/dst:PreviousTimestamp/dss:Timestamp/dss:RFC3161TimeStampToken";

	/**
	 * Constant attribute that represents the XPath for the tag <code>ds:Signature</code>.
	 */
	public static final String TIMESTAMP_PREVIOUS_XML_TIMESTAMPTOKEN = "/dst:RenewTimestamp/dst:PreviousTimestamp/dss:Timestamp";

	/**
	 * Constant attribute that represents the XPath for the tag <code>afxp:ReturnSigPolicyDocument</code>.
	 */
	public static final String RETURN_SIGN_POLICY_DOCUMENT = OPTIONAL_INPUT + "/afxp:ReturnSigPolicyDocument@Type";

	/**
	 * Constant attribute that represents the XPath for the tag <code>ds:Signature</code>.
	 */
	public static final String RETURN_SIGNED_DATA_INFO = OPTIONAL_INPUT + "/afxp:ReturnSignedDataInfo";
	
	/**
	 * Constant attribute that represents the XPath for the tag <code>afxp:ReturnNextUpdate</code>.
	 */
	public static final String RETURN_NEXT_UPDATE = OPTIONAL_INPUT + "/afxp:ReturnNextUpdate";

	/**
	 * Constant attribute that represents the XPath for the tag <code>afxp:ProcessAsNotBaseline</code>.
	 */
	public static final String PROCESS_AS_NOT_BASELINE = OPTIONAL_INPUT + "/afxp:ProcessAsNotBaseline";

	/********************	DSSBATCH_VERIFY ********************************/

	/**
	 * Constant attribute that represents the XPath for the attribute 'Type' of tag <code>afxp:BatchRequest</code>.
	 */
	public static final String BATCH_REQUEST_ATTR_TYPE = "@Type";

	/**
	 * Constant attribute that represents the XPath for the tag <code>afxp:Requests</code>.
	 */
	private static final String BATCH_REQUEST = "afxp:Requests";

	/**
	 * Constant attribute that represents the XPath for the tag <code>dss:VerifyRequest</code>.
	 */
	public static final String VERIFY_REQUEST = BATCH_REQUEST + "/dss:VerifyRequest";

	/**
	 * Constant attribute that represents the XPath for the attribute 'RequestID' of tag <code>dss:VerifyRequest</code>.
	 */
	public static final String VERIFY_REQUEST_ATTR_REQUEST_ID = "@RequestID";

	/**
	 * Constant attribute that represents type used for Verify Signature Batch Request.
	 */
	public static final String BATCH_VERIFY_SIGN_TYPE = "urn:afirma:dss:1.0:profile:XSS:BatchProtocol:VerifySignatureType";

	/**
	 * Constant attribute that represents type used for Verify Certificate Batch Request.
	 */
	public static final String BATCH_VERIFY_CERT_TYPE = "urn:afirma:dss:1.0:profile:XSS:BatchProtocol:VerifyCertificateType";

	/**
	 * Constant attribute that represents XPath for the tag <code>async:ResponseID</code>.
	 */
	public static final String ASYNC_RESPONSE_ID = OPTIONAL_INPUT + "/async:ResponseID";
    }

    /**
     * <p>Class that represents signature types identifiers.</p>
     * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
     * @version 1.0, 07/02/2011.
     */
    public final class SignTypesURIs {

	/**
	 * Constructor method for the class DSSContants.java.
	 */
	private SignTypesURIs() {
	}

	/** */
	/**
	 * Attribute that represents identifier for XADES signature 1.3.2. version.
	 */
	public static final String XADES_V_1_3_2 = "http://uri.etsi.org/01903/v1.3.2#";

	/**
	 * Attribute that represents identifier for XADES signature 1.2.2. version.
	 */
	public static final String XADES_V_1_2_2 = "http://uri.etsi.org/01903/v1.2.2#";

	/**
	 * Attribute that represents identifier for XADES signature 1.1.1. version.
	 */
	public static final String XADES_V_1_1_1 = "http://uri.etsi.org/01903/v1.1.1#";

	/**
	 * Attribute that represents identifier for CADES.
	 */
	public static final String CADES = "http://uri.etsi.org/01733/v1.7.3#";

	/**
	 * Attribute that represents identifier for XML_DSIG.
	 */
	public static final String XML_DSIG = "urn:ietf:rfc:3275";

	/**
	 * Attribute that represents identifier for CMS.
	 */
	public static final String CMS = "urn:ietf:rfc:3369";

	/**
	 * Attribute that represents identifier for CMS(TST).
	 */
	public static final String CMS_TST = "urn:afirma:dss:1.0:profile:XSS:forms:CMSWithTST";

	/**
	 * Attribute that represents identifier for PKCS7.
	 */
	public static final String PKCS7 = "urn:ietf:rfc:2315";

	/**
	 * Attribute that represents identifier for XML_TST.
	 */
	public static final String XML_TST = "urn:oasis:names:tc:dss:1.0:core:schema:XMLTimeStampToken";

	/**
	 * Attribute that represents identifier for ODF.
	 */
	public static final String ODF = "urn:afirma:dss:1.0:profile:XSS:forms:ODF";

	/**
	 * Attribute that represents identifier for PDF.
	 */
	public static final String PDF = "urn:afirma:dss:1.0:profile:XSS:forms:PDF";

	/**
	 *  Attribute that represents identifier for PAdES.
	 */
	public static final String PADES = "urn:afirma:dss:1.0:profile:XSS:forms:PAdES";
	
	/**
	 *  Attribute that represents identifier for CAdES Baseline.
	 */
	public static final String CADES_BASELINE_2_2_1 = "http://uri.etsi.org/103173/v2.2.1#";
	    
	/**
	 *  Attribute that represents identifier for PAdES Baseline.
	 */
	public static final String PADES_BASELINE_2_1_1 = "http://uri.etsi.org/103172/v2.1.1#";
	
	/**
	 *  Attribute that represents identifier for XAdES Baseline.
	 */
	public static final String XADES_BASELINE_2_1_1 = "http://uri.etsi.org/103171/v2.1.1#";

    }

    /**
     * <p>Class that defines the TimeStampToken types.</p>
     * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
     * @version 1.0, 09/01/2014.
     */
    public final class TimestampForm {

	/**
	 * Constructor method for internal class TimestampForm.
	 */
	private TimestampForm() {
	}

	/**
	 * Constant attribute that identifies the URI of an XML timestamp containing an XML signature.
	 */
	public static final String XML = "urn:oasis:names:tc:dss:1.0:core:schema:XMLTimeStampToken";

	/**
	 * Constant attribute that identifies the URI of an XML timestamp containing an ASN.1 TimeStampToken.
	 */
	public static final String RFC_3161 = "urn:ietf:rfc:3161";
    }

    /**
     * <p>Class that represents signature form identifiers.</p>
     * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
     * @version 1.0, 11/02/2011.
     */
    public final class SignatureForm {

	/**
	 * Constructor method for the class DSSContants.java.
	 */
	private SignatureForm() {
	}

	/**
	 * Attribute that represents BES identifier form.
	 */
	public static final String BES = "urn:oasis:names:tc:dss:1.0:profiles:AdES:forms:BES";

	/**
	 * Attribute that represents EPES identifier form.
	 */
	public static final String EPES = "urn:oasis:names:tc:dss:1.0:profiles:AdES:forms:EPES";

	/**
	 * Attribute that represents T identifier form.
	 */
	public static final String T = "urn:oasis:names:tc:dss:1.0:profiles:AdES:forms:ES-T";

	/**
	 * Attribute that represents C identifier form.
	 */
	public static final String C = "urn:oasis:names:tc:dss:1.0:profiles:AdES:forms:ES-C";

	/**
	 * Attribute that represents X identifier form.
	 */
	public static final String X = "urn:oasis:names:tc:dss:1.0:profiles:AdES:forms:ES-X";

	/**
	 * Attribute that represents X_1 identifier form.
	 */
	public static final String X_1 = "urn:oasis:names:tc:dss:1.0:profiles:AdES:forms:ES-X-1";

	/**
	 * Attribute that represents X_2 identifier form.
	 */
	public static final String X_2 = "urn:oasis:names:tc:dss:1.0:profiles:AdES:forms:ES-X-2";

	/**
	 * Attribute that represents X_L identifier form.
	 */
	public static final String X_L = "urn:oasis:names:tc:dss:1.0:profiles:AdES:forms:ES-X-L";

	/**
	 * Attribute that represents X_L_1 identifier form.
	 */
	public static final String X_L_1 = "urn:oasis:names:tc:dss:1.0:profiles:AdES:forms:ES-X-L-1";

	/**
	 * Attribute that represents X_L_2 identifier form.
	 */
	public static final String X_L_2 = "urn:oasis:names:tc:dss:1.0:profiles:AdES:forms:ES-X-L-2";

	/**
	 * Attribute that represents A identifier form.
	 */
	public static final String A = "urn:oasis:names:tc:dss:1.0:profiles:AdES:forms:ES-A";

	/**
	 *  Attribute that represents Basic identifier form.
	 */
	public static final String PADES_BASIC = "urn:afirma:dss:1.0:profile:XSS:PAdES:1.2.1:forms:Basico";

	/**
	 *  Attribute that represents BES identifier form..
	 */
	public static final String PADES_BES = "urn:afirma:dss:1.0:profile:XSS:PAdES:1.1.2:forms:BES";

	/**
	 *  Attribute that represents EPES identifier form..
	 */
	public static final String PADES_EPES = "urn:afirma:dss:1.0:profile:XSS:PAdES:1.1.2:forms:EPES";

	/**
	 *  Attribute that represents LTV identifier form..
	 */
	public static final String PADES_LTV = "urn:afirma:dss:1.0:profile:XSS:PAdES:1.1.2:forms:LTV";
	
	/**
	 *  Attribute that represents B_LEVEL identifier form..
	 */
	public static final String B_LEVEL = "urn:afirma:dss:1.0:profile:XSS:AdES:forms:B-Level";
	
	/**
	 *  Attribute that represents T_LEVEL identifier form..
	 */
	public static final String T_LEVEL = "urn:afirma:dss:1.0:profile:XSS:AdES:forms:T-Level";
	
	/**
	 *  Attribute that represents LT_LEVEL identifier form..
	 */
	public static final String LT_LEVEL = "urn:afirma:dss:1.0:profile:XSS:AdES:forms:LT-Level";
	
	/**
	 *  Attribute that represents LTA_LEVEL identifier form..
	 */
	public static final String LTA_LEVEL = "urn:afirma:dss:1.0:profile:XSS:AdES:forms:LTA-Level";

    }

    /**
     * <p>Class that represents the xml signature modes.</p>
     * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
     * @version 1.0, 11/02/2011.
     */
    public final class XmlSignatureMode {

	/**
	 * Constructor method for the class XmlSignatureMode.java.
	 */
	private XmlSignatureMode() {
	}

	/**
	 * Attribute that represents the ENVELOPING form.
	 */
	public static final String ENVELOPING = "urn:afirma:dss:1.0:profile:XSS:XMLSignatureMode:EnvelopingMode";

	/**
	 * Attribute that represents the EVELOPED form.
	 */
	public static final String ENVELOPED = "urn:afirma:dss:1.0:profile:XSS:XMLSignatureMode:EnvelopedMode";

	/**
	 * Attribute that represents the DETACHED form.
	 */
	public static final String DETACHED = "urn:afirma:dss:1.0:profile:XSS:XMLSignatureMode:DetachedMode";

    }

    /**
     * <p>Class that represents constants for algorithm types in calls DSS services.</p>
     * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
     * @version 1.0, 17/03/2011.
     */
    public final class AlgorithmTypes {

	/**
	 * Constructor method for the class DSSContants.java.
	 */
	private AlgorithmTypes() {
	}

	/**
	 * Attribute that represents MD2 identifier of algorithm types.
	 */
	public static final String MD2 = "urn:ietf:rfc:1319";

	/**
	 * Attribute that represents MD5 identifier of algorithm types.
	 */
	public static final String MD5 = "http://www.w3.org/2001/04/xmldsig-more#md5";

	/**
	 * Attribute that represents SHA1 identifier of algorithm types.
	 */
	public static final String SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";

	/**
	 * Attribute that represents SHA256 identifier of algorithm types.
	 */
	public static final String SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

	/**
	 * Attribute that represents SHA384 identifier of algorithm types.
	 */
	public static final String SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";

	/**
	 * Attribute that represents SHA512 identifier of algorithm types.
	 */
	public static final String SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";

    }

    /**
     * <p>Class that represents constants for report detail level in DSS services.</p>
     * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
     * @version 1.0, 17/03/2011.
     */
    public final class ReportDetailLevel {

	/**
	 * Constructor method for the class DSSContants.java.
	 */
	private ReportDetailLevel() {
	}

	/**
	 * Attribute that represents NO_DETAILS identifier for report detail level.
	 */
	public static final String NO_DETAILS = "urn:oasis:names:tc:dss:1.0:reportdetail:noDetails";

	/**
	 * Attribute that represents NO_PATH_DETAILS identifier for report detail level.
	 */
	public static final String NO_PATH_DETAILS = "urn:oasis:names:tc:dss:1.0:reportdetail:noPathDetails";

	/**
	 * Attribute that represents ALL_DETAILS identifier for report detail level.
	 */
	public static final String ALL_DETAILS = "urn:oasis:names:tc:dss:1.0:reportdetail:allDetails";

    }

    /**
     * <p>Class that represents constants for result process identifiers in DSS services.</p>
     * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
     * @version 1.0, 17/03/2011.
     */
    public final class ResultProcessIds {

	/**
	 * Constructor method for the class ResultProcessIds.java.
	 */
	private ResultProcessIds() {
	}

	/**
	 * Attribute that represents success identifier.
	 */
	public static final String SUCESS = "urn:oasis:names:tc:dss:1.0:resultmajor:Success";

	/**
	 * Attribute that represents requester error identifier.
	 */
	public static final String REQUESTER_ERROR = "urn:oasis:names:tc:dss:1.0:resultmajor:RequesterError";

	/**
	 * Attribute that represents responder error identifier.
	 */
	public static final String RESPONDER_ERROR = "urn:oasis:names:tc:dss:1.0:resultmajor:ResponderError";

	/**
	 * Attribute that represents insufficient information identifier.
	 */
	public static final String INSUFFICIENT_INFORMATION = "urn:oasis:names:tc:dss:1.0:resultmajor:InsufficientInformation";

	/**
	 * Attribute that represents valid signature identifier.
	 */
	public static final String VALID_SIGNATURE = "urn:afirma:dss:1.0:profile:XSS:resultmajor:ValidSignature";

	/**
	 * Attribute that represents invalid signature identifier.
	 */
	public static final String INVALID_SIGNATURE = "urn:afirma:dss:1.0:profile:XSS:resultmajor:InvalidSignature";

	/**
	 * Attribute that represents warning identifier.
	 */
	public static final String WARNING = "urn:oasis:names:tc:dss:1.0:resultmajor:Warning";

	/**
	 * Attribute that represents pending identifier.
	 */
	public static final String PENDING = "urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing:resultmajor:Pending";

	/**
	 * Constant attribute that identifies the correct status of a certificate.
	 */
	public static final String VALID_CERTIFICATE = "urn:afirma:dss:1.0:profile:XSS:detail:Certificate:code:Valid";
	

    }
    
    /**
     * <p>Class that represents constants for the different validation levels of certificate.</p>
     * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
     * @version 1.0, 17/03/2011.
     */
    public final class CertificateValidationLevel {

	/**
	 * Constructor method for the class DSSContants.java.
	 */
	private CertificateValidationLevel() {
	}

	/**
	 * URN that identifies the Not Validate Level.
	 */
	public static final String NOT_VALIDATE = "urn:afirma:dss:1.0:profile:XSS:certificate:NotValidate";
	

	/**
	 * URN that identifies the Basic Validation Level.
	 */
	public static final String BASIC_VALIDATION = "urn:afirma:dss:1.0:profile:XSS:certificate:BasicValidation";

	/**
	 * URN that identifies the CheckCertificateStatus Level.
	 */
	public static final String CHECK_CERTIFICATE_STATUS = "urn:afirma:dss:1.0:profile:XSS:certificate:CheckCertificateStatus";

	/**
	 * URN that identifies the CheckCertificatePath Level.
	 */
	public static final String CHECK_CERTIFICATE_PATH = "urn:afirma:dss:1.0:profile:XSS:certificate:CheckCertificatePath";


    }

}
