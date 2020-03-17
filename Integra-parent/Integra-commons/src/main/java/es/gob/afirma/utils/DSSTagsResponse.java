// Copyright (C) 2017 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.utils.DSSTagsResponse.java.</p>
 * <b>Description:</b><p>Class that defines tags related to the responses of DSS web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>25/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.2, 17/03/2020.
 */
package es.gob.afirma.utils;

/**
 * <p>Class that defines tags related to the responses of DSS web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 17/03/2020.
 */
public final class DSSTagsResponse {

    /**
     * Constructor method for the class DSSTagsResponse.java.
     */
    private DSSTagsResponse() {
    }

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:OptionalOutputs</code>.
     */
    public static final String OPTIONAL_OUTPUT = "dss:OptionalOutputs";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:Result</code>.
     */
    public static final String RESULT = "dss:Result";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:SignatureObject</code>.
     */
    public static final String SIGNATURE_OBJECT = "dss:SignatureObject";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:ResultMajor</code>.
     */
    public static final String RESULT_MAJOR = RESULT + "/dss:ResultMajor";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:ResultMinor</code>.
     */
    public static final String RESULT_MINOR = RESULT + "/dss:ResultMinor";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:ResultMessage</code>.
     */
    public static final String RESULT_MESSAGE = RESULT + "/dss:ResultMessage";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:SignatureType</code>.
     */
    public static final String SIGNATURE_TYPE = OPTIONAL_OUTPUT + "/dss:SignatureType";

    /**
     * Constant attribute that represents the XPath for the tag <code>ades:SignatureForm</code>.
     */
    public static final String SIGNATURE_FORM = OPTIONAL_OUTPUT + "/ades:SignatureForm";

    /**
     * Constant attribute that represents the XPath for the tag <code>arch:ArchiveIdentifier</code>.
     */
    public static final String ARCHIVE_IDENTIFIER = OPTIONAL_OUTPUT + "/xss:ArchiveInfo/arch:ArchiveIdentifier";

    /**
     * Constant attribute that represents the XPath for the tag <code>async:ResponseID</code>.
     */
    public static final String RESPONSE_ID = OPTIONAL_OUTPUT + "/async:ResponseID";

    /**
     * Constant attribute that represents the XPath for the tag <code>afxp:ResponseTime</code>.
     */
    public static final String RESPONSE_TIME = OPTIONAL_OUTPUT + "/afxp:ResponseTime";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:Signature</code>.
     */
    public static final String SIGNATURE = SIGNATURE_OBJECT + "/ds:Signature";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:Signature</code>.
     */
    public static final String SIGNATURE_PTR = SIGNATURE_OBJECT + "/dss:SignaturePtr";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:Base64Signature</code>.
     */
    public static final String SIGNATURE_B64 = SIGNATURE_OBJECT + "/dss:Base64Signature";

    /**
     * Constant attribute that represents the XPath for the tag <code>/dss:UpdatedSignature/dss:SignatureObject</code>.
     */
    public static final String UPDATED_SIGNATURE_OBJET = OPTIONAL_OUTPUT + "/dss:UpdatedSignature/dss:SignatureObject";

    /**
     * Constant attribute that represents the XPath for the tag <code>/dss:UpdatedSignature/dss:SignatureObject/dss:Signature</code>.
     */
    public static final String UPDATED_SIGNATURE = UPDATED_SIGNATURE_OBJET + "/ds:Signature";

    /**
     * Constant attribute that represents the XPath for the tag <code>/dss:UpdatedSignature/dss:SignatureObject/dss:SignaturePtr</code>.
     */
    public static final String UPDATED_SIGNATURE_PTR = UPDATED_SIGNATURE_OBJET + "/dss:SignaturePtr";

    /**
     * Constant attribute that represents the XPath for the tag <code>/dss:UpdatedSignature/dss:SignatureObject/dss:Base64Signature</code>.
     */
    public static final String UPDATED_SIGNATURE_B64 = UPDATED_SIGNATURE_OBJET + "/dss:Base64Signature";

    /**
     * Constant attribute that represents the XPath for the tag <code>/dss:OptionalOutputs/dss:DocumentWithSignature</code>.
     */
    public static final String DOCUMENT_WITH_SIGNATURE = OPTIONAL_OUTPUT + "/dss:DocumentWithSignature/dss:Document/dss:Base64XML";

    /**
     * Constant attribute that represents the XPath for the tag <code>/dss:OptionalOutputs/vr:VerificationReport</code>.
     */
    public static final String VERIFICATION_REPORT = OPTIONAL_OUTPUT + "/vr:VerificationReport";

    /**
     * Constant attribute that represents the XPath for the tag <code>/dss:OptionalOutputs/vr:VerificationReport/vr:IndividualSignatureReport</code>.
     */
    public static final String INDIVIDUAL_SIGNATURE_REPORT = VERIFICATION_REPORT + "/vr:IndividualSignatureReport";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:ResultMajor</code>.
     */
    public static final String IND_SIG_RESULT_MAJOR = INDIVIDUAL_SIGNATURE_REPORT + "/" + RESULT_MAJOR;

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:ResultMinor</code>.
     */
    public static final String IND_SIG_RESULT_MINOR = INDIVIDUAL_SIGNATURE_REPORT + RESULT_MINOR;

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:ResultMessage</code>.
     */
    public static final String IND_SIG_RESULT_MESSAGE = INDIVIDUAL_SIGNATURE_REPORT + RESULT_MESSAGE;

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details</code>.
     */
    public static final String IND_SIG_DETAILS = INDIVIDUAL_SIGNATURE_REPORT + "/vr:Details";

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details/afxp:ReadableCertificateInfo</code>.
     */
    public static final String IND_SIG_DETAILS_READABLE_CERTIFICATE_INFO = IND_SIG_DETAILS + "/afxp:ReadableCertificateInfo";

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details/afxp:ReadableField</code>.
     */
    public static final String IND_SIG_READABLE_CERT_INFO_READABLEFIELD = IND_SIG_DETAILS + "/afxp:ReadableField";

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details/afxp:ReadableField/afxp:FieldIdentity</code>.
     */
    public static final String IND_SIG_READABLE_CERT_INFO_FIELD_ID = IND_SIG_READABLE_CERT_INFO_READABLEFIELD + "/afxp:FieldIdentity";

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details/afxp:ReadableField/afxp:FieldValue</code>.
     */
    public static final String IND_SIG_READABLE_CERT_INFO_FIELD_VALUE = IND_SIG_READABLE_CERT_INFO_READABLEFIELD + "/afxp:FieldValue";

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details/sigpol:VerifiedUnderSignaturePolicy/sigpol:SignaturePolicy/sigpol:SignaturePolicyIdentifier</code>.
     */
    public static final String IND_SIG_POLICY_IDENTIFIER = IND_SIG_DETAILS + "/sigpol:VerifiedUnderSignaturePolicy/sigpol:SignaturePolicy/sigpol:SignaturePolicyIdentifier";

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details/vr:Properties/vr:UnsignedProperties/vr:UnsignedSignatureProperties/vr:SignatureTimeStamp/vr:TimeStampContent/vr:CreationTime</code>.
     */
    public static final String IND_SIG_TIMESTAMP_CREATION_TIME = IND_SIG_DETAILS + "/vr:Properties/vr:UnsignedProperties/vr:UnsignedSignatureProperties/vr:SignatureTimeStamp/vr:TimeStampContent/vr:CreationTime";

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details/vr:Properties/vr:UnsignedProperties/vr:UnsignedSignatureProperties/vr:SignatureTimeStamp/vr:TimeStampContent/vr:CreationTime</code>.
     */
    public static final String IND_SIG_POLICY_DOCUMENT = IND_SIG_DETAILS + "/afxp:SigPolicyDocument@Type";

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details/dss:ProcessingDetails/dss:ValidDetail</code>.
     */
    public static final String IND_SIG_VALID_DETAIL = IND_SIG_DETAILS + "/dss:ProcessingDetails/dss:ValidDetail";

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details/dss:ProcessingDetails/dss:ValidDetail@Type</code>.
     */
    public static final String IND_SIG_VALID_DETAIL_TYPE = IND_SIG_VALID_DETAIL + "@Type";

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details/dss:ProcessingDetails/dss:ValidDetail/dss:Code</code>.
     */
    public static final String IND_SIG_VALID_DETAIL_CODE = IND_SIG_VALID_DETAIL + "/dss:Code";

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details/dss:ProcessingDetails/dss:ValidDetail/dss:Message</code>.
     */
    public static final String IND_SIG_VALID_DETAIL_MESSAGE = IND_SIG_VALID_DETAIL + "/dss:Message";

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details/dss:ProcessingDetails/dss:ValidDetail</code>.
     */
    public static final String IND_SIG_INVALID_DETAIL = IND_SIG_DETAILS + "/dss:ProcessingDetails/dss:InvalidDetail";

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details/dss:ProcessingDetails/dss:ValidDetail@Type</code>.
     */
    public static final String IND_SIG_INVALID_DETAIL_TYPE = IND_SIG_INVALID_DETAIL + "@Type";

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details/dss:ProcessingDetails/dss:ValidDetail/dss:Code</code>.
     */
    public static final String IND_SIG_INVALID_DETAIL_CODE = IND_SIG_INVALID_DETAIL + "/dss:Code";

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details/dss:ProcessingDetails/dss:ValidDetail/dss:Message</code>.
     */
    public static final String IND_SIG_INVALID_DETAIL_MESSAGE = IND_SIG_INVALID_DETAIL + "/dss:Message";

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details/dss:ProcessingDetails/dss:ValidDetail</code>.
     */
    public static final String IND_SIG_INDETERMINATE_DETAIL = IND_SIG_DETAILS + "/dss:ProcessingDetails/dss:IndeterminateDetail";

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details/dss:ProcessingDetails/dss:ValidDetail@Type</code>.
     */
    public static final String IND_SIG_INDETERMINATE_DETAIL_TYPE = IND_SIG_INDETERMINATE_DETAIL + "@Type";

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details/dss:ProcessingDetails/dss:ValidDetail/dss:Code</code>.
     */
    public static final String IND_SIG_INDETERMINATE_DETAIL_CODE = IND_SIG_INDETERMINATE_DETAIL + "/dss:Code";

    /**
     * Constant attribute that represents the XPath for the tag <code>/vr:IndividualSignatureReport/vr:Details/dss:ProcessingDetails/dss:ValidDetail/dss:Message</code>.
     */
    public static final String IND_SIG_INDETERMINATE_DETAIL_MESSAGE = IND_SIG_INDETERMINATE_DETAIL + "/dss:Message";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:OptionalOutputs/afxp:SignedDataInfo</code>.
     */
    public static final String SIGNED_DATA_INFO = OPTIONAL_OUTPUT + "/afxp:SignedDataInfo";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:OptionalOutputs/afxp:SignedDataInfo/afxp:ContentData/afxp:BinaryValue</code>.
     */
    public static final String SIGNED_DATA_INFO_CONTENT_DATA = SIGNED_DATA_INFO + "/afxp:ContentData/afxp:BinaryValue";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:OptionalOutputs/afxp:SignedDataInfo/dss:DocumentHash/ds:DigestMethod</code>.
     */
    public static final String SIGN_DAT_INF_DOCUMENT_HASH_DIGEST_METHOD = SIGNED_DATA_INFO + "/dss:DocumentHash/ds:DigestMethod";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:OptionalOutputs/afxp:SignedDataInfo/dss:DocumentHash/ds:DigestValue</code>.
     */
    public static final String SIG_DAT_INF_DOCUMENT_HASH_DIGEST_VALUE = SIGNED_DATA_INFO + "/dss:DocumentHash/ds:DigestValue";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:OptionalOutputs/afxp:SignedDataInfo/afxp:SignedDataRefs</code>.
     */
    public static final String SIG_DAT_INF_SIGNED_DATA_REFS = SIGNED_DATA_INFO + "/afxp:SignedDataRefs";

    /**
     * Constant attribute that represents the XPath for the tag <code>afxp:ReadableCertificateInfo</code>.
     */
    public static final String READABLE_CERT_INFO = OPTIONAL_OUTPUT + "/afxp:ReadableCertificateInfo";

    /**
     * Constant attribute that represents the XPath for the tag <code>afxp:ReadableField/afxp:FieldIdentity</code>.
     */
    public static final String READABLE_FIELD_IDENTITY = READABLE_CERT_INFO + "/afxp:ReadableField/afxp:FieldIdentity";

    /**
     * Constant attribute that represents the XPath for the tag <code>afxp:FieldIdentity</code>.
     */
    public static final String FIELD_IDENTITY = "/afxp:ReadableField/afxp:FieldIdentity";

    /**
     * Constant attribute that represents the XPath for the tag <code>afxp:FieldValue</code>.
     */
    public static final String READABLE_FIELD_VALUE = "/afxp:FieldValue";

    /**
     * Constant attribute that represents the XPath for the tag <code>afxp:FieldValue</code>.
     */
    public static final String CERT_PATH = "/afxp:FieldValue";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:OptionalOutputs/vr:CertificatePathValidity/</code>.
     */
    public static final String CERT_PATH_VALIDITY = OPTIONAL_OUTPUT + "/vr:CertificatePathValidity";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:OptionalOutputs/vr:CertificatePathValidity/vr:CertificateIdentifier/ds:X509IssuerName/</code>.
     */
    public static final String CERT_PATH_VAL_IDENTIFIER_ISSUER = CERT_PATH_VALIDITY + "/vr:CertificateIdentifier/ds:X509IssuerName";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:OptionalOutputs/vr:CertificatePathValidity/vr:CertificateIdentifier/ds:X509SerialNumber</code>.
     */
    public static final String CERT_PATH_VAL_IDENTIFIER_SER_NUM = CERT_PATH_VALIDITY + "/vr:CertificateIdentifier/ds:X509SerialNumber";

    /**
     * Constant attribute that represents the XPath for the tag <code>vr:PathValiditySummary@Type</code>.
     */
    public static final String CERT_PATH_VAL_SUMMARY_TYPE = CERT_PATH_VALIDITY + "/vr:PathValiditySummary@Type";

    /**
     * Constant attribute that represents the XPath for the tag <code>vr:PathValiditySummary/dss:Code</code>.
     */
    public static final String CERT_PATH_VAL_SUMMARY_CODE = CERT_PATH_VALIDITY + "/vr:PathValiditySummary/dss:Code";

    /**
     * Constant attribute that represents the XPath for the tag <code>vr:PathValiditySummary/dss:Message</code>.
     */
    public static final String CERT_PATH_VAL_SUMMARY_MESSAGE = CERT_PATH_VALIDITY + "/vr:PathValiditySummary/dss:Message";

    /**
     * Constant attribute that represents the XPath for the tag <code>vr:PathValidityDetail/vr:CertificateValidity</code>.
     */
    public static final String CERT_PATH_VAL_DETAIL = CERT_PATH_VALIDITY + "/vr:PathValidityDetail/vr:CertificateValidity";

    /**
     * Constant attribute that represents the XPath for the tag <code>vr:PathValidityDetail/vr:CertificateValidity</code>.
     */
    public static final String BATCH_RESPONSE_ID = OPTIONAL_OUTPUT + "/async:ResponseID";

    /**
     * Constant attribute that represents the XPath for the tag <code>vr:PathValidityDetail/vr:CertificateValidity</code>.
     */
    public static final String BATCH_RESPONSE_TIME = OPTIONAL_OUTPUT + "/async:ResponseTime";

    /**
     * Constant attribute that represents the XPath for the tag <code>afxp:SignedDataInfo/afxp:DataInfo</code>.
     */
    public static final String DATA_INFO = OPTIONAL_OUTPUT + "/afxp:SignedDataInfo/afxp:DataInfo";

    /**
     * Constant attribute that represents the XPath for the tag <code>afxp:SignedDataInfo/afxp:DataInfo/afxp:ContentData/afxp:BinaryValue</code>.
     */
    public static final String DATA_INFO_CONTENT_DATA = DATA_INFO + "/afxp:ContentData/afxp:BinaryValue";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:DocumentHash/ds:DigestMethod@Algorithm</code>.
     */
    public static final String DATA_INFO_DOC_HASH_METHOD = DATA_INFO + "/dss:DocumentHash/ds:DigestMethod@Algorithm";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:DocumentHash/ds:DigestValue</code>.
     */
    public static final String DATA_INFO_DOC_HASH_VALUE = DATA_INFO + "/dss:DocumentHash/ds:DigestValue";

    /**
     * Constant attribute that represents the XPath for the tag <code>afxp:SignedDataRefs/afxp:SignedDataRef</code>.
     */
    public static final String DATA_INFO_SIGNED_DATA_REFS = DATA_INFO + "/afxp:SignedDataRefs/afxp:SignedDataRef";

    /**
     * Constant attribute that represents the XPath for the tag <code>afxp:SignedDataRefs/afxp:SignedDataRef/afxp:XPath</code>.
     */
    public static final String DATA_INFO_SIGNED_DATA_REF_XPATH = DATA_INFO_SIGNED_DATA_REFS + "/afxp:XPath";

    /**
     * Constant attribute that represents the XPath for the tag <code>afxp:Responses/</code>.
     */
    public static final String BATCH_RESPONSES = "afxp:Responses/";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:VerifyResponse</code>.
     */
    public static final String VERIFY_RESPONSE = "dss:VerifyResponse";

    /**
     * Constant attribute that represents the XPath for the tag <code>ds:Signature</code>.
     */
    public static final String TIMESTAMP_SIGNATURE_TIMESTAMPTOKEN = SIGNATURE_OBJECT + "/dss:Timestamp/ds:Signature";

    /**
     * Constant attribute that represents the XPath for the tag <code>dss:RFC3161TimeStampToken</code>.
     */
    public static final String TIMESTAMP_RFC3161_TIMESTAMPTOKEN = SIGNATURE_OBJECT + "/dss:Timestamp/dss:RFC3161TimeStampToken";

    /**
     * Constant attribute that represents the XPath for the tag <code>/dss:OptionalOutputs//dss:SigningTimeInfo/dss:SigningTime</code>.
     */
    public static final String SIG_INF_SIGNING_TIME = OPTIONAL_OUTPUT + "/dss:SigningTimeInfo/dss:SigningTime";

    /**
     * Constant attribute that represents the XPath for the tag <code>/dss:OptionalOutputs/dss:SigningTimeInfo/dss:SigningTimeBoundaries/dss:LowerBoundary</code>.
     */
    public static final String SIG_INF_LOWER_BOUNDARY = OPTIONAL_OUTPUT + "/dss:SigningTimeInfo/dss:SigningTimeBoundaries/dss:LowerBoundary";

    /**
     * Constant attribute that represents the XPath for the tag <code>/dss:OptionalOutputs/dss:SigningTimeInfo/dss:SigningTimeBoundaries/dss:UpperBoundary</code>.
     */
    public static final String SIG_INF_UPPER_BOUNDARY = OPTIONAL_OUTPUT + "/dss:SigningTimeInfo/dss:SigningTimeBoundaries/dss:UpperBoundary";

    /**
     * Constant attribute that represents the XPath for the tag <code>/dss:OptionalOutputs/dss:ProcessingDetails/dss:ValidDetail</code>.
     */
    public static final String OP_OUT_VALID_DETAIL = OPTIONAL_OUTPUT + "/dss:ProcessingDetails/dss:ValidDetail";

    /**
     * Constant attribute that represents the XPath for the tag <code>/dss:OptionalOutputs/dss:ProcessingDetails/dss:InvalidDetail</code>.
     */
    public static final String OP_OUT_INVALID_DETAIL = OPTIONAL_OUTPUT + "/dss:ProcessingDetails/dss:InvalidDetail";

    /**
     * Constant attribute that represents the XPath for the tag <code>/dss:OptionalOutputs/dss:ProcessingDetails/dss:IndeterminateDetail</code>.
     */
    public static final String OP_OUT_INDETERMINATE_DETAIL = OPTIONAL_OUTPUT + "/dss:ProcessingDetails/dss:IndeterminateDetail";

}
