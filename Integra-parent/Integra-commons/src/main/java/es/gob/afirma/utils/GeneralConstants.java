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
 * <b>File:</b><p>es.gob.afirma.utils.GeneralConstants.java</p>
 * <b>Description:</b><p>Class that defines constants related to the web services of @Firma and TS@.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>17/03/2011.</p>
 * @author Gobierno de España.
 * @version 1.1, 06/10/2017.
 */
package es.gob.afirma.utils;

/**
 * <p>Class that defines constants related to the web services of @Firma and TS@.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 06/10/2017.
 */
public final class GeneralConstants {

    /**
     * Constructor method for the class GeneralConstants.java.
     */
    private GeneralConstants() {
    }

    /**
     * Constant attribute that represents a delimiter for XPath.
     */
    public static final String PATH_DELIMITER = "/";

    /**
     * Attribute that represents 'AlmacenarDocumento' service name.
     */
    public static final String ALMACENAR_DOCUMENTO_REQUEST = "AlmacenarDocumento";

    /**
     * Attribute that represents 'StoreDocument' service name.
     */
    public static final String STORE_DOCUMENT_REQUEST = "StoreDocument";

    /**
     * Attribute that represents 'ValidarCertificado' service name.
     */
    public static final String VALIDACION_CERTIFICADO_REQUEST = "ValidarCertificado";

    /**
     * Attribute that represents 'ValidateCertificate' service name.
     */
    public static final String CERTIFICATE_VALIDATION_REQUEST = "ValidateCertificate";

    /**
     * Attribute that represents 'ObtenerInfoCertificado' service name.
     */
    public static final String OBTENER_INFO_CERTIFICADO = "ObtenerInfoCertificado";

    /**
     * Attribute that represents the 'GetInfoCertificate' service name.
     */
    public static final String GET_INFO_CERTIFICATE = "GetInfoCertificate";

    /**
     * Attribute that represents the 'ValidarFirma' service name.
     */
    public static final String VALIDAR_FIRMA_REQUEST = "ValidarFirma";

    /**
     * Attribute that represents the 'SignatureValidation' service name.
     */
    public static final String SIGNATURE_VALIDATION_REQUEST = "SignatureValidation";

    /**
     * Attribute that represents the 'ServerSignature' service name.
     */
    public static final String SERVER_SIGNATURE_REQUEST = "ServerSignature";

    /**
     * Attribute that represents the 'FirmaServidor' service name .
     */
    public static final String FIRMA_SERVIDOR_REQUEST = "FirmaServidor";

    /**
     * Attribute that represents the 'FirmaServidorCoSign' service name.
     */
    public static final String FIRMA_SERVIDOR_COSIGN_REQUEST = "FirmaServidorCoSign";

    /**
     * Attribute that represents the 'ServerSignatureCoSign' service name.
     */
    public static final String SERVER_SIGNATURE_COSIGN = "ServerSignatureCoSign";

    /**
     * Constants that represents the 'FirmaServidorCounterSign' request name.
     */
    public static final String FIRMA_SERVIDOR_COUNTERSIGN = "FirmaServidorCounterSign";

    /**
     * Constants that represents the 'ServerSignatureCounterSign' request name.
     */
    public static final String SERVER_SIGNATURE_COUNTER_SIGN = "ServerSignatureCounterSign";

    /**
     * Constants that represents the DSS signature request name.
     */
    public static final String DSS_AFIRMA_SIGN_REQUEST = "DSSAfirmaSign";

    /**
     * Constants that represents the name of the request for DSS services of TS@.
     */
    public static final String DSS_TSA_REQUEST = "DSSTSA";

    /**
     * Constants that represents method name for DSS signature service.
     */
    public static final String DSS_AFIRMA_SIGN_METHOD = "sign";

    /**
     * Constants that represents service name for three phase user signature F1.
     */
    public static final String THREE_PHASE_USER_SIGN_F1 = "ThreePhaseUserSignatureF1";

    /**
     * Constants that represents service name for 'FirmaUsuario3FasesF1'.
     */
    public static final String FIRMA_USUARIO_3FASES_F1 = "FirmaUsuario3FasesF1";

    /**
     * Constants that represents service name for three phase user signature CoSign F1.
     */
    public static final String THREE_PHASE_USER_SIGN_COSIGN_F1 = "ThreePhaseUserSignatureF1CoSign";

    /**
     * Constants that represents service name for 'FirmaUsuario3FasesF1CoSign'.
     */
    public static final String FIRMA_USUARIO_3FASES_F1_COSIGN = "FirmaUsuario3FasesF1CoSign";

    /**
     * Constants that represents service name for three phase user signature counterSign F1.
     */
    public static final String THREE_PHASE_USER_SIGN_COUNTERSIGN_F1 = "ThreePhaseUserSignatureF1CounterSign";

    /**
     * Constants that represents service name for 'FirmaUsuario3FasesF1CounterSign'.
     */
    public static final String FIRMA_USUARIO_3FASES_F1_COUNTER_SIGN = "FirmaUsuario3FasesF1CounterSign";

    /**
     * Constants that represents service name for three phase user signature F3.
     */
    public static final String THREE_PHASE_USER_SIGN_F3 = "ThreePhaseUserSignatureF3";

    /**
     * Constants that represents service name for FirmaUsuario3FasesF3.
     */
    public static final String FIRMA_USUARIO_3FASES_F3 = "FirmaUsuario3FasesF3";

    /**
     * Constants that represents service name for three phase user signature F2.
     */
    public static final String TWO_PHASE_USER_SIGN_F2 = "TwoPhaseUserSignatureF2";

    /**
     * Constants that represents service name for FirmaUsuario2FasesF2.
     */
    public static final String FIRMA_USUARIO2_FASES2 = "FirmaUsuario2FasesF2";

    /**
     * Constants that represents the service name for DSS @Firma verify.
     */
    public static final String DSS_AFIRMA_VERIFY_REQUEST = "DSSAfirmaVerify";

    /**
     * Constants that represents the service name for DSS AfirmaVerify Certificate.
     */
    public static final String DSS_AFIRMA_VERIFY_CERTIFICATE_REQUEST = "DSSAfirmaVerifyCertificate";

    /**
     * Constants that represents method name for DSS @Firma verify service.
     */
    public static final String DSS_AFIRMA_VERIFY_METHOD = "verify";

    /**
     * Constants that represents the service name for DSS batch verify certificate.
     */
    public static final String DSS_BATCH_VERIFY_CERTIFICATE_REQUEST = "DSSBatchVerifyCertificate";

    /**
     * Constants that represents the service name for DSS batch verify signature.
     */
    public static final String DSS_BATCH_VERIFY_SIGNATURE_REQUESTS = "DSSBatchVerifySignature";

    /**
     * Constants that represents method name for DSS verify certificates.
     */
    public static final String DSS_AFIRMA_VERIFY_CERTIFICATES_METHOD = "verifyCertificates";

    /**
     * Constants that represents method name for DSS verify signatures.
     */
    public static final String DSS_AFIRMA_VERIFY_SIGNATURES_METHOD = "verifySignatures";

    /**
     * Constants that represents the service name for DSSAsyncRequestStatus.
     */
    public static final String DSS_ASYNC_REQUEST_STATUS = "DSSAsyncRequestStatus";

    /**
     * Constants that represents method name for DSSAsyncRequestStatus.
     */
    public static final String DSS_ASYNC_REQUEST_STATUS_METHOD = "getProcessResponse";

    /**
     * Constant attribute that represents the name of the the service for generating time-stamps from TS@.
     */
    public static final String TSA_TIMESTAMP_SERVICE = "CreateTimeStampWS";

    /**
     * Constant attribute that represents the name of the the service for validating time-stamps from TS@.
     */
    public static final String TSA_TIMESTAMP_VALIDATION_SERVICE = "VerifyTimeStampWS";

    /**
     * Constant attribute that represents the name of the the service for renewing time-stamps from TS@.
     */
    public static final String TSA_RETIMESTAMP_SERVICE = "RenewTimeStampWS";

    /**
     * Constants that represents the service name for DSSAfirmaArchiveRetrieval.
     */
    public static final String DSS_AFIRMA_ARCHIVE_RETRIEVAL = "DSSAfirmaArchiveRetrieval";

    /**
     * Constants that represents method name for DSS verify certificates.
     */
    public static final String DSS_ARCHIVE_RETRIEVAL_METHOD = "archiveRetrieval";

    /**
     * Attribute that represents 'EliminarContenidoDocumento' service name.
     */
    public static final String ELIMINAR_CONTENIDO_DOCUMENTO = "EliminarContenidoDocumento";
    /**
     * Attribute that represents 'ObtenerContenidoDocumento'.
     */
    public static final String OBTENER_CONTENIDO_DOCUMENTO = "ObtenerContenidoDocumento";
    /**
     * Attribute that represents 'ObtenerContenidoDocumentoId'.
     */
    public static final String OBTENER_CONTENIDO_DOCUMENTO_ID = "ObtenerContenidoDocumentoId";
    /**
     * Attribute that represents 'ObtenerIdDocumento'.
     */
    public static final String OBTENER_ID_DOCUMENTO = "ObtenerIdDocumento";
    /**
     * Attribute that represents 'ObtenerFirmaTransaccion'.
     */
    public static final String OBTENER_FIRMA_TRANSACCION = "ObtenerFirmaTransaccion";

    /**
     * Attribute that represents 'applicationId'.
     */
    public static final String APPLICATION_ID = "applicationId";

    /**
     * Attribute that represents 'document'.
     */
    public static final String DOCUMENT = "document";

    /**
     * Attribute that represents 'name'.
     */
    public static final String NAME = "name";

    /**
     * Attribute that represents 'type'.
     */
    public static final String TYPE = "type";

    /**
     * Attribute that represents 'responseId'.
     */
    public static final String RESPONSE_ID = "responseId";

    /**
     * Attribute that represents 'keySelector'.
     */
    public static final String KEY_SELECTOR = "keySelector";

    /**
     * Attribute that represents 'documentRepository'.
     */
    public static final String DOC_REPOSITORY = "documentRepository";

    /**
     * Attribute that represents 'signatureRepository'.
     */
    public static final String SIG_REPOSITORY = "signatureRepository";

    /**
     * Attribute that represents 'signature'.
     */
    public static final String SIGNATURE = "signature";

    /**
     * Attribute that represents 'transactionId'.
     */
    public static final String TRANSACTION_ID = "transactionId";

    /**
     * Attribute that represents 'afxp:BatchResponse'.
     */
    public static final String ASYNC_BATCH_REPONSE = "afxp:BatchResponse";

    /**
     * Attribute that represents 'ds:X509Data'.
     */
    public static final String ASYNC_BATCH_DS_X509DATA = "ds:X509Data";

    /**
     * Attribute that represents 'dss:Response'.
     */
    public static final String ASYNC_DSS_RESPONSE = "dss:Response";

    /**
     * Attribute that represents 'bathVerifyCertificate'.
     */
    public static final String BATH_VERIFY_CERTIFICATE = "bathVerifyCertificate";

    /**
     * Attribute that represents 'bathVerifySignature'.
     */
    public static final String BATH_VERIFY_SIGNATURE = "bathVerifySignature";

    /**
     * Attribute that represents 'serverSignerResponse'.
     */
    public static final String SERVER_SIGNER_RESPONSE = "serverSignerResponse";

    /**
     * Attribute that represents 'invalidAsyncResponse'.
     */
    public static final String INVALID_ASYNC_RESPONSE = "invalidAsyncResponse";

    /**
     * Constant attribute that contains the String 'VerifyCertificateType'.
     */
    public static final String VERIFY_CERTIFICATE_TYPE = "VerifyCertificateType";
}
