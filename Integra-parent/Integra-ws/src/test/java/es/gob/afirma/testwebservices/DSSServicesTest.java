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
 * <b>File:</b><p>es.gob.afirma.testwebservices.DSSServicesTest.java.</p>
 * <b>Description:</b><p>Class that allows to tests the @Firma and TS@ DSS services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>23/01/2014.</p>
 * @author Gobierno de España.
 * @version 1.2, 06/03/2020.
 */
package es.gob.afirma.testwebservices;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;

import org.apache.xml.security.c14n.Canonicalizer;

import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.transformers.TransformersFacade;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerFacade;
import es.gob.afirma.utils.Base64CoderCommons;
import es.gob.afirma.utils.DSSConstants;
import es.gob.afirma.utils.DSSConstants.AlgorithmTypes;
import es.gob.afirma.utils.DSSConstants.DSSTagsRequest;
import es.gob.afirma.utils.DSSConstants.ReportDetailLevel;
import es.gob.afirma.utils.DSSConstants.ResultProcessIds;
import es.gob.afirma.utils.DSSConstants.SignTypesURIs;
import es.gob.afirma.utils.DSSConstants.SignatureForm;
import es.gob.afirma.utils.DSSConstants.XmlSignatureMode;
import es.gob.afirma.utils.GeneralConstants;
import es.gob.afirma.utils.UtilsFileSystemCommons;
import es.gob.afirma.wsServiceInvoker.Afirma5ServiceInvokerFacade;

/**
 * <p>Class that allows to tests the @Firma and TS@ DSS services.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.2, 06/03/2020.
 */
public class DSSServicesTest extends TestCase {

    /**
     * Attribute that represents application name for tests.
     */
    private static final String APPLICATION_NAME = "afirmaTest";

    /**
     * Attribute that represents tsa application name for tests.
     */
    private static final String TSA_APPLICATION_NAME = "pruebasTest";

    /**
     * Attribute that represents server signer for tests.
     */
    private static final String SERVER_SIGNER_NAME = "raul conde";

    /**
     * Attribute that represents XML signature in base64.
     */
    private static String signatureB64XML = null;

    /**
     * Attribute that represents XML enveloping signature.
     */
    private static String signXMLEnveloping = null;

    /**
     * Attribute that represents XML signature in base64.
     */
    private static String signatureB64 = null;

    /**
     * Attribute that represents signature archive Identifier .
     */
    private static String archiveIdentifier = null;

    /**
     * Attribute that represents signature archive Identifier .
     */
    private static String batchVerifyResultId = null;

    /**
     * Attribute that represents certificate path.
     */
    private static final String CERTIFICATE_NAME = "confianzaocsp.crt";
    
    /**
     * Test for @Firma DSS sign service.
     * @throws Exception If the test fails.
     */
    public void testDSSService() throws Exception {
	method01DSSAfirmaSign();
	method02DSSAfirmaCoSign();
	method03DSSAfirmaCounterSign();
	method04DSSAfirmaVerify();
	method05UpdateSignature();
	method05UpdateSignature();
	method06DSSAfirmaVerifyCertificate();
	method07DSSBatchVerifySignature();
	method08DSSBatchVerifyCertificate();
	method09DSSAsyncRequestStatus();
	method10DSSTimestampTSA();
    }

    /**
     * Test for @Firma DSS sign service.
     * @throws Exception If the test fails.
     */
    public void method01DSSAfirmaSign() throws Exception {

	String documentB64 = UtilsFileSystemCommons.readFileBase64Encoded("ficheroAfirmar.txt", true);

	Map<String, Object> inParams = new HashMap<String, Object>();
	inParams.put(DSSTagsRequest.BASE64DATA, documentB64);
	inParams.put(DSSTagsRequest.KEY_SELECTOR, SERVER_SIGNER_NAME);
	inParams.put(DSSTagsRequest.SIGNATURE_TYPE, SignTypesURIs.CMS);
	inParams.put(DSSTagsRequest.HASH_ALGORITHM, AlgorithmTypes.SHA1);
	inParams.put(DSSTagsRequest.ADDITIONAL_DOCUMENT_NAME, "ficheroAfirmar.txt");
	inParams.put(DSSTagsRequest.ADDITIONAL_DOCUMENT_TYPE, "txt");

	// paramámetros erróneos (generan un excepción).
	inParams.put(DSSTagsRequest.CLAIMED_IDENTITY, null);

	try {
	    TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);
	    fail("no se ha lanzado la excepción por parámetros inválidos");
	} catch (TransformersException e) {}

	// paramámetros no válidos (generan un mensaje de respuesta con un
	// error)
	inParams.put(DSSTagsRequest.CLAIMED_IDENTITY, "no_valido");
	String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);
	assertEquals(ResultProcessIds.REQUESTER_ERROR, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));

	// parámetros válidos (firma de tipo CADES y XADES)
	inParams.put(DSSTagsRequest.CLAIMED_IDENTITY, APPLICATION_NAME);

	// ->CADES
	inParams.put(DSSTagsRequest.SIGNATURE_TYPE, SignTypesURIs.CADES);
	inParams.put(DSSTagsRequest.SIGNATURE_FORM, SignatureForm.BES);
	xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);
	xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, APPLICATION_NAME);
	propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);
	assertNotNull(propertiesResult);
	assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	assertEquals(SignatureForm.BES, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("SignatureForm")));
	signatureB64 = propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("SignatureBase64")).toString();

	// ->XADES DETACHED
	inParams.put(DSSTagsRequest.SIGNATURE_TYPE, SignTypesURIs.XADES_V_1_3_2);
	inParams.put(DSSTagsRequest.SIGNATURE_FORM, SignatureForm.BES);
	inParams.put(DSSTagsRequest.XML_SIGNATURE_MODE, XmlSignatureMode.DETACHED);
	xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);
	xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, APPLICATION_NAME);
	propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);
	signatureB64XML = propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("SignatureBase64XML")).toString();
	archiveIdentifier = propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ArchiveIdentifier")).toString();
	assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	assertEquals(SignatureForm.BES, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("SignatureForm")));

	// ->XADES ENVELOPING
	inParams.put(DSSTagsRequest.CLAIMED_IDENTITY, APPLICATION_NAME);

	inParams.put(DSSTagsRequest.SIGNATURE_TYPE, SignTypesURIs.XADES_V_1_3_2);
	inParams.put(DSSTagsRequest.SIGNATURE_FORM, SignatureForm.BES);
	inParams.put(DSSTagsRequest.XML_SIGNATURE_MODE, XmlSignatureMode.ENVELOPING);
	xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);
	xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, APPLICATION_NAME);
	propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);
	signXMLEnveloping = propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("SignatureXML")).toString();
	assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	assertEquals(SignatureForm.BES, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("SignatureForm")));

    }

    /**
     * Test for @Firma DSS co-sign service.
     * @throws Exception If the test fails.
     */
    public void method02DSSAfirmaCoSign() throws Exception {

	Map<String, Object> inParams = new HashMap<String, Object>();
	inParams.put(DSSTagsRequest.CLAIMED_IDENTITY, APPLICATION_NAME);
	inParams.put(DSSTagsRequest.KEY_SELECTOR, SERVER_SIGNER_NAME);
	inParams.put(DSSTagsRequest.HASH_ALGORITHM, AlgorithmTypes.SHA1);
	inParams.put(DSSTagsRequest.DOCUMENT_ARCHIVE_ID, archiveIdentifier);
	inParams.put(DSSTagsRequest.PARALLEL_SIGNATURE, "");

	String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);
	assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
    }

    /**
     * Test for @Firma DSS counter-sign service.
     * @throws Exception If the test fails.
     */
    public void method03DSSAfirmaCounterSign() throws Exception {

	Map<String, Object> inParams = new HashMap<String, Object>();
	inParams.put(DSSTagsRequest.CLAIMED_IDENTITY, APPLICATION_NAME);
	inParams.put(DSSTagsRequest.KEY_SELECTOR, SERVER_SIGNER_NAME);
	inParams.put(DSSTagsRequest.HASH_ALGORITHM, AlgorithmTypes.SHA1);
	inParams.put(DSSTagsRequest.DOCUMENT_ARCHIVE_ID, archiveIdentifier);
	inParams.put(DSSTagsRequest.COUNTER_SIGNATURE, "");

	String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);
	assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
    }

    /**
     * Test for @Firma DSS verify service.
     * @throws Exception If the test fails.
     */
    public void method04DSSAfirmaVerify() throws Exception {

	Map<String, Object> inParams = new HashMap<String, Object>();

	inParams.put(DSSTagsRequest.CLAIMED_IDENTITY, APPLICATION_NAME);
	inParams.put(DSSTagsRequest.INCLUDE_CERTIFICATE, Boolean.TRUE.toString());
	inParams.put(DSSTagsRequest.INCLUDE_REVOCATION, Boolean.TRUE.toString());
	inParams.put(DSSTagsRequest.REPORT_DETAIL_LEVEL, ReportDetailLevel.ALL_DETAILS);
	inParams.put(DSSTagsRequest.RETURN_PROCESSING_DETAILS, "");
	inParams.put(DSSTagsRequest.RETURN_READABLE_CERT_INFO, "");
	inParams.put(DSSTagsRequest.ADDICIONAL_REPORT_OPT_SIGNATURE_TIMESTAMP, "urn:afirma:dss:1.0:profile:XSS:SignatureProperty:SignatureTimeStamp");

	// pruebas con firmas de tipo XML (XAdES Detached o Enveloped)
	Map<String, Object> xadesParams = new HashMap<String, Object>(inParams);
	xadesParams.put(DSSTagsRequest.SIGNATURE_PTR_ATR_WHICH, "1299585056969008");
	xadesParams.put(DSSTagsRequest.DOCUMENT_ATR_ID, "1299585056969008");
	xadesParams.put(DSSTagsRequest.BASE64XML, signatureB64XML);

	String xmlInput = TransformersFacade.getInstance().generateXml(xadesParams, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);
	// validamos si el resultado ha sido satisfactorio
	assertEquals(ResultProcessIds.VALID_SIGNATURE, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));

	// pruebas con firma de tipo XML (XAdES Enveloping)
	xadesParams = new HashMap<String, Object>(inParams);
	xadesParams.put(DSSTagsRequest.SIGNATURE_OBJECT, signXMLEnveloping);
	xmlInput = TransformersFacade.getInstance().generateXml(xadesParams, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);
	xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, APPLICATION_NAME);
	propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);
	// validamos si el resultado ha sido satisfactorio
	assertEquals(ResultProcessIds.VALID_SIGNATURE, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));

	// pruebas con firmas de tipo CAdES
	Map<String, Object> cadesParams = new HashMap<String, Object>(inParams);
	cadesParams.put(DSSTagsRequest.BASE64DATA, UtilsFileSystemCommons.readFileBase64Encoded("ficheroAfirmar.txt", true));
	cadesParams.put(DSSTagsRequest.SIGNATURE_BASE64, signatureB64);
	cadesParams.put(DSSTagsRequest.SIGNATURE_BASE64_ATR_TYPE, SignTypesURIs.CADES);

	xmlInput = TransformersFacade.getInstance().generateXml(cadesParams, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);
	xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, APPLICATION_NAME);
	propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);

	// extraemos la información de la firma
	Map<String, Object>[ ] signReports = (Map[ ]) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("IndividualSignatureReport"));
	Map<String, Object> individualSignReport = signReports[0];
	// comprobamos valores de la información del certificado (tipo mapa)
	Map<String, String> certificateInfo = (Map<String, String>) individualSignReport.get(TransformersFacade.getInstance().getParserParameterValue("ReadableCertificateInfo"));
	// assertEquals("3729941487142038484",
	// certificateInfo.get("serialNumber"));
	// assertEquals("ES", certificateInfo.get("pais"));
	assertEquals("DEFAULT", certificateInfo.get("idPolitica"));

	// comprobamos los valores del "ProcessingDetails"
	Map<?, ?>[ ] details = (Map[ ]) individualSignReport.get(TransformersFacade.getInstance().getParserParameterValue("ValidDetail"));
	assertFalse(details.length == 0);
	assertNotNull(details[0].get("dss:OptionalOutputs/vr:VerificationReport/vr:IndividualSignatureReport/vr:Details/dss:ProcessingDetails/dss:ValidDetail@Type"));

    }

    /**
     * Test for @Firma DSS upgrade service.
     * @throws Exception If the test fails.
     */
    public void method05UpdateSignature() throws Exception {

	Map<String, Object> inParams = new HashMap<String, Object>();
	inParams.put(DSSTagsRequest.CLAIMED_IDENTITY, APPLICATION_NAME);
	inParams.put(DSSTagsRequest.RETURN_UPDATED_SIGNATURE_ATR_TYPE, SignatureForm.T);

	// pruebas con firmas de tipo CAdES
	inParams.put(DSSTagsRequest.SIGNATURE_BASE64, signatureB64);
	inParams.put(DSSTagsRequest.SIGNATURE_PTR_ATR_WHICH, "1298045604559");

	String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);
	assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	assertEquals(SignatureForm.T, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("SignatureForm")));

	// pruebas con firmas de tipo XAdES Detached
	inParams.remove(DSSTagsRequest.SIGNATURE_BASE64);
	inParams.put(DSSTagsRequest.BASE64XML, signatureB64XML);
	inParams.put(DSSTagsRequest.DOCUMENT_ATR_ID, archiveIdentifier);
	inParams.put(DSSTagsRequest.SIGNATURE_PTR_ATR_WHICH, archiveIdentifier);

	xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);
	xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, APPLICATION_NAME);
	propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);
	assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	assertEquals(SignatureForm.T, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("SignatureForm")));

	// pruebas con firmas de tipo XAdES Enveloping
	inParams.remove(DSSTagsRequest.BASE64XML);
	inParams.remove(DSSTagsRequest.DOCUMENT_ATR_ID);
	inParams.remove(DSSTagsRequest.SIGNATURE_PTR_ATR_WHICH);
	inParams.put(DSSTagsRequest.RETURN_UPDATED_SIGNATURE_ATR_TYPE, SignatureForm.T);
	inParams.put(DSSTagsRequest.SIGNATURE_OBJECT, signXMLEnveloping);

	xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);

	xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, APPLICATION_NAME);

	propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);
	String signXml = propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("UpdatedSignatureXML")).toString();
	assertTrue(signXml.startsWith("<ds:Signature"));
    }

    /**
     * Test for @Firma DSS verify certificate service.
     * @throws Exception If the test fails.
     */
    public void method06DSSAfirmaVerifyCertificate() throws Exception {

	Map<String, Object> inParams = new HashMap<String, Object>();

	inParams.put(DSSTagsRequest.CLAIMED_IDENTITY, APPLICATION_NAME);
	inParams.put(DSSTagsRequest.INCLUDE_CERTIFICATE, "true");
	inParams.put(DSSTagsRequest.INCLUDE_REVOCATION, "true");
	inParams.put(DSSTagsRequest.REPORT_DETAIL_LEVEL, ReportDetailLevel.ALL_DETAILS);
	inParams.put(DSSTagsRequest.CHECK_CERTIFICATE_STATUS, "true");
	inParams.put(DSSTagsRequest.RETURN_READABLE_CERT_INFO, "");
	inParams.put(DSSTagsRequest.X509_CERTIFICATE, UtilsFileSystemCommons.readFileBase64Encoded(CERTIFICATE_NAME, true));
	String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATE_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATE_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATE_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);
	assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	// comprobamos valores de la información del certificado (tipo mapa)
	Map<String, String> certificateInfo = (Map<String, String>) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("CertificateInfo"));
	// assertEquals("3729941487142038484",
	// certificateInfo.get("serialNumber"));
	// assertEquals("ES", certificateInfo.get("pais"));
	assertEquals("DEFAULT", certificateInfo.get("idPolitica"));

	assertEquals("EMAIL=ca.integra@ricoh.es,CN=CA INTEGRA,OU=DEPARTAMENTO DE FIRMA,O=RICOH,L=SEVILLA,ST=ANDALUCIA,C=ES", propertiesResult.get("dss:OptionalOutputs/vr:CertificatePathValidity/vr:CertificateIdentifier/ds:X509IssuerName"));
	assertTrue(propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("CertificateValidity")) instanceof Map[ ]);
    }

    /**
     * Test for @Firma DSS batch verify signature service.
     * @throws Exception If the test fails.
     */
    public void method07DSSBatchVerifySignature() throws Exception {
	// parámetros de entrada generales
	Map<String, Object> inputParam = new HashMap<String, Object>();

	// parámetros para la firma 1 (XADES)
	Map<String, Object> signParams = new HashMap<String, Object>();
	signParams.put(DSSTagsRequest.INCLUDE_CERTIFICATE, "true");
	signParams.put(DSSTagsRequest.INCLUDE_REVOCATION, "true");
	signParams.put(DSSTagsRequest.REPORT_DETAIL_LEVEL, ReportDetailLevel.ALL_DETAILS);
	signParams.put(DSSTagsRequest.RETURN_PROCESSING_DETAILS, "");
	signParams.put(DSSTagsRequest.RETURN_READABLE_CERT_INFO, "");
	signParams.put(DSSTagsRequest.ADDICIONAL_REPORT_OPT_SIGNATURE_TIMESTAMP, "urn:afirma:dss:1.0:profile:XSS:SignatureProperty:SignatureTimeStamp");

	signParams.put(DSSTagsRequest.SIGNATURE_PTR_ATR_WHICH, "1299585056969008");
	signParams.put(DSSTagsRequest.DOCUMENT_ATR_ID, "1299585056969008");
	signParams.put(DSSTagsRequest.BASE64XML, signatureB64XML);
	signParams.put(DSSTagsRequest.VERIFY_REQUEST_ATTR_REQUEST_ID, "BCJJHGFBBCGEAA");

	// parámetros para la firma 2 (de tipo CAdES)
	Map<String, Object> signParams2 = new HashMap<String, Object>();

	signParams2.put(DSSTagsRequest.VERIFY_REQUEST_ATTR_REQUEST_ID, "BCJJHGFBBCGEBB");
	signParams2.put(DSSTagsRequest.BASE64DATA, UtilsFileSystemCommons.readFileBase64Encoded("ficheroAfirmar.txt", true));
	signParams2.put(DSSTagsRequest.SIGNATURE_BASE64, signatureB64);
	signParams2.put(DSSTagsRequest.SIGNATURE_BASE64_ATR_TYPE, SignTypesURIs.CADES);

	signParams2.put(DSSTagsRequest.INCLUDE_CERTIFICATE, "true");
	signParams2.put(DSSTagsRequest.INCLUDE_REVOCATION, "true");
	signParams2.put(DSSTagsRequest.REPORT_DETAIL_LEVEL, ReportDetailLevel.ALL_DETAILS);
	signParams2.put(DSSTagsRequest.RETURN_PROCESSING_DETAILS, "");
	signParams2.put(DSSTagsRequest.RETURN_READABLE_CERT_INFO, "");
	signParams2.put(DSSTagsRequest.ADDICIONAL_REPORT_OPT_SIGNATURE_TIMESTAMP, "urn:afirma:dss:1.0:profile:XSS:SignatureProperty:SignatureTimeStamp");

	// creamos dos peticiones de validación firma asíncronas.
	Map<?, ?>[ ] requests = { signParams, signParams2 };
	inputParam.put(DSSTagsRequest.VERIFY_REQUEST, requests);
	inputParam.put(DSSTagsRequest.CLAIMED_IDENTITY, APPLICATION_NAME);

	// tipo de validación por lotes: verificación de firmas
	inputParam.put(DSSTagsRequest.BATCH_REQUEST_ATTR_TYPE, DSSTagsRequest.BATCH_VERIFY_SIGN_TYPE);

	String xmlInput = TransformersFacade.getInstance().generateXml(inputParam, GeneralConstants.DSS_BATCH_VERIFY_SIGNATURE_REQUESTS, GeneralConstants.DSS_AFIRMA_VERIFY_SIGNATURES_METHOD, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_BATCH_VERIFY_SIGNATURE_REQUESTS, GeneralConstants.DSS_AFIRMA_VERIFY_SIGNATURES_METHOD, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_BATCH_VERIFY_SIGNATURE_REQUESTS, GeneralConstants.DSS_AFIRMA_VERIFY_SIGNATURES_METHOD, TransformersConstants.VERSION_10);
	assertEquals(ResultProcessIds.PENDING, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	batchVerifyResultId = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultProcessId"));
    }

    /**
     * Test for @Firma DSS batch verify certificate service.
     * @throws Exception If the test fails.
     */
    public void method08DSSBatchVerifyCertificate() throws Exception {
	// parámetros de entrada generales
	Map<String, Object> inputParams = new HashMap<String, Object>();

	// parámetros para el certificados 1
	Map<String, Object> certParams = new HashMap<String, Object>();

	certParams.put(DSSTagsRequest.INCLUDE_CERTIFICATE, "true");
	certParams.put(DSSTagsRequest.INCLUDE_REVOCATION, "true");
	certParams.put(DSSTagsRequest.REPORT_DETAIL_LEVEL, ReportDetailLevel.ALL_DETAILS);
	certParams.put(DSSTagsRequest.CHECK_CERTIFICATE_STATUS, "true");
	certParams.put(DSSTagsRequest.RETURN_READABLE_CERT_INFO, "");
	certParams.put(DSSTagsRequest.X509_CERTIFICATE, UtilsFileSystemCommons.readFileBase64Encoded(CERTIFICATE_NAME, true));

	certParams.put(DSSTagsRequest.INCLUDE_CERTIFICATE, "true");
	certParams.put(DSSTagsRequest.INCLUDE_REVOCATION, "true");
	certParams.put(DSSTagsRequest.REPORT_DETAIL_LEVEL, ReportDetailLevel.ALL_DETAILS);
	certParams.put(DSSTagsRequest.RETURN_READABLE_CERT_INFO, "");
	certParams.put(DSSTagsRequest.VERIFY_REQUEST_ATTR_REQUEST_ID, "BCJJHGFBBCGEAA");

	// parámetros para el certificados 2
	Map<String, Object> certParams2 = new HashMap<String, Object>();
	certParams2.putAll(certParams);
	certParams2.put(DSSTagsRequest.VERIFY_REQUEST_ATTR_REQUEST_ID, "BCJJHGFBBCGEBB");

	Map<?, ?>[ ] requests = { certParams, certParams2 };
	inputParams.put(DSSTagsRequest.VERIFY_REQUEST, requests);
	inputParams.put(DSSTagsRequest.CLAIMED_IDENTITY, APPLICATION_NAME);

	// tipo de validación por lotes: verificación de certificados
	inputParams.put(DSSTagsRequest.BATCH_REQUEST_ATTR_TYPE, DSSTagsRequest.BATCH_VERIFY_CERT_TYPE);

	String xmlInput = TransformersFacade.getInstance().generateXml(inputParams, GeneralConstants.DSS_BATCH_VERIFY_CERTIFICATE_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATES_METHOD, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_BATCH_VERIFY_CERTIFICATE_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATES_METHOD, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_BATCH_VERIFY_CERTIFICATE_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATES_METHOD, TransformersConstants.VERSION_10);
	assertEquals(ResultProcessIds.PENDING, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
    }

    /**
     * Test for @Firma DSS asynchronous service.
     * @throws Exception If the test fails.
     */
    public void method09DSSAsyncRequestStatus() throws Exception {
	// parámetros de entrada
	Map<String, Object> inputParam = new HashMap<String, Object>();

	inputParam.put(DSSTagsRequest.CLAIMED_IDENTITY, APPLICATION_NAME);
	inputParam.put(DSSTagsRequest.ASYNC_RESPONSE_ID, "1301394845513802");// certificados
	inputParam.put(DSSTagsRequest.ASYNC_RESPONSE_ID, batchVerifyResultId);// firmas

	String xmlInput = TransformersFacade.getInstance().generateXml(inputParam, GeneralConstants.DSS_ASYNC_REQUEST_STATUS, GeneralConstants.DSS_ASYNC_REQUEST_STATUS_METHOD, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_ASYNC_REQUEST_STATUS, GeneralConstants.DSS_ASYNC_REQUEST_STATUS_METHOD, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_ASYNC_REQUEST_STATUS, GeneralConstants.DSS_ASYNC_REQUEST_STATUS_METHOD, TransformersConstants.VERSION_10);

	assertEquals(ResultProcessIds.PENDING, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	// Para verificar los resultados de las validaciones de firma, esperar a
	// procesar las peticiones asíncronas.
	// assertEquals(ResultProcessIds.SUCESS,
	// propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	// assertEquals(2, ((Map[ ])
	// propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("VerifyResponse"))).length);
    }

    /**
     * Method that tests the DSS services from TS@.
     */
    public void method10DSSTimestampTSA() {

	/*
	 * Prueba 1:
	 * - Tipo de Sello de Tiempo: RFC 3161
	 * - Input Document: DocumentHash
	 */

	// Obtenemos el fichero que se va a sellar
	byte[ ] file = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);
	try {
	    /*
	     * INICIO SELLADO
	     */
	    MessageDigest md = MessageDigest.getInstance("SHA1");
	    md.update(file);
	    String inputDocumentProcessed = new String(Base64CoderCommons.encodeBase64(md.digest()));

	    Map<String, Object> inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.DIGEST_METHOD_ATR_ALGORITHM, DSSConstants.AlgorithmTypes.SHA1);
	    inParams.put(DSSTagsRequest.DIGEST_VALUE, inputDocumentProcessed);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.SIGNATURE_TYPE, DSSConstants.TimestampForm.RFC_3161);

	    String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    String xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_SERVICE, TSA_APPLICATION_NAME);

	    Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    String rfcTimeStamp = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("RFC3161Timestamp"));
	    /*
	     * FIN SELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.DIGEST_METHOD_ATR_ALGORITHM, DSSConstants.AlgorithmTypes.SHA1);
	    inParams.put(DSSTagsRequest.DIGEST_VALUE, inputDocumentProcessed);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_RFC3161_TIMESTAMPTOKEN, rfcTimeStamp);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    /*
	     * FIN VALIDACIÓN
	     */

	    /*
	     * INICIO RESELLADO
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.DIGEST_METHOD_ATR_ALGORITHM, DSSConstants.AlgorithmTypes.SHA1);
	    inParams.put(DSSTagsRequest.DIGEST_VALUE, inputDocumentProcessed);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_PREVIOUS_RFC3161_TIMESTAMPTOKEN, rfcTimeStamp);
	    inParams.put(DSSTagsRequest.SIGNATURE_TYPE, DSSConstants.TimestampForm.XML);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));

	    String xmlTimeStamp = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("XMLTimestamp"));
	    /*
	     * FIN RESELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.DIGEST_METHOD_ATR_ALGORITHM, DSSConstants.AlgorithmTypes.SHA1);
	    inParams.put(DSSTagsRequest.DIGEST_VALUE, inputDocumentProcessed);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_XML_TIMESTAMPTOKEN, xmlTimeStamp);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    /*
	     * FIN VALIDACIÓN
	     */

	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Prueba 2:
	 * - Tipo de Sello de Tiempo: RFC 3161
	 * - Input Document: Base64Data
	 */
	try {
	    /*
	     * INICIO SELLADO
	     */
	    file = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);
	    Map<String, Object> inParams = new HashMap<String, Object>();
	    String base64Data = new String(Base64CoderCommons.encodeBase64(file));
	    inParams.put(DSSTagsRequest.BASE64DATA, base64Data);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.SIGNATURE_TYPE, DSSConstants.TimestampForm.RFC_3161);

	    String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    String xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_SERVICE, TSA_APPLICATION_NAME);

	    Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    String rfcTimeStamp = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("RFC3161Timestamp"));
	    /*
	     * FIN SELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.BASE64DATA, base64Data);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_RFC3161_TIMESTAMPTOKEN, rfcTimeStamp);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    /*
	     * FIN VALIDACIÓN
	     */

	    /*
	     * INICIO RESELLADO
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.BASE64DATA, base64Data);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_PREVIOUS_RFC3161_TIMESTAMPTOKEN, rfcTimeStamp);
	    inParams.put(DSSTagsRequest.SIGNATURE_TYPE, DSSConstants.TimestampForm.XML);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));

	    String xmlTimeStamp = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("XMLTimestamp"));
	    /*
	     * FIN RESELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.BASE64DATA, base64Data);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_XML_TIMESTAMPTOKEN, xmlTimeStamp);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    /*
	     * FIN VALIDACIÓN
	     */
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Prueba 3:
	 * - Tipo de Sello de Tiempo: XML
	 * - Input Document: DocumentHash con transformada
	 */
	try {
	    /*
	     * INICIO SELLADO
	     */
	    file = UtilsFileSystemCommons.readFile("ficheroAfirmar2.xml", true);
	    org.apache.xml.security.Init.init();
	    byte[ ] canonicalizedFile = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS).canonicalize(file);
	    MessageDigest md = MessageDigest.getInstance("SHA1");
	    md.update(canonicalizedFile);
	    String inputDocumentProcessed = new String(Base64CoderCommons.encodeBase64(md.digest()));
	    Map<String, Object> inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.DOCUMENT_HASH_TRANSFORM_ATR_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
	    inParams.put(DSSTagsRequest.DIGEST_METHOD_ATR_ALGORITHM, DSSConstants.AlgorithmTypes.SHA1);
	    inParams.put(DSSTagsRequest.DIGEST_VALUE, inputDocumentProcessed);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.SIGNATURE_TYPE, DSSConstants.TimestampForm.XML);

	    String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    String xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_SERVICE, TSA_APPLICATION_NAME);

	    Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    String xmlTimeStamp = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("XMLTimestamp"));
	    /*
	     * FIN SELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    inParams = new HashMap<String, Object>();
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.DOCUMENT_HASH_TRANSFORM_ATR_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
	    inParams.put(DSSTagsRequest.DIGEST_METHOD_ATR_ALGORITHM, DSSConstants.AlgorithmTypes.SHA1);
	    inParams.put(DSSTagsRequest.DIGEST_VALUE, inputDocumentProcessed);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_XML_TIMESTAMPTOKEN, xmlTimeStamp);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    /*
	     * FIN VALIDACIÓN
	     */

	    /*
	     * INICIO RESELLADO
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.DOCUMENT_HASH_TRANSFORM_ATR_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
	    inParams.put(DSSTagsRequest.DIGEST_METHOD_ATR_ALGORITHM, DSSConstants.AlgorithmTypes.SHA1);
	    inParams.put(DSSTagsRequest.DIGEST_VALUE, inputDocumentProcessed);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_PREVIOUS_XML_TIMESTAMPTOKEN, xmlTimeStamp);
	    inParams.put(DSSTagsRequest.SIGNATURE_TYPE, DSSConstants.TimestampForm.XML);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));

	    String xmlReTimeStamp = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("XMLTimestamp"));
	    /*
	     * FIN RESELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.DOCUMENT_HASH_TRANSFORM_ATR_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
	    inParams.put(DSSTagsRequest.DIGEST_METHOD_ATR_ALGORITHM, DSSConstants.AlgorithmTypes.SHA1);
	    inParams.put(DSSTagsRequest.DIGEST_VALUE, inputDocumentProcessed);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_XML_TIMESTAMPTOKEN, xmlReTimeStamp);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    /*
	     * FIN VALIDACIÓN
	     */
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Prueba 4:
	 * - Tipo de Sello de Tiempo: XML
	 * - Input Document: Base64XML
	 * - Mecanismo de Autenticación: Usuario/Contraseña
	 * - La respuesta no viene firmada
	 * - La respuesta no viene encriptada
	 */
	try {
	    /*
	     * INICIO SELLADO
	     */
	    file = UtilsFileSystemCommons.readFile("ficheroAfirmar2.xml", true);
	    String inputDocumentProcessed = new String(Base64CoderCommons.encodeBase64(file));
	    Map<String, Object> inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.BASE64XML, inputDocumentProcessed);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.SIGNATURE_TYPE, DSSConstants.TimestampForm.XML);

	    String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    String xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_SERVICE, TSA_APPLICATION_NAME);

	    Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    String xmlTimeStamp = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("XMLTimestamp"));
	    /*
	     * FIN SELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.BASE64XML, inputDocumentProcessed);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_XML_TIMESTAMPTOKEN, xmlTimeStamp);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    /*
	     * FIN VALIDACIÓN
	     */

	    /*
	     * INICIO RESELLADO
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.BASE64XML, inputDocumentProcessed);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_PREVIOUS_XML_TIMESTAMPTOKEN, xmlTimeStamp);
	    inParams.put(DSSTagsRequest.SIGNATURE_TYPE, DSSConstants.TimestampForm.XML);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));

	    String xmlReTimeStamp = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("XMLTimestamp"));
	    /*
	     * FIN RESELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.BASE64XML, inputDocumentProcessed);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_XML_TIMESTAMPTOKEN, xmlReTimeStamp);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    /*
	     * FIN VALIDACIÓN
	     */

	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Prueba 5:
	 * - Tipo de Sello de Tiempo: XML
	 * - Input Document: InlineXML
	 * - Mecanismo de Autenticación: Usuario/Contraseña
	 * - La respuesta no viene firmada
	 * - La respuesta no viene encriptada
	 */
	try {
	    /*
	     * INICIO SELLADO
	     */
	    file = UtilsFileSystemCommons.readFile("ficheroAfirmar2.xml", true);
	    Map<String, Object> inParams = new HashMap<String, Object>();
	    String inlineXML = new String(file);
	    inParams.put(DSSTagsRequest.INLINEXML, inlineXML);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.SIGNATURE_TYPE, DSSConstants.TimestampForm.XML);

	    String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    String xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_SERVICE, TSA_APPLICATION_NAME);

	    Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    String xmlTimeStamp = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("XMLTimestamp"));
	    /*
	     * FIN SELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.INLINEXML, inlineXML);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_XML_TIMESTAMPTOKEN, xmlTimeStamp);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    /*
	     * FIN VALIDACIÓN
	     */

	    /*
	     * INICIO RESELLADO
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.INLINEXML, inlineXML);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_PREVIOUS_XML_TIMESTAMPTOKEN, xmlTimeStamp);
	    inParams.put(DSSTagsRequest.SIGNATURE_TYPE, DSSConstants.TimestampForm.XML);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));

	    String xmlReTimeStamp = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("XMLTimestamp"));
	    /*
	     * FIN RESELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.INLINEXML, inlineXML);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_XML_TIMESTAMPTOKEN, xmlReTimeStamp);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    /*
	     * FIN VALIDACIÓN
	     */
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Prueba 6:
	 * - Tipo de Sello de Tiempo: XML
	 * - Input Document: EscapedXML
	 */
	try {
	    /*
	     * INICIO SELLADO
	     */
	    file = UtilsFileSystemCommons.readFile("ficheroAfirmarEscapado.xml", true);
	    Map<String, Object> inParams = new HashMap<String, Object>();
	    String escapedXML = new String(file);
	    inParams.put(DSSTagsRequest.ESCAPEDXML, escapedXML);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.SIGNATURE_TYPE, DSSConstants.TimestampForm.XML);

	    String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    String xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_SERVICE, TSA_APPLICATION_NAME);

	    Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    String xmlTimeStamp = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("XMLTimestamp"));
	    /*
	     * FIN SELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.ESCAPEDXML, escapedXML);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_XML_TIMESTAMPTOKEN, xmlTimeStamp);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    /*
	     * FIN VALIDACIÓN
	     */

	    /*
	     * INICIO RESELLADO
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.ESCAPEDXML, escapedXML);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_PREVIOUS_XML_TIMESTAMPTOKEN, xmlTimeStamp);
	    inParams.put(DSSTagsRequest.SIGNATURE_TYPE, DSSConstants.TimestampForm.XML);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));

	    String xmlReTimeStamp = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("XMLTimestamp"));
	    /*
	     * FIN RESELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.ESCAPEDXML, escapedXML);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_XML_TIMESTAMPTOKEN, xmlReTimeStamp);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    /*
	     * FIN VALIDACIÓN
	     */
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Prueba 7:
	 * - Tipo de Sello de Tiempo: XML
	 * - Input Document: TransformedData
	 */
	try {
	    /*
	     * INICIO SELLADO
	     */
	    file = UtilsFileSystemCommons.readFile("ficheroAfirmar2.xml", true);
	    org.apache.xml.security.Init.init();
	    byte[ ] canonicalizedFile = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS).canonicalize(file);
	    String inputDocumentProcessed = new String(Base64CoderCommons.encodeBase64(canonicalizedFile));
	    Map<String, Object> inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.TRANSFORMED_DATA_TRANSFORM_ATR_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
	    inParams.put(DSSTagsRequest.TRANSFORMED_DATA_BASE64DATA, inputDocumentProcessed);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.SIGNATURE_TYPE, DSSConstants.TimestampForm.XML);

	    String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    String xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_SERVICE, TSA_APPLICATION_NAME);

	    Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    String xmlTimeStamp = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("XMLTimestamp"));
	    /*
	     * FIN SELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.TRANSFORMED_DATA_TRANSFORM_ATR_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
	    inParams.put(DSSTagsRequest.TRANSFORMED_DATA_BASE64DATA, inputDocumentProcessed);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_XML_TIMESTAMPTOKEN, xmlTimeStamp);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    /*
	     * FIN VALIDACIÓN
	     */

	    /*
	     * INICIO RESELLADO
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.TRANSFORMED_DATA_TRANSFORM_ATR_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
	    inParams.put(DSSTagsRequest.TRANSFORMED_DATA_BASE64DATA, inputDocumentProcessed);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_PREVIOUS_XML_TIMESTAMPTOKEN, xmlTimeStamp);
	    inParams.put(DSSTagsRequest.SIGNATURE_TYPE, DSSConstants.TimestampForm.XML);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));

	    String xmlReTimeStamp = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("XMLTimestamp"));
	    /*
	     * FIN RESELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    inParams = new HashMap<String, Object>();
	    inParams.put(DSSTagsRequest.TRANSFORMED_DATA_TRANSFORM_ATR_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
	    inParams.put(DSSTagsRequest.TRANSFORMED_DATA_BASE64DATA, inputDocumentProcessed);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, TSA_APPLICATION_NAME);
	    inParams.put(DSSTagsRequest.TIMESTAMP_XML_TIMESTAMPTOKEN, xmlReTimeStamp);

	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TSA_APPLICATION_NAME);

	    propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    assertNotNull(propertiesResult);
	    assertEquals(ResultProcessIds.SUCESS, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	    /*
	     * FIN VALIDACIÓN
	     */
	} catch (Exception e) {
	    assertTrue(false);
	}

    }

}
