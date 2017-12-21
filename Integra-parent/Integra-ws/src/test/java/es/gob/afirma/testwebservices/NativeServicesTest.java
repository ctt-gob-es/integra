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
 * <b>File:</b><p>es.gob.afirma.testwebservices.NativeServicesTest.java.</p>
 * <b>Description:</b><p>Class that allows to tests the @Firma native services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>23/01/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 23/01/2014.
 */
package es.gob.afirma.testwebservices;

import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;

import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersFacade;
import es.gob.afirma.utils.GeneralConstants;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.utils.NativeTagsRequest;
import es.gob.afirma.utils.UtilsFileSystemCommons;
import es.gob.afirma.wsServiceInvoker.Afirma5ServiceInvokerFacade;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerException;

/**
 * <p>Class that allows to tests the @Firma native services.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 13/04/2015.
 */
public class NativeServicesTest extends TestCase {

    /**
     * Attribute that represents application name.
     */
    private static final String APPLICATION_NAME = "afirmaTest";

    /**
     * Attribute that represents certificate path.
     */
    private static final String CERTIFICATE_NAME = "confianzaocsp.crt";

    /**
     * Attribute that represents server signer name.
     */
    private static final String SERVER_SIGNER = "raul conde";

    /**
     * Attribute that represents signature format used in the tests.
     */
    private static final String SIGNATURE_FORMAT = "XADES";

    /**
     * Attribute that represents transaction identifier for a server signature server process.
     */
    private static String transactionSignId = null;

    /**
     * Attribute that represents signature content.
     */
    private static String signatureContent = null;

    /**
     * Attribute that represents stored document identifier.
     */
    private static String documentId = null;
    /**
     * Attribute that represents stored document identifier.
     */
    private static String transactionId3PhaseF1 = null;

    /**
     * Constant attribute that represents the algorithm SHA1.
     */
    public static final String SHA1 = "SHA1";
    
    /**
     * Test for @Firma store document service.
     * @throws Exception If the test fails.
     */
    public void testNativeServices() throws Exception{
	method010StoreDocument();
	method020AlmacenarDocumento();
	method030ValidarCertificado();
	method040ValidateCertificate();
	method050ObtenerInfoCertificado();
	method060GetInfoCertificate();
	method070FirmaServidor();
	method080ServerSignature();
	method090FirmaServidorCoSign();
	method100CoSignSignatureServer();
	method110FirmaServidorCounterSign();
	method120ServerSignatureCounterSign();
	method230ValidarFirma();
    }

    /**
     * Test for @Firma store document service.
     * @throws Exception If the test fails.
     */
    public void method010StoreDocument() throws Exception {
	// prueba almacenamiento o custodia documento con valores erróneos (sin
	// documento)
	Map<String, Object> inParams = new HashMap<String, Object>();
	inParams.put(NativeTagsRequest.APPLICATION_ID, APPLICATION_NAME);
	inParams.put(NativeTagsRequest.DOCUMENT, null);
	inParams.put(NativeTagsRequest.DOCUMENT_NAME, "ficheroAfirmar.odt");
	inParams.put(NativeTagsRequest.DOCUMENT_TYPE, "odt");
	String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.STORE_DOCUMENT_REQUEST, GeneralConstants.STORE_DOCUMENT_REQUEST, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.STORE_DOCUMENT_REQUEST, GeneralConstants.STORE_DOCUMENT_REQUEST, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.STORE_DOCUMENT_REQUEST, GeneralConstants.STORE_DOCUMENT_REQUEST, TransformersConstants.VERSION_10);

	assertNotNull(propertiesResult);
	// debe devolver un error en los parámetros de respuesta
	assertNotNull(propertiesResult.get("errorCode"));

	// prueba almacenamiento o custodia documento con valores válidos.
	String certB64 = UtilsFileSystemCommons.readFileBase64Encoded("ficheroAfirmar.odt", true);
	inParams.put(NativeTagsRequest.DOCUMENT, certB64);
	xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.STORE_DOCUMENT_REQUEST, GeneralConstants.STORE_DOCUMENT_REQUEST, TransformersConstants.VERSION_10);
	xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.STORE_DOCUMENT_REQUEST, GeneralConstants.STORE_DOCUMENT_REQUEST, APPLICATION_NAME);
	propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.STORE_DOCUMENT_REQUEST, GeneralConstants.STORE_DOCUMENT_REQUEST, TransformersConstants.VERSION_10);

	assertEquals(Boolean.TRUE.toString(), propertiesResult.get("status"));

    }

    /**
     * Test for @Firma store document service.
     * @throws Exception If the test fails.
     */
    public void method020AlmacenarDocumento() throws Exception {

	// prueba almacenamiento o custodia documento con valores erróneos (sin
	// documento)
	Map<String, Object> inParams = new HashMap<String, Object>();
	inParams.put(NativeTagsRequest.ID_APLICACION, APPLICATION_NAME);
	inParams.put(NativeTagsRequest.DOCUMENT, null);
	inParams.put("parametros/nombreDocumento", "ficheroAfirmar.odt");
	inParams.put("parametros/tipoDocumento", "odt");
	String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, TransformersConstants.VERSION_10);
	assertNotNull(propertiesResult);

	// debe devolver un error en los parámetros de respuesta
	assertNotNull(propertiesResult.get("codigoError"));

	// prueba almacenamiento o custodia documento con valores válidos.
	String certB64 = UtilsFileSystemCommons.readFileBase64Encoded("ficheroAfirmar.odt", true);
	inParams.put(NativeTagsRequest.DOCUMENTO, certB64);
	xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, TransformersConstants.VERSION_10);
	xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, APPLICATION_NAME);
	propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, TransformersConstants.VERSION_10);

	assertEquals(Boolean.TRUE.toString(), propertiesResult.get("estado"));
	documentId = propertiesResult.get("idDocumento").toString();

	// prueba con parámetros erróneos que provocan excepción
	inParams.put(NativeTagsRequest.NOMBRE_DOCUMENTO, "	ficheroAfirmar.odt");
	try {
	    xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, TransformersConstants.VERSION_10);
	    xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, APPLICATION_NAME);
	    fail("se ha lanzado la excepción por parámetros de entrada inválidos");
	} catch (WSServiceInvokerException e) {}

    }

    /**
     * Test for @Firma verify certificate service.
     * @throws Exception If the test fails.
     */
    public void method030ValidarCertificado() throws Exception {
	// validación del certificado con modo validación 0.
	String certB64 = UtilsFileSystemCommons.readFileBase64Encoded(CERTIFICATE_NAME, true);
	Map<String, Object> inParams = new HashMap<String, Object>();
	inParams.put(NativeTagsRequest.ID_APLICACION, APPLICATION_NAME);
	inParams.put(NativeTagsRequest.CERTIFICADO, certB64);
	inParams.put(NativeTagsRequest.MODO_VALIDACION, "0");

	String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, TransformersConstants.VERSION_10);

	assertNotNull(propertiesResult);
	assertEquals("0", GenericUtilsCommons.getValueFromMapsTree("ResultadoValidacion/resultado", propertiesResult));

	// validación del certificado con modo validación 1.
	inParams.put(NativeTagsRequest.MODO_VALIDACION, "1");

	xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, TransformersConstants.VERSION_10);
	xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, APPLICATION_NAME);
	propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, TransformersConstants.VERSION_10);
	assertNotNull(propertiesResult);
	assertEquals("Estado Certificado OK", GenericUtilsCommons.getValueFromMapsTree("ResultadoValidacion/ValidacionEstado/descEstado", propertiesResult));

	// validación del certificado con modo validación 2.
	inParams.put(NativeTagsRequest.MODO_VALIDACION, "2");
	xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, TransformersConstants.VERSION_10);
	xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, APPLICATION_NAME);
	propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, TransformersConstants.VERSION_10);
	assertNotNull(propertiesResult);
	assertEquals("0", GenericUtilsCommons.getValueFromMapsTree("ResultadoValidacion/ValidacionSimple/codigoResultado", propertiesResult));

	// validación del certificado con modo validación 2 y con obtención de
	// información del certificado.
	inParams.put(NativeTagsRequest.OBTENER_INFO, Boolean.TRUE.toString());
	xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, TransformersConstants.VERSION_10);
	xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, APPLICATION_NAME);
	propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, TransformersConstants.VERSION_10);
	assertNotNull(propertiesResult);
	assertEquals("DEFAULT", GenericUtilsCommons.getValueFromMapsTree("InfoCertificado/idPolitica", propertiesResult));

	// prueba con validación con valores no válidos
	inParams.put(NativeTagsRequest.CERTIFICADO, null);
	xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, TransformersConstants.VERSION_10);
	xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, APPLICATION_NAME);
	propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, TransformersConstants.VERSION_10);
	assertNotNull(propertiesResult.get("codigoError"));
    }

    /**
     * Test for @Firma verify certificate service.
     * @throws Exception If the test fails.
     */
    public void method040ValidateCertificate() throws Exception {
	// validación del certificado con modo validación 0.
	String certB64 = UtilsFileSystemCommons.readFileBase64Encoded(CERTIFICATE_NAME, true);
	Map<String, Object> inParams = new HashMap<String, Object>();
	inParams.put(NativeTagsRequest.APPLICATION_ID, APPLICATION_NAME);
	inParams.put(NativeTagsRequest.CERTIFICATE, certB64);
	inParams.put(NativeTagsRequest.VALIDATION_MODE, "0");

	String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, TransformersConstants.VERSION_10);
	assertNotNull(propertiesResult);
	assertEquals("0", GenericUtilsCommons.getValueFromMapsTree("ValidationResult/result", propertiesResult));

	// validación del certificado con modo validación 1.
	inParams.put(NativeTagsRequest.VALIDATION_MODE, "1");
	xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, TransformersConstants.VERSION_10);
	xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, APPLICATION_NAME);
	propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, TransformersConstants.VERSION_10);

	assertNotNull(propertiesResult);
	assertEquals("Estado Certificado OK", GenericUtilsCommons.getValueFromMapsTree("ValidationResult/StatusValidation/statusDescription", propertiesResult));

	// validación del certificado con modo validación 2.
	inParams.put(NativeTagsRequest.VALIDATION_MODE, "2");
	xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, TransformersConstants.VERSION_10);
	xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, APPLICATION_NAME);
	propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, TransformersConstants.VERSION_10);

	assertNotNull(propertiesResult);
	assertEquals("0", GenericUtilsCommons.getValueFromMapsTree("ValidationResult/ChainValidation/resultCode", propertiesResult));

	// validación del certificado con modo validación 2 y con obtención de
	// información del certificado.
	inParams.put(NativeTagsRequest.GET_INFO, Boolean.TRUE.toString());
	xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, TransformersConstants.VERSION_10);
	xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, APPLICATION_NAME);
	propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, TransformersConstants.VERSION_10);
	assertNotNull(propertiesResult);
	assertEquals("DEFAULT", GenericUtilsCommons.getValueFromMapsTree("InfoCertificate/idPolitica", propertiesResult));

	// prueba con validación con valores no válidos
	inParams.put(NativeTagsRequest.CERTIFICATE, null);
	xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, TransformersConstants.VERSION_10);
	xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, APPLICATION_NAME);
	propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, TransformersConstants.VERSION_10);
	assertNotNull(propertiesResult.get("errorCode"));
    }

    /**
     * Test for @Firma get info from certificate service.
     * @throws Exception If the test fails.
     */
    public void method050ObtenerInfoCertificado() throws Exception {
	String certB64 = UtilsFileSystemCommons.readFileBase64Encoded(CERTIFICATE_NAME, true);

	Map<String, Object> inParams = new HashMap<String, Object>();
	inParams.put(NativeTagsRequest.ID_APLICACION, APPLICATION_NAME);
	inParams.put(NativeTagsRequest.CERTIFICADO, certB64);
	String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.OBTENER_INFO_CERTIFICADO, GeneralConstants.OBTENER_INFO_CERTIFICADO, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.OBTENER_INFO_CERTIFICADO, GeneralConstants.OBTENER_INFO_CERTIFICADO, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.OBTENER_INFO_CERTIFICADO, GeneralConstants.OBTENER_INFO_CERTIFICADO, TransformersConstants.VERSION_10);
	assertNotNull(propertiesResult);
	assertEquals("2", GenericUtilsCommons.getValueFromMapsTree("InfoCertificado/serialNumber", propertiesResult));

	// prueba con valores inválidos (devuelve un error en formato xml)
	inParams.put(NativeTagsRequest.CERTIFICADO, null);
	xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.OBTENER_INFO_CERTIFICADO, GeneralConstants.OBTENER_INFO_CERTIFICADO, TransformersConstants.VERSION_10);
	xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.OBTENER_INFO_CERTIFICADO, GeneralConstants.OBTENER_INFO_CERTIFICADO, APPLICATION_NAME);
	propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.OBTENER_INFO_CERTIFICADO, GeneralConstants.OBTENER_INFO_CERTIFICADO, TransformersConstants.VERSION_10);
	assertNotNull(propertiesResult.get("codigoError"));

	// prueba con valores inválidos (lanza una excepción)
	inParams.put(NativeTagsRequest.MODO_VALIDACION, "noNumerico");
	xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.OBTENER_INFO_CERTIFICADO, GeneralConstants.OBTENER_INFO_CERTIFICADO, TransformersConstants.VERSION_10);
	try {
	    Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.OBTENER_INFO_CERTIFICADO, GeneralConstants.OBTENER_INFO_CERTIFICADO, APPLICATION_NAME);
	    fail("se ha lanzado la excepción por parámetros de entrada inválidos");
	} catch (WSServiceInvokerException e) {}
    }

    /**
     * Test for @Firma get info from certificate service.
     * @throws Exception If the test fails.
     */
    public void method060GetInfoCertificate() throws Exception {
	String certB64 = UtilsFileSystemCommons.readFileBase64Encoded(CERTIFICATE_NAME, true);

	Map<String, Object> inParams = new HashMap<String, Object>();
	inParams.put(NativeTagsRequest.APPLICATION_ID, APPLICATION_NAME);
	inParams.put(NativeTagsRequest.CERTIFICATE, certB64);

	String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.GET_INFO_CERTIFICATE, GeneralConstants.GET_INFO_CERTIFICATE, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.GET_INFO_CERTIFICATE, GeneralConstants.GET_INFO_CERTIFICATE, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.GET_INFO_CERTIFICATE, GeneralConstants.GET_INFO_CERTIFICATE, TransformersConstants.VERSION_10);
	assertNotNull(propertiesResult);
	assertEquals("2", GenericUtilsCommons.getValueFromMapsTree("InfoCertificate/serialNumber", propertiesResult));
    }

    /**
     * Test for @Firma server signature service.
     * @throws Exception If the test fails.
     */
    public void method070FirmaServidor() throws Exception {

	String document = UtilsFileSystemCommons.readFileBase64Encoded("ficheroAfirmar.odt", true);

	Map<String, Object> inParams = new HashMap<String, Object>();
	inParams.put(NativeTagsRequest.ID_APLICACION, APPLICATION_NAME);
	inParams.put(NativeTagsRequest.DOCUMENTO, document);
	inParams.put(NativeTagsRequest.NOMBRE_DOCUMENTO, "ficheroAfirmar.odt");
	inParams.put(NativeTagsRequest.TIPO_DOCUMENTO, "odt");
	inParams.put(NativeTagsRequest.FIRMANTE, SERVER_SIGNER);
	inParams.put(NativeTagsRequest.ALGORITMO_HASH, NativeServicesTest.SHA1);
	inParams.put(NativeTagsRequest.FORMATO_FIRMA, SIGNATURE_FORMAT);

	String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.FIRMA_SERVIDOR_REQUEST, GeneralConstants.FIRMA_SERVIDOR_REQUEST, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.FIRMA_SERVIDOR_REQUEST, GeneralConstants.FIRMA_SERVIDOR_REQUEST, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.FIRMA_SERVIDOR_REQUEST, GeneralConstants.FIRMA_SERVIDOR_REQUEST, TransformersConstants.VERSION_10);
	assertNotNull(propertiesResult);
	assertEquals(Boolean.TRUE.toString(), propertiesResult.get("estado"));
	transactionSignId = propertiesResult.get("idTransaccion").toString();
	signatureContent = propertiesResult.get("firmaElectronica").toString();
    }

    /**
     * Test for @Firma server signature service.
     * @throws Exception If the test fails.
     */
    public void method080ServerSignature() throws Exception {

	String document = UtilsFileSystemCommons.readFileBase64Encoded("ficheroAfirmar.odt", true);

	Map<String, Object> inParams = new HashMap<String, Object>();
	inParams.put(NativeTagsRequest.APPLICATION_ID, APPLICATION_NAME);
	inParams.put(NativeTagsRequest.DOCUMENT, document);
	inParams.put(NativeTagsRequest.DOCUMENT_NAME, "ficheroAfirmar.odt");
	inParams.put(NativeTagsRequest.DOCUMENT_TYPE, "odt");
	inParams.put(NativeTagsRequest.SIGNER, SERVER_SIGNER);
	inParams.put(NativeTagsRequest.HASH_ALGORITHM, NativeServicesTest.SHA1);
	inParams.put(NativeTagsRequest.ESIGNATURE_FORMAT, SIGNATURE_FORMAT);

	String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.SERVER_SIGNATURE_REQUEST, GeneralConstants.SERVER_SIGNATURE_REQUEST, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.SERVER_SIGNATURE_REQUEST, GeneralConstants.SERVER_SIGNATURE_REQUEST, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.SERVER_SIGNATURE_REQUEST, GeneralConstants.SERVER_SIGNATURE_REQUEST, TransformersConstants.VERSION_10);
	assertNotNull(propertiesResult);
	assertEquals(Boolean.TRUE.toString(), propertiesResult.get("status"));
    }

    /**
     * Test for @Firma server co-signature service.
     * @throws Exception If the test fails.
     */
    public void method090FirmaServidorCoSign() throws Exception {

	Map<String, Object> inParams = new HashMap<String, Object>();
	inParams.put(NativeTagsRequest.ID_APLICACION, APPLICATION_NAME);
	inParams.put(NativeTagsRequest.ID_TRANSACCION, transactionSignId);
	inParams.put(NativeTagsRequest.FIRMANTE, SERVER_SIGNER);
	inParams.put(NativeTagsRequest.ALGORITMO_HASH, NativeServicesTest.SHA1);

	String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.FIRMA_SERVIDOR_COSIGN_REQUEST, GeneralConstants.FIRMA_SERVIDOR_COSIGN_REQUEST, TransformersConstants.VERSION_10);

	assertNotNull(xmlInput);
	assertTrue(xmlInput.indexOf("Excepcion") < 0);

	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.FIRMA_SERVIDOR_COSIGN_REQUEST, GeneralConstants.FIRMA_SERVIDOR_COSIGN_REQUEST, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.FIRMA_SERVIDOR_COSIGN_REQUEST, GeneralConstants.FIRMA_SERVIDOR_COSIGN_REQUEST, TransformersConstants.VERSION_10);
	assertNotNull(propertiesResult);
	assertEquals(Boolean.TRUE.toString(), propertiesResult.get("estado"));
    }

    /**
     * Test for @Firma server co-signature service.
     * @throws Exception If the test fails.
     */
    public void method100CoSignSignatureServer() throws Exception {

	Map<String, Object> inParams = new HashMap<String, Object>();
	inParams.put(NativeTagsRequest.APPLICATION_ID, APPLICATION_NAME);
	inParams.put(NativeTagsRequest.TRANSACTION_ID, transactionSignId);
	inParams.put(NativeTagsRequest.SIGNER, SERVER_SIGNER);
	inParams.put(NativeTagsRequest.HASH_ALGORITHM, NativeServicesTest.SHA1);

	String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.SERVER_SIGNATURE_COSIGN, GeneralConstants.SERVER_SIGNATURE_COSIGN, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.SERVER_SIGNATURE_COSIGN, GeneralConstants.SERVER_SIGNATURE_COSIGN, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.SERVER_SIGNATURE_COSIGN, GeneralConstants.SERVER_SIGNATURE_COSIGN, TransformersConstants.VERSION_10);
	assertNotNull(propertiesResult);
	assertEquals(Boolean.TRUE.toString(), propertiesResult.get("status"));
    }

    /**
     * Test for @Firma server counter-signature service.
     * @throws Exception If the test fails.
     */
    public void method110FirmaServidorCounterSign() throws Exception {

	Map<String, Object> inParams = new HashMap<String, Object>();
	inParams.put(NativeTagsRequest.ID_APLICACION, APPLICATION_NAME);
	inParams.put(NativeTagsRequest.ID_TRANSACCION, transactionSignId);
	inParams.put(NativeTagsRequest.FIRMANTE, SERVER_SIGNER);
	inParams.put(NativeTagsRequest.ALGORITMO_HASH, NativeServicesTest.SHA1);

	String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.FIRMA_SERVIDOR_COUNTERSIGN, GeneralConstants.FIRMA_SERVIDOR_COUNTERSIGN, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.FIRMA_SERVIDOR_COUNTERSIGN, GeneralConstants.FIRMA_SERVIDOR_COUNTERSIGN, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.FIRMA_SERVIDOR_COUNTERSIGN, GeneralConstants.FIRMA_SERVIDOR_COUNTERSIGN, TransformersConstants.VERSION_10);
	assertNotNull(propertiesResult);
	assertEquals(Boolean.TRUE.toString(), propertiesResult.get("estado"));
    }

    /**
     * Test for @Firma server counter-signature service.
     * @throws Exception If the test fails.
     */
    public void method120ServerSignatureCounterSign() throws Exception {

	Map<String, Object> inParams = new HashMap<String, Object>();
	inParams.put(NativeTagsRequest.APPLICATION_ID, APPLICATION_NAME);
	inParams.put(NativeTagsRequest.TRANSACTION_ID, transactionSignId);
	inParams.put(NativeTagsRequest.SIGNER, SERVER_SIGNER);
	inParams.put(NativeTagsRequest.HASH_ALGORITHM, NativeServicesTest.SHA1);

	String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.SERVER_SIGNATURE_COUNTER_SIGN, GeneralConstants.SERVER_SIGNATURE_COUNTER_SIGN, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.SERVER_SIGNATURE_COUNTER_SIGN, GeneralConstants.SERVER_SIGNATURE_COUNTER_SIGN, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.SERVER_SIGNATURE_COUNTER_SIGN, GeneralConstants.SERVER_SIGNATURE_COUNTER_SIGN, TransformersConstants.VERSION_10);
	assertNotNull(propertiesResult);
	assertEquals(Boolean.TRUE.toString(), propertiesResult.get("status"));
    }

    // /**
    // * Test for @Firma user signature three phases, phase one, service.
    // * @throws Exception If the test fails.
    // */
    // public void method130FirmaUsuario3FasesF1() throws Exception {
    //
    // Map<String, Object> inParams = new HashMap<String, Object>();
    // inParams.put(NativeTagsRequest.ID_APLICACION, APPLICATION_NAME);
    // inParams.put(NativeTagsRequest.ID_DOCUMENTO, documentId);
    // inParams.put(NativeTagsRequest.ALGORITMO_HASH, NativeServicesTest.SHA1);
    //
    // String xmlInput = TransformersFacade.getInstance().generateXml(inParams,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F1,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F1,
    // TransformersConstants.VERSION_10);
    //
    // String xmlOutput =
    // Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F1,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F1, APPLICATION_NAME);
    // Map<String, Object> propertiesResult =
    // TransformersFacade.getInstance().parseResponse(xmlOutput,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F1,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F1,
    // TransformersConstants.VERSION_10);
    // assertNotNull(propertiesResult);
    // assertEquals(Boolean.TRUE.toString(), propertiesResult.get("estado"));
    // transactionId3PhaseF1 = propertiesResult.get("idTransaccion").toString();
    //
    // }
    //
    // /**
    // * Test for @Firma user signature three phases, phase one, service.
    // * @throws Exception If the test fails.
    // */
    // public void method140UserSignature3PhasesF1() throws Exception {
    //
    // Map<String, Object> inParams = new HashMap<String, Object>();
    // inParams.put(NativeTagsRequest.APPLICATION_ID, APPLICATION_NAME);
    // inParams.put(NativeTagsRequest.DOCUMENT_ID, documentId);
    // inParams.put(NativeTagsRequest.HASH_ALGORITHM, NativeServicesTest.SHA1);
    //
    // String xmlInput = TransformersFacade.getInstance().generateXml(inParams,
    // GeneralConstants.THREE_PHASE_USER_SIGN_F1,
    // GeneralConstants.THREE_PHASE_USER_SIGN_F1,
    // TransformersConstants.VERSION_10);
    //
    // String xmlOutput =
    // Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput,
    // GeneralConstants.THREE_PHASE_USER_SIGN_F1,
    // GeneralConstants.THREE_PHASE_USER_SIGN_F1, APPLICATION_NAME);
    // Map<String, Object> propertiesResult =
    // TransformersFacade.getInstance().parseResponse(xmlOutput,
    // GeneralConstants.THREE_PHASE_USER_SIGN_F1,
    // GeneralConstants.THREE_PHASE_USER_SIGN_F1,
    // TransformersConstants.VERSION_10);
    // assertNotNull(propertiesResult);
    // assertEquals(Boolean.TRUE.toString(), propertiesResult.get("status"));
    // }
    //
    // /**
    // * Test for @Firma user signature three phases, phase three, service.
    // * @throws Exception If the test fails.
    // */
    // public void method150FirmaUsuario3FasesF3() throws Exception {
    //
    // Map<String, Object> inParams = new HashMap<String, Object>();
    // inParams.put(NativeTagsRequest.ID_APLICACION, APPLICATION_NAME);
    // inParams.put(NativeTagsRequest.ID_TRANSACCION, transactionId3PhaseF1);
    // inParams.put(NativeTagsRequest.FIRMA_ELECTRONICA, signatureContent);
    // inParams.put(NativeTagsRequest.CERTIFICADO_FIRMANTE,
    // UtilsFileSystemCommons.readFileBase64Encoded(CERTIFICATE_NAME, true));
    // inParams.put(NativeTagsRequest.FORMATO_FIRMA, SIGNATURE_FORMAT);
    //
    // String xmlInput = TransformersFacade.getInstance().generateXml(inParams,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F3,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F3,
    // TransformersConstants.VERSION_10);
    //
    // String xmlOutput =
    // Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F3,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F3, APPLICATION_NAME);
    // Map<String, Object> propertiesResult =
    // TransformersFacade.getInstance().parseResponse(xmlOutput,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F3,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F3,
    // TransformersConstants.VERSION_10);
    // assertNotNull(propertiesResult);
    // assertEquals(Boolean.TRUE.toString(), propertiesResult.get("estado"));
    // }
    //
    // /**
    // * Test for @Firma user signature three phases, phase three, service.
    // * @throws Exception If the test fails.
    // */
    // public void method160UserSignature3PhasesF3() throws Exception {
    //
    // Map<String, Object> inParams = new HashMap<String, Object>();
    // inParams.put(NativeTagsRequest.APPLICATION_ID, APPLICATION_NAME);
    // inParams.put(NativeTagsRequest.TRANSACTION_ID, transactionId3PhaseF1);
    // inParams.put(NativeTagsRequest.E_SIGNATURE, signatureContent);
    // inParams.put(NativeTagsRequest.SIGNER_CERTIFICATE,
    // UtilsFileSystemCommons.readFileBase64Encoded(CERTIFICATE_NAME, true));
    // inParams.put(NativeTagsRequest.ESIGNATURE_FORMAT, SIGNATURE_FORMAT);
    //
    // String xmlInput = TransformersFacade.getInstance().generateXml(inParams,
    // GeneralConstants.THREE_PHASE_USER_SIGN_F3,
    // GeneralConstants.THREE_PHASE_USER_SIGN_F3,
    // TransformersConstants.VERSION_10);
    // String xmlOutput =
    // Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput,
    // GeneralConstants.THREE_PHASE_USER_SIGN_F3,
    // GeneralConstants.THREE_PHASE_USER_SIGN_F3, APPLICATION_NAME);
    // Map<String, Object> propertiesResult =
    // TransformersFacade.getInstance().parseResponse(xmlOutput,
    // GeneralConstants.THREE_PHASE_USER_SIGN_F3,
    // GeneralConstants.THREE_PHASE_USER_SIGN_F3,
    // TransformersConstants.VERSION_10);
    // assertNotNull(propertiesResult);
    // assertEquals(Boolean.TRUE.toString(), propertiesResult.get("status"));
    // }
    //
    // /**
    // * Test for @Firma user signature three phases, phase one co-sign,
    // service.
    // * @throws Exception If the test fails.
    // */
    // public void method170FirmaUsuario3FasesF1Cosign() throws Exception {
    //
    // Map<String, Object> inParams = new HashMap<String, Object>();
    // inParams.put(NativeTagsRequest.ID_APLICACION, APPLICATION_NAME);
    // inParams.put(NativeTagsRequest.ID_TRANSACCION, transactionId3PhaseF1);
    // inParams.put(NativeTagsRequest.ALGORITMO_HASH, NativeServicesTest.SHA1);
    //
    // String xmlInput = TransformersFacade.getInstance().generateXml(inParams,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F1_COSIGN,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F1_COSIGN,
    // TransformersConstants.VERSION_10);
    // String xmlOutput =
    // Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F1_COSIGN,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F1_COSIGN, APPLICATION_NAME);
    // Map<String, Object> propertiesResult =
    // TransformersFacade.getInstance().parseResponse(xmlOutput,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F1_COSIGN,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F1_COSIGN,
    // TransformersConstants.VERSION_10);
    // assertNotNull(propertiesResult);
    // assertEquals(Boolean.TRUE.toString(), propertiesResult.get("estado"));
    // }
    //
    // /**
    // * Test for @Firma user signature three phases, phase one co-sign,
    // service.
    // * @throws Exception If the test fails.
    // */
    // public void method180ThreePhaseUserSignatureCoSign() throws Exception {
    //
    // Map<String, Object> inParams = new HashMap<String, Object>();
    // inParams.put(NativeTagsRequest.APPLICATION_ID, APPLICATION_NAME);
    // inParams.put(NativeTagsRequest.TRANSACTION_ID, transactionId3PhaseF1);
    // inParams.put(NativeTagsRequest.HASH_ALGORITHM, NativeServicesTest.SHA1);
    //
    // String xmlInput = TransformersFacade.getInstance().generateXml(inParams,
    // GeneralConstants.THREE_PHASE_USER_SIGN_COSIGN_F1,
    // GeneralConstants.THREE_PHASE_USER_SIGN_COSIGN_F1,
    // TransformersConstants.VERSION_10);
    //
    // String xmlOutput =
    // Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput,
    // GeneralConstants.THREE_PHASE_USER_SIGN_COSIGN_F1,
    // GeneralConstants.THREE_PHASE_USER_SIGN_COSIGN_F1, APPLICATION_NAME);
    // Map<String, Object> propertiesResult =
    // TransformersFacade.getInstance().parseResponse(xmlOutput,
    // GeneralConstants.THREE_PHASE_USER_SIGN_COSIGN_F1,
    // GeneralConstants.THREE_PHASE_USER_SIGN_COSIGN_F1,
    // TransformersConstants.VERSION_10);
    // assertNotNull(propertiesResult);
    // assertEquals(Boolean.TRUE.toString(), propertiesResult.get("status"));
    // }
    //
    // /**
    // * Test for @Firma user signature three phases, phase one counter-sign,
    // service.
    // * @throws Exception If the test fails.
    // */
    // public void method190FirmaUsuario3FasesF1CounterSign() throws Exception {
    //
    // Map<String, Object> inParams = new HashMap<String, Object>();
    // inParams.put(NativeTagsRequest.ID_APLICACION, APPLICATION_NAME);
    // inParams.put(NativeTagsRequest.ID_TRANSACCION, transactionId3PhaseF1);
    //
    // String xmlInput = TransformersFacade.getInstance().generateXml(inParams,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F1_COUNTER_SIGN,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F1_COUNTER_SIGN,
    // TransformersConstants.VERSION_10);
    // String xmlOutput =
    // Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F1_COUNTER_SIGN,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F1_COUNTER_SIGN, APPLICATION_NAME);
    // Map<String, Object> propertiesResult =
    // TransformersFacade.getInstance().parseResponse(xmlOutput,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F1_COUNTER_SIGN,
    // GeneralConstants.FIRMA_USUARIO_3FASES_F1_COUNTER_SIGN,
    // TransformersConstants.VERSION_10);
    // assertNotNull(propertiesResult);
    // assertEquals(Boolean.TRUE.toString(), propertiesResult.get("estado"));
    // }
    //
    // /**
    // * Test for @Firma user signature three phases, phase one counter-sign,
    // service.
    // * @throws Exception If the test fails.
    // */
    // public void method200ThreePhaseUserSignatureCounterSign() throws Exception
    // {
    //
    // Map<String, Object> inParams = new HashMap<String, Object>();
    // inParams.put(NativeTagsRequest.APPLICATION_ID, APPLICATION_NAME);
    // inParams.put(NativeTagsRequest.TRANSACTION_ID, transactionId3PhaseF1);
    //
    // String xmlInput = TransformersFacade.getInstance().generateXml(inParams,
    // GeneralConstants.THREE_PHASE_USER_SIGN_COUNTERSIGN_F1,
    // GeneralConstants.THREE_PHASE_USER_SIGN_COUNTERSIGN_F1,
    // TransformersConstants.VERSION_10);
    // String xmlOutput =
    // Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput,
    // GeneralConstants.THREE_PHASE_USER_SIGN_COUNTERSIGN_F1,
    // GeneralConstants.THREE_PHASE_USER_SIGN_COUNTERSIGN_F1, APPLICATION_NAME);
    // Map<String, Object> propertiesResult =
    // TransformersFacade.getInstance().parseResponse(xmlOutput,
    // GeneralConstants.THREE_PHASE_USER_SIGN_COUNTERSIGN_F1,
    // GeneralConstants.THREE_PHASE_USER_SIGN_COUNTERSIGN_F1,
    // TransformersConstants.VERSION_10);
    // assertNotNull(propertiesResult);
    // assertEquals(Boolean.TRUE.toString(), propertiesResult.get("status"));
    // }
    //
    // /**
    // * Test for @Firma user signature two phases, phase two, service.
    // * @throws Exception If the test fails.
    // */
    // public void method210FirmaUsuario2FasesF2() throws Exception {
    //
    // Map<String, Object> inParams = new HashMap<String, Object>();
    // inParams.put(NativeTagsRequest.ID_APLICACION, APPLICATION_NAME);
    // inParams.put(NativeTagsRequest.FIRMA_ELECTRONICA, signatureContent);
    // inParams.put(NativeTagsRequest.CERTIFICADO_FIRMANTE,
    // UtilsFileSystemCommons.readFileBase64Encoded(CERTIFICATE_NAME, true));
    // inParams.put(NativeTagsRequest.FORMATO_FIRMA, SIGNATURE_FORMAT);
    // inParams.put(NativeTagsRequest.DOCUMENTO,
    // UtilsFileSystemCommons.readFileBase64Encoded("ficheroAfirmar.odt",
    // true));
    // inParams.put(NativeTagsRequest.NOMBRE_DOCUMENTO, "ficheroAfirmar.odt");
    // inParams.put(NativeTagsRequest.TIPO_DOCUMENTO, "odt");
    // inParams.put(NativeTagsRequest.ALGORITMO_HASH, NativeServicesTest.SHA1);
    // inParams.put(NativeTagsRequest.CUSTODIAR_DOCUMENTO, "false");
    //
    // String xmlInput = TransformersFacade.getInstance().generateXml(inParams,
    // GeneralConstants.FIRMA_USUARIO2_FASES2,
    // GeneralConstants.FIRMA_USUARIO2_FASES2,
    // TransformersConstants.VERSION_10);
    //
    // String xmlOutput =
    // Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput,
    // GeneralConstants.FIRMA_USUARIO2_FASES2,
    // GeneralConstants.FIRMA_USUARIO2_FASES2, APPLICATION_NAME);
    // Map<String, Object> propertiesResult =
    // TransformersFacade.getInstance().parseResponse(xmlOutput,
    // GeneralConstants.FIRMA_USUARIO2_FASES2,
    // GeneralConstants.FIRMA_USUARIO2_FASES2,
    // TransformersConstants.VERSION_10);
    // assertNotNull(propertiesResult);
    // assertEquals(Boolean.TRUE.toString(), propertiesResult.get("estado"));
    // }
    //
    // /**
    // * Test for @Firma user signature two phases, phase two, service.
    // * @throws Exception If the test fails.
    // */
    // public void method220TwoPhaseUserSignatureF2() throws Exception {
    //
    // Map<String, Object> inParams = new HashMap<String, Object>();
    // inParams.put(NativeTagsRequest.APPLICATION_ID, APPLICATION_NAME);
    // inParams.put(NativeTagsRequest.E_SIGNATURE, signatureContent);
    // inParams.put(NativeTagsRequest.SIGNER_CERTIFICATE,
    // UtilsFileSystemCommons.readFileBase64Encoded(CERTIFICATE_NAME, true));
    // inParams.put(NativeTagsRequest.ESIGNATURE_FORMAT, SIGNATURE_FORMAT);
    // inParams.put(NativeTagsRequest.DOCUMENT,
    // UtilsFileSystemCommons.readFileBase64Encoded("ficheroAfirmar.odt",
    // true));
    // inParams.put(NativeTagsRequest.DOCUMENT_NAME, "ficheroAfirmar.odt");
    // inParams.put(NativeTagsRequest.DOCUMENT_TYPE, "odt");
    // inParams.put(NativeTagsRequest.HASH_ALGORITHM, NativeServicesTest.SHA1);
    // inParams.put(NativeTagsRequest.STORE_DOCUMENT, Boolean.FALSE.toString());
    //
    // String xmlInput = TransformersFacade.getInstance().generateXml(inParams,
    // GeneralConstants.TWO_PHASE_USER_SIGN_F2,
    // GeneralConstants.TWO_PHASE_USER_SIGN_F2,
    // TransformersConstants.VERSION_10);
    //
    // String xmlOutput =
    // Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput,
    // GeneralConstants.TWO_PHASE_USER_SIGN_F2,
    // GeneralConstants.TWO_PHASE_USER_SIGN_F2, APPLICATION_NAME);
    // Map<String, Object> propertiesResult =
    // TransformersFacade.getInstance().parseResponse(xmlOutput,
    // GeneralConstants.TWO_PHASE_USER_SIGN_F2,
    // GeneralConstants.TWO_PHASE_USER_SIGN_F2,
    // TransformersConstants.VERSION_10);
    // assertNotNull(propertiesResult);
    // assertEquals(Boolean.TRUE.toString(), propertiesResult.get("status"));
    // }

    /**
     * Test for @Firma verify signature service.
     * @throws Exception If the test fails.
     */
    public void method230ValidarFirma() throws Exception {
	// prueba con valores erróneos
	Map<String, Object> inParams = new HashMap<String, Object>();
	inParams.put(NativeTagsRequest.ID_APLICACION, APPLICATION_NAME);
	inParams.put(NativeTagsRequest.FIRMA_ELECTRONICA, signatureContent);
	inParams.put(NativeTagsRequest.FORMATO_FIRMA, "CMS");

	String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.VALIDAR_FIRMA_REQUEST, GeneralConstants.VALIDAR_FIRMA_REQUEST, TransformersConstants.VERSION_10);
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.VALIDAR_FIRMA_REQUEST, GeneralConstants.VALIDAR_FIRMA_REQUEST, APPLICATION_NAME);
	Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.VALIDAR_FIRMA_REQUEST, GeneralConstants.VALIDAR_FIRMA_REQUEST, TransformersConstants.VERSION_10);
	assertNotNull(propertiesResult);
    }

    // /**
    // * Test for @Firma verify signature service.
    // * @throws Exception If the test fails.
    // */
    // public void method240SignatureValidation() throws Exception {
    //
    // Map<String, Object> inParams = new HashMap<String, Object>();
    // inParams.put(NativeTagsRequest.APPLICATION_ID, APPLICATION_NAME);
    // inParams.put(NativeTagsRequest.E_SIGNATURE, null);
    // inParams.put(NativeTagsRequest.ESIGNATURE_FORMAT, SIGNATURE_FORMAT);
    //
    // String xmlInput = TransformersFacade.getInstance().generateXml(inParams,
    // GeneralConstants.SIGNATURE_VALIDATION_REQUEST,
    // GeneralConstants.SIGNATURE_VALIDATION_REQUEST,
    // TransformersConstants.VERSION_10);
    // String xmlOutput =
    // Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput,
    // GeneralConstants.SIGNATURE_VALIDATION_REQUEST,
    // GeneralConstants.SIGNATURE_VALIDATION_REQUEST, APPLICATION_NAME);
    //
    // Map<String, Object> propertiesResult =
    // TransformersFacade.getInstance().parseResponse(xmlOutput,
    // GeneralConstants.SIGNATURE_VALIDATION_REQUEST,
    // GeneralConstants.SIGNATURE_VALIDATION_REQUEST,
    // TransformersConstants.VERSION_10);
    // assertNotNull(propertiesResult);
    // // debe devolver un error en los parámetros de respuesta
    // assertNotNull(propertiesResult.get("errorCode"));
    //
    // // prueba con valores válidos
    // inParams.put(NativeTagsRequest.E_SIGNATURE, signatureContent);
    // xmlInput = TransformersFacade.getInstance().generateXml(inParams,
    // GeneralConstants.SIGNATURE_VALIDATION_REQUEST,
    // GeneralConstants.SIGNATURE_VALIDATION_REQUEST,
    // TransformersConstants.VERSION_10);
    // xmlOutput =
    // Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput,
    // GeneralConstants.SIGNATURE_VALIDATION_REQUEST,
    // GeneralConstants.SIGNATURE_VALIDATION_REQUEST, APPLICATION_NAME);
    // propertiesResult =
    // TransformersFacade.getInstance().parseResponse(xmlOutput,
    // GeneralConstants.SIGNATURE_VALIDATION_REQUEST,
    // GeneralConstants.SIGNATURE_VALIDATION_REQUEST,
    // TransformersConstants.VERSION_10);
    // assertEquals("Firma Electrónica correcta",
    // GenericUtilsCommons.getValueFromMapsTree("description/eSignatureValidation/conclusion",
    // propertiesResult));
    // }

}
