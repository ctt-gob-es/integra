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
 * <b>File:</b><p>es.gob.afirma.afirma5ServiceInvoker.Afirma5ServiceInvokerFacadeTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for {@link Afirma5ServiceInvokerFacade}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/04/2015.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/04/2015.
 */
package es.gob.afirma.afirma5ServiceInvoker;

import java.util.Properties;

import junit.framework.TestCase;
import es.gob.afirma.utils.GeneralConstants;
import es.gob.afirma.utils.UtilsFileSystemCommons;
import es.gob.afirma.wsServiceInvoker.Afirma5ServiceInvokerFacade;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerException;

/**
 * <p>Class that defines tests for {@link Afirma5ServiceInvokerFacade}.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 10/04/2015.
 */
public class Afirma5ServiceInvokerFacadeTest extends TestCase {

    /**
     * Constant attribute that represents the application client name.
     */
    private static final String APPLICATION_NAME = "afirmaTest";

    /**
     * Constant attribute that represents the error message to return when the input parameters aren't valid.
     */
    private static final String MSG_ERROR_NOT_VALID_PARAM = "No se ha lanzado la excepción por parámetros entrada no válidos";

    /**
     * Constant attribute that represents the error message to return when the input parameters are empty.
     */
    private static final String MSG_ERROR_EMPTY_PARAM = "No se ha lanzado la excepción por parámetros entrada vacíos";

    /**
     * Tests for {@link Afirma5ServiceInvokerFacade#invokeService(String, String, String, String)}.
     * @throws Exception If the test fails.
     */
    public void testInvokeService() throws Exception {

	// valores nulos.
	try {
	    Afirma5ServiceInvokerFacade.getInstance().invokeService(null, null, null, APPLICATION_NAME);
	    fail(MSG_ERROR_NOT_VALID_PARAM);
	} catch (WSServiceInvokerException e) {}
	// valores vacíos
	try {
	    Afirma5ServiceInvokerFacade.getInstance().invokeService("", "", "", APPLICATION_NAME);
	    fail(MSG_ERROR_EMPTY_PARAM);
	} catch (WSServiceInvokerException e) {}

	// VALORES NO VÁLIDOS:::..

	// xml no válido
	try {
	    Afirma5ServiceInvokerFacade.getInstance().invokeService("xmlPr", GeneralConstants.FIRMA_SERVIDOR_REQUEST, GeneralConstants.FIRMA_SERVIDOR_REQUEST, APPLICATION_NAME);
	    fail(MSG_ERROR_NOT_VALID_PARAM);
	} catch (WSServiceInvokerException e) {}

	// servicio no existente
	try {
	    Afirma5ServiceInvokerFacade.getInstance().invokeService(new String(UtilsFileSystemCommons.readFile("xmlTests/serviceInvoker/ServerSignatureRequest.xml", true)), "serviceTest", GeneralConstants.FIRMA_SERVIDOR_REQUEST, APPLICATION_NAME);
	    fail(MSG_ERROR_NOT_VALID_PARAM);
	} catch (WSServiceInvokerException e) {}

	// método no existente
	try {
	    Afirma5ServiceInvokerFacade.getInstance().invokeService(new String(UtilsFileSystemCommons.readFile("xmlTests/serviceInvoker/ServerSignatureRequest.xml", true)), GeneralConstants.FIRMA_SERVIDOR_REQUEST, "methodTest", APPLICATION_NAME);
	    fail(MSG_ERROR_NOT_VALID_PARAM);
	} catch (WSServiceInvokerException e) {}

	// Nombre de aplicación no existente/válida
	try {
	    Afirma5ServiceInvokerFacade.getInstance().invokeService(new String(UtilsFileSystemCommons.readFile("xmlTests/serviceInvoker/ServerSignatureRequest.xml", true)), GeneralConstants.FIRMA_SERVIDOR_REQUEST, GeneralConstants.FIRMA_SERVIDOR_REQUEST, "AppNoExiste");
	    fail(MSG_ERROR_NOT_VALID_PARAM);
	} catch (WSServiceInvokerException e) {}

	// valores válidos
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(new String(UtilsFileSystemCommons.readFile("xmlTests/serviceInvoker/ServerSignatureRequest.xml", true)), GeneralConstants.FIRMA_SERVIDOR_REQUEST, GeneralConstants.FIRMA_SERVIDOR_REQUEST, APPLICATION_NAME);
	assertNotNull(xmlOutput);
	assertTrue(xmlOutput.indexOf("<Respuesta><estado>true</estado>") > 0);

    }

    /**
     * Tests for {@link Afirma5ServiceInvokerFacade#invokeService(String, String, String, Properties)}.
     * @throws Exception If the test fails.
     */
    public void testInvokeServiceWithProperties() throws Exception {

	// valores nulos.
	try {
	    Afirma5ServiceInvokerFacade.getInstance().invokeService(null, null, null, new Properties());
	    fail(MSG_ERROR_NOT_VALID_PARAM);
	} catch (WSServiceInvokerException e) {}
	// valores vacíos
	try {
	    Afirma5ServiceInvokerFacade.getInstance().invokeService("", "", "", new Properties());
	    fail(MSG_ERROR_EMPTY_PARAM);
	} catch (WSServiceInvokerException e) {}

	// valores no válidos
	try {
	    Afirma5ServiceInvokerFacade.getInstance().invokeService("xmlPr", GeneralConstants.FIRMA_SERVIDOR_REQUEST, GeneralConstants.FIRMA_SERVIDOR_REQUEST, new Properties());
	    fail(MSG_ERROR_NOT_VALID_PARAM);
	} catch (WSServiceInvokerException e) {}

	try {
	    Afirma5ServiceInvokerFacade.getInstance().invokeService(new String(UtilsFileSystemCommons.readFile("xmlTests/serviceInvoker/ServerSignatureRequest.xml", true)), "serviceTest", GeneralConstants.FIRMA_SERVIDOR_REQUEST, getPropertiesForSvcInvoker());
	    fail(MSG_ERROR_NOT_VALID_PARAM);
	} catch (WSServiceInvokerException e) {}

	try {
	    Afirma5ServiceInvokerFacade.getInstance().invokeService(new String(UtilsFileSystemCommons.readFile("xmlTests/serviceInvoker/ServerSignatureRequest.xml", true)), GeneralConstants.FIRMA_SERVIDOR_REQUEST, "methodTest", getPropertiesForSvcInvoker());
	    fail(MSG_ERROR_NOT_VALID_PARAM);
	} catch (WSServiceInvokerException e) {}

	// valores no válidos con colección de propiedades incompleta
	try {
	    Properties prop = getPropertiesForSvcInvoker();
	    prop.remove("endPoint");
	    Afirma5ServiceInvokerFacade.getInstance().invokeService(new String(UtilsFileSystemCommons.readFile("xmlTests/serviceInvoker/ServerSignatureRequest.xml", true)), GeneralConstants.FIRMA_SERVIDOR_REQUEST, GeneralConstants.FIRMA_SERVIDOR_REQUEST, prop);
	    fail(MSG_ERROR_NOT_VALID_PARAM);
	} catch (WSServiceInvokerException e) {
	    assertTrue(true);
	}

	// valores válidos.
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(new String(UtilsFileSystemCommons.readFile("xmlTests/serviceInvoker/ServerSignatureRequest.xml", true)), GeneralConstants.FIRMA_SERVIDOR_REQUEST, GeneralConstants.FIRMA_SERVIDOR_REQUEST, getPropertiesForSvcInvoker());
	assertNotNull(xmlOutput);
	assertTrue(xmlOutput.indexOf("<Respuesta><estado>true</estado>") > 0);
    }

    /**
     * Tests for {@link Afirma5ServiceInvokerFacade#invokeService(String, String, String, String)}.
     * @throws Exception If the test fails.
     */
    public void testValidateCertificate() throws Exception {
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(new String(UtilsFileSystemCommons.readFile("xmlTests/serviceInvoker/peticion_ValidarCertificado.xml", true)), GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, APPLICATION_NAME);
	assertNotNull(xmlOutput);
	assertTrue(xmlOutput.indexOf("<resultado>0</resultado>") > 0);
    }

    /**
     * Tests for {@link Afirma5ServiceInvokerFacade#invokeService(String, String, String, String)}.
     * @throws Exception If the test fails.
     */
    public void testGetInfoCertificate() throws Exception {
	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(new String(UtilsFileSystemCommons.readFile("xmlTests/serviceInvoker/peticion_ObtenerInfoCertificado.xml", true)), GeneralConstants.OBTENER_INFO_CERTIFICADO, GeneralConstants.OBTENER_INFO_CERTIFICADO, APPLICATION_NAME);
	assertNotNull(xmlOutput);
	assertTrue(xmlOutput.indexOf("<idCampo>versionPolitica</idCampo>") > 0);
    }

    /**
     * Tests for {@link Afirma5ServiceInvokerFacade#invokeService(String, String, String, String)}.
     * @throws Exception If the test fails.
     */
    public void testServerSignature() throws Exception {

	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(new String(UtilsFileSystemCommons.readFile("xmlTests/serviceInvoker/ServerSignatureRequest.xml", true)), GeneralConstants.FIRMA_SERVIDOR_REQUEST, GeneralConstants.FIRMA_SERVIDOR_REQUEST, APPLICATION_NAME);
	assertNotNull(xmlOutput);
	assertTrue(xmlOutput.indexOf("<estado>true</estado>") > 0);
    }

    /**
     * Tests for {@link Afirma5ServiceInvokerFacade#invokeService(String, String, String, String)}.
     * @throws Exception If the test fails.
     */
    public void testServerSignatureCoSign() throws Exception {

	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(new String(UtilsFileSystemCommons.readFile("xmlTests/serviceInvoker/ServerSignatureCoSignRequest.xml", true)), GeneralConstants.FIRMA_SERVIDOR_COSIGN_REQUEST, GeneralConstants.FIRMA_SERVIDOR_COSIGN_REQUEST, APPLICATION_NAME);
	assertNotNull(xmlOutput);
	assertTrue(xmlOutput.indexOf("<estado>true</estado>") > 0);
    }

    /**
     * Tests for {@link Afirma5ServiceInvokerFacade#invokeService(String, String, String, String)}.
     * @throws Exception If the test fails.
     */
    public void testSignatureValidation() throws Exception {

	String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(new String(UtilsFileSystemCommons.readFile("xmlTests/serviceInvoker/SignatureValidationRequest.xml", true)), GeneralConstants.VALIDAR_FIRMA_REQUEST, GeneralConstants.VALIDAR_FIRMA_REQUEST, APPLICATION_NAME);
	assertNotNull(xmlOutput);
	assertTrue(xmlOutput.indexOf("<estado>true</estado>") > 0);
    }

    /**
     * Method that gets an instance of properties collections used in configuration parameters.
     * @return an instance of properties collections used in configuration parameters.
     */
    private Properties getPropertiesForSvcInvoker() {
	Properties result = new Properties();
	result.put("com.trustedstore", "truststoreWS.jks");
	result.put("com.trustedstorepassword", "12345");
	result.put("secureMode", "false");
	result.put("endPoint", "localhost:8080");
	result.put("servicePath", "afirmaws/services");
	result.put("callTimeout", "20000");
	result.put("authorizationMethod", "none");
	result.put("authorizationMethod.user", "SEIVM");
	result.put("authorizationMethod.password", "12345");
	result.put("authorizationMethod.passwordType", "c");
	result.put("authorizationMethod.userKeystore", "D:/Workspace/Afirma/Integ@/IntegrationKit/src/test/resources/SoapSigner.p12");
	result.put("authorizationMethod.userKeystorePassword", "12345");
	result.put("authorizationMethod.userKeystoreType", "PKCS12");

	return result;
    }
}
