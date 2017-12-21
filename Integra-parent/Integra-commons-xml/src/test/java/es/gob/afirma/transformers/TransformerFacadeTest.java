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
 * <b>File:</b><p>es.gob.afirma.transformers.TransformerFacadeTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for {@link TransformersFacade}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/04/2015.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/04/2015.
 */
package es.gob.afirma.transformers;

import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;

import org.w3c.dom.Document;

import es.gob.afirma.utils.GeneralConstants;
import es.gob.afirma.utils.UtilsFileSystemCommons;

/**
 * <p>Class that defines tests for {@link TransformersFacade}.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 13/04/2015.
 */
public class TransformerFacadeTest extends TestCase {

    /**
     * Tests for {@link TransformersFacade#generateXml(Map, String, String, String)}.
     * @throws Exception If the test fails.
     */
    public void testGenerateXml() throws Exception {
	// valores no válidos
	try {
	    TransformersFacade.getInstance().generateXml(null, null, null, null);
	    fail("No se ha lanzado la excepción por parámetros entrada no válidos");
	} catch (TransformersException e) {}

	try {
	    TransformersFacade.getInstance().generateXml(new HashMap<String, Object>(), null, null, null);
	    fail("No se ha lanzado la excepción por parámetros entrada no válidos");
	} catch (TransformersException e) {}

	try {
	    TransformersFacade.getInstance().generateXml(newInputParams(), "noValid", null, "novalid");
	    fail("No se ha lanzado la excepción por parámetros entrada no válidos");
	} catch (TransformersException e) {}

	try {
	    TransformersFacade.getInstance().generateXml(newInputParams(), "noValid", "novalid", "novalid");
	    fail("No se ha lanzado la excepción por parámetros entrada no válidos");
	} catch (TransformersException e) {}

	// valor válido
	String xmlInput = TransformersFacade.getInstance().generateXml(newInputParams(), GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, TransformersConstants.VERSION_10);
	assertNotNull(xmlInput);
	assertTrue(xmlInput.indexOf("<peticion>ValidarCertificado") >= 0);
    }

    /**
     * Tests for {@link TransformersFacade#parseResponse(String, String, String, String)}.
     * @throws Exception If the test fails.
     */
    public void testParseResponse() throws Exception {
	String inputXml = new String(UtilsFileSystemCommons.readFile("xmlTests/transformerService/ValidarCertificadoResponse.xml", true));

	// valores no válidos
	try {
	    TransformersFacade.getInstance().parseResponse(null, null, null, null);
	    fail("No se ha lanzado la excepción por parámetros entrada no válidos");
	} catch (TransformersException e) {}

	try {
	    TransformersFacade.getInstance().parseResponse("", "", "", "");
	    fail("No se ha lanzado la excepción por parámetros entrada no válidos");
	} catch (TransformersException e) {}

	try {
	    TransformersFacade.getInstance().parseResponse(inputXml, null, null, null);
	    fail("No se ha lanzado la excepción por parámetros entrada no válidos");
	} catch (TransformersException e) {}

	try {
	    TransformersFacade.getInstance().parseResponse("no_válido", "no_válido", "no_válido", "no_válido");
	    fail("No se ha lanzado la excepción por parámetros entrada no válidos");
	} catch (TransformersException e) {}

	try {
	    TransformersFacade.getInstance().parseResponse("no_válido", GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, TransformersConstants.VERSION_10);
	    fail("No se ha lanzado la excepción por parámetros entrada no válidos");
	} catch (TransformersException e) {}

	Map<String, Object> outParams = TransformersFacade.getInstance().parseResponse(inputXml, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, GeneralConstants.VALIDACION_CERTIFICADO_REQUEST, TransformersConstants.VERSION_10);
	assertEquals("0", ((Map<String, Object>) outParams.get("ResultadoValidacion")).get("resultado"));
    }

    /**
     * Tests for {@link TransformersFacade#getParserParameterValue(String)}.
     * @throws Exception If the test fails.
     */
    public void testGetParserParameterValue() throws Exception {
	// valores no válidos
	assertNull(TransformersFacade.getInstance().getParserParameterValue(null));
	assertNull(TransformersFacade.getInstance().getParserParameterValue("no válidos"));

	// valor válido
	String nodeXpath = TransformersFacade.getInstance().getParserParameterValue("ResultMayor");
	assertEquals("dss:Result/dss:ResultMajor", nodeXpath);
    }

    /**
     * Tests for {@link TransformersFacade#getXmlRequestFileByRequestType(String, String, String, String)}.
     * @throws Exception If the test fails.
     */
    public void testGetXmlRequestFileByRequestType() throws Exception {
	// valores no válidos
	try {
	    TransformersFacade.getInstance().getXmlRequestFileByRequestType(null, null, "", null);
	    fail("No se ha lanzado la excepción por parámetros entrada no válidos");
	} catch (TransformersException e) {}

	try {
	    TransformersFacade.getInstance().getXmlRequestFileByRequestType(GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, null, null, TransformersConstants.VERSION_10);
	    fail("No se ha lanzado la excepción por parámetros entrada no válidos");
	} catch (TransformersException e) {}

	try {
	    TransformersFacade.getInstance().getXmlRequestFileByRequestType("valor no válido", "method_noValid", "valor no válido", TransformersConstants.VERSION_10);
	    fail("No se ha lanzado la excepción por parámetros entrada no válidos");
	} catch (TransformersException e) {}

	// valores válidos
	Document doc = TransformersFacade.getInstance().getXmlRequestFileByRequestType(GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, TransformersConstants.REQUEST_CTE, TransformersConstants.VERSION_10);
	assertNotNull(doc);
    }

    /**
     * Tests for {@link TransformersFacade#getParserTemplateByRequestType(String, String, String)}.
     * @throws Exception If the test fails.
     */
    public void testGetParserTemplateByRequestType() throws Exception {
	// valores no válidos
	try {
	    TransformersFacade.getInstance().getParserTemplateByRequestType(null, null, null);
	    fail("No se ha lanzado la excepción por parámetros entrada no válidos");
	} catch (TransformersException e) {}

	try {
	    TransformersFacade.getInstance().getParserTemplateByRequestType(GeneralConstants.CERTIFICATE_VALIDATION_REQUEST, null, "");
	    fail("No se ha lanzado la excepción por parámetros entrada no válidos");
	} catch (TransformersException e) {}

	try {
	    TransformersFacade.getInstance().getParserTemplateByRequestType("valor no válido", "valor no válido", "valor no válido");
	    fail("No se ha lanzado la excepción por parámetros entrada no válidos");
	} catch (TransformersException e) {}

	// valores válidos
	Document doc = TransformersFacade.getInstance().getParserTemplateByRequestType(GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);
	assertNotNull(doc);
    }

    /**
     * Method that obtains a map with the input parameters related to the XML request of the web service for the tests.
     * @return the  map with the input parameters related to the XML request of the web service for the tests.
     */
    private Map<String, Object> newInputParams() {
	Map<String, Object> inParams = new HashMap<String, Object>();
	inParams.put("parametros/idAplicacion", "appPrueba");
	inParams.put("parametros/certificado", UtilsFileSystemCommons.readFileBase64Encoded("serversigner.cer", true));
	inParams.put("parametros/modoValidacion", "0");
	inParams.put("parametros/obtenerInfo", "true");
	return inParams;
    }
}
