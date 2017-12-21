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
 * <b>File:</b><p>es.gob.afirma.evisor.EVisorTransformerTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for eVisor requests and responses on XML format.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/04/2015.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/04/2015.
 */
package es.gob.afirma.evisor;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.util.HashMap;
import java.util.Map;

import junit.framework.Assert;

import org.junit.Test;

import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.transformers.TransformersFacade;
import es.gob.afirma.utils.Base64CoderCommons;
import es.gob.afirma.utils.EVisorConstants;
import es.gob.afirma.utils.EVisorConstants.EVisorTagsRequest;
import es.gob.afirma.utils.EVisorUtilCommons;
import es.gob.afirma.utils.UtilsFileSystemCommons;
import es.gob.afirma.utils.UtilsXML;

/**
 * <p>Class that defines tests for eVisor requests and responses on XML format.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 10/04/2015.
 */
public class EVisorTransformerTest {

    /**
     * Attribute that represents the XSD schema definition for <code>SignatureReportServices</code>.
     */
    private File xsdFile = new File(ClassLoader.getSystemResource("eVisor/SignatureReportServices.xsd").getFile());

    /**
     * Test to generate a request to <code>generateReport</code> method (a method of <code>SignatureReportService</code>) without mandatory parameters.
     * @throws Exception If the test fails.
     */
    @Test
    public void testGenerateReportWithoutMandatoryParams() throws Exception {
	Map<String, Object> inputParams = new HashMap<String, Object>();
	inputParams.put(EVisorTagsRequest.APPLICATION_ID, "applicationName");

	// creación xml sin todos los parámetros obligatorios
	String inputXml = TransformersFacade.getInstance().generateXml(inputParams, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.GENERATE_REPORT_METHOD, TransformersConstants.VERSION_10);
	try {
	    UtilsXML.getDocumentWithXsdValidation(xsdFile, new ByteArrayInputStream(inputXml.getBytes()));
	    Assert.fail();
	} catch (TransformersException e) {}
    }

    /**
     * Tests to generate requests to <code>generateReport</code> method (a method of <code>SignatureReportService</code>) with mandatory parameters.
     * @throws Exception If the test fails.
     */
    @Test
    public void testGenerateReportMandatoryParams() throws Exception {
	Map<String, Object> inputParams = new HashMap<String, Object>();
	inputParams.put(EVisorTagsRequest.APPLICATION_ID, "APPLICATION_NAME");
	inputParams.put(EVisorTagsRequest.TEMPLATE_ID, "TEMPLATE_ID");

	// Se indica la firma codificada en base64.
	inputParams.put(EVisorTagsRequest.ENCODED_SIGNATURE, Base64CoderCommons.encodeBase64("signB64"));

	// creación xml sin todos los parámetros obligatorios
	String inputXml = TransformersFacade.getInstance().generateXml(inputParams, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.GENERATE_REPORT_METHOD, TransformersConstants.VERSION_10);

	// validamos xml generado con todos los parámetros obligatorios.
	Assert.assertNotNull(UtilsXML.getDocumentWithXsdValidation(xsdFile, new ByteArrayInputStream(inputXml.getBytes())));

	// Se indica la firma almacenada en un repositorio
	inputParams.remove(EVisorTagsRequest.ENCODED_SIGNATURE);
	inputParams.put(EVisorTagsRequest.SIGN_REPO_REPOSITORY_ID, "repoId");
	inputParams.put(EVisorTagsRequest.SIGN_REPO_OBJECT_ID, "objectId");

	inputXml = TransformersFacade.getInstance().generateXml(inputParams, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.GENERATE_REPORT_METHOD, TransformersConstants.VERSION_10);
	Assert.assertNotNull(UtilsXML.getDocumentWithXsdValidation(xsdFile, new ByteArrayInputStream(inputXml.getBytes())));

	// Se indica la firma almacenada en un repositorio
	inputParams.remove(EVisorTagsRequest.SIGN_REPO_REPOSITORY_ID);
	inputParams.remove(EVisorTagsRequest.SIGN_REPO_OBJECT_ID);

	inputParams.put(EVisorTagsRequest.VALIDATION_RESPONSE, Base64CoderCommons.encodeBase64("VALIDATION_RESPONSE"));

	inputXml = TransformersFacade.getInstance().generateXml(inputParams, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.GENERATE_REPORT_METHOD, TransformersConstants.VERSION_10);
	Assert.assertNotNull(UtilsXML.getDocumentWithXsdValidation(xsdFile, new ByteArrayInputStream(inputXml.getBytes())));
    }

    /**
     * Tests to generate requests to <code>generateReport</code> method (a method of <code>SignatureReportService</code>) with optional parameters.
     * @throws Exception If the test fails.
     */
    @Test
    public void testGenerateReportWithOptionalParams() throws Exception {
	Map<String, Object> inputParams = new HashMap<String, Object>();
	inputParams.put(EVisorTagsRequest.APPLICATION_ID, "APPLICATION_NAME");
	inputParams.put(EVisorTagsRequest.TEMPLATE_ID, "TEMPLATE_ID");
	inputParams.put(EVisorTagsRequest.ENCODED_SIGNATURE, Base64CoderCommons.encodeBase64("signB64"));

	// parámetro srsm:IncludeSignature
	inputParams.put(EVisorTagsRequest.INCLUDE_SIGNATURE, "true");

	// parámetro srsm:Document/srsm:EncodedDocument
	inputParams.put(EVisorTagsRequest.ENCODED_DOCUMENT, Base64CoderCommons.encodeBase64("ENCODED_DOCUMENT"));

	// generamos xml
	String inputXml = TransformersFacade.getInstance().generateXml(inputParams, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.GENERATE_REPORT_METHOD, TransformersConstants.VERSION_10);

	// validamos xml generado
	Assert.assertNotNull(UtilsXML.getDocumentWithXsdValidation(xsdFile, new ByteArrayInputStream(inputXml.getBytes())));

	// eliminamos srsm:Document/srsm:EncodedDocument para probar el
	// parámetro srsm:Document/srsm:RepositoryLocation
	inputParams.remove(EVisorTagsRequest.ENCODED_DOCUMENT);

	// parámetros srsm:Document/srsm:RepositoryLocation
	inputParams.put(EVisorTagsRequest.DOC_REPO_ID, "srsm:RepositoryId");
	inputParams.put(EVisorTagsRequest.DOC_REPO_OBJECT_ID, "srsm:ObjectId");

	// parámetros srsm:Barcode
	Map<String, String> qRCodeParams = new HashMap<String, String>(3);
	qRCodeParams.put("QRCodeWidth", "600");
	qRCodeParams.put("QRCodeHeight", "600");
	qRCodeParams.put("Rotation", "90");

	// introducimos un conjunto de códigos de barra en los parámetros de
	// entrada.
	inputParams.put(EVisorTagsRequest.BARCODE, new Map<?, ?>[ ] { EVisorUtilCommons.newBarcodeMap("Prueba codigo barra tipo QRCode", "QRCode", qRCodeParams), EVisorUtilCommons.newBarcodeMap("986656487", "EAN128", null), EVisorUtilCommons.newBarcodeMap("Prueba codigo barra tipo DataMatrix", "DataMatrix", null) });
	// parámetro srsm:ExternalParameters
	Map<String, String> externalParameters = new HashMap<String, String>(2);
	externalParameters.put("externalParams1", "1111");
	externalParameters.put("externalParams2", "2222");
	inputParams.put(EVisorTagsRequest.EXTERNAL_PARAMETERS_PARAM, EVisorUtilCommons.newParameterMap(externalParameters));

	// generamos xml
	inputXml = TransformersFacade.getInstance().generateXml(inputParams, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.GENERATE_REPORT_METHOD, TransformersConstants.VERSION_10);
	// validamos xml generado
	Assert.assertNotNull(UtilsXML.getDocumentWithXsdValidation(xsdFile, new ByteArrayInputStream(inputXml.getBytes())));
    }

    /**
     * Test to generate a request to <code>validateReport</code> method (a method of <code>SignatureReportService</code>) without mandatory parameters.
     * @throws Exception If the test fails.
     */
    @Test
    public void testValidateReportWithoutMandatoryParams() throws Exception {
	Map<String, Object> inputParams = new HashMap<String, Object>();
	inputParams.put(EVisorTagsRequest.APPLICATION_ID, "");
	String inputXml = TransformersFacade.getInstance().generateXml(inputParams, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.VALIDATE_REPORT_METHOD, TransformersConstants.VERSION_10);
	UtilsXML.getDocumentWithXsdValidation(xsdFile, new ByteArrayInputStream(inputXml.getBytes()));
    }

    /**
     * Test to generate a request to <code>validateReport</code> method (a method of <code>SignatureReportService</code>) with mandatory parameters.
     * @throws Exception If the test fails.
     */
    @Test
    public void testValidateReportWithMandatoryParams() throws Exception {
	Map<String, Object> inputParams = new HashMap<String, Object>();
	inputParams.put(EVisorTagsRequest.APPLICATION_ID, "");
	inputParams.put(EVisorTagsRequest.REPORT, Base64CoderCommons.encodeBase64("REPORT"));
	String inputXml = TransformersFacade.getInstance().generateXml(inputParams, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.VALIDATE_REPORT_METHOD, TransformersConstants.VERSION_10);
	Assert.assertNotNull(UtilsXML.getDocumentWithXsdValidation(xsdFile, new ByteArrayInputStream(inputXml.getBytes())));
    }

    /**
     * Tests to generate a response from <code>generateReport</code> method.
     * @throws Exception If the test fails.
     */
    @Test
    public void testGenerateReportResponse() throws Exception {
	String xmlResponse = new String(UtilsFileSystemCommons.readFile("evisor/GenerationResponse.xml", true));
	Map<String, Object> outputParams = TransformersFacade.getInstance().parseResponse(xmlResponse, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.GENERATE_REPORT_METHOD, TransformersConstants.VERSION_10);
	Assert.assertEquals("0", outputParams.get("srsm:Result/srsm:Code"));
    }

    /**
     * Tests to generate a response from <code>validateReport</code> method.
     * @throws Exception If the test fails.
     */
    @Test
    public void testValidateReportResponse() throws Exception {
	String xmlResponse = new String(UtilsFileSystemCommons.readFile("evisor/ValidateReportResponse.xml", true));
	Map<String, Object> outputParams = TransformersFacade.getInstance().parseResponse(xmlResponse, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.VALIDATE_REPORT_METHOD, TransformersConstants.VERSION_10);
	Assert.assertEquals("0", outputParams.get("srsm:Result/srsm:Code"));
    }

}
