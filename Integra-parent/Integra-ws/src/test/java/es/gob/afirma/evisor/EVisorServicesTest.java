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
 * <b>File:</b><p>es.gob.afirma.evisor.EVisorServicesTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for eVisor services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/04/2015.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/04/2015.
 */
package es.gob.afirma.evisor;

import java.util.HashMap;
import java.util.Map;

import junit.framework.Assert;

import org.junit.Test;

import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersFacade;
import es.gob.afirma.utils.EVisorConstants;
import es.gob.afirma.utils.EVisorConstants.EVisorTagsRequest;
import es.gob.afirma.utils.EVisorUtilCommons;
import es.gob.afirma.utils.UtilsFileSystemCommons;
import es.gob.afirma.wsServiceInvoker.EvisorServiceInvokerFacade;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerException;

/**
 * <p>Class that defines tests for eVisor services.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 10/04/2015.
 */
public class EVisorServicesTest {

    /**
     * Constant attribute that represents application name for tests.
     */
    private static final String APPLICATION_NAME = "afirmaTestEVisor";

    /**
     * Constant attribute that represents template identifier.
     */
    private static final String TEMPLATE_ID = "pdf_escalado";

    /**
     * Tests for <code>generateReport</code> method of <code>SignatureReportService</code> with invalid values (null values, service or method
     * not exist, etc.).
     * @throws Exception If the tests fails.
     */
    @Test
    public void testGenerateReportInvalidValues() throws Exception {

	// interfaz de entrada xml no válida
	try {
	    EvisorServiceInvokerFacade.getInstance().invokeService("<srsm:GenerationRequest />", EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.GENERATE_REPORT_METHOD, APPLICATION_NAME);
	    Assert.fail();
	} catch (WSServiceInvokerException e) {}

	// método y servicio no existente
	try {
	    EvisorServiceInvokerFacade.getInstance().invokeService("<srsm:GenerationRequest />", "service", "method", APPLICATION_NAME);
	    Assert.fail();
	} catch (WSServiceInvokerException e) {}

	// aplicación no existente en EVisor
	try {
	    EvisorServiceInvokerFacade.getInstance().invokeService("<?xml version='1.0' encoding='UTF-8'?><srsm:GenerationRequest xmlns:srsm='urn:es:gob:signaturereport:services:messages' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'><srsm:ApplicationId>tgs.nvm1</srsm:ApplicationId><srsm:TemplateId>template_test</srsm:TemplateId><srsm:Signature><srsm:EncodedSignature>JVBERi0xL</srsm:EncodedSignature></srsm:Signature></srsm:GenerationRequest>", EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.GENERATE_REPORT_METHOD, APPLICATION_NAME);
	    Assert.fail();
	} catch (WSServiceInvokerException e) {}

    }

    /**
     * Test for <code>generateReport</code> method of <code>SignatureReportService</code> with a valid value.
     * @throws Exception If the test fails.
     */
    @Test
    public void testGenerateReport() throws Exception {

	Map<String, Object> inputParams = new HashMap<String, Object>();

	String signB64 = UtilsFileSystemCommons.readFileBase64Encoded("evisor/PADES_Signature.pdf", true);

	inputParams.put(EVisorTagsRequest.APPLICATION_ID, APPLICATION_NAME);
	inputParams.put(EVisorTagsRequest.TEMPLATE_ID, TEMPLATE_ID);
	inputParams.put(EVisorTagsRequest.ENCODED_SIGNATURE, signB64);

	inputParams.put(EVisorTagsRequest.INCLUDE_SIGNATURE, "true");

	Map<String, String> qRCodeParams = new HashMap<String, String>(2);
	qRCodeParams.put("QRCodeWidth", "600");
	qRCodeParams.put("QRCodeHeight", "600");
	qRCodeParams.put("Rotation", "90");

	// introducimos un conjunto de códigos de barra en los parámetros de
	// entrada.
	inputParams.put(EVisorTagsRequest.BARCODE, new Map<?, ?>[ ] { EVisorUtilCommons.newBarcodeMap("Prueba código barra tipo QRCode", "QRCode", qRCodeParams), EVisorUtilCommons.newBarcodeMap("986656487", "EAN128", null), EVisorUtilCommons.newBarcodeMap("Prueba código barra tipo DataMatrix", "DataMatrix", null) });

	String inputXml = TransformersFacade.getInstance().generateXml(inputParams, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.GENERATE_REPORT_METHOD, TransformersConstants.VERSION_10);

	String outputXml = EvisorServiceInvokerFacade.getInstance().invokeService(inputXml, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.GENERATE_REPORT_METHOD, APPLICATION_NAME);

	Map<String, Object> result = TransformersFacade.getInstance().parseResponse(outputXml, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.GENERATE_REPORT_METHOD, TransformersConstants.VERSION_10);

	// Assert.assertEquals("0", result.get("srsm:Result/srsm:Code"));

	if (!"0".equals(result.get("srsm:Result/srsm:Code")) && !"5".equals(result.get("srsm:Result/srsm:Code"))) {
	    Assert.fail();
	}

    }

    /**
     * Tests for <code>validateReport</code> method of <code>SignatureReportService</code> with invalid values
     * (input XML message not valid, service or method not exist, etc.).
     * @throws Exception If the test fails.
     */
    @Test
    public void testValidateReportInvalidValues() throws Exception {

	// interfaz de entrada xml no válida
	try {
	    EvisorServiceInvokerFacade.getInstance().invokeService("<srsm:ValidationReportRequest />", EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.VALIDATE_REPORT_METHOD, APPLICATION_NAME);
	    Assert.fail();
	} catch (WSServiceInvokerException e) {}

	// método no existente
	try {
	    EvisorServiceInvokerFacade.getInstance().invokeService("<srsm:ValidationReportRequest />", EVisorConstants.SIGNATURE_REPORT_SERVICE, "method", APPLICATION_NAME);
	    Assert.fail();
	} catch (WSServiceInvokerException e) {}

	// aplicación no existente en EVisor
	try {
	    EvisorServiceInvokerFacade.getInstance().invokeService("<?xml version='1.0' encoding='UTF-8'?><srsm:ValidationReportRequest xmlns:srsm='urn:es:gob:signaturereport:services:messages' 	xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'><srsm:ApplicationId>asddd</srsm:ApplicationId><srsm:Report /></srsm:ValidationReportRequest>", EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.VALIDATE_REPORT_METHOD, APPLICATION_NAME);
	    Assert.fail();
	} catch (WSServiceInvokerException e) {}

    }

    /**
     * Tests for <code>validateReport</code> method of <code>SignatureReportService</code> with a valid value.
     * @throws Exception If the test fails.
     */
    @Test
    public void testValidateReport() throws Exception {
	Map<String, Object> inputParams = new HashMap<String, Object>();

	String evisorReport = UtilsFileSystemCommons.readFileBase64Encoded("evisor/reportSigned.pdf", true);

	inputParams.put(EVisorTagsRequest.APPLICATION_ID, APPLICATION_NAME);
	inputParams.put(EVisorTagsRequest.REPORT, evisorReport);

	String inputXml = TransformersFacade.getInstance().generateXml(inputParams, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.VALIDATE_REPORT_METHOD, TransformersConstants.VERSION_10);

	String outputXml = EvisorServiceInvokerFacade.getInstance().invokeService(inputXml, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.VALIDATE_REPORT_METHOD, APPLICATION_NAME);

	Map<String, Object> result = TransformersFacade.getInstance().parseResponse(outputXml, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.VALIDATE_REPORT_METHOD, TransformersConstants.VERSION_10);

	// Assert.assertEquals("0", result.get("srsm:Result/srsm:Code"));

	if (!"0".equals(result.get("srsm:Result/srsm:Code")) && !"105".equals(result.get("srsm:Result/srsm:Code"))) {
	    Assert.fail();
	}
    }

}
