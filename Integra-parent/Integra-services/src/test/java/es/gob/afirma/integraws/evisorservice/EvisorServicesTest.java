package es.gob.afirma.integraws.evisorservice;

import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.junit.Test;

import es.gob.afirma.integraws.beans.BarcodeEvisorRequest;
import es.gob.afirma.integraws.beans.BarcodeTypeEnum;
import es.gob.afirma.integraws.beans.ParameterEvisorRequest;
import es.gob.afirma.integraws.beans.RequestEvisorGenerateReport;
import es.gob.afirma.integraws.beans.RequestEvisorValidateReport;
import es.gob.afirma.integraws.beans.ResponseEvisorGenerateReport;
import es.gob.afirma.integraws.beans.ResponseEvisorValidateReport;
import es.gob.afirma.integraws.ws.impl.EvisorServices;
import es.gob.afirma.utils.UtilsFileSystemCommons;

public class EvisorServicesTest extends TestCase {

    /**
     * Constant attribute that represents application name.
     */
    private static final String EVISOR_APPLICATION_ID = "afirmaTestEVisor";

    /**
     * Constant attribute that represents the XAdES signatures for test.
     */
    private static final String SIGNATURE_XADES = "signatures/XML/XAdES-BES.xml";
    
    private static final String TEMPLATE_ID = "pdf_escalado";
    
    @Test
    public final void testGenerateReportEvisor() {

	RequestEvisorGenerateReport request = new RequestEvisorGenerateReport();
	
	request.setApplicationId(EVISOR_APPLICATION_ID);
	request.setTemplateId(TEMPLATE_ID);
	
	byte[ ] bytearray = UtilsFileSystemCommons.readFile(SIGNATURE_XADES, true);
	request.setSignature(bytearray);
	request.setIncludeSignature("true");
	
	List<BarcodeEvisorRequest> barcodes = new ArrayList<BarcodeEvisorRequest>();
	
	List<ParameterEvisorRequest> parameters = new ArrayList<ParameterEvisorRequest>();
	ParameterEvisorRequest param1 = new ParameterEvisorRequest();
	param1.setParameterId("QRCodeWidth");
	param1.setParameterValue("600");
	parameters.add(param1);
	
	ParameterEvisorRequest param2 = new ParameterEvisorRequest();
	param2.setParameterId("QRCodeHeight");
	param2.setParameterValue("600");
	parameters.add(param2);
	
	ParameterEvisorRequest param3 = new ParameterEvisorRequest();
	param3.setParameterId("Rotation");
	param3.setParameterValue("90");
	parameters.add(param3);
	
	BarcodeEvisorRequest barcode1 = new BarcodeEvisorRequest();
	barcode1.setBarcodeMessage("Prueba código barra tipo QRCode");
	barcode1.setBarcodeType(BarcodeTypeEnum.QRCODE);
	barcode1.setConfigurationParameterList(parameters);
	barcodes.add(barcode1);
	
	BarcodeEvisorRequest barcode2 = new BarcodeEvisorRequest();
	barcode2.setBarcodeMessage("986656487");
	barcode2.setBarcodeType(BarcodeTypeEnum.EAN128);
	barcode2.setConfigurationParameterList(null);
	barcodes.add(barcode2);
	
	BarcodeEvisorRequest barcode3 = new BarcodeEvisorRequest();
	barcode3.setBarcodeMessage("Prueba código barra tipo DataMatrix");
	barcode3.setBarcodeType(BarcodeTypeEnum.DATAMATRIX);
	barcode3.setConfigurationParameterList(null);
	barcodes.add(barcode3);
	
	request.setBarcodeList(barcodes);
	
	List<ParameterEvisorRequest> externalParameters = new ArrayList<ParameterEvisorRequest>();
	ParameterEvisorRequest eParam1 = new ParameterEvisorRequest();
	eParam1.setParameterId("externalParams1");
	eParam1.setParameterValue("1111");
	ParameterEvisorRequest eParam2 = new ParameterEvisorRequest();
	eParam2.setParameterId("externalParams2");
	eParam2.setParameterValue("2222");
	
	externalParameters.add(eParam1);
	externalParameters.add(eParam2);
	request.setExternalParameterList(externalParameters);
	
	request.setIdClient("prueba");
	
	EvisorServices service = new EvisorServices();
	ResponseEvisorGenerateReport resp = service.generateReport(request);
	
	assertTrue(resp.isIntegraSuccess());
	
    }
    
    @Test
    public final void testValidateReportEvisor() {

	RequestEvisorValidateReport request = new RequestEvisorValidateReport();
	
	request.setApplicationId(EVISOR_APPLICATION_ID);
	
	byte[ ] bytearray = UtilsFileSystemCommons.readFile("reportSigned.pdf", true);
	
	request.setReport(bytearray);
	
	request.setIdClient("prueba");
	
	EvisorServices service = new EvisorServices();
	ResponseEvisorValidateReport resp = service.validateReport(request);
	
	assertTrue(resp.isIntegraSuccess());
	
    }

    
}
