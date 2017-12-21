package es.gob.afirma.integraws.afirmaservice;

import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.junit.Test;

import es.gob.afirma.integraFacade.pojo.DetailLevelEnum;
import es.gob.afirma.integraFacade.pojo.HashAlgorithmEnum;
import es.gob.afirma.integraFacade.pojo.OptionalParameters;
import es.gob.afirma.integraFacade.pojo.SignatureFormatEnum;
import es.gob.afirma.integraFacade.pojo.VerificationReport;
import es.gob.afirma.integraFacade.pojo.VerifyCertificateRequest;
import es.gob.afirma.integraFacade.pojo.VerifySignatureRequest;
import es.gob.afirma.integraws.beans.RequestServerArchive;
import es.gob.afirma.integraws.beans.RequestServerBatchVerifyCertificate;
import es.gob.afirma.integraws.beans.RequestServerBatchVerifySignature;
import es.gob.afirma.integraws.beans.RequestServerCoSign;
import es.gob.afirma.integraws.beans.RequestServerCounterSign;
import es.gob.afirma.integraws.beans.RequestServerPending;
import es.gob.afirma.integraws.beans.RequestServerSign;
import es.gob.afirma.integraws.beans.RequestServerUpgradeSignature;
import es.gob.afirma.integraws.beans.RequestServerVerifyCertificate;
import es.gob.afirma.integraws.beans.RequestServerVerifySignature;
import es.gob.afirma.integraws.beans.RequestValidateOCSP;
import es.gob.afirma.integraws.beans.ResponseServerArchive;
import es.gob.afirma.integraws.beans.ResponseServerAsynchronous;
import es.gob.afirma.integraws.beans.ResponseServerBatchVerifyCertificate;
import es.gob.afirma.integraws.beans.ResponseServerBatchVerifySignature;
import es.gob.afirma.integraws.beans.ResponseServerSign;
import es.gob.afirma.integraws.beans.ResponseServerVerifyCertificate;
import es.gob.afirma.integraws.beans.ResponseServerVerifySignature;
import es.gob.afirma.integraws.beans.ResponseValidateOCSP;
import es.gob.afirma.integraws.ws.impl.AfirmaServices;
import es.gob.afirma.utils.UtilsFileSystemCommons;

public class AfirmaServicesTest extends TestCase {

    /**
     * Constant attribute that represents application name.
     */
    private static final String APPLICATION_NAME = "afirmaTest";

    /**
     * Constant attribute that represents the certificate file name.
     */
    private static final String CERTIFICATE_NAME = "confianzaocsp.crt";

    /**
     * Constant attribute that represents the certificate name.
     */
    private static final String SERVER_SIGNER_NAME = "raul conde";

    /**
     * Constant attribute that represents the XAdES signatures for test.
     */
    private static final String SIGNATURE_XADES = "signatures/XML/XAdES-BES.xml";

    
    @Test
    public final void testServerSign() throws Exception {
	RequestServerSign request = new RequestServerSign();
	
	byte[ ] bytearray = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);

	request.setKeySelector(SERVER_SIGNER_NAME);
	request.setApplicationId(APPLICATION_NAME);
	request.setDocument(bytearray);
	request.setIdClient("prueba");
	
	AfirmaServices service = new AfirmaServices();
	ResponseServerSign resp = service.serverSign(request);
	
	assertTrue(resp.isIntegraSuccess());
	
	
    }

    @Test
    public final void testServerCoSign() {
	
	RequestServerCoSign request = new RequestServerCoSign();

	String idTransaction = "145346464856296185";

	request.setTransactionId(idTransaction);
	request.setKeySelector(SERVER_SIGNER_NAME);
	request.setApplicationId(APPLICATION_NAME);
	request.setHashAlgorithm(HashAlgorithmEnum.SHA1);
	request.setIdClient("prueba");

	AfirmaServices service = new AfirmaServices();
	ResponseServerSign resp = service.serverCoSign(request);
	
	assertTrue(resp.isIntegraSuccess());
    }
    
    @Test
    public final void testServerCounterSign() {
	
	RequestServerCounterSign request = new RequestServerCounterSign();

	String idTransaction = "145346464856296185";

	request.setTransactionId(idTransaction);
	request.setKeySelector(SERVER_SIGNER_NAME);
	request.setApplicationId(APPLICATION_NAME);
	request.setHashAlgorithm(HashAlgorithmEnum.SHA1);
	request.setIdClient("prueba");

	AfirmaServices service = new AfirmaServices();
	ResponseServerSign resp = service.serverCounterSign(request);
	
	assertTrue(resp.isIntegraSuccess());
    }
    
    @Test
    public final void testVerifyCertificate() {

	RequestServerVerifyCertificate request = new RequestServerVerifyCertificate();

	request.setApplicationId(APPLICATION_NAME);
	
	byte[ ] bytearray = UtilsFileSystemCommons.readFile(CERTIFICATE_NAME, true);

	request.setCertificate(bytearray);
	request.setReturnReadableCertificateInfo(true);
	VerificationReport verRep = new VerificationReport();
	verRep.setIncludeCertificateValues(true);
	verRep.setCheckCertificateStatus(true);
	verRep.setIncludeRevocationValues(true);
	verRep.setReportDetailLevel(DetailLevelEnum.ALL_DETAILS);

	request.setReturnVerificationReport(verRep);
	request.setIdClient("prueba");

	AfirmaServices service = new AfirmaServices();
	ResponseServerVerifyCertificate resp = service.serverVerifyCertificate(request);
	
	assertTrue(resp.isIntegraSuccess());

    }

    @Test
    public final void testVerifySignature() {
	
	RequestServerVerifySignature request = new RequestServerVerifySignature();

	request.setApplicationId(APPLICATION_NAME);

	byte[ ] bytearray = UtilsFileSystemCommons.readFile(SIGNATURE_XADES, true);

	request.setSignature(bytearray);

	OptionalParameters optParam = new OptionalParameters();
	optParam.setReturnProcessingDetails(true);
	optParam.setReturnReadableCertificateInfo(true);

	request.setOptionalParameters(optParam);

	VerificationReport verRep = new VerificationReport();
	verRep.setReportDetailLevel(DetailLevelEnum.ALL_DETAILS);
	verRep.setIncludeRevocationValues(true);
	verRep.setIncludeCertificateValues(true);

	request.setVerificationReport(verRep);
	request.setIdClient("prueba");

	AfirmaServices service = new AfirmaServices();
	ResponseServerVerifySignature resp = service.serverVerifySignature(request);
	
	assertTrue(resp.isIntegraSuccess());

    }

    @Test
    public final void testGetArchiveRetrieval() {
	
	RequestServerArchive request = new RequestServerArchive();
	String transactionId = "145370857263893101";
	request.setTransactionId(transactionId);
	request.setApplicationId(APPLICATION_NAME);
	request.setIdClient("prueba");

	AfirmaServices service = new AfirmaServices();
	ResponseServerArchive resp = service.serverGetArchiveRetrieval(request);
	
	assertTrue(resp.isIntegraSuccess());

    }

    @Test
    public final void testBatchVerifySignature() {
	
	RequestServerBatchVerifySignature request = new RequestServerBatchVerifySignature();
	request.setApplicationId(APPLICATION_NAME);
	request.setIdClient("prueba");

	// signature1
	VerifySignatureRequest verSigReq = new VerifySignatureRequest();
	verSigReq.setApplicationId(APPLICATION_NAME);

	byte[ ] bytearray = UtilsFileSystemCommons.readFile(SIGNATURE_XADES, true);

	verSigReq.setSignature(bytearray);

	VerificationReport verRep = new VerificationReport();
	verRep.setIncludeCertificateValues(true);
	verRep.setCheckCertificateStatus(true);
	verRep.setIncludeRevocationValues(true);
	verRep.setReportDetailLevel(DetailLevelEnum.ALL_DETAILS);
	verSigReq.setVerificationReport(verRep);

	// signature2
	VerifySignatureRequest verSigReq2 = new VerifySignatureRequest();
	verSigReq2.setApplicationId(APPLICATION_NAME);

	byte[ ] bytearray2 = UtilsFileSystemCommons.readFile(SIGNATURE_XADES, true);
	verSigReq2.setSignature(bytearray2);

	VerificationReport verRep2 = new VerificationReport();
	verRep2.setIncludeCertificateValues(true);
	verRep2.setCheckCertificateStatus(true);
	verRep2.setIncludeRevocationValues(true);
	verRep2.setReportDetailLevel(DetailLevelEnum.ALL_DETAILS);
	verSigReq2.setVerificationReport(verRep2);

	// Se añaden a la petición
	List<VerifySignatureRequest> listCertificates = new ArrayList<VerifySignatureRequest>();
	listCertificates.add(verSigReq);
	listCertificates.add(verSigReq2);

	request.setListVerifySignature(listCertificates);

	request.setApplicationId(APPLICATION_NAME);
	request.setIdClient("prueba");

	AfirmaServices service = new AfirmaServices();
	ResponseServerBatchVerifySignature resp = service.serverBatchVerifySignature(request);
	
	assertTrue(resp.isIntegraSuccess());
    }

    @Test
    public final void testBatchVerifyCertificate() {

	RequestServerBatchVerifyCertificate request = new RequestServerBatchVerifyCertificate();

	// certificado1
	VerifyCertificateRequest verCerReq = new VerifyCertificateRequest();
	verCerReq.setApplicationId(APPLICATION_NAME);

	byte[ ] bytearray = UtilsFileSystemCommons.readFile(CERTIFICATE_NAME, true);
	
	verCerReq.setCertificate(bytearray);
	verCerReq.setReturnReadableCertificateInfo(true);

	VerificationReport verRep = new VerificationReport();
	verRep.setIncludeCertificateValues(true);
	verRep.setCheckCertificateStatus(true);
	verRep.setIncludeRevocationValues(true);
	verRep.setReportDetailLevel(DetailLevelEnum.ALL_DETAILS);
	verCerReq.setReturnVerificationReport(verRep);

	// certificado2
	VerifyCertificateRequest verCerReq2 = new VerifyCertificateRequest();
	verCerReq2.setApplicationId(APPLICATION_NAME);

	verCerReq2.setCertificate(bytearray);
	verCerReq2.setReturnReadableCertificateInfo(true);

	VerificationReport verRep2 = new VerificationReport();
	verRep2.setIncludeCertificateValues(true);
	verRep2.setCheckCertificateStatus(true);
	verRep2.setIncludeRevocationValues(true);
	verRep2.setReportDetailLevel(DetailLevelEnum.ALL_DETAILS);
	verCerReq2.setReturnVerificationReport(verRep2);

	// Se añaden a la petición
	List<VerifyCertificateRequest> listCertificates = new ArrayList<VerifyCertificateRequest>();
	listCertificates.add(verCerReq);
	listCertificates.add(verCerReq2);
	

	request.setListVerifyCertificate(listCertificates);
	request.setApplicationId(APPLICATION_NAME);
	request.setIdClient("prueba");

	AfirmaServices service = new AfirmaServices();
	ResponseServerBatchVerifyCertificate resp = service.serverBatchVerifyCertificate(request);
	
	assertTrue(resp.isIntegraSuccess());
    }

    @Test
    public final void testUpgradeSignature() {
	
	RequestServerUpgradeSignature request = new RequestServerUpgradeSignature();

	byte[ ] bytearray = UtilsFileSystemCommons.readFile(SIGNATURE_XADES, true);

	request.setSignature(bytearray);
	request.setApplicationId(APPLICATION_NAME);
	request.setSignatureFormat(SignatureFormatEnum.XAdES_T);
	request.setIdClient("prueba");

	AfirmaServices service = new AfirmaServices();
	ResponseServerSign resp = service.serverUpgradeSignature(request);
	
	assertTrue(resp.isIntegraSuccess());

    }

    @Test
    public final void testAsynchronousRequest() {
	
	RequestServerPending request = new RequestServerPending();
	request.setApplicationId(APPLICATION_NAME);
	request.setIdClient("prueba");
	request.setResponseId("123456789");

	AfirmaServices service = new AfirmaServices();
	ResponseServerAsynchronous resp = service.serverAsynchronousRequest(request);
	
	assertTrue(resp.isIntegraSuccess());
    }

    @Test
    public final void testValidateOCSP() {
	
	RequestValidateOCSP request = new RequestValidateOCSP();

	// Set place a nickname in the request
	request.setIdClient("prueba");
	byte[ ] bytearray = UtilsFileSystemCommons.readFile(CERTIFICATE_NAME, true);

	request.setCertificate(bytearray);
	
	AfirmaServices service = new AfirmaServices();
	ResponseValidateOCSP resp = service.serverValidateCertificateOcsp(request);
	
	assertTrue(resp.isIntegraSuccess());

    }
}
