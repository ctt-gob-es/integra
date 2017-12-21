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
 * <b>File:</b><p>es.gob.afirma.integraWSFacade.IntegraFacadeWSDSSTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for {@link IntegraFacadeWSDSS}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/04/2015.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/04/2015.
 */
package es.gob.afirma.integraWSFacade;

import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.junit.Test;
import org.junit.runner.RunWith;

import es.gob.afirma.general.SorterRunner;
import es.gob.afirma.integraFacade.IntegraFacadeWSDSS;
import es.gob.afirma.integraFacade.pojo.ArchiveRequest;
import es.gob.afirma.integraFacade.pojo.ArchiveResponse;
import es.gob.afirma.integraFacade.pojo.BatchVerifyCertificateRequest;
import es.gob.afirma.integraFacade.pojo.BatchVerifyCertificateResponse;
import es.gob.afirma.integraFacade.pojo.CoSignRequest;
import es.gob.afirma.integraFacade.pojo.CounterSignRequest;
import es.gob.afirma.integraFacade.pojo.DetailLevelEnum;
import es.gob.afirma.integraFacade.pojo.HashAlgorithmEnum;
import es.gob.afirma.integraFacade.pojo.OptionalParameters;
import es.gob.afirma.integraFacade.pojo.ServerSignerRequest;
import es.gob.afirma.integraFacade.pojo.ServerSignerResponse;
import es.gob.afirma.integraFacade.pojo.SignatureFormatEnum;
import es.gob.afirma.integraFacade.pojo.UpgradeSignatureRequest;
import es.gob.afirma.integraFacade.pojo.VerificationReport;
import es.gob.afirma.integraFacade.pojo.VerifyCertificateRequest;
import es.gob.afirma.integraFacade.pojo.VerifyCertificateResponse;
import es.gob.afirma.integraFacade.pojo.VerifySignatureRequest;
import es.gob.afirma.integraFacade.pojo.VerifySignatureResponse;
import es.gob.afirma.utils.UtilsFileSystemCommons;

/**
 * <p>Class that defines tests for {@link IntegraFacadeWSDSS}.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 10/04/2015.
 */
@RunWith(SorterRunner.class)
public class IntegraFacadeWSDSSTest extends TestCase {

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

    /**
     * Test for {@link IntegraFacadeWSDSS#sign(ServerSignerRequest)}.
     * @throws Exception If the test fails.
     */
    @Test
    public final void testSign() throws Exception {

	ServerSignerRequest serSigReq = new ServerSignerRequest();

	byte[ ] documentB64 = UtilsFileSystemCommons.getArrayByteFileBase64Encoded("ficheroAfirmar.txt", true);
	serSigReq.setDocument(documentB64);

	serSigReq.setKeySelector(SERVER_SIGNER_NAME);
	serSigReq.setApplicationId(APPLICATION_NAME);
	serSigReq.setSignatureFormat(SignatureFormatEnum.CAdES);
	serSigReq.setIgnoreGracePeriod(false);
	ServerSignerResponse serSigRes = IntegraFacadeWSDSS.getInstance().sign(serSigReq);

	System.out.println("SersigRes asyncResponse: " + serSigRes.getAsyncResponse());
	System.out.println("SersigRes transactionId: " + serSigRes.getTransactionId());
	System.out.println("SersigRes signatureFormat: " + serSigRes.getSignatureFormat());
	if (serSigRes.getResult() != null) {
	    if (!"urn:oasis:names:tc:dss:1.0:resultmajor:Success".equals(serSigRes.getResult().getResultMajor())) {
		assertTrue(false);
	    }
	    System.out.println("SersigRes Result major: " + serSigRes.getResult().getResultMajor());
	    System.out.println("SersigRes REsult minor: " + serSigRes.getResult().getResultMinor());
	    System.out.println("SersigRes REsult message: " + serSigRes.getResult().getResultMessage());
	} else {
	    assertTrue(false);
	}
	if (serSigRes.getSignature() != null) {
	    System.out.println("signature: " + serSigRes.getSignature().toString());
	}
	if (serSigRes.getUpdatedSignature() != null) {
	    System.out.println("updated Signature: " + serSigRes.getUpdatedSignature().toString());
	}

    }

    /**
     * Test for {@link IntegraFacadeWSDSS#coSign(CoSignRequest)}.
     * @throws Exception If the test fails.
     */
    @Test
    public final void testCoSign() throws Exception {

	String idTransaction = "145346464856296185";
	CoSignRequest coSigReq = new CoSignRequest();
	coSigReq.setTransactionId(idTransaction);
	coSigReq.setKeySelector(SERVER_SIGNER_NAME);
	coSigReq.setApplicationId(APPLICATION_NAME);
	coSigReq.setHashAlgorithm(HashAlgorithmEnum.SHA1);

	ServerSignerResponse ssr = IntegraFacadeWSDSS.getInstance().coSign(coSigReq);

	if (!"urn:oasis:names:tc:dss:1.0:resultmajor:Success".equals(ssr.getResult().getResultMajor())) {
	    assertTrue(false);
	}

    }

    /**
     * Test for {@link IntegraFacadeWSDSS#counterSign(CounterSignRequest)}.
     * @throws Exception If the test fails.
     */
    @Test
    public final void testCounterSign() throws Exception {

	String idTransaction = "145346464856296185";
	CounterSignRequest couSigReq = new CounterSignRequest();
	couSigReq.setTransactionId(idTransaction);
	couSigReq.setKeySelector(SERVER_SIGNER_NAME);
	couSigReq.setApplicationId(APPLICATION_NAME);
	couSigReq.setHashAlgorithm(HashAlgorithmEnum.SHA1);

	ServerSignerResponse ssr = IntegraFacadeWSDSS.getInstance().counterSign(couSigReq);

	if (!"urn:oasis:names:tc:dss:1.0:resultmajor:Success".equals(ssr.getResult().getResultMajor())) {
	    assertTrue(false);
	}

    }

    /**
     * Test for {@link IntegraFacadeWSDSS#verifySignature(VerifySignatureRequest)}.
     * @throws Exception If the test fails.
     */
    @Test
    public void testVerifySignature() throws Exception {

	VerifySignatureRequest verSigReq = new VerifySignatureRequest();
	verSigReq.setApplicationId(APPLICATION_NAME);

	byte[ ] signB64 = UtilsFileSystemCommons.readFile(SIGNATURE_XADES, true);
	verSigReq.setSignature(signB64);

	OptionalParameters optParam = new OptionalParameters();
	optParam.setReturnProcessingDetails(true);
	optParam.setReturnReadableCertificateInfo(true);
	verSigReq.setOptionalParameters(optParam);

	VerificationReport verRep = new VerificationReport();
	verRep.setReportDetailLevel(DetailLevelEnum.ALL_DETAILS);
	verRep.setIncludeRevocationValues(true);
	verRep.setIncludeCertificateValues(true);

	verSigReq.setVerificationReport(verRep);

	VerifySignatureResponse vsr = IntegraFacadeWSDSS.getInstance().verifySignature(verSigReq);

	if (!"urn:afirma:dss:1.0:profile:XSS:resultmajor:ValidSignature".equals(vsr.getResult().getResultMajor())) {
	    assertTrue(false);
	}

    }

    /**
     * Test for {@link IntegraFacadeWSDSS#upgradeSignature(UpgradeSignatureRequest)}.
     * @throws Exception If the test fails.
     */
    @Test
    public void testUpgradeSignature() throws Exception {
	UpgradeSignatureRequest upgSigReq = new UpgradeSignatureRequest();
	// firma sin codificar
	byte[ ] signature = UtilsFileSystemCommons.readFile(SIGNATURE_XADES, true);

	upgSigReq.setSignature(signature);
	upgSigReq.setApplicationId(APPLICATION_NAME);
	upgSigReq.setSignatureFormat(SignatureFormatEnum.XAdES_T);

	ServerSignerResponse serSigRes = IntegraFacadeWSDSS.getInstance().upgradeSignature(upgSigReq);

	System.out.println("Resultado:");
	if (serSigRes != null) {
	    if (!"urn:oasis:names:tc:dss:1.0:resultmajor:Success".equals(serSigRes.getResult().getResultMajor())) {
		assertTrue(false);
	    }
	    System.out.println("serSigRes.asyncResponse():" + serSigRes.getAsyncResponse());
	    System.out.println("serSigRes.idTransaction:" + serSigRes.getTransactionId());
	    System.out.println("serSigRes.signatureFormat:" + serSigRes.getSignatureFormat());
	    if (serSigRes.getSignature() != null) {
		System.out.println("serSigRes.signature:" + serSigRes.getSignature().toString());
	    }
	    if (serSigRes.getUpdatedSignature() != null) {
		System.out.println("serSigRes.updatedSignature:" + serSigRes.getUpdatedSignature().toString());
	    }

	} else {
	    assertTrue(false);
	}

    }

    /**
     * Test for {@link IntegraFacadeWSDSS#verifyCertificate(VerifyCertificateRequest)}.
     * @throws Exception If the test fails.
     */
    @Test
    public void testVerifyCertificate() throws Exception {
	VerifyCertificateRequest verCerReq = new VerifyCertificateRequest();

	verCerReq.setApplicationId(APPLICATION_NAME);
	byte[ ] certificate = UtilsFileSystemCommons.readFile(CERTIFICATE_NAME, true);
	verCerReq.setCertificate(certificate);
	verCerReq.setReturnReadableCertificateInfo(true);
	VerificationReport verRep = new VerificationReport();
	verRep.setIncludeCertificateValues(true);
	verRep.setCheckCertificateStatus(true);
	verRep.setIncludeRevocationValues(true);
	verRep.setReportDetailLevel(DetailLevelEnum.ALL_DETAILS);
	verCerReq.setReturnVerificationReport(verRep);
	VerifyCertificateResponse verCerRes = IntegraFacadeWSDSS.getInstance().verifyCertificate(verCerReq);
	System.out.println("Resultado:");

	if (verCerRes.getCertificatePathValidity() != null) {
	    if (!"urn:oasis:names:tc:dss:1.0:resultmajor:Success".equals(verCerRes.getResult().getResultMajor())) {
		assertTrue(false);
	    }
	    System.out.println("certificatePathValidity.detail:" + verCerRes.getCertificatePathValidity().getDetail());
	    System.out.println("certificatePathValidity.identifier:" + verCerRes.getCertificatePathValidity().getIdentifier());
	    System.out.println("certificatePathValidity.summary:" + verCerRes.getCertificatePathValidity().getSummary());
	} else {
	    assertTrue(false);
	}

	if (verCerRes.getReadableCertificateInfo() != null) {
	    for (String key: verCerRes.getReadableCertificateInfo().keySet()) {
		System.out.println(key + "--" + verCerRes.getReadableCertificateInfo().get(key));
	    }
	}
	System.out.println("Result Major:" + verCerRes.getResult().getResultMajor());
	System.out.println("Result Minor:" + verCerRes.getResult().getResultMinor());
	System.out.println("Result Message:" + verCerRes.getResult().getResultMessage());
    }

    /**
     * Test for {@link IntegraFacadeWSDSS#batchVerifyCertificate(BatchVerifyCertificateRequest)}.
     * @throws Exception If the test fails.
     */
    @Test
    public void testBatchVerifyCertificate() throws Exception {
	// certificado1
	VerifyCertificateRequest verCerReq = new VerifyCertificateRequest();
	verCerReq.setApplicationId(APPLICATION_NAME);
	byte[ ] certificate = UtilsFileSystemCommons.readFile(CERTIFICATE_NAME, true);
	verCerReq.setCertificate(certificate);
	verCerReq.setReturnReadableCertificateInfo(true);
	VerificationReport verRep = new VerificationReport();
	verRep.setIncludeCertificateValues(true);
	verRep.setCheckCertificateStatus(true);
	verRep.setIncludeRevocationValues(true);
	verRep.setReportDetailLevel(DetailLevelEnum.ALL_DETAILS);
	verCerReq.setReturnVerificationReport(verRep);

	// Certificado2
	VerifyCertificateRequest verCerReq2 = new VerifyCertificateRequest();
	verCerReq2.setApplicationId(APPLICATION_NAME);
	byte[ ] certificate2 = UtilsFileSystemCommons.readFile(CERTIFICATE_NAME, true);
	verCerReq2.setCertificate(certificate2);
	verCerReq2.setReturnReadableCertificateInfo(true);
	VerificationReport verRep2 = new VerificationReport();
	verRep2.setIncludeCertificateValues(true);
	verRep2.setCheckCertificateStatus(true);
	verRep2.setIncludeRevocationValues(false);
	verRep2.setReportDetailLevel(DetailLevelEnum.ALL_DETAILS);
	verCerReq2.setReturnVerificationReport(verRep2);

	BatchVerifyCertificateRequest batch = new BatchVerifyCertificateRequest();
	List<VerifyCertificateRequest> listCertificates = new ArrayList<VerifyCertificateRequest>();
	listCertificates.add(verCerReq);
	listCertificates.add(verCerReq2);

	batch.setListVerifyCertificate(listCertificates);

	batch.setApplicationId(APPLICATION_NAME);

	BatchVerifyCertificateResponse response = IntegraFacadeWSDSS.getInstance().batchVerifyCertificate(batch);

	if (response != null) {

	    System.out.println("datos verifyCertificateResponse*******");
	    System.out.println("asyncResponse:" + response.getAsyncResponse());
	    if (response.getResult() != null) {
		if (!"urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing:resultmajor:Pending".equals(response.getResult().getResultMajor())) {
		    assertTrue(false);
		}
		System.out.println("result major:" + response.getResult().getResultMajor());
		System.out.println("result minor:" + response.getResult().getResultMinor());
		System.out.println("result message:" + response.getResult().getResultMessage());
	    } else {
		assertTrue(false);
	    }
	    if (response.getListVerifyResponse() != null && !response.getListVerifyResponse().isEmpty()) {
		for (VerifyCertificateResponse res: response.getListVerifyResponse()) {

		    if (res.getCertificatePathValidity() != null) {
			System.out.println("certificatePathValidity.detail:" + res.getCertificatePathValidity().getDetail());
			System.out.println("certificatePathValidity.identifier:" + res.getCertificatePathValidity().getIdentifier());
			System.out.println("certificatePathValidity.summary:" + res.getCertificatePathValidity().getSummary());
		    }

		    if (res.getReadableCertificateInfo() != null) {
			for (String key: res.getReadableCertificateInfo().keySet()) {
			    System.out.println(key + "--" + res.getReadableCertificateInfo().get(key));
			}
		    }
		    System.out.println("Result Major indiv:" + res.getResult().getResultMajor());
		    System.out.println("Result Minor indiv:" + res.getResult().getResultMinor());
		    System.out.println("Result Message indiv:" + res.getResult().getResultMessage());
		}

	    }
	} else {
	    assertTrue(false);
	}

    }

    /**
     * Test for {@link IntegraFacadeWSDSS#getArchiveRetrieval(ArchiveRequest)}.
     * @throws Exception If the test fails.
     */
    @Test
    public void testGetArchiveRetrieval() throws Exception {
	String transactionId = "145370857263893101";
	ArchiveRequest archiveRequest = new ArchiveRequest();
	archiveRequest.setApplicationId(APPLICATION_NAME);
	archiveRequest.setTransactionId(transactionId);

	ArchiveResponse archiveResponse = IntegraFacadeWSDSS.getInstance().getArchiveRetrieval(archiveRequest);

	if (archiveResponse != null) {
	    System.out.println("Datos ArchiverRetrieval");
	    if (archiveResponse.getResult() != null) {
		if (!"urn:oasis:names:tc:dss:1.0:resultmajor:Success".equals(archiveResponse.getResult().getResultMajor())) {
		    assertTrue(false);
		}
		System.out.println("result major:" + archiveResponse.getResult().getResultMajor());
		System.out.println("result minor:" + archiveResponse.getResult().getResultMinor());
		System.out.println("result message:" + archiveResponse.getResult().getResultMessage());
	    } else {
		assertTrue(false);
	    }

	    if (archiveResponse.getSignature() != null) {
		System.out.println("signature:" + archiveResponse.getSignature().toString());
	    }
	}

    }
}