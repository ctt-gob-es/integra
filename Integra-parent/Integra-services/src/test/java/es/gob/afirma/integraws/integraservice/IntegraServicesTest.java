package es.gob.afirma.integraws.integraservice;

import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.junit.Test;

import es.gob.afirma.integraFacade.pojo.SignatureFormatEnum;
import es.gob.afirma.integraws.beans.RequestGetSignedData;
import es.gob.afirma.integraws.beans.RequestPAdESRubricSign;
import es.gob.afirma.integraws.beans.RequestSign;
import es.gob.afirma.integraws.beans.RequestUpgradeSign;
import es.gob.afirma.integraws.beans.RequestVerifySign;
import es.gob.afirma.integraws.beans.ResponseGetSignedData;
import es.gob.afirma.integraws.beans.ResponseSign;
import es.gob.afirma.integraws.beans.ResponseUpgradeSign;
import es.gob.afirma.integraws.beans.ResponseVerifySign;
import es.gob.afirma.integraws.beans.SignerToUpgrade;
import es.gob.afirma.integraws.ws.impl.IntegraServices;
import es.gob.afirma.utils.UtilsFileSystemCommons;

public class IntegraServicesTest extends TestCase {

	/**
	 * Constant attribute that represents the coordinate horizontal lower left of the image position.
	 */
	private static final int LOWER_LEFT_X = 200;

	/**
	 * Constant attribute that represents the coordinate vertically lower left of the image position.
	 */
	private static final int LOWER_LEFT_Y = 40;

	/**
	 * Constant attribute that represents the coordinate horizontal upper right of the image position.
	 */
	private static final int UPPER_RIGHT_X = 310;

	/**
	 * Constant attribute that represents the coordinate vertically upper right of the image position.
	 */
	private static final int UPPER_RIGHT_Y = 80;

	/**
	 * Constant attribute that represents the image to be inserted as a rubric in the PDF.
	 */
	private static final String PATH_IMAGE = "image/rubrica.png";

	/**
	 * Constant attribute that represents the PDF file name defined for tests. 
	 */
	private static final String PDF_DOCUMENT_PATH = "pdfToSignRubric.pdf";
	/**
	 * Constant attribute that represents the PDF file name defined for tests. 
	 */
	private static final String PDF_DOCUMENT_PATH_TO_COSIGN_RUBRIC = "pdfToCoSignRubric.pdf";

	@Test
	public final void testSign() {

		RequestSign request = new RequestSign();
		request.setIdClient("prueba");
		request.setAlias("raul conde");
		request.setSignatureFormat(SignatureFormatEnum.CAdES);

		byte[ ] bytearray = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);

		request.setDataToSign(bytearray);

		IntegraServices service = new IntegraServices();
		ResponseSign resp = service.generateSignature(request);

		assertTrue(resp.isIntegraSuccess());

	}

	@Test
	public final void testCoSign() {

		byte[ ] localSign;

		RequestSign requestprev = new RequestSign();
		requestprev.setIdClient("prueba");
		requestprev.setAlias("raul conde");
		requestprev.setSignatureFormat(SignatureFormatEnum.CAdES);

		byte[ ] bytearray = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);

		requestprev.setDataToSign(bytearray);

		IntegraServices service = new IntegraServices();
		ResponseSign respprev = service.generateSignature(requestprev);

		assertTrue(respprev.isIntegraSuccess());

		localSign = respprev.getSign();

		RequestSign request = new RequestSign();
		request.setIdClient("prueba");
		request.setAlias("raul conde");
		request.setSignatureFormat(SignatureFormatEnum.CAdES);

		request.setDataToSign(bytearray);
		request.setSignature(localSign);

		// IntegraServices service = new IntegraServices();
		ResponseSign resp = service.generateCoSignature(request);

		assertTrue(resp.isIntegraSuccess());
	}

	@Test
	public final void testCounterSign() {

		byte[ ] localSign;

		RequestSign requestprev = new RequestSign();
		requestprev.setIdClient("prueba");
		requestprev.setAlias("raul conde");
		requestprev.setSignatureFormat(SignatureFormatEnum.CAdES);

		byte[ ] bytearray = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);

		requestprev.setDataToSign(bytearray);

		IntegraServices service = new IntegraServices();
		ResponseSign respprev = service.generateSignature(requestprev);

		assertTrue(respprev.isIntegraSuccess());

		localSign = respprev.getSign();

		RequestSign request = new RequestSign();
		request.setIdClient("prueba");
		request.setAlias("raul conde");
		request.setSignatureFormat(SignatureFormatEnum.CAdES);

		request.setSignature(localSign);

		// IntegraServices service = new IntegraServices();
		ResponseSign resp = service.generateCounterSignature(request);

		assertTrue(resp.isIntegraSuccess());
	}

	@Test
	public final void testUpgradeSign() {

		byte[ ] localSign;

		RequestSign requestprev = new RequestSign();
		requestprev.setIdClient("prueba");
		requestprev.setAlias("raul conde");
		requestprev.setSignatureFormat(SignatureFormatEnum.CAdES);

		byte[ ] bytearray = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);

		requestprev.setDataToSign(bytearray);

		IntegraServices service = new IntegraServices();
		ResponseSign respprev = service.generateSignature(requestprev);

		assertTrue(respprev.isIntegraSuccess());

		localSign = respprev.getSign();

		RequestVerifySign requestVal = new RequestVerifySign();
		requestVal.setIdClient("prueba");

		requestVal.setSignedData(bytearray);

		requestVal.setSignature(localSign);

		// IntegraServices serviceVal = new IntegraServices();
		ResponseVerifySign respVal = service.verifySignature(requestVal);

		assertTrue(respVal.isIntegraSuccess());

		RequestUpgradeSign request = new RequestUpgradeSign();
		request.setIdClient("prueba");

		SignerToUpgrade stu = new SignerToUpgrade();
		stu.setSigner(respVal.getValidationResult().getSignersList().get(0).getSigningCertificate());

		List<SignerToUpgrade> s2u = new ArrayList<SignerToUpgrade>();
		s2u.add(stu);

		request.setListSigners(s2u);

		request.setSignature(localSign);

		ResponseUpgradeSign resp = service.upgradeSignature(request);

		assertTrue(resp.isIntegraSuccess());

	}

	@Test
	public final void testGenerateSignaturePAdESRubric() {

		RequestPAdESRubricSign request = new RequestPAdESRubricSign();

		request.setIdClient("pruebaPades");

		request.setAlias("raul conde");
		request.setIncludeSignaturePolicy(false);
		request.setIncludeTimestamp(false);

		byte[ ] bytearrayPdf = UtilsFileSystemCommons.readFile(PDF_DOCUMENT_PATH, true);

		request.setDataToSign(bytearrayPdf);

		request.setImagePage("-1");

		byte[ ] bytearrayImage = UtilsFileSystemCommons.readFile(PATH_IMAGE, true);

		request.setImage(bytearrayImage);
		request.setLowerLeftX(LOWER_LEFT_X);
		request.setLowerLeftY(LOWER_LEFT_Y);
		request.setUpperRightX(UPPER_RIGHT_X);
		request.setUpperRightY(UPPER_RIGHT_Y);

		IntegraServices service = new IntegraServices();
		ResponseSign resp = service.generateSignaturePAdESRubric(request);

		assertTrue(resp.isIntegraSuccess());

	}

	@Test
	public final void testGenerateMultiSignaturePAdESRubric() {
		RequestPAdESRubricSign request = new RequestPAdESRubricSign();

		request.setIdClient("pruebaPades");

		request.setAlias("raul conde");
		request.setIncludeSignaturePolicy(false);
		request.setIncludeTimestamp(false);

		byte[ ] bytearrayPdf = UtilsFileSystemCommons.readFile(PDF_DOCUMENT_PATH_TO_COSIGN_RUBRIC, true);

		request.setDataToSign(bytearrayPdf);

		request.setImagePage("-1");

		byte[ ] bytearrayImage = UtilsFileSystemCommons.readFile(PATH_IMAGE, true);

		request.setImage(bytearrayImage);
		request.setLowerLeftX(LOWER_LEFT_X);
		request.setLowerLeftY(LOWER_LEFT_Y);
		request.setUpperRightX(UPPER_RIGHT_X);
		request.setUpperRightY(UPPER_RIGHT_Y);

		IntegraServices service = new IntegraServices();
		ResponseSign resp = service.generateMultiSignaturePAdESRubric(request);

		assertTrue(resp.isIntegraSuccess());
	}

	@Test
	public final void testVerifySign() {

		byte[ ] localSign;

		RequestSign requestprev = new RequestSign();
		requestprev.setIdClient("prueba");
		requestprev.setAlias("raul conde");
		requestprev.setSignatureFormat(SignatureFormatEnum.CAdES);

		byte[ ] bytearray = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);

		requestprev.setDataToSign(bytearray);

		IntegraServices service = new IntegraServices();
		ResponseSign respprev = service.generateSignature(requestprev);

		assertTrue(respprev.isIntegraSuccess());

		localSign = respprev.getSign();

		RequestVerifySign request = new RequestVerifySign();
		request.setIdClient("prueba");

		request.setSignedData(bytearray);

		request.setSignature(localSign);

		// IntegraServices service = new IntegraServices();
		ResponseVerifySign resp = service.verifySignature(request);

		assertTrue(resp.isIntegraSuccess());

	}

	@Test
	public final void testGetSingedData() {

		byte[ ] localSign;

		RequestSign requestprev = new RequestSign();
		requestprev.setIdClient("prueba");
		requestprev.setAlias("raul conde");
		requestprev.setSignatureFormat(SignatureFormatEnum.CAdES);

		byte[ ] bytearray = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);

		requestprev.setDataToSign(bytearray);

		IntegraServices service = new IntegraServices();
		ResponseSign respprev = service.generateSignature(requestprev);

		assertTrue(respprev.isIntegraSuccess());

		localSign = respprev.getSign();

		RequestGetSignedData request = new RequestGetSignedData();
		request.setIdClient("prueba");

		request.setSignature(localSign);

		// IntegraServices service = new IntegraServices();
		ResponseGetSignedData resp = service.getSignedData(request);

		assertTrue(resp.isIntegraSuccess());
	}

}
