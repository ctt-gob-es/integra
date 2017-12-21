// Copyright (C) 2017 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.signature.pades.PAdESBaselineSignerTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for {@link PAdESBaselineSigner}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>25/01/2016.</p>
 * @author Gobierno de España.
 * @version 1.2, 14/03/2017.
 */
package es.gob.afirma.signature.pades;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.Security;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.codec.Base64;

import es.gob.afirma.signature.AbstractSignatureTest;
import es.gob.afirma.signature.ISignatureFormatDetector;
import es.gob.afirma.signature.OriginalSignedData;
import es.gob.afirma.signature.SignatureConstants;
import es.gob.afirma.signature.SignatureFormatDetector;
import es.gob.afirma.signature.SignatureFormatDetectorCadesPades;
import es.gob.afirma.signature.SignatureProperties;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.signature.validation.PDFValidationResult;
import es.gob.afirma.signature.validation.ValidationResult;
import es.gob.afirma.utils.UtilsFileSystemCommons;

/**
 * <p>Class that defines tests for {@link PAdESBaselineSigner}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 14/03/2017.
 */
public class PAdESBaselineSignerTest extends AbstractSignatureTest {

    /**
     * Constant attribute that represents the message which identifies an exception isn't thrown. 
     */
    protected static final String ERROR_EXCEPTION_NOT_THROWED = "No se ha lanzado la excepción esperada";

    /**
     * Constant attribute that represents the image to be inserted as a rubric in the PDF.
     */
    private static final String PATH_IMAGE = "src/test/resources/image/rubrica.png";

    /**
     * Constant attribute that represents the image to be inserted as a rubric in the PDF with invalid format.
     */
    private static final String PATH_IMAGE_INVALID = "src/test/resources/image/rubrica_formato_invalido.tif";

    /**
     * Test for methods {@link PAdESBaselineSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link PAdESBaselineSigner#verifySignature(byte[])}.
     */
    public final void testSignWithoutTimestamp() {

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("pdfToSign.pdf", true);
	System.out.println("!!!!!!!!!!!! 1");

	PAdESBaselineSigner signer = new PAdESBaselineSigner();
	byte[ ] padesBLevelSignature = null;
	byte[ ] padesTLevelSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	System.out.println("!!!!!!!!!!!! 2");
	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.PADES_CONTACT_PROP, "Ricoh");
	extraParams.put(SignatureProperties.PADES_LOCATION_PROP, "Seville");
	extraParams.put(SignatureProperties.PADES_REASON_PROP, "Document signed for tests");
	extraParams.put(SignatureProperties.PADES_CERTIFICATION_LEVEL, SignatureConstants.PDF_APPROVAL);
	System.out.println("!!!!!!!!!!!! 3");
	/*
	 * Generación y Validación de firma PAdES B-Level explícita sin política de firma y algoritmo SHA-1
	 */
	try {
	    padesBLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_PADES_B_LEVEL, null);
	    System.out.println("!!!!!!!!!!!! 4");
	    assertEquals(SignatureFormatDetectorCadesPades.getSignatureFormat(padesBLevelSignature), ISignatureFormatDetector.FORMAT_PADES_B_LEVEL);
	    System.out.println("!!!!!!!!!!!! 5");
	    PDFValidationResult vr = signer.verifySignature(padesBLevelSignature);
	    System.out.println("!!!!!!!!!!!! 6" + vr.getErrorMsg());
	    assertTrue(vr.isCorrect());

	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Actualización de firma PAdES B-Level sin política de firma a PAdES T-Level
	 */
	try {
	    padesTLevelSignature = signer.upgrade(padesBLevelSignature, null);
	    System.out.println("!!!!!!!!!!!! 7");
	    assertEquals(SignatureFormatDetectorCadesPades.getSignatureFormat(padesTLevelSignature), ISignatureFormatDetector.FORMAT_PADES_T_LEVEL);
	    System.out.println("!!!!!!!!!!!! 8");
	    PDFValidationResult vr = signer.verifySignature(padesTLevelSignature);
	    System.out.println("!!!!!!!!!!!! 9" + vr.getErrorMsg());
	    assertTrue(vr.isCorrect());
	    System.out.println("!!!!!!!!!!!! 10");
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Generación y Validación de firma PAdES B-Level implícita con política de firma y algoritmo SHA-256
	 */
	try {
	    padesBLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_PADES_B_LEVEL, "PDF_AGE_1.9");
	    System.out.println("!!!!!!!!!!!! 11");
	    assertEquals(SignatureFormatDetectorCadesPades.getSignatureFormat(padesBLevelSignature), ISignatureFormatDetector.FORMAT_PADES_B_LEVEL);
	    System.out.println("!!!!!!!!!!!! 12");
	    PDFValidationResult vr = signer.verifySignature(padesBLevelSignature);
	    System.out.println("!!!!!!!!!!!! 13");
	    assertTrue(vr.isCorrect());
	    System.out.println("!!!!!!!!!!!! 14");
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Actualización de firma PAdES B-Level con política de firma a PAdES T-Level
	 */
	try {
	    padesTLevelSignature = signer.upgrade(padesBLevelSignature, null);
	    System.out.println("!!!!!!!!!!!! 1");
	    assertEquals(SignatureFormatDetectorCadesPades.getSignatureFormat(padesTLevelSignature), ISignatureFormatDetector.FORMAT_PADES_T_LEVEL);
	    System.out.println("!!!!!!!!!!!! 1");
	    PDFValidationResult vr = signer.verifySignature(padesTLevelSignature);
	    System.out.println("!!!!!!!!!!!! 1");
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

    }

    /**
     * Test for methods {@link PAdESBaselineSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link PAdESBaselineSigner#verifySignature(byte[])}.
     */
    public final void testSignWithTimestamp() {
	Security.addProvider(new BouncyCastleProvider());
	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("pdfToSign.pdf", true);

	PAdESBaselineSigner signer = new PAdESBaselineSigner();
	byte[ ] padesTLevelSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.PADES_CONTACT_PROP, "Ricoh");
	extraParams.put(SignatureProperties.PADES_LOCATION_PROP, "Seville");
	extraParams.put(SignatureProperties.PADES_REASON_PROP, "Document signed for tests");
	extraParams.put(SignatureProperties.PADES_CERTIFICATION_LEVEL, PdfSignatureAppearance.NOT_CERTIFIED);

	/*
	 * Generación y Validación de firma PAdES T-Level explícita sin política de firma y algoritmo SHA-384
	 */
	try {
	    padesTLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA384WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, extraParams, true, ISignatureFormatDetector.FORMAT_PADES_B_LEVEL, null);
	    assertEquals(SignatureFormatDetectorCadesPades.getSignatureFormat(padesTLevelSignature), ISignatureFormatDetector.FORMAT_PADES_T_LEVEL);
	    PDFValidationResult vr = signer.verifySignature(padesTLevelSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Generación y Validación de firma PAdES T-Level explícita con política de firma y algoritmo SHA-512
	 */
	try {
	    padesTLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, extraParams, true, ISignatureFormatDetector.FORMAT_PADES_B_LEVEL, "PDF_AGE_1.9");
	    assertEquals(SignatureFormatDetectorCadesPades.getSignatureFormat(padesTLevelSignature), ISignatureFormatDetector.FORMAT_PADES_T_LEVEL);
	    PDFValidationResult vr = signer.verifySignature(padesTLevelSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

    }

    /**
     * Test for method {@link PAdESBaselineSigner#getSignedData(byte[])}.
     */
    public final void testGetSignedData() {

	byte[ ] signature = UtilsFileSystemCommons.readFile("signatures/PDF/PDF.pdf", true);
	PAdESBaselineSigner pbs = new PAdESBaselineSigner();
	OriginalSignedData osd = new OriginalSignedData();

	try {
	    osd = pbs.getSignedData(signature);

	    assertNotNull(osd.getSignedData());
	    assertNotNull(osd.getMimetype());
	    assertNull(osd.getHashAlgorithm());
	    assertNull(osd.getHashSignedData());

	} catch (SigningException e) {
	    assertTrue(false);
	}

    }

    /**
     * Test for method {@link PAdESBaselineSigner#getSignedData(byte[])}.
     */
    public final void testGetSignedDataParamNull() {

	PAdESBaselineSigner pbs = new PAdESBaselineSigner();
	OriginalSignedData osd = new OriginalSignedData();

	try {
	    osd = pbs.getSignedData(null);
	} catch (SigningException e) {
	    assertTrue(true);
	}

    }

    /**
     * Test for method {@link PadesSigner#coSign(byte[], byte[], String, java.security.KeyStore.PrivateKeyEntry, Properties, boolean, String, String)}.
     * 
     * @throws Exception If the method fails.
     */
    public final void testCoSign() throws Exception {
	PAdESBaselineSigner pbs = new PAdESBaselineSigner();
	byte[ ] result = null;
	// test con valores nulos
	try {
	    pbs.coSign(null, null, null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	try {
	    pbs.coSign(new byte[0], null, null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	try {
	    pbs.coSign(new byte[0], null, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	// test con valores inválidos (algoritmo no soportado)
	try {
	    pbs.coSign(getPdfDocumentCosign(), null, "MD5withRSA", getCertificatePrivateKey(), null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.PADES_CONTACT_PROP, "Ricoh");
	extraParams.put(SignatureProperties.PADES_LOCATION_PROP, "Seville");
	extraParams.put(SignatureProperties.PADES_REASON_PROP, "Document signed for demonstrate this authenticity");

	// test con parámetros válidos
	result = pbs.coSign(getPdfDocumentCosign(), null, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_B_LEVEL, null);
	PDFValidationResult vr = pbs.verifySignature(result);
	assertTrue(vr.isCorrect());
	//
	// test con formato no permitido
	try {
	    result = pbs.coSign(getPdfDocumentCosign(), null, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_CADES_A, null);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	// test con parámetros opcionales no permitidos
	extraParams.put(SignatureProperties.CADES_POLICY_QUALIFIER_PROP, "");
	try {
	    result = pbs.coSign(getPdfDocumentCosign(), null, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_B_LEVEL, null);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}
    }

    /**
     * Test for method {@link PadesSigner#counterSign(byte[], String, java.security.KeyStore.PrivateKeyEntry, Properties, boolean, String, String)}.
     * 
     * @throws Exception If the method fails.
     */
    public final void testCounter() throws Exception {
	PAdESBaselineSigner pbs = new PAdESBaselineSigner();
	byte[ ] result = null;
	// test con valores nulos
	try {
	    pbs.counterSign(null, null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	try {
	    pbs.counterSign(new byte[0], null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	try {
	    pbs.counterSign(new byte[0], SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	// test con valores inválidos (algoritmo no soportado)
	try {
	    pbs.counterSign(getPdfDocumentCosign(), "MD5withRSA", getCertificatePrivateKey(), null, false, null, null);

	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.PADES_CONTACT_PROP, "Ricoh");
	extraParams.put(SignatureProperties.PADES_LOCATION_PROP, "Seville");
	extraParams.put(SignatureProperties.PADES_REASON_PROP, "Document signed for demonstrate this authenticity");

	// test con parámetros válidos
	result = pbs.counterSign(getPdfDocumentCosign(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_B_LEVEL, null);
	PDFValidationResult vr = pbs.verifySignature(result);
	assertTrue(vr.isCorrect());

	// test con formato no permitido
	try {
	    result = pbs.counterSign(getPdfDocumentCosign(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_CADES_A, null);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	// test con parámetros opcionales no permitidos.
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "");
	try {
	    result = pbs.counterSign(getPdfDocumentCosign(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_B_LEVEL, null);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

    }

    /**
     * Test for method {@link PadesSigner#sign(byte[], String, String, java.security.KeyStore.PrivateKeyEntry, Properties, boolean, String, String).
     * 
     * @throws Exception If the method fails.
     */
    public final void testSignWithRubric() throws Exception {

	PAdESBaselineSigner pbs = new PAdESBaselineSigner();

	Properties extraParams = new Properties();

	extraParams.put(SignatureProperties.PADES_CONTACT_PROP, "Ricoh");
	extraParams.put(SignatureProperties.PADES_LOCATION_PROP, "Seville");
	extraParams.put(SignatureProperties.PADES_REASON_PROP, "Document signed for demonstrate this authenticity");

	String imageB64 = Base64.encodeBytes(PATH_IMAGE.getBytes());
	extraParams.put(SignatureProperties.PADES_IMAGE, imageB64);
	extraParams.put(SignatureProperties.PADES_IMAGE_PAGE, "-1");
	extraParams.put(SignatureProperties.PADES_LOWER_LEFT_X, "20");
	extraParams.put(SignatureProperties.PADES_LOWER_LEFT_Y, "40");
	extraParams.put(SignatureProperties.PADES_UPPER_RIGHT_X, "250");
	extraParams.put(SignatureProperties.PADES_UPPER_RIGHT_Y, "150");

	// test con valores válidos
	byte[ ] result = pbs.sign(getPdfDocumentToSignRubric(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_B_LEVEL, null);

	PDFValidationResult vr = pbs.verifySignature(result);
	assertTrue(vr.isCorrect());

	// insertar rúbrica pasando un número de página inválido
	extraParams.put(SignatureProperties.PADES_IMAGE_PAGE, "0");
	try {
	    result = pbs.sign(getPdfDocumentToSignRubric(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_B_LEVEL, null);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	// insertar rúbrica pasando un número de página mayor que el número de
	// páginas del documento.
	extraParams.put(SignatureProperties.PADES_IMAGE_PAGE, "10");
	try {
	    result = pbs.sign(getPdfDocumentToSignRubric(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_B_LEVEL, null);
	} catch (SigningException e) {
	    assertTrue(true);
	}

	// Test 4 - insertar rúbrica pasando una imagen con formato inválido.
	imageB64 = Base64.encodeBytes(PATH_IMAGE_INVALID.getBytes());
	extraParams.put(SignatureProperties.PADES_IMAGE, imageB64);
	try {
	    result = pbs.sign(getPdfDocumentToSignRubric(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_B_LEVEL, null);
	} catch (SigningException e) {
	    assertTrue(true);
	}

    }

    /**
     * Test for method {@link PadesSigner#coSign(byte[], byte[], String, java.security.KeyStore.PrivateKeyEntry, Properties, boolean, String, String)}.
     * 
     * @throws Exception If the method fails.
     */
    public final void testCoSignWithRubric() throws Exception {

	PAdESBaselineSigner pbs = new PAdESBaselineSigner();

	Properties extraParams = new Properties();

	extraParams.put(SignatureProperties.PADES_CONTACT_PROP, "Ricoh");
	extraParams.put(SignatureProperties.PADES_LOCATION_PROP, "Seville");
	extraParams.put(SignatureProperties.PADES_REASON_PROP, "Document signed for demonstrate this authenticity");

	String imageB64 = Base64.encodeBytes(PATH_IMAGE.getBytes());
	extraParams.put(SignatureProperties.PADES_IMAGE, imageB64);
	extraParams.put(SignatureProperties.PADES_IMAGE_PAGE, "1");
	extraParams.put(SignatureProperties.PADES_LOWER_LEFT_X, "300");
	extraParams.put(SignatureProperties.PADES_LOWER_LEFT_Y, "40");
	extraParams.put(SignatureProperties.PADES_UPPER_RIGHT_X, "530");
	extraParams.put(SignatureProperties.PADES_UPPER_RIGHT_Y, "150");

	// 1 - Test con valores válidos
	byte[ ] result = pbs.coSign(getPdfDocumentToCosignRubric(), null, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_B_LEVEL, null);
	PDFValidationResult vr = pbs.verifySignature(result);
	assertTrue(vr.isCorrect());

	String fileKey = "D:/Tmp/PAdES/Pades_Rubrica_CoSign.pdf";
	FileOutputStream fos;
	try {
	    fos = new FileOutputStream(fileKey);

	    fos.write(result);
	    fos.close();
	} catch (FileNotFoundException e) {
	    System.out.println(e.getMessage());
	} catch (IOException e) {
	    System.out.println(e.getMessage());
	}

	// Test 2 - Insertar rúbrica pasando un número de página inválido
	extraParams.put(SignatureProperties.PADES_IMAGE_PAGE, "0");

	// borramos la propiedad que se añadió en el test anterior donde se
	// indicaba el formato de la firma pades para crear el signedData
	// (específico para PAdES).
	extraParams.remove(SignatureConstants.SIGN_FORMAT_PADES);
	try {
	    result = pbs.coSign(getPdfDocumentToCosignRubric(), null, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_B_LEVEL, null);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	// Test 3 - Insertar rúbrica pasando un número de página mayor que el
	// número de
	// páginas del documento.
	extraParams.put(SignatureProperties.PADES_IMAGE_PAGE, "10");
	// borramos la propiedad que se añadió en el test anterior donde se
	// indicaba el formato de la firma pades para crear el signedData
	// (específico para PAdES).
	extraParams.remove(SignatureConstants.SIGN_FORMAT_PADES);
	try {
	    result = pbs.coSign(getPdfDocumentToCosignRubric(), null, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_B_LEVEL, null);
	} catch (SigningException e) {
	    assertTrue(true);
	}

	// Test 4 - insertar rúbrica pasando una imagen con formato inválido.
	imageB64 = Base64.encodeBytes(PATH_IMAGE_INVALID.getBytes());
	extraParams.put(SignatureProperties.PADES_IMAGE, imageB64);
	try {
	    result = pbs.coSign(getPdfDocumentToCosignRubric(), null, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_B_LEVEL, null);
	} catch (SigningException e) {
	    assertTrue(true);
	}
    }

    /**
     * Test for method {@link PadesSigner#counterSign(byte[], String, java.security.KeyStore.PrivateKeyEntry, Properties, boolean, String, String, String).
     * 
     * @throws Exception If the method fails.
     */
    public final void testCounterSignWithRubric() throws Exception {

	PAdESBaselineSigner pbs = new PAdESBaselineSigner();

	Properties extraParams = new Properties();

	extraParams.put(SignatureProperties.PADES_CONTACT_PROP, "Ricoh");
	extraParams.put(SignatureProperties.PADES_LOCATION_PROP, "Seville");
	extraParams.put(SignatureProperties.PADES_REASON_PROP, "Document signed for demonstrate this authenticity");

	String imageB64 = Base64.encodeBytes(PATH_IMAGE.getBytes());
	extraParams.put(SignatureProperties.PADES_IMAGE, imageB64);
	extraParams.put(SignatureProperties.PADES_IMAGE_PAGE, "1");
	extraParams.put(SignatureProperties.PADES_LOWER_LEFT_X, "300");
	extraParams.put(SignatureProperties.PADES_LOWER_LEFT_Y, "40");
	extraParams.put(SignatureProperties.PADES_UPPER_RIGHT_X, "530");
	extraParams.put(SignatureProperties.PADES_UPPER_RIGHT_Y, "150");

	// Test 1 - test con valores válidos
	byte[ ] result = pbs.counterSign(getPdfDocumentToCosignRubric(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_B_LEVEL, null);
	PDFValidationResult vr = pbs.verifySignature(result);
	assertTrue(vr.isCorrect());

	String fileKey = "D:/Tmp/PAdES/Pades_Rubrica_CounterSign.pdf";
	FileOutputStream fos;
	try {
	    fos = new FileOutputStream(fileKey);

	    fos.write(result);
	    fos.close();
	} catch (FileNotFoundException e) {
	    System.out.println(e.getMessage());
	} catch (IOException e) {
	    System.out.println(e.getMessage());
	}

	// Test 2 - Insertar rúbrica pasando un número de página inválido
	extraParams.put(SignatureProperties.PADES_IMAGE_PAGE, "0");

	// borramos la propiedad que se añadió en el test anterior donde se
	// indicaba el formato de la firma pades para crear el signedData
	// (específico para PAdES).
	extraParams.remove(SignatureConstants.SIGN_FORMAT_PADES);
	try {
	    result = pbs.counterSign(getPdfDocumentToCosignRubric(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_B_LEVEL, null);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	// Test 3 - Insertar rúbrica pasando un número de página mayor que el
	// número de
	// páginas del documento.
	extraParams.put(SignatureProperties.PADES_IMAGE_PAGE, "10");
	// borramos la propiedad que se añadió en el test anterior donde se
	// indicaba el formato de la firma pades para crear el signedData
	// (específico para PAdES).
	extraParams.remove(SignatureConstants.SIGN_FORMAT_PADES);
	try {
	    result = pbs.counterSign(getPdfDocumentCosign(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_B_LEVEL, null);
	} catch (SigningException e) {
	    assertTrue(true);
	}

	// Test 4 - insertar rúbrica pasando una imagen con formato inválido.
	imageB64 = Base64.encodeBytes(PATH_IMAGE_INVALID.getBytes());
	extraParams.put(SignatureProperties.PADES_IMAGE, imageB64);
	try {
	    result = pbs.counterSign(getPdfDocumentCosign(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_B_LEVEL, null);
	} catch (SigningException e) {
	    assertTrue(true);
	}
    }
}
