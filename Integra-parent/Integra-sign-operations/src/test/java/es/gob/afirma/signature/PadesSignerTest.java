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
 * <b>File:</b><p>es.gob.afirma.signature.PadesSignerTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for {@link PadesSigner}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/04/2015.</p>
 * @author Gobierno de España.
 * @version 1.2, 14/03/2017.
 */
package es.gob.afirma.signature;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import com.lowagie.text.pdf.codec.Base64;

import es.gob.afirma.signature.pades.PadesSigner;
import es.gob.afirma.signature.validation.PDFValidationResult;
import es.gob.afirma.utils.Base64CoderCommons;
import es.gob.afirma.utils.UtilsFileSystemCommons;

/**
 * <p>Class that defines tests for {@link PadesSigner}.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.2, 14/03/2017.
 */
public class PadesSignerTest extends AbstractSignatureTest {

    /**
     * Constant attribute that represents the image to be inserted as a rubric in the PDF.
     */
    private static final String PATH_IMAGE = "src/test/resources/image/rubrica.png";

    /**
     * Constant attribute that represents the image to be inserted as a rubric in the PDF with invalid format.
     */
    private static final String PATH_IMAGE_INVALID = "src/test/resources/image/rubrica_formato_invalido.tif";

    /**
     * Tests for {@link PadesSigner#sign(byte[], String, String, java.security.KeyStore.PrivateKeyEntry, Properties, boolean, String, String)}.
     * @throws Exception If the test fails.
     */
    public final void testSign() throws Exception {

	PadesSigner ps = new PadesSigner();
	// test con valores nulos
	try {
	    ps.sign(null, null, null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {}

	try {
	    ps.sign(new byte[0], null, null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {}

	try {
	    ps.sign(new byte[0], SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {}

	// test con valores inválidos (algoritmo no soportado)
	try {
	    ps.sign(getTextDocument(), "MD5withRSA", null, getCertificatePrivateKey(), null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {}

	// test con valores válidos (firma explícita no soportada en firmas PDF
	// y se ignora parámetro --> se realiza de forma implícita)
	byte[ ] result = ps.sign(getPdfDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, getCertificatePrivateKey(), null, false, SignatureFormatDetector.FORMAT_PADES_BES, null);
	System.out.println("\n------>>PDF FIRMADO (firma explícita)PDF ------¬  \n" + new String(Base64CoderCommons.encodeBase64(result)));

	// test con valores válidos (firma implícita)
	result = ps.sign(getPdfDocument(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), null, false, SignatureFormatDetector.FORMAT_PADES_BES, null);
	System.out.println("\n------>>PDF FIRMADO (firma implícita)PDF ------¬  \n" + new String(Base64CoderCommons.encodeBase64(result)));

	// test con valores válidos (firma implícita con política de firma de
	// AGE)
	Properties extraParams = new Properties();

	extraParams.put(SignatureProperties.PADES_CONTACT_PROP, "Ricoh");
	extraParams.put(SignatureProperties.PADES_LOCATION_PROP, "Seville");
	extraParams.put(SignatureProperties.PADES_REASON_PROP, "Document signed for demonstrate this authenticity");

	result = ps.sign(getPdfDocument(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_EPES, null);
	
	System.out.println("\n------>>PDF FIRMADO (firma implícita con política de firma de AGE)------¬ \n" + new String(Base64CoderCommons.encodeBase64(result)));
    }

    /**
     * Tests for {@link PadesSigner#sign(byte[], String, String, java.security.KeyStore.PrivateKeyEntry, Properties, boolean, String, String)} with timestamp.
     */
    public final void testSignWithTimestamp() {
	PadesSigner padesSigner = new PadesSigner();

	// Obtenemos el fichero que se va a sellar
	byte[ ] file = UtilsFileSystemCommons.readFile("pdfToSign.pdf", true);

	/*
	 * Test 1: Generación de firma PAdES-T que no permite ser modificada posteriormente
	 */
	try {
	    byte[ ] padesEPES = padesSigner.sign(file, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), null, true, SignatureFormatDetector.FORMAT_PADES_EPES, "2.16.724.1.3.1.1.2.1.9");
	    PDFValidationResult vr = padesSigner.verifySignature(padesEPES);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Generación de firma PAdES-T con política de firma que no permite ser modificada posteriormente
	 */
	try {
	    byte[ ] padesEPES = padesSigner.sign(file, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), null, true, SignatureFormatDetector.FORMAT_PADES_EPES, "PDF_AGE_1.9");
	    PDFValidationResult vr = padesSigner.verifySignature(padesEPES);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 3: Generación de firma PAdES-T con política de firma que permite ser modificada posteriormente
	 */
	try {
	    byte[ ] padesEPES = padesSigner.sign(file, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), null, true, SignatureFormatDetector.FORMAT_PADES_EPES, "PDF_AGE_1.9");
	    PDFValidationResult vr = padesSigner.verifySignature(padesEPES);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Tests for {@link PadesSigner#upgrade(byte[], List)}.
     */
    public final void testUpgrade() {
	PadesSigner padesSigner = new PadesSigner();

	// Obtenemos el fichero que se va a sellar
	byte[ ] file = UtilsFileSystemCommons.readFile("pdfToSign.pdf", true);

	/*
	 * Test 1: Actualización de todos los firmantes de una firma PAdES-BES que permite ser modificada posteriormente
	 */
	try {
	    Properties extraParams = new Properties();
	    extraParams.put(SignatureProperties.PADES_CERTIFICATION_LEVEL, "CERTIFIED_FORM_FILLING_AND_ANNOTATIONS");
	    byte[ ] pdfSignature = padesSigner.sign(file, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_BES, null);
	    byte[ ] upgradedSignature = padesSigner.upgrade(pdfSignature, null);
	    PDFValidationResult vr = padesSigner.verifySignature(upgradedSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Actualización de todos los firmantes de una firma PAdES-BES que no permite ser modificada posteriormente
	 */
	try {
	    byte[ ] pdfSignature = padesSigner.sign(file, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), null, false, SignatureFormatDetector.FORMAT_PADES_BES, null);
	    byte[ ] upgradedSignature = padesSigner.upgrade(pdfSignature, null);
	    PDFValidationResult vr = padesSigner.verifySignature(upgradedSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(true);
	}

	/*
	 * Test 3: Actualización de un firmante de una firma PAdES-BES que permite ser modificada posteriormente
	 */
	try {
	    List<X509Certificate> listCertificates = new ArrayList<X509Certificate>();
	    listCertificates.add(getCertificate());
	    Properties extraParams = new Properties();
	    extraParams.put(SignatureProperties.PADES_CERTIFICATION_LEVEL, "CERTIFIED_FORM_FILLING_AND_ANNOTATIONS");
	    byte[ ] pdfSignature = padesSigner.sign(file, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_BES, null);
	    byte[ ] upgradedSignature = padesSigner.upgrade(pdfSignature, listCertificates);
	    PDFValidationResult vr = padesSigner.verifySignature(upgradedSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Tests for {@link PadesSigner#verifySignature(byte[])}.
     */
    public final void testValidate() {

	PadesSigner padesSigner = new PadesSigner();

	/*
	 * Test 1: Validar una firma PDF
	 */
	byte[ ] pdf = UtilsFileSystemCommons.readFile("signatures/PDF/PDF.pdf", true);
	if (padesSigner.verifySignature(pdf).isCorrect()) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Validar una firma PAdES-Basic
	 */
	byte[ ] padesBasic = UtilsFileSystemCommons.readFile("signatures/PDF/PAdES-Basic.pdf", true);
	if (!padesSigner.verifySignature(padesBasic).isCorrect()) {
	    assertTrue(false);
	}

	/*
	 * Test 3: Validar una firma PAdES-BES
	 */
	byte[ ] padesBES = UtilsFileSystemCommons.readFile("signatures/PDF/PAdES-BES.pdf", true);
	if (!padesSigner.verifySignature(padesBES).isCorrect()) {
	    assertTrue(false);
	}

	/*
	 * Test 4: Validar una firma PAdES-EPES
	 */
	byte[ ] padesEPES = UtilsFileSystemCommons.readFile("signatures/PDF/PAdES-EPES.pdf", true);
	if (!padesSigner.verifySignature(padesEPES).isCorrect()) {
	    assertTrue(false);
	}

	/*
	 * Test 5: Validar una firma PAdES-LTV
	 */
	byte[ ] padesLTV = UtilsFileSystemCommons.readFile("signatures/PDF/PAdES-LTV.pdf", true);
	if (!padesSigner.verifySignature(padesLTV).isCorrect()) {
	    assertTrue(false);
	}

    }

    /**
        * Test for method {@link PadesSigner#getSignedData(byte[])}.
        */
    public final void testGetSignedData() {

	byte[ ] signature = UtilsFileSystemCommons.readFile("signatures/PDF/PDF.pdf", true);
	PadesSigner ps = new PadesSigner();
	OriginalSignedData osd = new OriginalSignedData();

	try {
	    osd = ps.getSignedData(signature);

	    assertNotNull(osd.getSignedData());
	    assertNotNull(osd.getMimetype());
	    assertNull(osd.getHashAlgorithm());
	    assertNull(osd.getHashSignedData());

	} catch (SigningException e) {
	    assertTrue(false);
	}

    }

    /**
     * Test for method {@link PadesSigner#getSignedData(byte[])}.
     */
    public final void testGetSignedDataParamNull() {

	PadesSigner ps = new PadesSigner();
	OriginalSignedData osd = new OriginalSignedData();

	try {
	    osd = ps.getSignedData(null);
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
	PadesSigner ps = new PadesSigner();
	byte[ ] result = null;
	// test con valores nulos
	try {
	    ps.coSign(null, null, null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	try {
	    ps.coSign(new byte[0], null, null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	try {
	    ps.coSign(new byte[0], null, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	// test con valores inválidos (algoritmo no soportado)
	try {
	    ps.coSign(getPdfDocumentCosign(), null, "MD5withRSA", getCertificatePrivateKey(), null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.PADES_CONTACT_PROP, "Ricoh");
	extraParams.put(SignatureProperties.PADES_LOCATION_PROP, "Seville");
	extraParams.put(SignatureProperties.PADES_REASON_PROP, "Document signed for demonstrate this authenticity");

	// test con parámetros válidos
	result = ps.coSign(getPdfDocumentCosign(), null, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_BES, null);
	PDFValidationResult vr = ps.verifySignature(result);
	assertTrue(vr.isCorrect());

	// test con formato no permitido
	try {
	    result = ps.coSign(getPdfDocumentCosign(), null, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_CADES_A, null);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	// test con parámetros opcionales no permitidos
	extraParams.put(SignatureProperties.CADES_POLICY_QUALIFIER_PROP, "");
	try {
	    result = ps.coSign(getPdfDocumentCosign(), null, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_BES, null);
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
	PadesSigner ps = new PadesSigner();
	byte[ ] result = null;
	// test con valores nulos
	try {
	    ps.counterSign(null, null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	try {
	    ps.counterSign(new byte[0], null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	try {
	    ps.counterSign(new byte[0], SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	// test con valores inválidos (algoritmo no soportado)
	try {
	    ps.counterSign(getPdfDocumentCosign(), "MD5withRSA", getCertificatePrivateKey(), null, false, null, null);

	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.PADES_CONTACT_PROP, "Ricoh");
	extraParams.put(SignatureProperties.PADES_LOCATION_PROP, "Seville");
	extraParams.put(SignatureProperties.PADES_REASON_PROP, "Document signed for demonstrate this authenticity");

	// test con parámetros válidos
	result = ps.counterSign(getPdfDocumentCosign(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_BES, null);
	PDFValidationResult vr = ps.verifySignature(result);
	assertTrue(vr.isCorrect());

	// test con formato no permitido
	try {
	    result = ps.counterSign(getPdfDocumentCosign(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_CADES_A, null);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	// test con parámetros opcionales no permitidos.
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "");
	try {
	    result = ps.counterSign(getPdfDocumentCosign(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_BES, null);
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

	PadesSigner ps = new PadesSigner();

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

	// Test 1 - test con valores válidos
	byte[ ] result = ps.sign(getPdfDocumentToSignRubric(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_EPES, null);
	PDFValidationResult vr = ps.verifySignature(result);
	assertTrue(vr.isCorrect());

	// Test 2 - insertar rúbrica pasando un número de página inválido
	extraParams.put(SignatureProperties.PADES_IMAGE_PAGE, "0");
	try {
	    result = ps.sign(getPdfDocumentToSignRubric(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_EPES, null);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	// Test 3 - insertar rúbrica pasando un número de página mayor que el
	// número de páginas del documento.
	extraParams.put(SignatureProperties.PADES_IMAGE_PAGE, "10");
	try {
	    result = ps.sign(getPdfDocumentToSignRubric(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_EPES, null);
	} catch (SigningException e) {
	    assertTrue(true);
	}

	// Test 4 - insertar rúbrica pasando una imagen con formato inválido.
	imageB64 = Base64.encodeBytes(PATH_IMAGE_INVALID.getBytes());
	extraParams.put(SignatureProperties.PADES_IMAGE, imageB64);
	try {
	    result = ps.sign(getPdfDocumentToSignRubric(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_EPES, null);
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

	PadesSigner ps = new PadesSigner();

	Properties extraParams = new Properties();

	extraParams.put(SignatureProperties.PADES_CONTACT_PROP, "Ricoh");
	extraParams.put(SignatureProperties.PADES_LOCATION_PROP, "Seville");
	extraParams.put(SignatureProperties.PADES_REASON_PROP, "Document signed for demonstrate this authenticity");

	String imageB64 = Base64.encodeBytes(PATH_IMAGE.getBytes());
	extraParams.put(SignatureProperties.PADES_IMAGE, imageB64);
	extraParams.put(SignatureProperties.PADES_IMAGE_PAGE, "1");
	extraParams.put(SignatureProperties.PADES_LOWER_LEFT_X, "200");
	extraParams.put(SignatureProperties.PADES_LOWER_LEFT_Y, "40");
	extraParams.put(SignatureProperties.PADES_UPPER_RIGHT_X, "310");
	extraParams.put(SignatureProperties.PADES_UPPER_RIGHT_Y, "80");

	// 1 - Test con valores válidos
	byte[ ] result = ps.coSign(getPdfDocumentToCosignRubric(), null, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_BES, null);
	PDFValidationResult vr = ps.verifySignature(result);
	assertTrue(vr.isCorrect());

	// Test 2 - Insertar rúbrica pasando un número de página inválido
	extraParams.put(SignatureProperties.PADES_IMAGE_PAGE, "0");
	// borramos la propiedad que se añadió en el test anterior donde se
	// indicaba el formato de la firma pades para crear el signedData
	// (específico para PAdES).
	extraParams.remove(SignatureConstants.SIGN_FORMAT_PADES);
	try {
	    result = ps.coSign(getPdfDocumentToCosignRubric(), null, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_BES, null);
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
	    result = ps.coSign(getPdfDocumentToCosignRubric(), null, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_BES, null);
	} catch (SigningException e) {
	    assertTrue(true);
	}

	// Test 4 - insertar rúbrica pasando una imagen con formato inválido.
	imageB64 = Base64.encodeBytes(PATH_IMAGE_INVALID.getBytes());
	extraParams.put(SignatureProperties.PADES_IMAGE, imageB64);
	try {
	    result = ps.coSign(getPdfDocumentToCosignRubric(), null, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_BES, null);
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

	PadesSigner ps = new PadesSigner();

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
	byte[ ] result = ps.counterSign(getPdfDocumentToCosignRubric(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_BES, null);
	PDFValidationResult vr = ps.verifySignature(result);
	assertTrue(vr.isCorrect());

	// Test 2 - Insertar rúbrica pasando un número de página inválido
	extraParams.put(SignatureProperties.PADES_IMAGE_PAGE, "0");

	// borramos la propiedad que se añadió en el test anterior donde se
	// indicaba el formato de la firma pades para crear el signedData
	// (específico para PAdES).
	extraParams.remove(SignatureConstants.SIGN_FORMAT_PADES);
	try {
	    result = ps.counterSign(getPdfDocumentToCosignRubric(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_BES, null);
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
	    result = ps.counterSign(getPdfDocumentCosign(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_BES, null);
	} catch (SigningException e) {
	    assertTrue(true);
	}

	// Test 4 - insertar rúbrica pasando una imagen con formato inválido.
	// borramos la propiedad que se añadió en el test anterior donde se
	// indicaba el formato de la firma pades para crear el signedData
	// (específico para PAdES).
	extraParams.remove(SignatureConstants.SIGN_FORMAT_PADES);
	imageB64 = Base64.encodeBytes(PATH_IMAGE_INVALID.getBytes());
	extraParams.put(SignatureProperties.PADES_IMAGE, imageB64);
	try {
	    result = ps.counterSign(getPdfDocumentCosign(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), extraParams, false, SignatureFormatDetector.FORMAT_PADES_BES, null);
	} catch (SigningException e) {
	    assertTrue(true);

	}
    }
}
