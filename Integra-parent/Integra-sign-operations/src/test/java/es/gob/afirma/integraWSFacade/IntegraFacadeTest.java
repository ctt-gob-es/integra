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
 * <b>File:</b><p>es.gob.afirma.integraWSFacade.IntegraFacadeTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for {@link IntegraFacade}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/04/2015.</p>
 * @author Gobierno de España.
 * @version 1.2, 14/03/2017.
 */
package es.gob.afirma.integraWSFacade;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Properties;

import junit.framework.TestCase;
import es.gob.afirma.integraFacade.IntegraFacade;
import es.gob.afirma.properties.IIntegraConstants;
import es.gob.afirma.properties.IntegraProperties;
import es.gob.afirma.signature.ISignatureFormatDetector;
import es.gob.afirma.signature.OriginalSignedData;
import es.gob.afirma.signature.SignatureConstants;
import es.gob.afirma.signature.SignatureFormatDetector;
import es.gob.afirma.signature.SignatureProperties;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.signature.validation.PDFValidationResult;
import es.gob.afirma.signature.validation.ValidationResult;
import es.gob.afirma.utils.UtilsFileSystemCommons;

/**
 * <p>Class that defines tests for {@link IntegraFacade}.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.2, 14/03/2017.
 */
public class IntegraFacadeTest extends TestCase {

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
     * Constant attribute that represents the image to be inserted as a rubric in the PDF with invalid format.
     */
    private static final String PATH_IMAGE_INVALID = "image/rubrica_formato_invalido.tif";

    /**
     * Constant attribute that represents the PDF file name defined for tests. 
     */
    private static final String PDF_DOCUMENT_PATH = "signatures/PDF/pdfToSignRubric.pdf";
    /**
     * Constant attribute that represents the PDF file name defined for tests. 
     */
    private static final String PDF_DOCUMENT_PATH_TO_COSIGN_RUBRIC = "signatures/PDF/pdfToCoSignRubric.pdf";

    /**
     * Method that obtains the private key to use for tests.
     * @return the private key to use for tests.
     */
    private PrivateKeyEntry getCertificatePrivateKey() {
	KeyStore.Entry key = null;
	try {
	    InputStream is = new FileInputStream(ClassLoader.getSystemResource("keyStoreJCEKS.jks").getFile());
	    KeyStore ks = KeyStore.getInstance("JCEKS");
	    char[ ] password = "12345".toCharArray();
	    ks.load(is, password);
	    key = ks.getEntry("raul conde", new KeyStore.PasswordProtection(password));
	} catch (Exception e) {
	    return null;
	}
	return (KeyStore.PrivateKeyEntry) key;

    }

    public void testCAdESSignature() {
	renameProperties("integraFacadeCades.properties");

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);
	PrivateKeyEntry privateKey = getCertificatePrivateKey();

	byte[ ] signatureCAdESBES = null;
	byte[ ] coSignatureCAdESBES = null;
	byte[ ] counterSignatureCAdESBES = null;
	byte[ ] signatureCAdESEPES = null;
	byte[ ] coSignatureCAdESEPES = null;
	byte[ ] counterSignatureCAdESEPES = null;
	byte[ ] signatureCAdEST = null;
	byte[ ] coSignatureCAdEST = null;
	byte[ ] counterSignatureCAdEST = null;

	/*
	 * Test 1: Generación, Actualización y Validación de firma CAdES sin política de firma ni sello de tiempo
	 */
	try {
	    signatureCAdESBES = IntegraFacade.generateSignature(dataToSign, privateKey, false, false);
	    if (!SignatureFormatDetector.getSignatureFormat(signatureCAdESBES).equals(ISignatureFormatDetector.FORMAT_CADES_BES) && !SignatureFormatDetector.getSignatureFormat(signatureCAdESBES).equals(ISignatureFormatDetector.FORMAT_CADES_B_LEVEL)) {
		assertTrue(false);
	    }
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(signatureCAdESBES, dataToSign);
	    assertTrue(vr.isCorrect());
	    coSignatureCAdESBES = IntegraFacade.generateCoSignature(signatureCAdESBES, dataToSign, privateKey, false, false);
	    vr = (ValidationResult) IntegraFacade.verifySignature(coSignatureCAdESBES, dataToSign);
	    assertTrue(vr.isCorrect());
	    counterSignatureCAdESBES = IntegraFacade.generateCounterSignature(signatureCAdESBES, privateKey, false, false);
	    vr = (ValidationResult) IntegraFacade.verifySignature(counterSignatureCAdESBES, dataToSign);
	    assertTrue(vr.isCorrect());
	    signatureCAdEST = IntegraFacade.upgradeSignature(signatureCAdESBES, null);
	    if (!SignatureFormatDetector.getSignatureFormat(signatureCAdEST).equals(ISignatureFormatDetector.FORMAT_CADES_T) && !SignatureFormatDetector.getSignatureFormat(signatureCAdEST).equals(ISignatureFormatDetector.FORMAT_CADES_T_LEVEL)) {
		assertTrue(false);
	    }
	    vr = (ValidationResult) IntegraFacade.verifySignature(signatureCAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Generación, Actualización y Validación de firma CAdES con política de firma sin sello de tiempo
	 */
	try {
	    signatureCAdESEPES = IntegraFacade.generateSignature(dataToSign, privateKey, true, false);
	    if (!SignatureFormatDetector.getSignatureFormat(signatureCAdESEPES).equals(ISignatureFormatDetector.FORMAT_CADES_EPES) && !SignatureFormatDetector.getSignatureFormat(signatureCAdESEPES).equals(ISignatureFormatDetector.FORMAT_CADES_B_LEVEL)) {
		assertTrue(false);
	    }
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(signatureCAdESEPES, dataToSign);
	    assertTrue(vr.isCorrect());
	    coSignatureCAdESEPES = IntegraFacade.generateCoSignature(signatureCAdESEPES, dataToSign, privateKey, true, false);
	    vr = (ValidationResult) IntegraFacade.verifySignature(coSignatureCAdESEPES, dataToSign);
	    assertTrue(vr.isCorrect());
	    counterSignatureCAdESEPES = IntegraFacade.generateCounterSignature(signatureCAdESEPES, privateKey, true, false);
	    vr = (ValidationResult) IntegraFacade.verifySignature(counterSignatureCAdESEPES, dataToSign);
	    assertTrue(vr.isCorrect());
	    signatureCAdEST = IntegraFacade.upgradeSignature(signatureCAdESEPES, null);
	    if (!SignatureFormatDetector.getSignatureFormat(signatureCAdEST).equals(ISignatureFormatDetector.FORMAT_CADES_T) && !SignatureFormatDetector.getSignatureFormat(signatureCAdEST).equals(ISignatureFormatDetector.FORMAT_CADES_T_LEVEL)) {
		assertTrue(false);
	    }
	    vr = (ValidationResult) IntegraFacade.verifySignature(signatureCAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 3: Generación y Validación de firma CAdES sin política de firma y con sello de tiempo
	 */
	try {
	    signatureCAdEST = IntegraFacade.generateSignature(dataToSign, privateKey, false, true);
	    if (!SignatureFormatDetector.getSignatureFormat(signatureCAdEST).equals(ISignatureFormatDetector.FORMAT_CADES_T) && !SignatureFormatDetector.getSignatureFormat(signatureCAdEST).equals(ISignatureFormatDetector.FORMAT_CADES_T_LEVEL)) {
		assertTrue(false);
	    }
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(signatureCAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	    coSignatureCAdEST = IntegraFacade.generateCoSignature(signatureCAdEST, dataToSign, privateKey, false, true);
	    vr = (ValidationResult) IntegraFacade.verifySignature(coSignatureCAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	    counterSignatureCAdEST = IntegraFacade.generateCounterSignature(signatureCAdEST, privateKey, false, true);
	    vr = (ValidationResult) IntegraFacade.verifySignature(counterSignatureCAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 4: Generación y Validación de firma CAdES con política de firma y sello de tiempo
	 */
	try {
	    signatureCAdEST = IntegraFacade.generateSignature(dataToSign, privateKey, true, true);
	    if (!SignatureFormatDetector.getSignatureFormat(signatureCAdEST).equals(ISignatureFormatDetector.FORMAT_CADES_T) && !SignatureFormatDetector.getSignatureFormat(signatureCAdEST).equals(ISignatureFormatDetector.FORMAT_CADES_T_LEVEL)) {
		assertTrue(false);
	    }
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(signatureCAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	    coSignatureCAdEST = IntegraFacade.generateCoSignature(signatureCAdEST, dataToSign, privateKey, true, true);
	    vr = (ValidationResult) IntegraFacade.verifySignature(coSignatureCAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	    counterSignatureCAdEST = IntegraFacade.generateCounterSignature(signatureCAdEST, privateKey, true, true);
	    vr = (ValidationResult) IntegraFacade.verifySignature(counterSignatureCAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    public void testXAdESSignature() {
	renameProperties("integraFacadeXades.properties");

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);
	PrivateKeyEntry privateKey = getCertificatePrivateKey();

	byte[ ] signatureXAdESBES = null;
	byte[ ] coSignatureXAdESBES = null;
	byte[ ] counterSignatureXAdESBES = null;
	byte[ ] signatureXAdESEPES = null;
	byte[ ] coSignatureXAdESEPES = null;
	byte[ ] counterSignatureXAdESEPES = null;
	byte[ ] signatureXAdEST = null;
	byte[ ] coSignatureXAdEST = null;
	byte[ ] counterSignatureXAdEST = null;

	/*
	 * Test 1: Generación, Actualización y Validación de firma XAdES sin política de firma ni sello de tiempo
	 */
	try {
	    signatureXAdESBES = IntegraFacade.generateSignature(dataToSign, privateKey, false, false);
	    if (!SignatureFormatDetector.getSignatureFormat(signatureXAdESBES).equals(ISignatureFormatDetector.FORMAT_XADES_BES) && !SignatureFormatDetector.getSignatureFormat(signatureXAdESBES).equals(ISignatureFormatDetector.FORMAT_XADES_B_LEVEL)) {
		assertTrue(false);
	    }
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(signatureXAdESBES, dataToSign);
	    assertTrue(vr.isCorrect());
	    coSignatureXAdESBES = IntegraFacade.generateCoSignature(signatureXAdESBES, dataToSign, privateKey, false, false);
	    vr = (ValidationResult) IntegraFacade.verifySignature(coSignatureXAdESBES, dataToSign);
	    assertTrue(vr.isCorrect());
	    counterSignatureXAdESBES = IntegraFacade.generateCounterSignature(signatureXAdESBES, privateKey, false, false);
	    vr = (ValidationResult) IntegraFacade.verifySignature(counterSignatureXAdESBES, dataToSign);
	    assertTrue(vr.isCorrect());
	    signatureXAdEST = IntegraFacade.upgradeSignature(signatureXAdESBES, null);
	    if (!SignatureFormatDetector.getSignatureFormat(signatureXAdEST).equals(ISignatureFormatDetector.FORMAT_XADES_T) && !SignatureFormatDetector.getSignatureFormat(signatureXAdEST).equals(ISignatureFormatDetector.FORMAT_XADES_T_LEVEL)) {
		assertTrue(false);
	    }
	    vr = (ValidationResult) IntegraFacade.verifySignature(signatureXAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Generación, Actualización y Validación de firma XAdES con política de firma sin sello de tiempo
	 */
	try {
	    signatureXAdESEPES = IntegraFacade.generateSignature(dataToSign, privateKey, true, false);
	    if (!SignatureFormatDetector.getSignatureFormat(signatureXAdESEPES).equals(ISignatureFormatDetector.FORMAT_XADES_EPES) && !SignatureFormatDetector.getSignatureFormat(signatureXAdESEPES).equals(ISignatureFormatDetector.FORMAT_XADES_B_LEVEL)) {
		assertTrue(false);
	    }
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(signatureXAdESEPES, dataToSign);
	    assertTrue(vr.isCorrect());
	    coSignatureXAdESEPES = IntegraFacade.generateCoSignature(signatureXAdESEPES, dataToSign, privateKey, true, false);
	    vr = (ValidationResult) IntegraFacade.verifySignature(coSignatureXAdESEPES, dataToSign);
	    assertTrue(vr.isCorrect());
	    counterSignatureXAdESEPES = IntegraFacade.generateCounterSignature(signatureXAdESEPES, privateKey, true, false);
	    vr = (ValidationResult) IntegraFacade.verifySignature(counterSignatureXAdESEPES, dataToSign);
	    assertTrue(vr.isCorrect());
	    signatureXAdEST = IntegraFacade.upgradeSignature(signatureXAdESEPES, null);
	    if (!SignatureFormatDetector.getSignatureFormat(signatureXAdEST).equals(ISignatureFormatDetector.FORMAT_XADES_T) && !SignatureFormatDetector.getSignatureFormat(signatureXAdEST).equals(ISignatureFormatDetector.FORMAT_XADES_T_LEVEL)) {
		assertTrue(false);
	    }
	    vr = (ValidationResult) IntegraFacade.verifySignature(signatureXAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 3: Generación y Validación de firma XAdES sin política de firma y con sello de tiempo
	 */
	try {
	    signatureXAdEST = IntegraFacade.generateSignature(dataToSign, privateKey, false, true);
	    if (!SignatureFormatDetector.getSignatureFormat(signatureXAdEST).equals(ISignatureFormatDetector.FORMAT_XADES_T) && !SignatureFormatDetector.getSignatureFormat(signatureXAdEST).equals(ISignatureFormatDetector.FORMAT_XADES_T_LEVEL)) {
		assertTrue(false);
	    }
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(signatureXAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	    coSignatureXAdEST = IntegraFacade.generateCoSignature(signatureXAdEST, dataToSign, privateKey, false, true);
	    vr = (ValidationResult) IntegraFacade.verifySignature(coSignatureXAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	    counterSignatureXAdEST = IntegraFacade.generateCounterSignature(signatureXAdEST, privateKey, false, true);
	    vr = (ValidationResult) IntegraFacade.verifySignature(counterSignatureXAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 4: Generación y Validación de firma XAdES con política de firma y sello de tiempo
	 */
	try {
	    signatureXAdEST = IntegraFacade.generateSignature(dataToSign, privateKey, true, true);
	    if (!SignatureFormatDetector.getSignatureFormat(signatureXAdEST).equals(ISignatureFormatDetector.FORMAT_XADES_T) && !SignatureFormatDetector.getSignatureFormat(signatureXAdEST).equals(ISignatureFormatDetector.FORMAT_XADES_T_LEVEL)) {
		assertTrue(false);
	    }
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(signatureXAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	    coSignatureXAdEST = IntegraFacade.generateCoSignature(signatureXAdEST, dataToSign, privateKey, true, true);
	    vr = (ValidationResult) IntegraFacade.verifySignature(coSignatureXAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	    counterSignatureXAdEST = IntegraFacade.generateCounterSignature(signatureXAdEST, privateKey, true, true);
	    vr = (ValidationResult) IntegraFacade.verifySignature(counterSignatureXAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    public void testPAdESSignature() {
	renameProperties("integraFacadePades.properties");

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("pdfToSign.pdf", true);
	PrivateKeyEntry privateKey = getCertificatePrivateKey();

	byte[ ] signaturePAdESBES = null;
	byte[ ] signaturePAdESEPES = null;
	byte[ ] signaturePAdEST = null;
	byte[ ] signaturePAdESCoSign = null;
	byte[ ] signaturePAdESCounterSign = null;
	/*
	 * Test 1: Generación, Actualización y Validación de firma PAdES sin política de firma ni sello de tiempo
	 */
	try {
	    signaturePAdESBES = IntegraFacade.generateSignature(dataToSign, privateKey, false, false);
	    if (!SignatureFormatDetector.getSignatureFormat(signaturePAdESBES).equals(ISignatureFormatDetector.FORMAT_PADES_BES) && !SignatureFormatDetector.getSignatureFormat(signaturePAdESBES).equals(ISignatureFormatDetector.FORMAT_PADES_B_LEVEL)) {
		assertTrue(false);
	    }
	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdESBES, dataToSign);
	    assertTrue(vr.isCorrect());
	    signaturePAdEST = IntegraFacade.upgradeSignature(signaturePAdESBES, null);
	    if (!SignatureFormatDetector.getSignatureFormat(signaturePAdEST).equals(ISignatureFormatDetector.FORMAT_PADES_LTV) && !SignatureFormatDetector.getSignatureFormat(signaturePAdEST).equals(ISignatureFormatDetector.FORMAT_PADES_T_LEVEL)) {
		assertTrue(false);
	    }
	    vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Generación, Actualización y Validación de firma PAdES con política de firma sin sello de tiempo
	 */
	try {
	    signaturePAdESEPES = IntegraFacade.generateSignature(dataToSign, privateKey, true, false);
	    if (!SignatureFormatDetector.getSignatureFormat(signaturePAdESEPES).equals(ISignatureFormatDetector.FORMAT_PADES_EPES) && !SignatureFormatDetector.getSignatureFormat(signaturePAdESEPES).equals(ISignatureFormatDetector.FORMAT_PADES_B_LEVEL)) {
		assertTrue(false);
	    }
	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdESEPES, dataToSign);
	    assertTrue(vr.isCorrect());
	    signaturePAdEST = IntegraFacade.upgradeSignature(signaturePAdESEPES, null);
	    if (!SignatureFormatDetector.getSignatureFormat(signaturePAdEST).equals(ISignatureFormatDetector.FORMAT_PADES_LTV) && !SignatureFormatDetector.getSignatureFormat(signaturePAdEST).equals(ISignatureFormatDetector.FORMAT_PADES_T_LEVEL)) {
		assertTrue(false);
	    }
	    vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 3: Generación y Validación de firma PAdES sin política de firma y con sello de tiempo
	 */
	try {
	    signaturePAdEST = IntegraFacade.generateSignature(dataToSign, privateKey, false, true);
	    if (!SignatureFormatDetector.getSignatureFormat(signaturePAdEST).equals(ISignatureFormatDetector.FORMAT_PADES_LTV) && !SignatureFormatDetector.getSignatureFormat(signaturePAdEST).equals(ISignatureFormatDetector.FORMAT_PADES_T_LEVEL)) {
		assertTrue(false);
	    }
	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 4: Generación y Validación de firma PAdES con política de firma y sello de tiempo
	 */
	try {
	    signaturePAdEST = IntegraFacade.generateSignature(dataToSign, privateKey, true, true);
	    if (!SignatureFormatDetector.getSignatureFormat(signaturePAdEST).equals(ISignatureFormatDetector.FORMAT_PADES_LTV) && !SignatureFormatDetector.getSignatureFormat(signaturePAdEST).equals(ISignatureFormatDetector.FORMAT_PADES_T_LEVEL)) {
		assertTrue(false);
	    }
	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdEST, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 5: Co- firma de una firma PAdES 
	 */
	try {
	    signaturePAdESCoSign = IntegraFacade.generateCoSignature(signaturePAdESBES, null, privateKey, false, false);
	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdESCoSign, null);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 6: Co- firma de una firma PAdES con parámetros nulos
	 */
	try {
	    signaturePAdESCoSign = IntegraFacade.generateCoSignature(null, null, null, false, false);
	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdESCoSign, null);
	    assertTrue(!vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(true);
	}

	/*
	 * Test 7: Contra-firma de una firma PAdES 
	 */
	try {
	    signaturePAdESCounterSign = IntegraFacade.generateCounterSignature(signaturePAdESBES, privateKey, false, false);

	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdESCounterSign, null);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	* Test 7: Contra-firma de una firma PAdES con parámetros nulos
	 */
	try {
	    signaturePAdESCounterSign = IntegraFacade.generateCounterSignature(null, null, false, false);

	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdESCounterSign, null);
	    assertTrue(!vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(true);
	}
    }

    public void testCAdESBaselineSignature() {
	renameProperties("integraFacadeCadesB.properties");

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);
	PrivateKeyEntry privateKey = getCertificatePrivateKey();

	byte[ ] signatureCAdESBLevel = null;
	byte[ ] coSignatureCAdESBLevel = null;
	byte[ ] counterSignatureCAdESBLevel = null;
	byte[ ] signatureCAdESBLevelWithPolicy = null;
	byte[ ] coSignatureCAdESBLevelWithPolicy = null;
	byte[ ] counterSignatureCAdESBLevelWithPolicy = null;
	byte[ ] signatureCAdESTLevel = null;
	byte[ ] coSignatureCAdESTLevel = null;
	byte[ ] counterSignatureCAdESTLevel = null;

	/*
	 * Test 1: Generación, Actualización y Validación de firma CAdES Baseline sin política de firma ni sello de tiempo
	 */
	try {
	    signatureCAdESBLevel = IntegraFacade.generateSignature(dataToSign, privateKey, false, false);
	    assertEquals(SignatureFormatDetector.getSignatureFormat(signatureCAdESBLevel), ISignatureFormatDetector.FORMAT_CADES_B_LEVEL);
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(signatureCAdESBLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	    coSignatureCAdESBLevel = IntegraFacade.generateCoSignature(signatureCAdESBLevel, dataToSign, privateKey, false, false);
	    vr = (ValidationResult) IntegraFacade.verifySignature(coSignatureCAdESBLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	    counterSignatureCAdESBLevel = IntegraFacade.generateCounterSignature(signatureCAdESBLevel, privateKey, false, false);
	    vr = (ValidationResult) IntegraFacade.verifySignature(counterSignatureCAdESBLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	    signatureCAdESTLevel = IntegraFacade.upgradeSignature(signatureCAdESBLevel, null);
	    assertEquals(SignatureFormatDetector.getSignatureFormat(signatureCAdESTLevel), ISignatureFormatDetector.FORMAT_CADES_T_LEVEL);
	    vr = (ValidationResult) IntegraFacade.verifySignature(signatureCAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Generación, Actualización y Validación de firma CAdES Baseline con política de firma sin sello de tiempo
	 */
	try {
	    signatureCAdESBLevelWithPolicy = IntegraFacade.generateSignature(dataToSign, privateKey, true, false);
	    assertEquals(SignatureFormatDetector.getSignatureFormat(signatureCAdESBLevelWithPolicy), ISignatureFormatDetector.FORMAT_CADES_B_LEVEL);
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(signatureCAdESBLevelWithPolicy, dataToSign);
	    assertTrue(vr.isCorrect());
	    coSignatureCAdESBLevelWithPolicy = IntegraFacade.generateCoSignature(signatureCAdESBLevelWithPolicy, dataToSign, privateKey, true, false);
	    vr = (ValidationResult) IntegraFacade.verifySignature(coSignatureCAdESBLevelWithPolicy, dataToSign);
	    assertTrue(vr.isCorrect());
	    counterSignatureCAdESBLevelWithPolicy = IntegraFacade.generateCounterSignature(signatureCAdESBLevelWithPolicy, privateKey, true, false);
	    vr = (ValidationResult) IntegraFacade.verifySignature(counterSignatureCAdESBLevelWithPolicy, dataToSign);
	    assertTrue(vr.isCorrect());
	    signatureCAdESTLevel = IntegraFacade.upgradeSignature(signatureCAdESBLevelWithPolicy, null);
	    assertEquals(SignatureFormatDetector.getSignatureFormat(signatureCAdESTLevel), ISignatureFormatDetector.FORMAT_CADES_T_LEVEL);
	    vr = (ValidationResult) IntegraFacade.verifySignature(signatureCAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 3: Generación y Validación de firma CAdES Baseline sin política de firma y con sello de tiempo
	 */
	try {
	    signatureCAdESTLevel = IntegraFacade.generateSignature(dataToSign, privateKey, false, true);
	    assertEquals(SignatureFormatDetector.getSignatureFormat(signatureCAdESTLevel), ISignatureFormatDetector.FORMAT_CADES_T_LEVEL);
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(signatureCAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	    coSignatureCAdESTLevel = IntegraFacade.generateCoSignature(signatureCAdESTLevel, dataToSign, privateKey, false, true);
	    vr = (ValidationResult) IntegraFacade.verifySignature(coSignatureCAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	    counterSignatureCAdESTLevel = IntegraFacade.generateCounterSignature(signatureCAdESTLevel, privateKey, false, true);
	    vr = (ValidationResult) IntegraFacade.verifySignature(counterSignatureCAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 4: Generación y Validación de firma CAdES Baseline con política de firma y sello de tiempo
	 */
	try {
	    signatureCAdESTLevel = IntegraFacade.generateSignature(dataToSign, privateKey, true, true);
	    assertEquals(SignatureFormatDetector.getSignatureFormat(signatureCAdESTLevel), ISignatureFormatDetector.FORMAT_CADES_T_LEVEL);
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(signatureCAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	    coSignatureCAdESTLevel = IntegraFacade.generateCoSignature(signatureCAdESTLevel, dataToSign, privateKey, true, true);
	    vr = (ValidationResult) IntegraFacade.verifySignature(coSignatureCAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	    counterSignatureCAdESTLevel = IntegraFacade.generateCounterSignature(signatureCAdESTLevel, privateKey, true, true);
	    vr = (ValidationResult) IntegraFacade.verifySignature(counterSignatureCAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    public void testXAdESBaselineSignature() {
	renameProperties("integraFacadeXadesB.properties");

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);
	PrivateKeyEntry privateKey = getCertificatePrivateKey();

	byte[ ] signatureXAdESBLevel = null;
	byte[ ] coSignatureXAdESBLevel = null;
	byte[ ] counterSignatureXAdESBLevel = null;
	byte[ ] signatureXAdESBLevelWithPolicy = null;
	byte[ ] coSignatureXAdESBLevelWithPolicy = null;
	byte[ ] counterSignatureXAdESBLevelWithPolicy = null;
	byte[ ] signatureXAdESTLevel = null;
	byte[ ] coSignatureXAdESTLevel = null;
	byte[ ] counterSignatureXAdESTLevel = null;

	/*
	 * Test 1: Generación, Actualización y Validación de firma XAdES Baseline sin política de firma ni sello de tiempo
	 */
	try {
	    signatureXAdESBLevel = IntegraFacade.generateSignature(dataToSign, privateKey, false, false);
	    assertEquals(SignatureFormatDetector.getSignatureFormat(signatureXAdESBLevel), ISignatureFormatDetector.FORMAT_XADES_B_LEVEL);
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(signatureXAdESBLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	    coSignatureXAdESBLevel = IntegraFacade.generateCoSignature(signatureXAdESBLevel, dataToSign, privateKey, false, false);
	    vr = (ValidationResult) IntegraFacade.verifySignature(coSignatureXAdESBLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	    counterSignatureXAdESBLevel = IntegraFacade.generateCounterSignature(signatureXAdESBLevel, privateKey, false, false);
	    vr = (ValidationResult) IntegraFacade.verifySignature(counterSignatureXAdESBLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	    signatureXAdESTLevel = IntegraFacade.upgradeSignature(signatureXAdESBLevel, null);
	    assertEquals(SignatureFormatDetector.getSignatureFormat(signatureXAdESTLevel), ISignatureFormatDetector.FORMAT_XADES_T_LEVEL);
	    vr = (ValidationResult) IntegraFacade.verifySignature(signatureXAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Generación, Actualización y Validación de firma XAdES Baseline con política de firma sin sello de tiempo
	 */
	try {
	    signatureXAdESBLevelWithPolicy = IntegraFacade.generateSignature(dataToSign, privateKey, true, false);
	    assertEquals(SignatureFormatDetector.getSignatureFormat(signatureXAdESBLevelWithPolicy), ISignatureFormatDetector.FORMAT_XADES_B_LEVEL);
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(signatureXAdESBLevelWithPolicy, dataToSign);
	    assertTrue(vr.isCorrect());
	    coSignatureXAdESBLevelWithPolicy = IntegraFacade.generateCoSignature(signatureXAdESBLevelWithPolicy, dataToSign, privateKey, true, false);
	    vr = (ValidationResult) IntegraFacade.verifySignature(coSignatureXAdESBLevelWithPolicy, dataToSign);
	    assertTrue(vr.isCorrect());
	    counterSignatureXAdESBLevelWithPolicy = IntegraFacade.generateCounterSignature(signatureXAdESBLevelWithPolicy, privateKey, true, false);
	    vr = (ValidationResult) IntegraFacade.verifySignature(counterSignatureXAdESBLevelWithPolicy, dataToSign);
	    assertTrue(vr.isCorrect());
	    signatureXAdESTLevel = IntegraFacade.upgradeSignature(signatureXAdESBLevelWithPolicy, null);
	    assertEquals(SignatureFormatDetector.getSignatureFormat(signatureXAdESTLevel), ISignatureFormatDetector.FORMAT_XADES_T_LEVEL);
	    vr = (ValidationResult) IntegraFacade.verifySignature(signatureXAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 3: Generación y Validación de firma XAdES Baseline sin política de firma y con sello de tiempo
	 */
	try {
	    signatureXAdESTLevel = IntegraFacade.generateSignature(dataToSign, privateKey, false, true);
	    assertEquals(SignatureFormatDetector.getSignatureFormat(signatureXAdESTLevel), ISignatureFormatDetector.FORMAT_XADES_T_LEVEL);
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(signatureXAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	    coSignatureXAdESTLevel = IntegraFacade.generateCoSignature(signatureXAdESTLevel, dataToSign, privateKey, false, true);
	    vr = (ValidationResult) IntegraFacade.verifySignature(coSignatureXAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	    counterSignatureXAdESTLevel = IntegraFacade.generateCounterSignature(signatureXAdESTLevel, privateKey, false, true);
	    vr = (ValidationResult) IntegraFacade.verifySignature(counterSignatureXAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 4: Generación y Validación de firma XAdES Baseline con política de firma y sello de tiempo
	 */
	try {
	    signatureXAdESTLevel = IntegraFacade.generateSignature(dataToSign, privateKey, true, true);
	    assertEquals(SignatureFormatDetector.getSignatureFormat(signatureXAdESTLevel), ISignatureFormatDetector.FORMAT_XADES_T_LEVEL);
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(signatureXAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	    coSignatureXAdESTLevel = IntegraFacade.generateCoSignature(signatureXAdESTLevel, dataToSign, privateKey, true, true);
	    vr = (ValidationResult) IntegraFacade.verifySignature(coSignatureXAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	    counterSignatureXAdESTLevel = IntegraFacade.generateCounterSignature(signatureXAdESTLevel, privateKey, true, true);
	    vr = (ValidationResult) IntegraFacade.verifySignature(counterSignatureXAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    public void testPAdESBaselineSignature() {
	renameProperties("integraFacadePadesB.properties");

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("pdfToSign.pdf", true);
	PrivateKeyEntry privateKey = getCertificatePrivateKey();

	byte[ ] signaturePAdESBLevel = null;
	byte[ ] signaturePAdESBLevelWithPolicy = null;
	byte[ ] signaturePAdESTLevel = null;
	byte[ ] signaturePAdESBCoSign = null;
	byte[ ] signaturePAdESCounterSign = null;
	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.PADES_CERTIFICATION_LEVEL, SignatureConstants.PDF_APPROVAL);

	/*
	 * Test 1: Generación, Actualización y Validación de firma PAdES Baseline sin política de firma ni sello de tiempo
	 */
	try {
	    signaturePAdESBLevel = IntegraFacade.generateSignature(dataToSign, privateKey, false, false);
	    assertEquals(SignatureFormatDetector.getSignatureFormat(signaturePAdESBLevel), ISignatureFormatDetector.FORMAT_PADES_B_LEVEL);
	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdESBLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	    signaturePAdESTLevel = IntegraFacade.upgradeSignature(signaturePAdESBLevel, null);
	    assertEquals(SignatureFormatDetector.getSignatureFormat(signaturePAdESTLevel), ISignatureFormatDetector.FORMAT_PADES_T_LEVEL);
	    vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Generación, Actualización y Validación de firma PAdES Baseline con política de firma sin sello de tiempo
	 */
	try {
	    signaturePAdESBLevelWithPolicy = IntegraFacade.generateSignature(dataToSign, privateKey, true, false);
	    assertEquals(SignatureFormatDetector.getSignatureFormat(signaturePAdESBLevelWithPolicy), ISignatureFormatDetector.FORMAT_PADES_B_LEVEL);
	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdESBLevelWithPolicy, dataToSign);
	    assertTrue(vr.isCorrect());
	    signaturePAdESTLevel = IntegraFacade.upgradeSignature(signaturePAdESBLevelWithPolicy, null);
	    assertEquals(SignatureFormatDetector.getSignatureFormat(signaturePAdESTLevel), ISignatureFormatDetector.FORMAT_PADES_T_LEVEL);
	    vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 3: Generación y Validación de firma PAdES Baseline sin política de firma y con sello de tiempo
	 */
	try {
	    signaturePAdESTLevel = IntegraFacade.generateSignature(dataToSign, privateKey, false, true);
	    assertEquals(SignatureFormatDetector.getSignatureFormat(signaturePAdESTLevel), ISignatureFormatDetector.FORMAT_PADES_T_LEVEL);
	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 4: Generación y Validación de firma PAdES Baseline con política de firma y sello de tiempo
	 */
	try {
	    signaturePAdESTLevel = IntegraFacade.generateSignature(dataToSign, privateKey, true, true);
	    assertEquals(SignatureFormatDetector.getSignatureFormat(signaturePAdESTLevel), ISignatureFormatDetector.FORMAT_PADES_T_LEVEL);
	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdESTLevel, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 5: Cofirma de una firma PAdES Baseline
	 */
	try {
	    signaturePAdESBCoSign = IntegraFacade.generateCoSignature(signaturePAdESBLevel, null, privateKey, false, false);
	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdESBCoSign, null);
	    assertTrue(vr.isCorrect());

	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 6: Cofirma de una firma PAdES Baseline con parámetros nulos.
	 */
	try {
	    signaturePAdESBCoSign = IntegraFacade.generateCoSignature(null, null, null, false, false);
	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdESBCoSign, null);
	    assertTrue(!vr.isCorrect());

	} catch (Exception e) {
	    assertTrue(true);
	}
	/*
	 * Test 7: Contra-firma de una firma PAdES Baseline
	 */
	try {
	    signaturePAdESCounterSign = IntegraFacade.generateCounterSignature(signaturePAdESBLevel, privateKey, false, false);

	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdESCounterSign, null);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 8: Contra-firma de una firma PAdES Baseline, con parámetros nulos.
	 */
	try {
	    signaturePAdESCounterSign = IntegraFacade.generateCounterSignature(null, null, false, false);

	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdESCounterSign, null);
	    assertTrue(!vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(true);
	}

    }

    // public void testASiCSBaselineSignature() {
    // /*
    // * Test 1: Validación de firma ASiC-S Baseline que contiene una firma
    // CAdES sin política de firma ni sello de tiempo
    // */
    //
    // /*
    // * Test 2: Validación de firma ASiC-S Baseline que contiene una firma
    // XAdES sin política de firma ni sello de tiempo
    // */
    //
    // /*
    // * Test 3: Validación de firma ASiC-S Baseline que contiene una firma
    // CAdES con política de firma sin sello de tiempo
    // */
    //
    // /*
    // * Test 4: Validación de firma ASiC-S Baseline que contiene una firma
    // XAdES con política de firma sin sello de tiempo
    // */
    //
    // /*
    // * Test 5: Actualización y Validación de firma ASiC-S Baseline que
    // contiene una firma CAdES sin política de firma ni sello de tiempo
    // */
    //
    // /*
    // * Test 6: Actualización y Validación de firma ASiC-S Baseline que
    // contiene una firma CAdES con política de firma sin sello de tiempo
    // */
    //
    // /*
    // * Test 7: Actualización y Validación de firma ASiC-S Baseline que
    // contiene una firma XAdES sin política de firma ni sello de tiempo
    // */
    //
    // /*
    // * Test 8: Actualización y Validación de firma ASiC-S Baseline que
    // contiene una firma XAdES con política de firma sin sello de tiempo
    // */
    //
    // }

    private static void renameProperties(String fileToRename) {
	String url;
	if (System.getProperty("integra.config") != null) {
	    url = System.getProperty("integra.config") + "/";
	} else {
	    url = IntegraProperties.class.getClassLoader().getResource(IIntegraConstants.DEFAULT_PROPERTIES_FILE).toString();
	}

	url = url.replace(IIntegraConstants.DEFAULT_PROPERTIES_FILE, "");
	url = url.replace("file:/", "");
	File f1 = new File(url + IIntegraConstants.DEFAULT_PROPERTIES_FILE);

	System.out.println("delete: " + f1.delete());

	File f2 = new File(url + fileToRename);

	try {
	    InputStream is = null;
	    OutputStream os = null;
	    try {
		is = new FileInputStream(f2);
		os = new FileOutputStream(f1);
		byte[ ] buffer = new byte[1024];
		int length;
		while ((length = is.read(buffer)) > 0) {
		    os.write(buffer, 0, length);
		}
	    } finally {
		is.close();
		os.close();
	    }
	} catch (IOException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}

    }

    /**
     * Test for methods {@link IntegraFacade#getSignedData(byte[])}.
     */
    public final void testGetSignedData() {
	byte[ ] signature = null;
	OriginalSignedData osd = null;

	/* Test 1: Obtención datos firma PAdES */
	signature = UtilsFileSystemCommons.readFile("signatures/PDF/PAdES-BES.pdf", true);
	try {
	    osd = IntegraFacade.getSignedData(signature);
	    assertNotNull(osd.getSignedData());
	    assertNotNull(osd.getMimetype());
	    assertNull(osd.getHashAlgorithm());
	    assertNull(osd.getHashSignedData());
	} catch (SigningException e) {
	    assertTrue(false);
	}

	/* Test 2: Obtención datos firmas XAdES, firmas no permitidas*/

	signature = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-A.xml", true);
	try {
	    osd = IntegraFacade.getSignedData(signature);
	} catch (SigningException e) {
	    assertTrue(true);
	}

	/* Test 3: Obtención datos firma CAdES implicita */
	signature = UtilsFileSystemCommons.readFile("signatures/ASN1/CAdES-EPES.p7s", true);
	try {
	    osd = IntegraFacade.getSignedData(signature);
	    assertNotNull(osd.getSignedData());
	    assertNotNull(osd.getMimetype());
	    assertNull(osd.getHashAlgorithm());
	    assertNull(osd.getHashSignedData());
	} catch (SigningException e) {
	    assertTrue(false);
	}

	/* Test 4: Obtención datos firma CAdES explícita */
	signature = UtilsFileSystemCommons.readFile("signatures/ASN1/CAdES-Explicit.p7s", true);
	try {
	    osd = IntegraFacade.getSignedData(signature);
	    assertNull(osd.getSignedData());
	    assertNotNull(osd.getMimetype());
	    assertNotNull(osd.getHashAlgorithm());
	    assertNotNull(osd.getHashSignedData());
	} catch (SigningException e) {
	    assertTrue(false);
	}

	/* Test 5: Obtención datos firma ASiC-S */
	signature = UtilsFileSystemCommons.readFile("signatures/ASiC/ASiC_S_XAdES.asics", true);
	try {
	    osd = IntegraFacade.getSignedData(signature);
	    assertNotNull(osd.getSignedData());
	    assertNotNull(osd.getMimetype());
	    assertNull(osd.getHashAlgorithm());
	    assertNull(osd.getHashSignedData());
	} catch (SigningException e) {
	    assertTrue(false);
	}

	/* Test 5: Obtención datos firma ASiC-S con sello de tiempo*/
	signature = UtilsFileSystemCommons.readFile("signatures/ASiC/ASiC_S_Timestamp.asics", true);
	try {
	    osd = IntegraFacade.getSignedData(signature);

	} catch (SigningException e) {
	    assertTrue(true);
	}

    }

    /**
     * Test for methods {@link IntegraFacade#generateSignaturePAdESRubric(byte[], PrivateKeyEntry, boolean, boolean, String, String, int, int, int, int)}.
     */
    public final void testPAdESSignatureWithRubric() {
	renameProperties("integraFacadePades.properties");

	// documento que se va a firmar.
	byte[ ] dataToSign = UtilsFileSystemCommons.readFile(PDF_DOCUMENT_PATH, true);

	byte[ ] image = UtilsFileSystemCommons.readFile(PATH_IMAGE, true);

	// parámetros relacionados con la rúbrica y la posición que ocupará en
	// el documento.
	String imagePage = "-1"; // se inserta en la última página de documento.

	PrivateKeyEntry privateKey = getCertificatePrivateKey();

	byte[ ] signaturePAdESRubric = null;
	byte[ ] signaturePAdESBaselineRubric = null;
	/*
	 * Test 1: Generación de firma PAdES con Rúbrica
	 */
	try {
	    signaturePAdESRubric = IntegraFacade.generateSignaturePAdESRubric(dataToSign, privateKey, false, false, image, imagePage, LOWER_LEFT_X, LOWER_LEFT_Y, UPPER_RIGHT_X, UPPER_RIGHT_Y);
	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdESRubric, dataToSign);
	    assertTrue(vr.isCorrect());

	} catch (Exception e) {
	    assertTrue(false);
	}
	/*
	* Test 2: Insertar rúbrica pasando un número de página inválido
	*/
	try {
	    signaturePAdESRubric = IntegraFacade.generateSignaturePAdESRubric(dataToSign, privateKey, false, false, image, "0", LOWER_LEFT_X, LOWER_LEFT_Y, UPPER_RIGHT_X, UPPER_RIGHT_Y);

	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	} catch (SigningException e) {
	    assertTrue(false);
	}

	/*
	* Test 3: Insertar rúbrica pasando un número de página mayor que el
	número de páginas del documento.
	*/
	try {
	    signaturePAdESRubric = IntegraFacade.generateSignaturePAdESRubric(dataToSign, privateKey, false, false, image, "10", LOWER_LEFT_X, LOWER_LEFT_Y, UPPER_RIGHT_X, UPPER_RIGHT_Y);

	} catch (SigningException e) {
	    assertTrue(true);
	}

	/*
	* Test 4: Generación de firma PAdES Baseline con Rúbrica
	*/

	renameProperties("integraFacadePadesB.properties");
	try {
	    signaturePAdESBaselineRubric = IntegraFacade.generateSignaturePAdESRubric(dataToSign, privateKey, false, false, image, imagePage, LOWER_LEFT_X, LOWER_LEFT_Y, UPPER_RIGHT_X, UPPER_RIGHT_Y);
	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdESBaselineRubric, dataToSign);
	    assertTrue(vr.isCorrect());

	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 5: Generación de firma PAdES Baseline con Rúbrica con formato no permitido.
	 */
	try {
	    image = UtilsFileSystemCommons.readFile(PATH_IMAGE_INVALID, true);
	    signaturePAdESBaselineRubric = IntegraFacade.generateSignaturePAdESRubric(dataToSign, privateKey, false, false, image, imagePage, LOWER_LEFT_X, LOWER_LEFT_Y, UPPER_RIGHT_X, UPPER_RIGHT_Y);
	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(signaturePAdESBaselineRubric, dataToSign);
	    assertFalse(vr.isCorrect());

	} catch (SigningException e) {
	    assertTrue(true);
	}

    }

    /**
     * Test for methods {@link IntegraFacade#generateMultiSignaturePAdESRubric(byte[], PrivateKeyEntry, boolean, boolean, byte[], String, int, int, int, int).
     */
    public final void testPAdESMultiSignatureWithRubric() {
	renameProperties("integraFacadePades.properties");

	// documento que se va a firmar.
	byte[ ] dataToCoSign = UtilsFileSystemCommons.readFile(PDF_DOCUMENT_PATH_TO_COSIGN_RUBRIC, true);

	byte[ ] image = UtilsFileSystemCommons.readFile(PATH_IMAGE, true);

	// parámetros relacionados con la rúbrica y la posición que ocupará en
	// el documento.
	String imagePage = "1";

	PrivateKeyEntry privateKey = getCertificatePrivateKey();

	byte[ ] multiSignaturePAdESRubric = null;
	byte[ ] multiSignaturePAdESBaselineRubric = null;
	/*
	 * Test 1: Generación de firma PAdES con Rúbrica
	 */
	try {
	    multiSignaturePAdESRubric = IntegraFacade.generateMultiSignaturePAdESRubric(dataToCoSign, privateKey, false, false, image, imagePage, LOWER_LEFT_X, LOWER_LEFT_Y, UPPER_RIGHT_X, UPPER_RIGHT_Y);
	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(multiSignaturePAdESRubric, dataToCoSign);
	    assertTrue(vr.isCorrect());

	} catch (Exception e) {
	    assertTrue(false);
	}
	/*
	* Test 2: Insertar rúbrica pasando un número de página inválido
	*/
	try {
	    multiSignaturePAdESRubric = IntegraFacade.generateMultiSignaturePAdESRubric(dataToCoSign, privateKey, false, false, image, "0", LOWER_LEFT_X, LOWER_LEFT_Y, UPPER_RIGHT_X, UPPER_RIGHT_Y);

	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	} catch (SigningException e) {
	    assertTrue(false);
	}

	/*
	* Test 3: Insertar rúbrica pasando un número de página mayor que el
	número de páginas del documento.
	*/
	try {
	    multiSignaturePAdESRubric = IntegraFacade.generateMultiSignaturePAdESRubric(dataToCoSign, privateKey, false, false, image, "10", LOWER_LEFT_X, LOWER_LEFT_Y, UPPER_RIGHT_X, UPPER_RIGHT_Y);

	} catch (SigningException e) {
	    assertTrue(true);
	}

	/*
	* Test 4: Generación de firma PAdES Baseline con Rúbrica
	*/

	renameProperties("integraFacadePadesB.properties");
	try {
	    multiSignaturePAdESBaselineRubric = IntegraFacade.generateMultiSignaturePAdESRubric(dataToCoSign, privateKey, false, false, image, imagePage, LOWER_LEFT_X, LOWER_LEFT_Y, UPPER_RIGHT_X, UPPER_RIGHT_Y);
	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(multiSignaturePAdESBaselineRubric, dataToCoSign);
	    assertTrue(vr.isCorrect());

	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 5: Generación de firma PAdES Baseline con Rúbrica con formato no permitido.
	 */
	try {
	    image = UtilsFileSystemCommons.readFile(PATH_IMAGE_INVALID, true);
	    multiSignaturePAdESBaselineRubric = IntegraFacade.generateMultiSignaturePAdESRubric(dataToCoSign, privateKey, false, false, image, imagePage, LOWER_LEFT_X, LOWER_LEFT_Y, UPPER_RIGHT_X, UPPER_RIGHT_Y);
	    PDFValidationResult vr = (PDFValidationResult) IntegraFacade.verifySignature(multiSignaturePAdESBaselineRubric, dataToCoSign);
	    assertFalse(vr.isCorrect());

	} catch (SigningException e) {
	    assertTrue(true);
	}

    }

    /**
     * Test for methods {@link IntegraFacade#generateSignature(byte[], PrivateKeyEntry, boolean, boolean).
     * 
     */
    public final void testGenerateSignatureASiCSBaseline() {
	byte[ ] dataToSignCades = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);
	byte[ ] dataToSignXades = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);

	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	byte[ ] asicsBaselineCadesB = null;
	byte[ ] asicsBaselineXadesB = null;
	/*
	 * Test 1 : Generacion de firma ASiC-S Baseline con una firma CAdES Baseline.
	 */
	renameProperties("integraFacadeAsicsCadesB.properties");
	try {
	    asicsBaselineCadesB = IntegraFacade.generateSignature(dataToSignCades, privateKey, false, false);
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(asicsBaselineCadesB, dataToSignCades);
	    assertTrue(vr.isCorrect());
	} catch (SigningException e) {
	    assertTrue(false);
	}

	/*
	* Test 2: Generación de firma ASiC-S Baseline con una firma CAdES
	Baseline y sello de tiempo.
	*/
	try {
	    asicsBaselineCadesB = IntegraFacade.generateSignature(dataToSignCades, privateKey, false, true);
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(asicsBaselineCadesB, dataToSignCades);
	    assertTrue(vr.isCorrect());
	} catch (SigningException e) {
	    assertTrue(false);
	}

	/*
	* Test 3 : Generacion de firma ASiC-S Baseline con una firma CAdES
	Baseline, con sello de tiempo y política de firma.
	*/
	renameProperties("integraFacadeAsicsCadesB.properties");
	try {
	    asicsBaselineCadesB = IntegraFacade.generateSignature(dataToSignCades, privateKey, true, false);
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(asicsBaselineCadesB, dataToSignCades);
	    assertTrue(vr.isCorrect());
	} catch (SigningException e) {
	    assertTrue(false);
	}

	/*
	* Test 4: Generación de firma ASiC-S Baseline con una firma XAdES
	Baseline.
	*/
	renameProperties("integraFacadeAsicsXadesB.properties");
	try {
	    asicsBaselineXadesB = IntegraFacade.generateSignature(dataToSignXades, privateKey, false, true);
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(asicsBaselineXadesB, dataToSignXades);
	    assertTrue(vr.isCorrect());
	} catch (SigningException e) {
	    assertTrue(false);
	}

	/*
	 * Test 5: Generación de firma ASiC-S Baseline con una firma XAdES Baseline con sello de tiempo.
	 */
	renameProperties("integraFacadeAsicsXadesB.properties");
	try {
	    asicsBaselineXadesB = IntegraFacade.generateSignature(dataToSignXades, privateKey, false, true);

	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(asicsBaselineXadesB, dataToSignXades);
	    assertTrue(vr.isCorrect());
	} catch (SigningException e) {
	    assertTrue(false);
	}

	/*
	* Test 6: Generación de firma ASiC-S Baseline con una firma XAdES
	Baseline con sello de tiempo y política de firma.
	*/
	renameProperties("integraFacadeAsicsXadesB.properties");
	try {
	    asicsBaselineXadesB = IntegraFacade.generateSignature(dataToSignXades, privateKey, true, true);
	    ValidationResult vr = (ValidationResult) IntegraFacade.verifySignature(asicsBaselineXadesB, dataToSignXades);
	    assertTrue(vr.isCorrect());
	} catch (SigningException e) {
	    assertTrue(false);
	}

    }

}
