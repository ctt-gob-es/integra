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
 * <b>File:</b><p>es.gob.afirma.signature.cades.CAdESBaselineSigner.java.</p>
 * <b>Description:</b><p>Class that defines tests for {@link CAdESBaselineSigner}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>18/01/2016.</p>
 * @author Gobierno de España.
 * @version 1.3, 06/03/2020.
 */
package es.gob.afirma.signature.cades;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.MessageDigest;

import es.gob.afirma.signature.ISignatureFormatDetector;
import es.gob.afirma.signature.OriginalSignedData;
import es.gob.afirma.signature.SignatureConstants;
import es.gob.afirma.signature.SignatureFormatDetectorCadesPades;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.signature.validation.ValidationResult;
import es.gob.afirma.utils.CryptoUtilCommons;
import es.gob.afirma.utils.UtilsFileSystemCommons;
import junit.framework.TestCase;

/**
 * <p>Class that defines tests for {@link CAdESBaselineSigner}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.3, 06/03/2020.
 */
public class CAdESBaselineSignerTest extends TestCase {

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

    /**
     * Test for methods {@link CAdESBaselineSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link CAdESBaselineSigner#coSign(byte[], byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link CAdESBaselineSigner#counterSign(byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link CAdESBaselineSigner#verifySignature(byte[], byte[])}.
     */
    public final void testSignWithoutTimestamp() {

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);

	// byte[ ] dataToSign =
	// UtilsFileSystemCommons.readFile("D:/KitPruebas/bin/firmaElectronica/fileToSign.log",
	// false);

	CAdESBaselineSigner signer = new CAdESBaselineSigner();
	byte[ ] cadesBLevelSignature = null;
	byte[ ] cadesBLevelCoSignature = null;
	byte[ ] cadesBLevelCounterSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();

	/*
	 * Generación y Validación de firma CAdES B-Level explícita sin política de firma y algoritmo SHA-256
	 */
	try {
	    cadesBLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    assertEquals(SignatureFormatDetectorCadesPades.getSignatureFormat(cadesBLevelSignature), ISignatureFormatDetector.FORMAT_CADES_B_LEVEL);
	    ValidationResult vr = signer.verifySignature(cadesBLevelSignature, dataToSign);
	    assertTrue(vr.isCorrect());

	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma CAdES B-Level explícita sin política de firma y algoritmo SHA-1
	 */
	try {
	    cadesBLevelCoSignature = signer.coSign(cadesBLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(cadesBLevelCoSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de contra-firma CAdES B-Level explícita sin política de firma y algoritmo SHA-512
	 */
	try {
	    cadesBLevelCounterSignature = signer.counterSign(cadesBLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(cadesBLevelCounterSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Generación y Validación de firma CAdES B-Level explícita con política de firma y algoritmo SHA-256
	 */
	try {
	    cadesBLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    assertEquals(SignatureFormatDetectorCadesPades.getSignatureFormat(cadesBLevelSignature), ISignatureFormatDetector.FORMAT_CADES_B_LEVEL);
	    ValidationResult vr = signer.verifySignature(cadesBLevelSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma CAdES B-Level explícita con política de firma y algoritmo SHA-1
	 */
	try {
	    cadesBLevelCoSignature = signer.coSign(cadesBLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    ValidationResult vr = signer.verifySignature(cadesBLevelCoSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de contra-firma CAdES B-Level explícita con política de firma y algoritmo SHA-512
	 */
	try {
	    cadesBLevelCounterSignature = signer.counterSign(cadesBLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    ValidationResult vr = signer.verifySignature(cadesBLevelCoSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Generación y Validación de firma CAdES B-Level explícita sin política de firma, algoritmo SHA-256 y con hash de fichero.
	 */
	try {
	    MessageDigest md = MessageDigest.getInstance(CryptoUtilCommons.HASH_ALGORITHM_SHA256);
	    byte[ ] hashToSign = md.digest(dataToSign);
	    cadesBLevelSignature = signer.sign(hashToSign, CryptoUtilCommons.HASH_ALGORITHM_SHA256, SignatureConstants.SIGN_MODE_EXPLICIT_HASH, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    assertEquals(SignatureFormatDetectorCadesPades.getSignatureFormat(cadesBLevelSignature), ISignatureFormatDetector.FORMAT_CADES_B_LEVEL);
	    ValidationResult vr = signer.verifySignature(cadesBLevelSignature, dataToSign);
	    assertTrue(vr.isCorrect());

	} catch (Exception e) {
	    assertTrue(false);
	}

    }

    /**
     * Test for methods {@link CAdESBaselineSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link CAdESBaselineSigner#coSign(byte[], byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link CAdESBaselineSigner#counterSign(byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link CAdESBaselineSigner#verifySignature(byte[], byte[])}.
     */
    public final void testSignWithTimestamp() {

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);
	// byte[ ] dataToSign =
	// UtilsFileSystemCommons.readFile("D:/KitPruebas/bin/firmaElectronica/fileToSign.log",
	// false);

	CAdESBaselineSigner signer = new CAdESBaselineSigner();
	byte[ ] cadesTLevelSignature = null;
	byte[ ] cadesTLevelCoSignature = null;
	byte[ ] cadesTLevelCounterSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();

	/*
	 * Generación y Validación de firma CAdES T-Level explícita sin política de firma y algoritmo SHA-256
	 */
	try {
	    cadesTLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, true, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    assertEquals(SignatureFormatDetectorCadesPades.getSignatureFormat(cadesTLevelSignature), ISignatureFormatDetector.FORMAT_CADES_T_LEVEL);
	    ValidationResult vr = signer.verifySignature(cadesTLevelSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma CAdES T-Level explícita sin política de firma y algoritmo SHA-1
	 */
	try {
	    cadesTLevelCoSignature = signer.coSign(cadesTLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, privateKey, null, true, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(cadesTLevelCoSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de contra-firma CAdES T-Level explícita sin
	política de firma y algoritmo SHA-512
	*/
	try {
	    cadesTLevelCounterSignature = signer.counterSign(cadesTLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, null, true, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(cadesTLevelCounterSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de firma CAdES T-Level explícita con
	política de firma y algoritmo SHA-256
	*/
	try {
	    cadesTLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, true, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    assertEquals(SignatureFormatDetectorCadesPades.getSignatureFormat(cadesTLevelSignature), ISignatureFormatDetector.FORMAT_CADES_T_LEVEL);
	    ValidationResult vr = signer.verifySignature(cadesTLevelSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de co-firma CAdES T-Level explícita con
	política de firma y algoritmo SHA-1
	*/
	try {
	    cadesTLevelCoSignature = signer.coSign(cadesTLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, privateKey, null, true, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    ValidationResult vr = signer.verifySignature(cadesTLevelCoSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de contra-firma CAdES T-Level explícita con
	política de firma y algoritmo SHA-512
	*/
	try {
	    cadesTLevelCounterSignature = signer.counterSign(cadesTLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, null, true, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    ValidationResult vr = signer.verifySignature(cadesTLevelCoSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
        * Test for methods {@link CAdESBaselineSigner#getSignedData(byte[])}.
        */
    public final void testGetSignedDataCadesImplicit() {

	// se obtiene la firma CAdES implícita
	byte[ ] signature = UtilsFileSystemCommons.readFile("signatures/ASN1/CAdES_B_implicit.p7s", true);
	CAdESBaselineSigner csb = new CAdESBaselineSigner();
	OriginalSignedData osd = new OriginalSignedData();

	try {
	    // se obtiene los datos firmados
	    osd = csb.getSignedData(signature);
	    assertNotNull(osd.getSignedData());
	    assertNotNull(osd.getMimetype());
	    assertNull(osd.getHashAlgorithm());
	    assertNull(osd.getHashSignedData());

	} catch (SigningException e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for methods {@link CAdESBaselineSigner#getSignedData(byte[])}.
     */
    public final void testGetSignedDataCadesExplicit() {

	// se obtiene firma CAdES explícita
	byte[ ] signature = UtilsFileSystemCommons.readFile("signatures/ASN1/CAdES-Explicit.p7s", true);
	CAdESBaselineSigner csb = new CAdESBaselineSigner();
	OriginalSignedData osd = new OriginalSignedData();

	try {
	    // se obtiene los datos firmados

	    osd = csb.getSignedData(signature);
	    assertNull(osd.getSignedData());
	    assertNotNull(osd.getMimetype());
	    assertNotNull(osd.getHashAlgorithm());
	    assertNotNull(osd.getHashSignedData());
	} catch (SigningException e) {
	    assertTrue(false);
	}

    }

}
