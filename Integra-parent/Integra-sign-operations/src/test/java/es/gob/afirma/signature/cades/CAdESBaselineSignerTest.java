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
// https://eupl.eu/1.1/es/

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
import es.gob.afirma.utils.Base64CoderCommons;
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
	    final InputStream is = new FileInputStream(ClassLoader.getSystemResource("keyStoreJCEKS.jks").getFile());
	    final KeyStore ks = KeyStore.getInstance("JCEKS");
	    final char[ ] password = "12345".toCharArray();
	    ks.load(is, password);
	    key = ks.getEntry("raul conde", new KeyStore.PasswordProtection(password));
	} catch (final Exception e) {
	    return null;
	}
	return (KeyStore.PrivateKeyEntry) key;

    }
    
    /**
     * Method that obtains the private key to use for tests.
     * @return the private key to use for tests.
     */
    private PrivateKeyEntry getCertificateECCPrivateKey() {
	KeyStore.Entry key = null;
	try {
	    final InputStream is = new FileInputStream(ClassLoader.getSystemResource("ECC_Signer.p12").getFile());
	    final KeyStore ks = KeyStore.getInstance("PKCS12");
	    final char[ ] password = "ciudadanosw_ecc_2023v1".toCharArray();
	    ks.load(is, password);
	    key = ks.getEntry("MANUELA BLANCO VIDAL - NIF:10000322Z", new KeyStore.PasswordProtection(password));
	} catch (final Exception e) {
	    return null;
	}
	return (KeyStore.PrivateKeyEntry) key;

    }

    /**
     * Test for methods {@link CAdESBaselineSigner#sign(byte[], String, String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link CAdESBaselineSigner#coSign(byte[], byte[], String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link CAdESBaselineSigner#counterSign(byte[], String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link CAdESBaselineSigner#verifySignature(byte[], byte[])}.
     */
    public final void testSignWithoutTimestamp() {

	final byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);

	// byte[ ] dataToSign =
	// UtilsFileSystemCommons.readFile("D:/KitPruebas/bin/firmaElectronica/fileToSign.log",
	// false);

	final CAdESBaselineSigner signer = new CAdESBaselineSigner();
	byte[ ] cadesBLevelSignature = null;
	byte[ ] cadesBLevelCoSignature = null;
	byte[ ] cadesBLevelCounterSignature = null;
	final PrivateKeyEntry privateKey = getCertificatePrivateKey();

	/*
	 * Generación y Validación de firma CAdES B-Level explícita sin política de firma y algoritmo SHA-256
	 */
	try {
	    cadesBLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    assertEquals(SignatureFormatDetectorCadesPades.getSignatureFormat(cadesBLevelSignature), ISignatureFormatDetector.FORMAT_CADES_B_LEVEL);
	    final ValidationResult vr = signer.verifySignature(cadesBLevelSignature, dataToSign);
	    assertTrue(vr.isCorrect());

	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma CAdES B-Level explícita sin política de firma y algoritmo SHA-1
	 */
	try {
	    cadesBLevelCoSignature = signer.coSign(cadesBLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    final ValidationResult vr = signer.verifySignature(cadesBLevelCoSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de contra-firma CAdES B-Level explícita sin política de firma y algoritmo SHA-512
	 */
	try {
	    cadesBLevelCounterSignature = signer.counterSign(cadesBLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    final ValidationResult vr = signer.verifySignature(cadesBLevelCounterSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 * Generación y Validación de firma CAdES B-Level explícita con política de firma y algoritmo SHA-256
	 */
	try {
	    cadesBLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    assertEquals(SignatureFormatDetectorCadesPades.getSignatureFormat(cadesBLevelSignature), ISignatureFormatDetector.FORMAT_CADES_B_LEVEL);
	    final ValidationResult vr = signer.verifySignature(cadesBLevelSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma CAdES B-Level explícita con política de firma y algoritmo SHA-1
	 */
	try {
	    cadesBLevelCoSignature = signer.coSign(cadesBLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    final ValidationResult vr = signer.verifySignature(cadesBLevelCoSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de contra-firma CAdES B-Level explícita con política de firma y algoritmo SHA-512
	 */
	try {
	    cadesBLevelCounterSignature = signer.counterSign(cadesBLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    final ValidationResult vr = signer.verifySignature(cadesBLevelCoSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 * Generación y Validación de firma CAdES B-Level explícita sin política de firma, algoritmo SHA-256 y con hash de fichero.
	 */
	try {
	    final MessageDigest md = MessageDigest.getInstance(CryptoUtilCommons.HASH_ALGORITHM_SHA256);
	    final byte[ ] hashToSign = md.digest(dataToSign);
	    cadesBLevelSignature = signer.sign(hashToSign, CryptoUtilCommons.HASH_ALGORITHM_SHA256, SignatureConstants.SIGN_MODE_EXPLICIT_HASH, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    assertEquals(SignatureFormatDetectorCadesPades.getSignatureFormat(cadesBLevelSignature), ISignatureFormatDetector.FORMAT_CADES_B_LEVEL);
	    final ValidationResult vr = signer.verifySignature(cadesBLevelSignature, dataToSign);
	    assertTrue(vr.isCorrect());

	} catch (final Exception e) {
	    assertTrue(false);
	}

    }
    
    /**
     * Test for methods {@link CAdESBaselineSigner#sign(byte[], String, String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link CAdESBaselineSigner#coSign(byte[], byte[], String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link CAdESBaselineSigner#counterSign(byte[], String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link CAdESBaselineSigner#verifySignature(byte[], byte[])}.
     */
    public final void testSignECCWithoutTimestamp() {

	final byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);

	// byte[ ] dataToSign =
	// UtilsFileSystemCommons.readFile("D:/KitPruebas/bin/firmaElectronica/fileToSign.log",
	// false);

	final CAdESBaselineSigner signer = new CAdESBaselineSigner();
	byte[ ] cadesBLevelSignature = null;
	byte[ ] cadesBLevelCoSignature = null;
	byte[ ] cadesBLevelCounterSignature = null;
	final PrivateKeyEntry privateKey = getCertificateECCPrivateKey();

	/*
	 * Generación y Validación de firma CAdES B-Level explícita sin política de firma y algoritmo SHA-256
	 */
	try {
	    cadesBLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256, SignatureConstants.SIGN_MODE_IMPLICIT, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    assertEquals(SignatureFormatDetectorCadesPades.getSignatureFormat(cadesBLevelSignature), ISignatureFormatDetector.FORMAT_CADES_B_LEVEL);
	    final ValidationResult vr = signer.verifySignature(cadesBLevelSignature, dataToSign);
	    assertTrue(vr.isCorrect());
		System.out.println("\n-->>FIRMA RESULTANTE : \n" + new String(Base64CoderCommons.encodeBase64(cadesBLevelSignature)));

	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma CAdES B-Level explícita sin política de firma y algoritmo SHA-1
	 */
	try {
	    cadesBLevelCoSignature = signer.coSign(cadesBLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    final ValidationResult vr = signer.verifySignature(cadesBLevelCoSignature, dataToSign);
	    assertTrue(vr.isCorrect());
		System.out.println("\n-->>FIRMA RESULTANTE : \n" + new String(Base64CoderCommons.encodeBase64(cadesBLevelCoSignature)));
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de contra-firma CAdES B-Level explícita sin política de firma y algoritmo SHA-512
	 */
	try {
	    cadesBLevelCounterSignature = signer.counterSign(cadesBLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    final ValidationResult vr = signer.verifySignature(cadesBLevelCounterSignature, dataToSign);
	    assertTrue(vr.isCorrect());
		System.out.println("\n-->>FIRMA RESULTANTE : \n" + new String(Base64CoderCommons.encodeBase64(cadesBLevelCounterSignature)));
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 * Generación y Validación de firma CAdES B-Level explícita con política de firma y algoritmo SHA-256
	 */
	try {
	    cadesBLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    assertEquals(SignatureFormatDetectorCadesPades.getSignatureFormat(cadesBLevelSignature), ISignatureFormatDetector.FORMAT_CADES_B_LEVEL);
	    final ValidationResult vr = signer.verifySignature(cadesBLevelSignature, dataToSign);
	    assertTrue(vr.isCorrect());
		System.out.println("\n-->>FIRMA RESULTANTE : \n" + new String(Base64CoderCommons.encodeBase64(cadesBLevelSignature)));
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma CAdES B-Level explícita con política de firma y algoritmo SHA-1
	 */
	try {
	    cadesBLevelCoSignature = signer.coSign(cadesBLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    final ValidationResult vr = signer.verifySignature(cadesBLevelCoSignature, dataToSign);
	    assertTrue(vr.isCorrect());
		System.out.println("\n-->>FIRMA RESULTANTE : \n" + new String(Base64CoderCommons.encodeBase64(cadesBLevelCoSignature)));
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de contra-firma CAdES B-Level explícita con política de firma y algoritmo SHA-512
	 */
	try {
	    cadesBLevelCounterSignature = signer.counterSign(cadesBLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    final ValidationResult vr = signer.verifySignature(cadesBLevelCoSignature, dataToSign);
	    assertTrue(vr.isCorrect());
		System.out.println("\n-->>FIRMA RESULTANTE : \n" + new String(Base64CoderCommons.encodeBase64(cadesBLevelCounterSignature)));
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 * Generación y Validación de firma CAdES B-Level explícita sin política de firma, algoritmo SHA-256 y con hash de fichero.
	 */
	try {
	    final MessageDigest md = MessageDigest.getInstance(CryptoUtilCommons.HASH_ALGORITHM_SHA256);
	    final byte[ ] hashToSign = md.digest(dataToSign);
	    cadesBLevelSignature = signer.sign(hashToSign, CryptoUtilCommons.HASH_ALGORITHM_SHA256, SignatureConstants.SIGN_MODE_EXPLICIT_HASH, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    assertEquals(SignatureFormatDetectorCadesPades.getSignatureFormat(cadesBLevelSignature), ISignatureFormatDetector.FORMAT_CADES_B_LEVEL);
	    final ValidationResult vr = signer.verifySignature(cadesBLevelSignature, dataToSign);
	    assertTrue(vr.isCorrect());
		System.out.println("\n-->>FIRMA RESULTANTE : \n" + new String(Base64CoderCommons.encodeBase64(cadesBLevelSignature)));

	} catch (final Exception e) {
	    assertTrue(false);
	}

    }

    /**
     * Test for methods {@link CAdESBaselineSigner#sign(byte[], String, String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link CAdESBaselineSigner#coSign(byte[], byte[], String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link CAdESBaselineSigner#counterSign(byte[], String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link CAdESBaselineSigner#verifySignature(byte[], byte[])}.
     */
    public final void testSignWithTimestamp() {

	final byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);
	// byte[ ] dataToSign =
	// UtilsFileSystemCommons.readFile("D:/KitPruebas/bin/firmaElectronica/fileToSign.log",
	// false);

	final CAdESBaselineSigner signer = new CAdESBaselineSigner();
	byte[ ] cadesTLevelSignature = null;
	byte[ ] cadesTLevelCoSignature = null;
	byte[ ] cadesTLevelCounterSignature = null;
	final PrivateKeyEntry privateKey = getCertificatePrivateKey();

	/*
	 * Generación y Validación de firma CAdES T-Level explícita sin política de firma y algoritmo SHA-256
	 */
	try {
	    cadesTLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, true, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    assertEquals(SignatureFormatDetectorCadesPades.getSignatureFormat(cadesTLevelSignature), ISignatureFormatDetector.FORMAT_CADES_T_LEVEL);
	    final ValidationResult vr = signer.verifySignature(cadesTLevelSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma CAdES T-Level explícita sin política de firma y algoritmo SHA-1
	 */
	try {
	    cadesTLevelCoSignature = signer.coSign(cadesTLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, privateKey, null, true, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    final ValidationResult vr = signer.verifySignature(cadesTLevelCoSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de contra-firma CAdES T-Level explícita sin
	política de firma y algoritmo SHA-512
	*/
	try {
	    cadesTLevelCounterSignature = signer.counterSign(cadesTLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, null, true, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    final ValidationResult vr = signer.verifySignature(cadesTLevelCounterSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de firma CAdES T-Level explícita con
	política de firma y algoritmo SHA-256
	*/
	try {
	    cadesTLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, true, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    assertEquals(SignatureFormatDetectorCadesPades.getSignatureFormat(cadesTLevelSignature), ISignatureFormatDetector.FORMAT_CADES_T_LEVEL);
	    final ValidationResult vr = signer.verifySignature(cadesTLevelSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de co-firma CAdES T-Level explícita con
	política de firma y algoritmo SHA-1
	*/
	try {
	    cadesTLevelCoSignature = signer.coSign(cadesTLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, privateKey, null, true, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    final ValidationResult vr = signer.verifySignature(cadesTLevelCoSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de contra-firma CAdES T-Level explícita con
	política de firma y algoritmo SHA-512
	*/
	try {
	    cadesTLevelCounterSignature = signer.counterSign(cadesTLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, null, true, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    final ValidationResult vr = signer.verifySignature(cadesTLevelCoSignature, dataToSign);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}
    }

    /**
        * Test for methods {@link CAdESBaselineSigner#getSignedData(byte[])}.
        */
    public final void testGetSignedDataCadesImplicit() {

	// se obtiene la firma CAdES implícita
	final byte[ ] signature = UtilsFileSystemCommons.readFile("signatures/ASN1/CAdES_B_implicit.p7s", true);
	final CAdESBaselineSigner csb = new CAdESBaselineSigner();
	OriginalSignedData osd = new OriginalSignedData();

	try {
	    // se obtiene los datos firmados
	    osd = csb.getSignedData(signature);
	    assertNotNull(osd.getSignedData());
	    assertNotNull(osd.getMimetype());
	    assertNull(osd.getHashAlgorithm());
	    assertNull(osd.getHashSignedData());

	} catch (final SigningException e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for methods {@link CAdESBaselineSigner#getSignedData(byte[])}.
     */
    public final void testGetSignedDataCadesExplicit() {

	// se obtiene firma CAdES explícita
	final byte[ ] signature = UtilsFileSystemCommons.readFile("signatures/ASN1/CAdES-Explicit.p7s", true);
	final CAdESBaselineSigner csb = new CAdESBaselineSigner();
	OriginalSignedData osd = new OriginalSignedData();

	try {
	    // se obtiene los datos firmados

	    osd = csb.getSignedData(signature);
	    assertNull(osd.getSignedData());
	    assertNotNull(osd.getMimetype());
	    assertNotNull(osd.getHashAlgorithm());
	    assertNotNull(osd.getHashSignedData());
	} catch (final SigningException e) {
	    assertTrue(false);
	}

    }

}
