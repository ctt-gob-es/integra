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
 * <b>File:</b><p>es.gob.afirma.signature.CadesSignerTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for {@link CadesSigner}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/04/2015.</p>
 * @author Gobierno de España.
 * @version 1.3, 06/03/2020.
 */
package es.gob.afirma.signature;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import es.gob.afirma.signature.cades.CadesSigner;
import es.gob.afirma.signature.validation.ValidationResult;
import es.gob.afirma.utils.Base64CoderCommons;
import es.gob.afirma.utils.CryptoUtilCommons;
import es.gob.afirma.utils.UtilsFileSystemCommons;

/**
 * <p>Class that defines tests for {@link CadesSigner}.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.3, 06/03/2020.
 */
public class CadesSignerTest extends AbstractSignatureTest {

    /**
     * Tests for {@link CadesSigner#verifySignature(byte[], byte[])}.
     * @throws Exception If the test fails.
     */
    public void testVerifySignature() throws Exception {
	// test con valores nulos
	CadesSigner cs = new CadesSigner();
	try {
	    cs.verifySignature(null, new byte[0]);
	    assertTrue(false);
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	}

	// test con valores inválidos (documento a firmar vacío)
	assertFalse(cs.verifySignature(getCadesSignature(), new byte[1]).isCorrect());

	// test con valores inválidos (sin datos de la firma)
	assertFalse(cs.verifySignature(new byte[1], getTextDocument()).isCorrect());

	// test con valores válidos
	assertTrue(cs.verifySignature(getCadesSignature(), getTextDocument()).isCorrect());
    }

    /**
     * Tests for {@link CadesSigner#sign(byte[], String, String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, String, String)}.
     * @throws Exception If the test fails.
     */
    public void testSign() throws Exception {
	CadesSigner cs = new CadesSigner();

	// test con valores nulos
	try {
	    cs.sign(null, null, null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {}

	try {
	    cs.sign(new byte[0], null, null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {}

	try {
	    cs.sign(new byte[0], SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {}

	// test con valores inválidos (algoritmo no soportado)
	try {
	    cs.sign(getTextDocument(), "MD5withRSA", null, getCertificatePrivateKey(), null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (SigningException e) {}

	// test con valores válidos (firma explícita)
	byte[ ] result = cs.sign(getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, getCertificatePrivateKey(), null, false, SignatureFormatDetector.FORMAT_CADES_BES, null);
	// validamos firma
	System.out.println("!!!!" + cs.verifySignature(result, null).getErrorMsg());
	assertTrue(cs.verifySignature(result, getTextDocument()).isCorrect());
	System.out.println("\n-->>FIRMA RESULTANTE (explícita): \n" + new String(Base64CoderCommons.encodeBase64(result)));
	
	// test con valores válidos (firma explícita con hash)
	MessageDigest md = MessageDigest.getInstance(CryptoUtilCommons.HASH_ALGORITHM_SHA256); 
	byte[] digest = md.digest(getTextDocument());
	byte[ ] result2 = cs.sign(digest, CryptoUtilCommons.HASH_ALGORITHM_SHA256, SignatureConstants.SIGN_MODE_EXPLICIT_HASH, getCertificatePrivateKey(), null, false, SignatureFormatDetector.FORMAT_CADES_BES, null);
	// validamos firma
	System.out.println("!!!!" + cs.verifySignature(result2, null).getErrorMsg());
	assertTrue(cs.verifySignature(result2, getTextDocument()).isCorrect());
	System.out.println("\n-->>FIRMA RESULTANTE (explícita): \n" + new String(Base64CoderCommons.encodeBase64(result2)));

	// test con valores válidos (firma implícita)
	result = cs.sign(getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), null, false, SignatureFormatDetector.FORMAT_CADES_BES, null);
	System.out.println("\n-->>FIRMA RESULTANTE (implícita): \n" + new String(Base64CoderCommons.encodeBase64(result)));
	// validamos firma
	assertTrue(cs.verifySignature(result, null).isCorrect());

	// test con valores válidos (firma implícita con política de firma de
	// AGE)
	result = cs.sign(getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), null, false, SignatureFormatDetector.FORMAT_CADES_EPES, null);
	System.out.println("\n-->>FIRMA RESULTANTE (firma implícita con política de firma de AGE): \n" + new String(Base64CoderCommons.encodeBase64(result)));
	// validamos firma
	assertTrue(cs.verifySignature(result, getTextDocument()).isCorrect());

    }

    /**
     * Tests for {@link CadesSigner#counterSign(byte[], String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, String, String)}.
     * @throws Exception If the test fails.
     */
    public void testCounterSign() throws Exception {
	CadesSigner cs = new CadesSigner();
	// test con valores nulos
	try {
	    cs.counterSign(null, null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {}

	try {
	    cs.counterSign(new byte[0], null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {}

	try {
	    cs.counterSign(new byte[0], SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {}

	// test con valores inválidos (algoritmo no soportado)
	try {
	    cs.counterSign(getTextDocument(), "MD5withRSA", getCertificatePrivateKey(), null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (SigningException e) {}

	// test con valores válidos
	byte[ ] result = cs.counterSign(getCadesSignature(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), null, false, SignatureFormatDetector.FORMAT_CADES_BES, null);
	// validamos firma
	assertTrue(cs.verifySignature(result, getTextDocument()).isCorrect());

	// test contrafirma de una contrafirma
	result = cs.counterSign(result, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), null, false, SignatureFormatDetector.FORMAT_CADES_BES, null);
	// validamos la contrafirma
	assertTrue(cs.verifySignature(result, getTextDocument()).isCorrect());

	// test firma con dos contrafirmas (en cascada) y una cofirma
	result = cs.counterSign(result, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), null, false, SignatureFormatDetector.FORMAT_CADES_BES, null);
	// validamos la contrafirma
	assertTrue(cs.verifySignature(result, getTextDocument()).isCorrect());
    }

    /**
     * Tests for {@link CadesSigner#coSign(byte[], byte[], String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, String, String)}.
     * @throws Exception If the test fails.
     */
    public void testCoSign() throws Exception {
	CadesSigner cadesSigner = new CadesSigner();
	// test con valores nulos
	try {
	    cadesSigner.coSign(null, null, null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {}

	try {
	    cadesSigner.coSign(new byte[0], null, null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {}

	try {
	    cadesSigner.coSign(new byte[0], new byte[0], null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {}

	try {
	    cadesSigner.coSign(new byte[0], new byte[0], SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (IllegalArgumentException e) {}

	// test con valores válidos.
	// cofirma simple
	byte[ ] result = cadesSigner.coSign(getCadesSignature(), getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), null, false, SignatureFormatDetector.FORMAT_CADES_BES, null);
	assertTrue(cadesSigner.verifySignature(result, getTextDocument()).isCorrect());

	// cofirma de una firma con 2 contrafirmas (en cascada)
	result = cadesSigner.coSign(UtilsFileSystemCommons.readFile("signatures/CADES_2CounterSign.p7s", true), getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA384WITHRSA, getCertificatePrivateKey(), null, false, SignatureFormatDetector.FORMAT_CADES_BES, null);
	assertTrue(cadesSigner.verifySignature(result, getTextDocument()).isCorrect());
    }

    /**
     * Tests for generating CAdES signatures with timestamp.
     * @throws Exception If the test fails.
     */
    public void testSignWithTimestamp() {
	CadesSigner cadesSigner = new CadesSigner();

	/*
	 * Test 1: Generación de firma CAdES-T explícita
	 */
	try {
	    byte[ ] signature = cadesSigner.sign(getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, getCertificatePrivateKey(), null, true, SignatureFormatDetector.FORMAT_CADES_BES, null);
	    byte[ ] coSignature = cadesSigner.coSign(signature, getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, getCertificatePrivateKey(), null, false, SignatureFormatDetector.FORMAT_CADES_BES, null);
	    byte[ ] counterSignature = cadesSigner.counterSign(coSignature, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, getCertificatePrivateKey(), null, false, SignatureFormatDetector.FORMAT_CADES_BES, null);
	    byte[ ] upgradedSignature = cadesSigner.upgrade(counterSignature, null);
	    cadesSigner.upgrade(upgradedSignature, null);
	    // Validamos la firma
	    ValidationResult vr = cadesSigner.verifySignature(signature, getTextDocument());
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Generación de firma CAdES-T implícita
	 */
	try {
	    byte[ ] signature = cadesSigner.sign(getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), null, true, SignatureFormatDetector.FORMAT_CADES_BES, null);

	    // Validamos la firma
	    ValidationResult vr = cadesSigner.verifySignature(signature, getTextDocument());
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 3: Generación de firma CAdES-T implícita con política de firma
	 */
	try {
	    cadesSigner.sign(getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA384WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, getCertificatePrivateKey(), null, true, SignatureFormatDetector.FORMAT_CADES_EPES, "ASN1_AGE_1.9");
	} catch (Exception e) {
	    assertTrue(true);
	}
    }

    /**
     * Tests for generating CAdES co-signatures with timestamp.
     * @throws Exception If the test fails.
     */
    public void testCoSignWithTimestamp() {
	CadesSigner cadesSigner = new CadesSigner();
	byte[ ] signature = null;

	// Validamos la firma
	try {
	    signature = cadesSigner.sign(getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, getCertificatePrivateKey(), null, true, SignatureFormatDetector.FORMAT_CADES_EPES, "ASN1_AGE_1.9");
	    // Validamos la firma
	    ValidationResult vr = cadesSigner.verifySignature(signature, getTextDocument());
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 1: Generación de co-firma CAdES-T
	 */
	try {
	    byte[ ] coSignature = cadesSigner.coSign(signature, getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), null, true, SignatureFormatDetector.FORMAT_CADES_EPES, "ASN1_AGE_1.9");

	    // Validamos la firma
	    ValidationResult vr = cadesSigner.verifySignature(coSignature, getTextDocument());
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Generación de co-firma CAdES-T con política de firma
	 */
	try {
	    byte[ ] coSignature = cadesSigner.coSign(signature, getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, getCertificatePrivateKey(), null, true, SignatureFormatDetector.FORMAT_CADES_EPES, "ASN1_AGE_1.9");

	    // Validamos la firma
	    ValidationResult vr = cadesSigner.verifySignature(coSignature, getTextDocument());
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Tests for generating CAdES counter-ignatures with timestamp.
     * @throws Exception If the test fails.
     */
    public void testCounterSignWithTimestamp() {
	CadesSigner cadesSigner = new CadesSigner();
	byte[ ] signature = null;

	/*
	 * Test 1: Generación de contra-firma CAdES-T
	 */
	try {
	    signature = cadesSigner.sign(getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, getCertificatePrivateKey(), null, true, SignatureFormatDetector.FORMAT_CADES_EPES, "ASN1_AGE_1.9");
	    byte[ ] counterSignature = cadesSigner.counterSign(signature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), null, true, SignatureFormatDetector.FORMAT_CADES_EPES, "ASN1_AGE_1.9");

	    // Validamos la firma
	    ValidationResult vr = cadesSigner.verifySignature(counterSignature, getTextDocument());
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Generación de contra-firma CAdES-T con política de firma
	 */
	try {
	    byte[ ] counterSignature = cadesSigner.counterSign(signature, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), null, true, SignatureFormatDetector.FORMAT_CADES_EPES, "ASN1_AGE_1.9");

	    // Validamos la firma
	    ValidationResult vr = cadesSigner.verifySignature(counterSignature, getTextDocument());
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Tests for {@link CadesSigner#upgrade(byte[], List)}.
     * @throws Exception If the test fails.
     */
    public void testUpgrade() {
	CadesSigner cadesSigner = new CadesSigner();

	/*
	 * Test 1: Actualización de una firma CAdES-BES implícita sin indicar firmante
	 */
	try {
	    byte[ ] signature = cadesSigner.sign(getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, getCertificatePrivateKey(), null, false, SignatureFormatDetector.FORMAT_CADES_BES, null);
	    byte[ ] upgradedSignature = cadesSigner.upgrade(signature, null);

	    // Validamos la firma
	    ValidationResult vr = cadesSigner.verifySignature(upgradedSignature, getTextDocument());
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Actualización de una firma CAdES-BES explícita indicando firmante
	 */
	try {
	    List<X509Certificate> listCertificates = new ArrayList<X509Certificate>();
	    listCertificates.add(getCertificate());
	    byte[ ] signature = cadesSigner.sign(getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, getCertificatePrivateKey(), null, false, SignatureFormatDetector.FORMAT_CADES_BES, null);
	    byte[ ] upgradedSignature = cadesSigner.upgrade(signature, listCertificates);

	    // Validamos la firma
	    ValidationResult vr = cadesSigner.verifySignature(upgradedSignature, getTextDocument());
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

    }

    /**
        * Test for methods {@link CadesSigner#getSignedData(byte[])}.
        */
    public final void testGetSignedDataCadesImplicit() {

	// se obtiene la firma CAdES implícita
	byte[ ] signature = UtilsFileSystemCommons.readFile("signatures/ASN1/CAdES-XL1.p7s", true);

	CadesSigner cs = new CadesSigner();
	OriginalSignedData osd = new OriginalSignedData();

	try {
	    // se obtiene los datos firmados
	    osd = cs.getSignedData(signature);
	    assertNotNull(osd.getSignedData());
	    assertNotNull(osd.getMimetype());
	    assertNull(osd.getHashAlgorithm());
	    assertNull(osd.getHashSignedData());
	} catch (SigningException e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for method {@link CadesSigner#getSignedData(byte[])}.
     */
    public final void testGetSignedDataCadesExplicit() {

	// se obtiene firma CAdES explícita
	byte[ ] signature = UtilsFileSystemCommons.readFile("signatures/ASN1/CAdES-Explicit.p7s", true);
	CadesSigner cs = new CadesSigner();
	OriginalSignedData osd = new OriginalSignedData();

	try {
	    // se obtiene los datos firmados
	    osd = cs.getSignedData(signature);
	    assertNull(osd.getSignedData());
	    assertNotNull(osd.getMimetype());
	    assertNotNull(osd.getHashAlgorithm());
	    assertNotNull(osd.getHashSignedData());
	} catch (SigningException e) {
	    assertTrue(false);
	}

    }

}
