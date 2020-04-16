// Copyright (C) 2020 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.signature.xades.XAdESBaselineSignerTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for {@link XAdESBaselineSigner}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>25/01/2016.</p>
 * @author Gobierno de España.
 * @version 1.3, 16/04/2020.
 */
package es.gob.afirma.signature.xades;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import es.gob.afirma.integraFacade.pojo.TransformData;
import es.gob.afirma.signature.ISignatureFormatDetector;
import es.gob.afirma.signature.SignatureConstants;
import es.gob.afirma.signature.SignatureFormatDetectorXades;
import es.gob.afirma.signature.SignatureProperties;
import es.gob.afirma.signature.validation.ValidationResult;
import es.gob.afirma.utils.UtilsFileSystemCommons;
import junit.framework.TestCase;

/**
 * <p>Class that defines tests for {@link XAdESBaselineSigner}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.3, 16/04/2020.
 */
public class XAdESBaselineSignerTest extends TestCase {

    /**
     * Constant attribute that represents the message which identifies an exception isn't thrown. 
     */
    protected static final String ERROR_EXCEPTION_NOT_THROWED = "No se ha lanzado la excepción esperada";

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
     * Test for methods {@link XAdESBaselineSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#coSign(byte[], byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#counterSign(byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link XAdESBaselineSigner#verifySignature(byte[])}.
     */
    public final void testSignDetachedWithoutPolicyWithoutTimestamp() {

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);

	XAdESBaselineSigner signer = new XAdESBaselineSigner();
	byte[ ] xadesBLevelSignature = null;
	byte[ ] xadesBLevelCoSignature = null;
	byte[ ] xadesBLevelCounterSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "Description Test");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP, "UTF-8");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, "application-xml");

	/*
	 * Generación y Validación de firma XAdES B-Level detached sin política de firma y algoritmo SHA-1
	 */
	try {
	    xadesBLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    assertEquals(SignatureFormatDetectorXades.getSignatureFormat(xadesBLevelSignature), ISignatureFormatDetector.FORMAT_XADES_B_LEVEL);
	    ValidationResult vr = signer.verifySignature(xadesBLevelSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma XAdES B-Level detached sin política de firma y algoritmo SHA-256
	 */
	try {
	    xadesBLevelCoSignature = signer.coSign(xadesBLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(xadesBLevelCoSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de contra-firma XAdES B-Level detached sin política de firma y algoritmo SHA-384
	 */
	try {
	    xadesBLevelCounterSignature = signer.counterSign(xadesBLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA384WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(xadesBLevelCounterSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for methods {@link XAdESBaselineSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#coSign(byte[], byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#counterSign(byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link XAdESBaselineSigner#verifySignature(byte[])}.
     */
    public final void testSignEnvelopedWithoutPolicyWithoutTimestamp() {

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);

	XAdESBaselineSigner signer = new XAdESBaselineSigner();
	byte[ ] xadesBLevelSignature = null;
	byte[ ] xadesBLevelCoSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "Description Test");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP, "UTF-8");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, "application-xml");

	/*
	 * Generación y Validación de firma XAdES B-Level enveloped sin política de firma y algoritmo SHA-1
	 */
	try {
	    xadesBLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    assertEquals(SignatureFormatDetectorXades.getSignatureFormat(xadesBLevelSignature), ISignatureFormatDetector.FORMAT_XADES_B_LEVEL);
	    ValidationResult vr = signer.verifySignature(xadesBLevelSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma XAdES B-Level enveloped sin política de firma y algoritmo SHA-256
	 */
	try {
	    xadesBLevelCoSignature = signer.coSign(xadesBLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(xadesBLevelCoSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de contra-firma XAdES B-Level enveloped sin política de firma y algoritmo SHA-512
	 */
	try {
	    try {
		signer.counterSign(xadesBLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
		fail(ERROR_EXCEPTION_NOT_THROWED);
	    } catch (IllegalArgumentException e) {}
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for methods {@link XAdESBaselineSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#coSign(byte[], byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#counterSign(byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link XAdESBaselineSigner#verifySignature(byte[])}.
     */
    public final void testSignEnvelopingWithoutPolicyWithoutTimestamp() {

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);

	XAdESBaselineSigner signer = new XAdESBaselineSigner();
	byte[ ] xadesBLevelSignature = null;
	byte[ ] xadesBLevelCoSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "Description Test");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP, "UTF-8");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, "application-xml");

	/*
	 * Generación y Validación de firma XAdES B-Level enveloping sin política de firma y algoritmo SHA-1
	 */
	try {
	    xadesBLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    assertEquals(SignatureFormatDetectorXades.getSignatureFormat(xadesBLevelSignature), ISignatureFormatDetector.FORMAT_XADES_B_LEVEL);
	    ValidationResult vr = signer.verifySignature(xadesBLevelSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma XAdES B-Level enveloping sin política de firma y algoritmo SHA-256
	 */
	try {
	    xadesBLevelCoSignature = signer.coSign(xadesBLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(xadesBLevelCoSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de contra-firma XAdES B-Level enveloping sin política de firma y algoritmo SHA-512
	 */
	try {
	    try {
		signer.counterSign(xadesBLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
		fail(ERROR_EXCEPTION_NOT_THROWED);
	    } catch (IllegalArgumentException e) {}
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for methods {@link XAdESBaselineSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#coSign(byte[], byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#counterSign(byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link XAdESBaselineSigner#verifySignature(byte[])}.
     */
    public final void testSignDetachedWithPolicyWithoutTimestamp() {

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);

	XAdESBaselineSigner signer = new XAdESBaselineSigner();
	byte[ ] xadesBLevelSignature = null;
	byte[ ] xadesBLevelCoSignature = null;
	byte[ ] xadesBLevelCounterSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "Description Test");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP, "UTF-8");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, "application-xml");

	/*
	 * Generación y Validación de firma XAdES B-Level detached con política de firma y algoritmo SHA-1
	 */
	try {
	    xadesBLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, "XML_AGE_1.9_URL");
	    assertEquals(SignatureFormatDetectorXades.getSignatureFormat(xadesBLevelSignature), ISignatureFormatDetector.FORMAT_XADES_B_LEVEL);
	    ValidationResult vr = signer.verifySignature(xadesBLevelSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma XAdES B-Level detached con política de firma y algoritmo SHA-256
	 */
	try {
	    xadesBLevelCoSignature = signer.coSign(xadesBLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, "XML_AGE_1.9_URL");
	    ValidationResult vr = signer.verifySignature(xadesBLevelCoSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de contra-firma XAdES B-Level detached con política de firma y algoritmo SHA-512
	 */
	try {
	    xadesBLevelCounterSignature = signer.counterSign(xadesBLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, "XML_AGE_1.9_URL");
	    ValidationResult vr = signer.verifySignature(xadesBLevelCounterSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for methods {@link XAdESBaselineSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#coSign(byte[], byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#counterSign(byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link XAdESBaselineSigner#verifySignature(byte[])}.
     */
    public final void testSignEnvelopedWithPolicyWithoutTimestamp() {

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);

	XAdESBaselineSigner signer = new XAdESBaselineSigner();
	byte[ ] xadesBLevelSignature = null;
	byte[ ] xadesBLevelCoSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "Description Test");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP, "UTF-8");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, "application-xml");

	/*
	 * Generación y Validación de firma XAdES B-Level enveloped con política de firma y algoritmo SHA-1
	 */
	try {
	    xadesBLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, "XML_AGE_1.9_URL");
	    assertEquals(SignatureFormatDetectorXades.getSignatureFormat(xadesBLevelSignature), ISignatureFormatDetector.FORMAT_XADES_B_LEVEL);
	    ValidationResult vr = signer.verifySignature(xadesBLevelSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma XAdES B-Level enveloped con política de firma y algoritmo SHA-256
	 */
	try {
	    xadesBLevelCoSignature = signer.coSign(xadesBLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, "XML_AGE_1.9_URL");
	    ValidationResult vr = signer.verifySignature(xadesBLevelCoSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de contra-firma XAdES B-Level enveloped con política de firma y algoritmo SHA-512
	 */
	try {
	    try {
		signer.counterSign(xadesBLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, "XML_AGE_1.9_URL");
		fail(ERROR_EXCEPTION_NOT_THROWED);
	    } catch (IllegalArgumentException e) {}
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for methods {@link XAdESBaselineSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#coSign(byte[], byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#counterSign(byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link XAdESBaselineSigner#verifySignature(byte[])}.
     */
    public final void testSignDetachedWithoutPolicyWithTimestamp() {

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);

	XAdESBaselineSigner signer = new XAdESBaselineSigner();
	byte[ ] xadesTLevelSignature = null;
	byte[ ] xadesTLevelCoSignature = null;
	byte[ ] xadesTLevelCounterSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "Description Test");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP, "UTF-8");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, "application-xml");

	/*
	 * Generación y Validación de firma XAdES T-Level detached sin política de firma y algoritmo SHA-1
	 */
	try {
	    xadesTLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, extraParams, true, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    assertEquals(SignatureFormatDetectorXades.getSignatureFormat(xadesTLevelSignature), ISignatureFormatDetector.FORMAT_XADES_T_LEVEL);
	    ValidationResult vr = signer.verifySignature(xadesTLevelSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma XAdES T-Level detached sin política de firma y algoritmo SHA-256
	 */
	try {
	    xadesTLevelCoSignature = signer.coSign(xadesTLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, privateKey, extraParams, true, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(xadesTLevelCoSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de contra-firma XAdES T-Level detached sin política de firma y algoritmo SHA-384
	 */
	try {
	    xadesTLevelCounterSignature = signer.counterSign(xadesTLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA384WITHRSA, privateKey, extraParams, true, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(xadesTLevelCounterSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for methods {@link XAdESBaselineSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#coSign(byte[], byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#counterSign(byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link XAdESBaselineSigner#verifySignature(byte[])}.
     */
    public final void testSignEnvelopedWithoutPolicyWithTimestamp() {

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);

	XAdESBaselineSigner signer = new XAdESBaselineSigner();
	byte[ ] xadesTLevelSignature = null;
	byte[ ] xadesTLevelCoSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "Description Test");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP, "UTF-8");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, "application-xml");

	/*
	 * Generación y Validación de firma XAdES T-Level enveloped sin política de firma y algoritmo SHA-1
	 */
	try {
	    xadesTLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED, privateKey, extraParams, true, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    assertEquals(SignatureFormatDetectorXades.getSignatureFormat(xadesTLevelSignature), ISignatureFormatDetector.FORMAT_XADES_T_LEVEL);
	    ValidationResult vr = signer.verifySignature(xadesTLevelSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma XAdES T-Level enveloped sin política de firma y algoritmo SHA-256
	 */
	try {
	    xadesTLevelCoSignature = signer.coSign(xadesTLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, privateKey, extraParams, true, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(xadesTLevelCoSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de contra-firma XAdES T-Level enveloped sin política de firma y algoritmo SHA-512
	 */
	try {
	    try {
		signer.counterSign(xadesTLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, extraParams, true, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
		fail(ERROR_EXCEPTION_NOT_THROWED);
	    } catch (IllegalArgumentException e) {}
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for methods {@link XAdESBaselineSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#coSign(byte[], byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#counterSign(byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link XAdESBaselineSigner#verifySignature(byte[])}.
     */
    public final void testSignEnvelopingWithoutPolicyWithTimestamp() {

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);

	XAdESBaselineSigner signer = new XAdESBaselineSigner();
	byte[ ] xadesTLevelSignature = null;
	byte[ ] xadesTLevelCoSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "Description Test");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP, "UTF-8");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, "application-xml");

	/*
	 * Generación y Validación de firma XAdES T-Level enveloping sin política de firma y algoritmo SHA-1
	 */
	try {
	    xadesTLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING, privateKey, extraParams, true, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    assertEquals(SignatureFormatDetectorXades.getSignatureFormat(xadesTLevelSignature), ISignatureFormatDetector.FORMAT_XADES_T_LEVEL);
	    ValidationResult vr = signer.verifySignature(xadesTLevelSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma XAdES T-Level enveloping sin política de firma y algoritmo SHA-256
	 */
	try {
	    xadesTLevelCoSignature = signer.coSign(xadesTLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, privateKey, extraParams, true, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(xadesTLevelCoSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de contra-firma XAdES T-Level enveloping sin política de firma y algoritmo SHA-512
	 */
	try {
	    try {
		signer.counterSign(xadesTLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, extraParams, true, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
		fail(ERROR_EXCEPTION_NOT_THROWED);
	    } catch (IllegalArgumentException e) {}
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for methods {@link XAdESBaselineSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#coSign(byte[], byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#counterSign(byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link XAdESBaselineSigner#verifySignature(byte[])}.
     */
    public final void testSignExternallyDetachedWithoutPolicyWithTimestamp() {

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);

	XAdESBaselineSigner signer = new XAdESBaselineSigner();
	byte[ ] xadesTLevelSignature = null;
	byte[ ] xadesTLevelCoSignature = null;
	byte[ ] xadesTLevelCounterSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	Properties extraParams = new Properties();
	
	// Creamos listado de propiedades adicionales que incluirá el objeto
	// manifest con todas las referencias externas.
	ReferenceDataBaseline rd = new ReferenceDataBaseline("http://www.w3.org/2000/09/xmldsig#sha1", "zyjp8GJOX69990Kkqw8ioPXGExk=");
	String xPath = "self::text()[ancestor-or-self::node()=/Class/e[1]]";
	TransformData transform = new TransformData("http://www.w3.org/2000/09/xmldsig#base64", null);
	TransformData transform2 = new TransformData("http://www.w3.org/TR/1999/REC-xpath-19991116", Collections.singletonList(xPath));
	List<TransformData> transformList = new ArrayList<TransformData>(2);
	transformList.add(transform);
	transformList.add(transform2);
	rd.setTransforms(transformList);
	rd.setId("idAttribute");
	rd.setType("typeAttribute");
	rd.setUri("uriAttribute");
	rd.setDataFormatDescription("Description Test");
	rd.setDataFormatEncoding("UTF-8");
	rd.setDataFormatMimeType( "application-xml");
	List<ReferenceDataBaseline> rdlist = Collections.singletonList(rd);
	extraParams.put(SignatureConstants.MF_REFERENCES_PROPERTYNAME, rdlist);

	/*
	 * Generación y Validación de firma XAdES T-Level externally detached sin política de firma y algoritmo SHA-1
	 */
	try {
	    xadesTLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_EXTERNALLY_DETACHED, privateKey, extraParams, true, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    assertEquals(SignatureFormatDetectorXades.getSignatureFormat(xadesTLevelSignature), ISignatureFormatDetector.FORMAT_XADES_T_LEVEL);
	    ValidationResult vr = signer.verifySignature(xadesTLevelSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma XAdES T-Level externally detached sin política de firma y algoritmo SHA-256
	 */
	try {
	    xadesTLevelCoSignature = signer.coSign(xadesTLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, privateKey, extraParams, true, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(xadesTLevelCoSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de contra-firma XAdES T-Level externally detached sin política de firma y algoritmo SHA-512
	 */
	try {
	    xadesTLevelCounterSignature = signer.counterSign(xadesTLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, extraParams, true, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(xadesTLevelCounterSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for methods {@link XAdESBaselineSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#verifySignature(byte[]),
     * and {@link XAdESBaselineSigner#verifySignature(byte[])}.
     */
    public final void testUpgradeDetachedWithPolicy() {

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);

	XAdESBaselineSigner signer = new XAdESBaselineSigner();
	byte[ ] xadesBLevelSignature = null;
	byte[ ] xadesBLevelCoSignature = null;
	byte[ ] xadesBLevelCounterSignature = null;
	byte[ ] xadesTLevelSignature = null;
	byte[ ] xadesTLevelCoSignature = null;
	byte[ ] xadesTLevelCounterSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "Description Test");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP, "UTF-8");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, "application-xml");

	/*
	 * Generación de firma XAdES B-Level detached con política de firma y algoritmo SHA-1 y actualización a XAdES T-Level
	 */
	try {
	    xadesBLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, "XML_AGE_1.9_URL");
	    xadesTLevelSignature = signer.upgrade(xadesBLevelSignature, null);
	    assertEquals(SignatureFormatDetectorXades.getSignatureFormat(xadesTLevelSignature), ISignatureFormatDetector.FORMAT_XADES_T_LEVEL);
	    ValidationResult vr = signer.verifySignature(xadesTLevelSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación de co-firma XAdES B-Level detached con política de firma y algoritmo SHA-256 y actualización a XAdES T-Level
	 */
	try {
	    xadesBLevelCoSignature = signer.coSign(xadesBLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, "XML_AGE_1.9_URL");
	    xadesTLevelCoSignature = signer.upgrade(xadesBLevelCoSignature, null);
	    ValidationResult vr = signer.verifySignature(xadesTLevelCoSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación de contra-firma XAdES B-Level detached con política de firma y algoritmo SHA-512 y actualización a XAdES T-Level
	 */
	try {
	    xadesBLevelCounterSignature = signer.counterSign(xadesBLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, "XML_AGE_1.9_URL");
	    xadesTLevelCounterSignature = signer.upgrade(xadesBLevelCounterSignature, null);
	    ValidationResult vr = signer.verifySignature(xadesTLevelCounterSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for methods {@link XAdESBaselineSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#coSign(byte[], byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#counterSign(byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link XAdESBaselineSigner#verifySignature(byte[])}.
     */
    public final void testUpgradeEnvelopedWithPolicy() {

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);

	XAdESBaselineSigner signer = new XAdESBaselineSigner();
	byte[ ] xadesBLevelSignature = null;
	byte[ ] xadesBLevelCoSignature = null;
	byte[ ] xadesTLevelSignature = null;
	byte[ ] xadesTLevelCoSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "Description Test");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP, "UTF-8");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, "application-xml");

	/*
	 * Generación de firma XAdES B-Level enveloped con política de firma y algoritmo SHA-1 y actualización a XAdES T-Level
	 */
	try {
	    xadesBLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, "XML_AGE_1.9_URL");
	    xadesTLevelSignature = signer.upgrade(xadesBLevelSignature, null);
	    assertEquals(SignatureFormatDetectorXades.getSignatureFormat(xadesTLevelSignature), ISignatureFormatDetector.FORMAT_XADES_T_LEVEL);
	    ValidationResult vr = signer.verifySignature(xadesTLevelSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación de co-firma XAdES B-Level enveloped con política de firma y algoritmo SHA-256 y actualización a XAdES T-Level
	 */
	try {
	    xadesBLevelCoSignature = signer.coSign(xadesBLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, "XML_AGE_1.9_URL");
	    xadesTLevelCoSignature = signer.upgrade(xadesBLevelCoSignature, null);
	    ValidationResult vr = signer.verifySignature(xadesTLevelCoSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación de contra-firma XAdES B-Level enveloped con política de firma y algoritmo SHA-512 y actualización a XAdES T-Level
	 */
	try {
	    try {
		signer.counterSign(xadesBLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, "XML_AGE_1.9_URL");
		fail(ERROR_EXCEPTION_NOT_THROWED);
	    } catch (IllegalArgumentException e) {}
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for methods {@link XAdESBaselineSigner#getSignedData(byte[])}.
     */
    public final void testGetSignedData() {
	XAdESBaselineSigner signer = new XAdESBaselineSigner();
	byte[ ] signature = UtilsFileSystemCommons.readFile("signatures/XAdES-Cosign.xml", true);
	try {
	    signer.getSignedData(signature);
	} catch (Exception e) {
	    assertTrue(true);
	}

    }
    
    /**
     * Test for methods {@link XAdESBaselineSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#coSign(byte[], byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XAdESBaselineSigner#counterSign(byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link XAdESBaselineSigner#verifySignature(byte[])}.
     */
    public final void testSignExternallyDetachedWithoutPolicyWithoutTimestamp() {

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);

	XAdESBaselineSigner signer = new XAdESBaselineSigner();
	byte[ ] xadesBLevelSignature = null;
	byte[ ] xadesBLevelCoSignature = null;
	byte[ ] xadesBLevelCounterSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	Properties extraParams = new Properties();
	
	
	// Creamos listado de propiedades adicionales que incluirá el objeto
	// manifest con todas las referencias externas.
	ReferenceDataBaseline rd = new ReferenceDataBaseline("http://www.w3.org/2000/09/xmldsig#sha1", "zyjp8GJOX69990Kkqw8ioPXGExk=");
	String xPath = "self::text()[ancestor-or-self::node()=/Class/e[1]]";
	TransformData transform = new TransformData("http://www.w3.org/2000/09/xmldsig#base64", null);
	TransformData transform2 = new TransformData("http://www.w3.org/TR/1999/REC-xpath-19991116", Collections.singletonList(xPath));
	List<TransformData> transformList = new ArrayList<TransformData>(2);
	transformList.add(transform);
	transformList.add(transform2);
	rd.setTransforms(transformList);
	rd.setDataFormatDescription("Description Test");
	rd.setDataFormatEncoding("UTF-8");
	rd.setDataFormatMimeType("application-xml");
	rd.setId("idAttribute");
	rd.setType("typeAttribute");
	rd.setUri("https://ec.europa.eu/cefdigital/wiki/display/CEFDIGITAL/eSignature+standards");
	
	ReferenceDataBaseline rd2 = new ReferenceDataBaseline("http://www.w3.org/2000/09/xmldsig#sha1", "zyjp8GJOX69990Kkqw8ioPXGExqq");
	rd2.setDataFormatDescription("Description Test 2");
	rd2.setDataFormatEncoding("UTF-8");
	rd2.setDataFormatMimeType("application-xml");
	rd2.setId("idAttribute2");
	rd2.setType("typeAttribute");
	rd2.setUri("https://ec.europa.eu/cefdigital/wiki/display/CEFDIGITAL/DSS");
	
	ReferenceDataBaseline rd3 = new ReferenceDataBaseline("http://www.w3.org/2000/09/xmldsig#sha1", "zyjp8GJOX69990Kkqw8ioPXGExqE");
	rd3.setDataFormatDescription("Description Test 3");
	rd3.setDataFormatEncoding("UTF-8");
	rd3.setDataFormatMimeType("application-xml");
	rd3.setId("idAttribute3");
	rd3.setType("typeAttribute");
	rd3.setUri("https://ec.europa.eu/cefdigital/wiki/display/CEFDIGITAL/DSS");
	
	List<ReferenceDataBaseline> rdlist = new ArrayList<>();
	rdlist.add(rd);
	rdlist.add(rd2);
	rdlist.add(rd3);
	
	extraParams.put(SignatureConstants.MF_REFERENCES_PROPERTYNAME, rdlist);

	/*
	 * Generación y Validación de firma XAdES B-Level externally detached sin política de firma y algoritmo SHA-1
	 */
	try { 
	    xadesBLevelSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_EXTERNALLY_DETACHED, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    assertEquals(SignatureFormatDetectorXades.getSignatureFormat(xadesBLevelSignature), ISignatureFormatDetector.FORMAT_XADES_B_LEVEL);
	    ValidationResult vr = signer.verifySignature(xadesBLevelSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma XAdES B-Level externally detached sin política de firma y algoritmo SHA-256
	 */
	try {
	    xadesBLevelCoSignature = signer.coSign(xadesBLevelSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(xadesBLevelCoSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de contra-firma XAdES B-Level externally detached sin política de firma y algoritmo SHA-512
	 */
	try {
	    xadesBLevelCounterSignature = signer.counterSign(xadesBLevelSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(xadesBLevelCounterSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }
}
