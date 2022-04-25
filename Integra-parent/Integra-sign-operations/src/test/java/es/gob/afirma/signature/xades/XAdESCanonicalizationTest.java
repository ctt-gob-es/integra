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
 * <b>File:</b><p>es.gob.afirma.signature.xades.XadesSignerTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for {@link XadesSigner}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>25/01/2016.</p>
 * @author Gobierno de España.
 * @version 1.3, 16/04/2020.
 */
package es.gob.afirma.signature.xades;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import org.apache.xml.crypto.dsig.CanonicalizationMethod;

import es.gob.afirma.integraFacade.pojo.TransformData;
import es.gob.afirma.signature.ISignatureFormatDetector;
import es.gob.afirma.signature.SignatureConstants;
import es.gob.afirma.signature.SignatureFormatDetectorXades;
import es.gob.afirma.signature.SignatureProperties;
import es.gob.afirma.signature.validation.ValidationResult;
import es.gob.afirma.utils.UtilsFileSystemCommons;
import junit.framework.TestCase;

/**
 * <p>Class that defines tests setting the canonizalization algorithm for {@link XadesSigner}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.3, 16/04/2020.
 */
public class XAdESCanonicalizationTest extends TestCase {

    private static final boolean DEBUG = false;
    
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
     * Test for methods {@link XadesSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XadesSigner#coSign(byte[], byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XadesSigner#counterSign(byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link XadesSigner#verifySignature(byte[])}.
     */
    public final void testSignDetached() {

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);

	XadesSigner signer = new XadesSigner();
	byte[ ] xadesSignature = null;
	byte[ ] xadesCoSignature = null;
	byte[ ] xadesCounterSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "Description Test");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP, "UTF-8");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, "application-xml");
	extraParams.put(SignatureProperties.XADES_CANONICALIZATION_METHOD, CanonicalizationMethod.INCLUSIVE);

	/*
	 * Generación y Validación de firma XAdES BES detached
	 */
	try {
	    xadesSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	    save(xadesSignature, "XAdES-Sign-Detached-");
	    assertEquals(SignatureFormatDetectorXades.getSignatureFormat(xadesSignature), ISignatureFormatDetector.FORMAT_XADES_B_LEVEL);
	    ValidationResult vr = signer.verifySignature(xadesSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma XAdES BES detached
	 */
	try {
	    xadesCoSignature = signer.coSign(xadesSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	    save(xadesCoSignature, "XAdES-Co-Detached-");
	    ValidationResult vr = signer.verifySignature(xadesCoSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de contra-firma XAdES BES detached
	 */
	try {
	    xadesCounterSignature = signer.counterSign(xadesSignature, SignatureConstants.SIGN_ALGORITHM_SHA384WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	    save(xadesCounterSignature, "XAdES-Counter-Detached-");
	    ValidationResult vr = signer.verifySignature(xadesCounterSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }
    
    /**
     * Test for methods {@link XadesSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XadesSigner#coSign(byte[], byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XadesSigner#counterSign(byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link XadesSigner#verifySignature(byte[])}.
     */
    public final void testSignEnveloped() {

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);

	XadesSigner signer = new XadesSigner();
	byte[ ] xadesSignature = null;
	byte[ ] xadesCoSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "Description Test");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP, "UTF-8");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, "application-xml");
	extraParams.put(SignatureProperties.XADES_CANONICALIZATION_METHOD, CanonicalizationMethod.INCLUSIVE);

	/*
	 * Generación y Validación de firma XAdES BES enveloped
	 */
	try {
	    xadesSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	    save(xadesSignature, "XAdES-Sign-Enveloped-");
	    assertEquals(SignatureFormatDetectorXades.getSignatureFormat(xadesSignature), ISignatureFormatDetector.FORMAT_XADES_B_LEVEL);
	    ValidationResult vr = signer.verifySignature(xadesSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma XAdES BES enveloped
	 */
	try {
	    xadesCoSignature = signer.coSign(xadesSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	    save(xadesCoSignature, "XAdES-Co-Enveloped-");
	    ValidationResult vr = signer.verifySignature(xadesCoSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  La generación de contra-firma XAdES BES enveloped no esta soportada y debe lanzar una excepcion
	 */
	try {
	    try {
		signer.counterSign(xadesSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
		fail(ERROR_EXCEPTION_NOT_THROWED);
	    } catch (IllegalArgumentException e) {}
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for methods {@link XadesSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XadesSigner#coSign(byte[], byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XadesSigner#counterSign(byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link XadesSigner#verifySignature(byte[])}.
     */
    public final void testSignEnveloping() {

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);

	XadesSigner signer = new XadesSigner();
	byte[ ] xadesSignature = null;
	byte[ ] xadesCoSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "Description Test");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP, "UTF-8");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, "application-xml");
	extraParams.put(SignatureProperties.XADES_CANONICALIZATION_METHOD, CanonicalizationMethod.INCLUSIVE);

	/*
	 * Generación y Validación de firma XAdES BES enveloping
	 */
	try {
	    xadesSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	    save(xadesSignature, "XAdES-Sign-Enveloping-");
	    assertEquals(SignatureFormatDetectorXades.getSignatureFormat(xadesSignature), ISignatureFormatDetector.FORMAT_XADES_B_LEVEL);
	    ValidationResult vr = signer.verifySignature(xadesSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma XAdES BES enveloping
	 */
	try {
	    xadesCoSignature = signer.coSign(xadesSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	    save(xadesCoSignature, "XAdES-Co-Enveloping-");
	    ValidationResult vr = signer.verifySignature(xadesCoSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  La generación de contra-firma XAdES BES enveloping no esta soportada y debe lanzar una excepcion
	 */
	try {
	    try {
		signer.counterSign(xadesSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
		fail(ERROR_EXCEPTION_NOT_THROWED);
	    } catch (IllegalArgumentException e) {}
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for methods {@link XadesSigner#sign(byte[], String, String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XadesSigner#coSign(byte[], byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * {@link XadesSigner#counterSign(byte[], String, PrivateKeyEntry, java.util.Properties, boolean, String, String)},
     * and {@link XadesSigner#verifySignature(byte[])}.
     */
    public final void testSignExternallyDetached() {

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);

	XadesSigner signer = new XadesSigner();
	byte[ ] xadesSignature = null;
	byte[ ] xadesCoSignature = null;
	byte[ ] xadesCounterSignature = null;
	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	Properties extraParams = new Properties();
	
	
	// Creamos listado de propiedades adicionales que incluirá el objeto
	// manifest con todas las referencias externas.
	ReferenceData rd = new ReferenceData("http://www.w3.org/2000/09/xmldsig#sha1", "zyjp8GJOX69990Kkqw8ioPXGExk=");
	String xPath = "self::text()[ancestor-or-self::node()=/Class/e[1]]";
	TransformData transform = new TransformData("http://www.w3.org/2000/09/xmldsig#base64", null);
	TransformData transform2 = new TransformData("http://www.w3.org/TR/1999/REC-xpath-19991116", Collections.singletonList(xPath));
	List<TransformData> transformList = new ArrayList<TransformData>(2);
	transformList.add(transform);
	transformList.add(transform2);
	rd.setTransforms(transformList);
	rd.setId("idAttribute");
	rd.setType("typeAttribute");
	rd.setUri("https://ec.europa.eu/cefdigital/wiki/display/CEFDIGITAL/eSignature+standards");
	
	ReferenceData rd2 = new ReferenceData("http://www.w3.org/2000/09/xmldsig#sha1", "zyjp8GJOX69990Kkqw8ioPXGExqq");
	rd2.setId("idAttribute2");
	rd2.setType("typeAttribute");
	rd2.setUri("https://ec.europa.eu/cefdigital/wiki/display/CEFDIGITAL/DSS");
	
	ReferenceData rd3 = new ReferenceData("http://www.w3.org/2000/09/xmldsig#sha1", "zyjp8GJOX69990Kkqw8ioPXGExqE");
	rd3.setId("idAttribute3");
	rd3.setType("typeAttribute");
	rd3.setUri("https://ec.europa.eu/cefdigital/wiki/display/CEFDIGITAL/DSS");
	
	List<ReferenceData> rdlist = new ArrayList<>();
	rdlist.add(rd);
	rdlist.add(rd2);
	rdlist.add(rd3);
	
	extraParams.put(SignatureConstants.MF_REFERENCES_PROPERTYNAME, rdlist);
	extraParams.put(SignatureProperties.XADES_CANONICALIZATION_METHOD, CanonicalizationMethod.INCLUSIVE);

	/*
	 * Generación y Validación de firma XAdES BES externally detached
	 */
	try { 
	    xadesSignature = signer.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_EXTERNALLY_DETACHED, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	    save(xadesSignature, "XAdES-Sign-ExDetached-");
	    assertEquals(SignatureFormatDetectorXades.getSignatureFormat(xadesSignature), ISignatureFormatDetector.FORMAT_XADES_B_LEVEL);
	    ValidationResult vr = signer.verifySignature(xadesSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de co-firma XAdES BES externally detached
	 */
	try {
	    xadesCoSignature = signer.coSign(xadesSignature, dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	    save(xadesCoSignature, "XAdES-Co-ExDetached-");
	    ValidationResult vr = signer.verifySignature(xadesCoSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 *  Generación y Validación de contra-firma XAdES BES externally detached
	 */
	try {
	    xadesCounterSignature = signer.counterSign(xadesSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	    save(xadesCounterSignature, "XAdES-Counter-ExDetached-");
	    ValidationResult vr = signer.verifySignature(xadesCounterSignature);
	    assertTrue(vr.isCorrect());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }
    
    private static void save(byte[] data, final String prefix) throws Exception {
	
	if (DEBUG) {
	    File tempFile = File.createTempFile(prefix, ".xml");
	    try (FileOutputStream fos = new FileOutputStream(tempFile)) {
		fos.write(data);
	    }
	    System.out.println("Datos guardados en: " + tempFile.getAbsolutePath());
	}
    }

}
