// Copyright (C) 2012-15 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.signature.asic.ASiCSBaselineSignerTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for {@link ASiCSBaselineSigner}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>29/01/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 29/01/2016.
 */
package es.gob.afirma.signature.asic;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Properties;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import es.gob.afirma.signature.ISignatureFormatDetector;
import es.gob.afirma.signature.OriginalSignedData;
import es.gob.afirma.signature.SignatureConstants;
import es.gob.afirma.signature.SignatureFormatDetectorASiC;
import es.gob.afirma.signature.SignatureProperties;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.signature.cades.CAdESBaselineSigner;
import es.gob.afirma.signature.validation.ValidationResult;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.utils.UtilsFileSystemCommons;
import es.gob.afirma.utils.UtilsResourcesCommons;
import junit.framework.TestCase;

/**
 * <p>Class that defines tests for {@link ASiCSBaselineSigner}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 29/01/2016.
 */
public class ASiCSBaselineSignerTest extends TestCase {

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

    private byte[ ] createASiCSWithASN1Signature(final byte[ ] signature, final byte[ ] signedFile) throws IOException {
	final OutputStream baos = new ByteArrayOutputStream();
	final OutputStream outZip = new ZipOutputStream(baos);

	try {
	    // Añadimos la carpeta META-INF
	    ((ZipOutputStream) outZip).putNextEntry(new ZipEntry("META-INF/"));

	    // Añadimos la firma ASN.1
	    final String signatureName = "META-INF/signature.p7s";
	    final ZipEntry signatureZIPEntry = new ZipEntry(signatureName);
	    ((ZipOutputStream) outZip).putNextEntry(signatureZIPEntry);
	    addEntryToZip(signature, outZip, signatureName);
	    ((ZipOutputStream) outZip).closeEntry();

	    // Añadimos el fichero firmado
	    final String signedFileName = "ficheroAfirmar.txt";
	    final ZipEntry signedFileZIPEntry = new ZipEntry(signedFileName);
	    ((ZipOutputStream) outZip).putNextEntry(signedFileZIPEntry);
	    addEntryToZip(signedFile, outZip, signedFileName);
	    ((ZipOutputStream) outZip).closeEntry();

	    // Añadimos el fichero mimetype
	    final String mimetypeFileName = "mimetype";
	    final byte[ ] mimetypeBytes = UtilsFileSystemCommons.readFile("ASiC/mimetype", true);
	    final ZipEntry mimetypeZIPEntry = new ZipEntry(mimetypeFileName);
	    ((ZipOutputStream) outZip).putNextEntry(mimetypeZIPEntry);
	    addEntryToZip(mimetypeBytes, outZip, mimetypeFileName);
	    ((ZipOutputStream) outZip).closeEntry();

	    // Devolvemos el array de bytes que se corresponde con el nuevo
	    // fichero ZIP
	    ((ZipOutputStream) outZip).finish();
	} finally {
	    UtilsResourcesCommons.safeCloseOutputStream(outZip);
	    UtilsResourcesCommons.safeCloseOutputStream(baos);
	}
	return ((ByteArrayOutputStream) baos).toByteArray();
    }

    private void addEntryToZip(final byte[ ] entryBytes, final OutputStream out, final String entryName) throws IOException {
	final InputStream in = new ByteArrayInputStream(entryBytes);
	final byte[ ] buffer = new byte[1024];
	int bytesRead = 0;
	try {
	    while ((bytesRead = in.read(buffer)) != -1) {
		out.write(buffer, 0, bytesRead);
	    }
	} finally {
	    // Cerramos recursos
	    UtilsResourcesCommons.safeCloseInputStream(in);
	}
    }

    /**
     * Test for methods {@link ASiCSBaselineSigner#upgrade(byte[], java.util.List)} and {@link ASiCSBaselineSigner#verifySignature(byte[])}.
     */
    public final void testUpgrade() {

	final byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ASiC/ficheroAfirmar.txt", true);
	final PrivateKeyEntry privateKey = getCertificatePrivateKey();
	byte[ ] cadesBLevelSignature = null;
	byte[ ] asicSSignature = null;
	byte[ ] upgradedASiCSignature = null;
	final Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "Description Test");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP, "UTF-8");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, "application-xml");

	/*
	 * Generamos una firma CAdES Baseline explícita sin política de firma ni sello de tiempo usando SHA-1
	 */
	try {
	    final CAdESBaselineSigner cadesBaselineSigner = new CAdESBaselineSigner();
	    cadesBLevelSignature = cadesBaselineSigner.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);

	    // cades explicita
	    final byte[ ] cadesExplicitSignature = UtilsFileSystemCommons.readFile("signatures/ASN1/CAdES-Explicit.p7s", true);
	    // Construímos la firma ASiC-S
	    asicSSignature = createASiCSWithASN1Signature(cadesExplicitSignature, dataToSign);

	    // Comprobamos que, efectivamente, sea ASiC-S
	    assertEquals(ISignatureFormatDetector.FORMAT_ASIC_S_B_LEVEL, SignatureFormatDetectorASiC.getSignatureFormat(asicSSignature));

	    // // Actualizamos la firma CAdES contenida
	    final ASiCSBaselineSigner asicSBaselineSignatureManager = new ASiCSBaselineSigner();
	    upgradedASiCSignature = asicSBaselineSignatureManager.upgrade(asicSSignature, null);

	    // // Comprobamos que ahora la firma ASiC-S contiene una firma CAdES
	    // // T-Level
	    assertEquals(ISignatureFormatDetector.FORMAT_ASIC_S_T_LEVEL, SignatureFormatDetectorASiC.getSignatureFormat(upgradedASiCSignature));

	    // // Validamos la firma ASiC-S resultante
	    final ValidationResult vr = asicSBaselineSignatureManager.verifySignature(upgradedASiCSignature);
	    assertTrue(vr.isCorrect());

	} catch (final Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for methods {@link ASiCSBaselineSigner#getSignedData(byte[])}.
     * 
     */
    public final void testGetSignedData() {

	// obtenemos la firma ASiCs (Cades)
	final byte[ ] asicSSignature = UtilsFileSystemCommons.readFile("signatures/ASiC/AsiCsWithASN1.asics", true);

	final ASiCSBaselineSigner asicsBaselineSigner = new ASiCSBaselineSigner();

	// se obtienen los datos firmados
	try {
	    final OriginalSignedData osd = asicsBaselineSigner.getSignedData(asicSSignature);
	    assertNotNull(osd.getSignedData());
	    assertNotNull(osd.getMimetype());
	    assertNull(osd.getHashAlgorithm());
	    assertNull(osd.getHashSignedData());

	} catch (final SigningException e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for methods {@link ASiCSBaselineSigner#getSignedData(byte[])}.
     * 
     */
    public final void testGetSignedDataTimeStamp() {

	// obtenemos la firma que contiene un sello de tiempo
	final byte[ ] asicSSignature = UtilsFileSystemCommons.readFile("signatures/ASiC/ASiC_S_Timestamp.asics", true);
	final ASiCSBaselineSigner asicsBaselineSigner = new ASiCSBaselineSigner();

	// se obtienen los datos firmados, saltará una excepción
	try {
	    final OriginalSignedData osd = asicsBaselineSigner.getSignedData(asicSSignature);

	} catch (final SigningException e) {
	    assertTrue(true);
	}
    }

    /**
     * Test for method {@link ASiCSBaselineSigner#sign(byte[], String, String, java.security.KeyStore.PrivateKeyEntry, Properties, boolean, String, String)}.
     * @throws TransformersException 
     */
    public final void testSignWithoutTimestamp() throws TransformersException {
	final byte[ ] dataToSignCades = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);
	final byte[ ] dataToSignXades = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);
	final PrivateKeyEntry privateKey = getCertificatePrivateKey();

	final ASiCSBaselineSigner signer = new ASiCSBaselineSigner();

	byte[ ] asicsCadesBaseline = null;
	final byte[ ] asicsXadesBaseline = null;

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma CAdES
	Baseline explícita, con política de firma y algoritmo SHA-512
	*/
	try {
	    asicsCadesBaseline = signer.sign(dataToSignCades, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    final ValidationResult vr = signer.verifySignature(asicsCadesBaseline);
	    assertTrue(vr.isCorrect());

	} catch (final SigningException e) {
	    assertTrue(false);
	}

    }
    
    /**
     * Test for method {@link ASiCSBaselineSigner#sign(byte[], String, String, java.security.KeyStore.PrivateKeyEntry, Properties, boolean, String, String)}.
     */
    public final void testSignECCWithoutTimestamp() {
	final byte[ ] dataToSignCades = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);
	final byte[ ] dataToSignXades = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);
	final PrivateKeyEntry privateKey = getCertificateECCPrivateKey();

	final ASiCSBaselineSigner signer = new ASiCSBaselineSigner();

	byte[ ] asicsCadesBaseline = null;
	byte[ ] asicsXadesBaseline = null;

	/*
	 * Generación y Validación de firma ASiCs Baseline con firma CAdES Baseline, sin política de firma, algoritmo SHA-256 (válido) y explícita.
	 */
	try {
	    asicsCadesBaseline = signer.sign(dataToSignCades, SignatureConstants.SIGN_ALGORITHM_SHA256, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    assertEquals(SignatureFormatDetectorASiC.getSignatureFormat(asicsCadesBaseline), ISignatureFormatDetector.FORMAT_ASIC_S_B_LEVEL);
	    final ValidationResult vr = signer.verifySignature(asicsCadesBaseline);
	    assertTrue(vr.isCorrect());

	} catch (final SigningException e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma CAdES
	Baseline IMPLICITA, sin política de firma y algoritmo SHA-512
	*/
	try {
	    asicsCadesBaseline = signer.sign(dataToSignCades, SignatureConstants.SIGN_ALGORITHM_SHA512, SignatureConstants.SIGN_MODE_IMPLICIT, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    final ValidationResult vr = signer.verifySignature(asicsCadesBaseline);
	    assertTrue(vr.isCorrect());

	} catch (final SigningException e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma CAdES
	Baseline explícita, con política de firma y algoritmo SHA-512
	*/
	try {
	    asicsCadesBaseline = signer.sign(dataToSignCades, SignatureConstants.SIGN_ALGORITHM_SHA512, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    final ValidationResult vr = signer.verifySignature(asicsCadesBaseline);
	    assertTrue(vr.isCorrect());

	} catch (final SigningException e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma CAdES
	Baseline explícita, con política de firma y algoritmo no permitido
	*/
	try {
	    asicsCadesBaseline = signer.sign(dataToSignCades, null, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    final ValidationResult vr = signer.verifySignature(asicsCadesBaseline);
	    assertFalse(vr.isCorrect());

	} catch (final IllegalArgumentException e) {
	    assertTrue(true);
	} catch (final SigningException e) {
	    assertTrue(false);
	}

	final Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.XADES_CLAIMED_ROLE_PROP, "emisor");
	// extraParams.put(SignatureProperties.XADES_POLICY_QUALIFIER_PROP, "");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP, "UTF-8");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, "");
	extraParams.put(SignatureProperties.XADES_CANONICALIZATION_METHOD, "http://www.w3.org/2006/12/xml-c14n11");
	/*
	* Generación y Validación de firma ASiC-S Baseline con firma XAdES
	Baseline detached, sin política de firma.
	*/
	try {

	    asicsXadesBaseline = signer.sign(dataToSignXades, SignatureConstants.SIGN_ALGORITHM_SHA256, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	   
	    final ValidationResult vr = signer.verifySignature(asicsXadesBaseline);
	    assertTrue(vr.isCorrect());
	} catch (final SigningException e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma XAdES
	Baseline detached, con política de firma.
	*/
	try {

	    asicsXadesBaseline = signer.sign(dataToSignXades, SignatureConstants.SIGN_ALGORITHM_SHA512, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, "XML_AGE_1.9_URL");

	    final ValidationResult vr = signer.verifySignature(asicsXadesBaseline);
	    assertTrue(vr.isCorrect());
	} catch (final SigningException e) {
	    assertTrue(true);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma XAdES
	Baseline con parámetros adiciones no permitidos.
	*/
	try {

	    extraParams.put(SignatureProperties.CADES_POLICY_QUALIFIER_PROP, "");

	    asicsXadesBaseline = signer.sign(dataToSignXades, SignatureConstants.SIGN_ALGORITHM_SHA512, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    final ValidationResult vr = signer.verifySignature(asicsXadesBaseline);
	    assertTrue(!vr.isCorrect());
	} catch (final IllegalArgumentException e) {
	    assertTrue(true);
	} catch (final SigningException e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for method {@link ASiCSBaselineSigner#sign(byte[], String, String, java.security.KeyStore.PrivateKeyEntry, Properties, boolean, String, String)}.
     */
    public final void testSignWithTimestamp() {
	final byte[ ] dataToSignCades = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);
	final byte[ ] dataToSignXades = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);
	final PrivateKeyEntry privateKey = getCertificatePrivateKey();

	final ASiCSBaselineSigner signer = new ASiCSBaselineSigner();

	byte[ ] asicsCadesBaseline = null;
	byte[ ] asicsXadesBaseline = null;

	/*
	 * Generación y Validación de firma ASiCs Baseline con firma CAdES Baseline, sin política de firma, algoritmo SHA-256 (válido) y explícita.
	 */
	try {
	    asicsCadesBaseline = signer.sign(dataToSignCades, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, true, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);

	    final ValidationResult vr = signer.verifySignature(asicsCadesBaseline);
	    assertTrue(vr.isCorrect());

	} catch (final SigningException e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma CAdES
	Baseline IMPLICITA, sin política de firma y algoritmo SHA-512
	*/
	try {
	    asicsCadesBaseline = signer.sign(dataToSignCades, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, privateKey, null, true, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    final ValidationResult vr = signer.verifySignature(asicsCadesBaseline);
	    assertTrue(vr.isCorrect());

	} catch (final SigningException e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma CAdES
	Baseline explícita, con política de firma y algoritmo SHA-512
	*/
	try {
	    asicsCadesBaseline = signer.sign(dataToSignCades, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, true, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    final ValidationResult vr = signer.verifySignature(asicsCadesBaseline);
	    assertTrue(vr.isCorrect());

	} catch (final SigningException e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma CAdES
	Baseline explícita, con política de firma y algoritmo no permitido
	*/
	try {
	    asicsCadesBaseline = signer.sign(dataToSignCades, null, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    final ValidationResult vr = signer.verifySignature(asicsCadesBaseline);
	    assertFalse(vr.isCorrect());

	} catch (final IllegalArgumentException e) {
	    assertTrue(true);
	} catch (final SigningException e) {
	    assertTrue(false);
	}

	final Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.XADES_CLAIMED_ROLE_PROP, "emisor");
	extraParams.put(SignatureProperties.XADES_POLICY_QUALIFIER_PROP, "");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "Description Test");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP, "UTF-8");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, "application-xml");
	extraParams.put(SignatureProperties.XADES_CANONICALIZATION_METHOD, "http://www.w3.org/2006/12/xml-c14n11");
	/*
	* Generación y Validación de firma ASiC-S Baseline con firma XAdES
	Baseline detached, sin política de firma.
	*/
	try {

	    asicsXadesBaseline = signer.sign(dataToSignXades, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, extraParams, true, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);

	    final ValidationResult vr = signer.verifySignature(asicsXadesBaseline);
	    assertTrue(vr.isCorrect());
	} catch (final SigningException e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma XAdES
	Baseline detached, con política de firma.
	*/
	try {

	    asicsXadesBaseline = signer.sign(dataToSignXades, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, extraParams, true, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, "XML_AGE_1.9_URL");

	    final ValidationResult vr = signer.verifySignature(asicsXadesBaseline);
	    assertTrue(vr.isCorrect());
	} catch (final SigningException e) {
	    assertTrue(true);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma XAdES
	Baseline con parámetros adiciones no permitidos.
	*/
	try {

	    extraParams.put(SignatureProperties.CADES_POLICY_QUALIFIER_PROP, "");

	    asicsXadesBaseline = signer.sign(dataToSignXades, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, extraParams, true, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    final ValidationResult vr = signer.verifySignature(asicsXadesBaseline);
	    assertTrue(!vr.isCorrect());
	} catch (final IllegalArgumentException e) {
	    assertTrue(true);
	} catch (final SigningException e) {
	    assertTrue(false);
	}
    }
}
