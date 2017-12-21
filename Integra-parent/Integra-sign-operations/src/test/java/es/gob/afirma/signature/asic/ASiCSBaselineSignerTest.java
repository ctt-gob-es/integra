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
// http://joinup.ec.europa.eu/software/page/eupl/licence-eupl

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

import junit.framework.TestCase;
import es.gob.afirma.signature.ISignatureFormatDetector;
import es.gob.afirma.signature.OriginalSignedData;
import es.gob.afirma.signature.SignatureConstants;
import es.gob.afirma.signature.SignatureFormatDetectorASiC;
import es.gob.afirma.signature.SignatureProperties;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.signature.validation.ValidationResult;
import es.gob.afirma.signature.cades.CAdESBaselineSigner;
import es.gob.afirma.utils.UtilsFileSystemCommons;
import es.gob.afirma.utils.UtilsResourcesCommons;

/**
 * <p>Class that defines tests for {@link ASiCSBaselineSigner}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 29/01/2016.
 */
public class ASiCSBaselineSignerTest extends TestCase {

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

    private byte[ ] createASiCSWithASN1Signature(byte[ ] signature, byte[ ] signedFile) throws IOException {
	OutputStream baos = new ByteArrayOutputStream();
	OutputStream outZip = new ZipOutputStream(baos);

	try {
	    // Añadimos la carpeta META-INF
	    ((ZipOutputStream) outZip).putNextEntry(new ZipEntry("META-INF/"));

	    // Añadimos la firma ASN.1
	    String signatureName = "META-INF/signature.p7s";
	    ZipEntry signatureZIPEntry = new ZipEntry(signatureName);
	    ((ZipOutputStream) outZip).putNextEntry(signatureZIPEntry);
	    addEntryToZip(signature, outZip, signatureName);
	    ((ZipOutputStream) outZip).closeEntry();

	    // Añadimos el fichero firmado
	    String signedFileName = "ficheroAfirmar.txt";
	    ZipEntry signedFileZIPEntry = new ZipEntry(signedFileName);
	    ((ZipOutputStream) outZip).putNextEntry(signedFileZIPEntry);
	    addEntryToZip(signedFile, outZip, signedFileName);
	    ((ZipOutputStream) outZip).closeEntry();

	    // Añadimos el fichero mimetype
	    String mimetypeFileName = "mimetype";
	    byte[ ] mimetypeBytes = UtilsFileSystemCommons.readFile("ASiC/mimetype", true);
	    ZipEntry mimetypeZIPEntry = new ZipEntry(mimetypeFileName);
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

    private void addEntryToZip(byte[ ] entryBytes, OutputStream out, String entryName) throws IOException {
	InputStream in = new ByteArrayInputStream(entryBytes);
	byte[ ] buffer = new byte[1024];
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

	byte[ ] dataToSign = UtilsFileSystemCommons.readFile("ASiC/ficheroAfirmar.txt", true);
	PrivateKeyEntry privateKey = getCertificatePrivateKey();
	byte[ ] cadesBLevelSignature = null;
	byte[ ] asicSSignature = null;
	byte[ ] upgradedASiCSignature = null;
	Properties extraParams = new Properties();
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "Description Test");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP, "UTF-8");
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, "application-xml");

	/*
	 * Generamos una firma CAdES Baseline explícita sin política de firma ni sello de tiempo usando SHA-1
	 */
	try {
	    CAdESBaselineSigner cadesBaselineSigner = new CAdESBaselineSigner();
	    cadesBLevelSignature = cadesBaselineSigner.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);

	    // cades explicita
	    byte[ ] cadesExplicitSignature = UtilsFileSystemCommons.readFile("signatures/ASN1/CAdES-Explicit.p7s", true);
	    // Construímos la firma ASiC-S
	    asicSSignature = createASiCSWithASN1Signature(cadesExplicitSignature, dataToSign);

	    // Comprobamos que, efectivamente, sea ASiC-S
	    assertEquals(ISignatureFormatDetector.FORMAT_ASIC_S_B_LEVEL, SignatureFormatDetectorASiC.getSignatureFormat(asicSSignature));

	    // // Actualizamos la firma CAdES contenida
	    ASiCSBaselineSigner asicSBaselineSignatureManager = new ASiCSBaselineSigner();
	    upgradedASiCSignature = asicSBaselineSignatureManager.upgrade(asicSSignature, null);

	    // // Comprobamos que ahora la firma ASiC-S contiene una firma CAdES
	    // // T-Level
	    assertEquals(ISignatureFormatDetector.FORMAT_ASIC_S_T_LEVEL, SignatureFormatDetectorASiC.getSignatureFormat(upgradedASiCSignature));

	    // // Validamos la firma ASiC-S resultante
	    ValidationResult vr = asicSBaselineSignatureManager.verifySignature(upgradedASiCSignature);
	    assertTrue(vr.isCorrect());

	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for methods {@link ASiCSBaselineSigner#getSignedData(byte[])}.
     * 
     */
    public final void testGetSignedData() {

	// obtenemos la firma ASiCs (Cades)
	byte[ ] asicSSignature = UtilsFileSystemCommons.readFile("signatures/ASiC/AsiCsWithASN1.asics", true);

	ASiCSBaselineSigner asicsBaselineSigner = new ASiCSBaselineSigner();

	// se obtienen los datos firmados
	try {
	    OriginalSignedData osd = asicsBaselineSigner.getSignedData(asicSSignature);
	    assertNotNull(osd.getSignedData());
	    assertNotNull(osd.getMimetype());
	    assertNull(osd.getHashAlgorithm());
	    assertNull(osd.getHashSignedData());

	} catch (SigningException e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for methods {@link ASiCSBaselineSigner#getSignedData(byte[])}.
     * 
     */
    public final void testGetSignedDataTimeStamp() {

	// obtenemos la firma que contiene un sello de tiempo
	byte[ ] asicSSignature = UtilsFileSystemCommons.readFile("signatures/ASiC/ASiC_S_Timestamp.asics", true);
	ASiCSBaselineSigner asicsBaselineSigner = new ASiCSBaselineSigner();

	// se obtienen los datos firmados, saltará una excepción
	try {
	    OriginalSignedData osd = asicsBaselineSigner.getSignedData(asicSSignature);

	} catch (SigningException e) {
	    assertTrue(true);
	}
    }

    /**
     * Test for method {@link ASiCSBaselineSigner#sign(byte[], String, String, PrivateKeyEntry, Properties, boolean, String, String)}.
     */
    public final void testSignWithoutTimestamp() {
	byte[ ] dataToSignCades = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);
	byte[ ] dataToSignXades = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);
	PrivateKeyEntry privateKey = getCertificatePrivateKey();

	ASiCSBaselineSigner signer = new ASiCSBaselineSigner();

	byte[ ] asicsCadesBaseline = null;
	byte[ ] asicsXadesBaseline = null;

	/*
	 * Generación y Validación de firma ASiCs Baseline con firma CAdES Baseline, sin política de firma, algoritmo SHA-256 (válido) y explícita.
	 */
	try {
	    asicsCadesBaseline = signer.sign(dataToSignCades, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    assertEquals(SignatureFormatDetectorASiC.getSignatureFormat(asicsCadesBaseline), ISignatureFormatDetector.FORMAT_ASIC_S_B_LEVEL);
	    ValidationResult vr = signer.verifySignature(asicsCadesBaseline);
	    assertTrue(vr.isCorrect());

	} catch (SigningException e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma CAdES
	Baseline IMPLÍCITA, sin política de firma y algoritmo SHA-512
	*/
	try {
	    asicsCadesBaseline = signer.sign(dataToSignCades, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(asicsCadesBaseline);
	    assertTrue(vr.isCorrect());

	} catch (SigningException e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma CAdES
	Baseline explícita, con política de firma y algoritmo SHA-512
	*/
	try {
	    asicsCadesBaseline = signer.sign(dataToSignCades, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    ValidationResult vr = signer.verifySignature(asicsCadesBaseline);
	    assertTrue(vr.isCorrect());

	} catch (SigningException e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma CAdES
	Baseline explícita, con política de firma y algoritmo no permitido
	*/
	try {
	    asicsCadesBaseline = signer.sign(dataToSignCades, null, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    ValidationResult vr = signer.verifySignature(asicsCadesBaseline);
	    assertFalse(vr.isCorrect());

	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	} catch (SigningException e) {
	    assertTrue(false);
	}

	Properties extraParams = new Properties();
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

	    asicsXadesBaseline = signer.sign(dataToSignXades, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	   
	    ValidationResult vr = signer.verifySignature(asicsXadesBaseline);
	    assertTrue(vr.isCorrect());
	} catch (SigningException e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma XAdES
	Baseline detached, con política de firma.
	*/
	try {

	    asicsXadesBaseline = signer.sign(dataToSignXades, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, "XML_AGE_1.9_URL");

	    ValidationResult vr = signer.verifySignature(asicsXadesBaseline);
	    assertTrue(vr.isCorrect());
	} catch (SigningException e) {
	    assertTrue(true);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma XAdES
	Baseline con parámetros adiciones no permitidos.
	*/
	try {

	    extraParams.put(SignatureProperties.CADES_POLICY_QUALIFIER_PROP, "");

	    asicsXadesBaseline = signer.sign(dataToSignXades, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, extraParams, false, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(asicsXadesBaseline);
	    assertTrue(!vr.isCorrect());
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	} catch (SigningException e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for method {@link ASiCSBaselineSigner#sign(byte[], String, String, PrivateKeyEntry, Properties, boolean, String, String)}.
     */
    public final void testSignWithTimestamp() {
	byte[ ] dataToSignCades = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);
	byte[ ] dataToSignXades = UtilsFileSystemCommons.readFile("ficheroAfirmar.xml", true);
	PrivateKeyEntry privateKey = getCertificatePrivateKey();

	ASiCSBaselineSigner signer = new ASiCSBaselineSigner();

	byte[ ] asicsCadesBaseline = null;
	byte[ ] asicsXadesBaseline = null;

	/*
	 * Generación y Validación de firma ASiCs Baseline con firma CAdES Baseline, sin política de firma, algoritmo SHA-256 (válido) y explícita.
	 */
	try {
	    asicsCadesBaseline = signer.sign(dataToSignCades, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, true, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);

	    ValidationResult vr = signer.verifySignature(asicsCadesBaseline);
	    assertTrue(vr.isCorrect());

	} catch (SigningException e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma CAdES
	Baseline IMPLÍCITA, sin política de firma y algoritmo SHA-512
	*/
	try {
	    asicsCadesBaseline = signer.sign(dataToSignCades, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_IMPLICIT, privateKey, null, true, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(asicsCadesBaseline);
	    assertTrue(vr.isCorrect());

	} catch (SigningException e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma CAdES
	Baseline explícita, con política de firma y algoritmo SHA-512
	*/
	try {
	    asicsCadesBaseline = signer.sign(dataToSignCades, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, true, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    ValidationResult vr = signer.verifySignature(asicsCadesBaseline);
	    assertTrue(vr.isCorrect());

	} catch (SigningException e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma CAdES
	Baseline explícita, con política de firma y algoritmo no permitido
	*/
	try {
	    asicsCadesBaseline = signer.sign(dataToSignCades, null, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, false, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, "ASN1_AGE_1.9");
	    ValidationResult vr = signer.verifySignature(asicsCadesBaseline);
	    assertFalse(vr.isCorrect());

	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	} catch (SigningException e) {
	    assertTrue(false);
	}

	Properties extraParams = new Properties();
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

	    ValidationResult vr = signer.verifySignature(asicsXadesBaseline);
	    assertTrue(vr.isCorrect());
	} catch (SigningException e) {
	    assertTrue(false);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma XAdES
	Baseline detached, con política de firma.
	*/
	try {

	    asicsXadesBaseline = signer.sign(dataToSignXades, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, extraParams, true, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, "XML_AGE_1.9_URL");

	    ValidationResult vr = signer.verifySignature(asicsXadesBaseline);
	    assertTrue(vr.isCorrect());
	} catch (SigningException e) {
	    assertTrue(true);
	}

	/*
	* Generación y Validación de firma ASiC-S Baseline con firma XAdES
	Baseline con parámetros adiciones no permitidos.
	*/
	try {

	    extraParams.put(SignatureProperties.CADES_POLICY_QUALIFIER_PROP, "");

	    asicsXadesBaseline = signer.sign(dataToSignXades, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, extraParams, true, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, null);
	    ValidationResult vr = signer.verifySignature(asicsXadesBaseline);
	    assertTrue(!vr.isCorrect());
	} catch (IllegalArgumentException e) {
	    assertTrue(true);
	} catch (SigningException e) {
	    assertTrue(false);
	}
    }
}
