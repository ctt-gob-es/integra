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
 * <b>File:</b><p>es.gob.afirma.signature.XadesSignerTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for {@link XadesSigner}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/04/2015.</p>
 * @author Gobierno de España.
 * @version 1.2, 14/03/2017.
 */
package es.gob.afirma.signature;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import es.gob.afirma.integraFacade.pojo.TransformData;
import es.gob.afirma.logger.Logger;
import es.gob.afirma.signature.validation.ValidationResult;
import es.gob.afirma.signature.xades.ReferenceData;
import es.gob.afirma.signature.xades.XadesSigner;
import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersFacade;
import es.gob.afirma.utils.Base64CoderCommons;
import es.gob.afirma.utils.DSSConstants.DSSTagsRequest;
import es.gob.afirma.utils.DSSConstants.ReportDetailLevel;
import es.gob.afirma.utils.DSSConstants.ResultProcessIds;
import es.gob.afirma.utils.GeneralConstants;
import es.gob.afirma.utils.UtilsCertificateCommons;
import es.gob.afirma.utils.UtilsFileSystemCommons;
import es.gob.afirma.wsServiceInvoker.Afirma5ServiceInvokerFacade;

/**
 * <p>Class that defines tests for {@link XadesSigner}.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.2, 14/03/2017.
 */
public class XadesSignerTest extends AbstractSignatureTest {

    /**
     * Attribute that allows to verify signatures against an external validation platform.
     */
    private static final boolean EXTERNAL_VERIFY = false;

    /**
     * Tests for {@link XadesSigner#sign(byte[], String, String, java.security.KeyStore.PrivateKeyEntry, Properties, boolean, String, String)} with invalid
     * values.
     * @throws Exception If the test fails.
     */
    public void testSignInvalidValues() throws Exception {

	final XadesSigner xadesSign = new XadesSigner();
	// Prueba con valores nulos
	try {
	    xadesSign.sign(null, null, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (final IllegalArgumentException e) {}

	try {
	    xadesSign.sign(null, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING, getCertificatePrivateKey(), null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (final IllegalArgumentException e) {}

	// Prueba con valores no válidos (algoritmo no soportado)
	try {
	    xadesSign.sign(new byte[0], "MD5withRSA", SignatureConstants.SIGN_FORMAT_XADES_DETACHED, getCertificatePrivateKey(), null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (final IllegalArgumentException e) {}

	// Modo de firma no soportado
	try {
	    xadesSign.sign(new byte[0], SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, "XMLDSig Enveloped", getCertificatePrivateKey(), null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (final IllegalArgumentException e) {}

    }

    /**
     * Tests for signing a binary file as an enveloping signature.
     * @throws Exception If the test fails.
     */
    public void testSignBinaryEnveloping() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();
	final byte[ ] dataToSign = getTextDocument();
	final byte[ ] signature = xadesSign.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA384WITHECDSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING, getCertificatePrivateKey(), getDataFormatParams(), false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	// validamos firma
	assertTrue(xadesSign.verifySignature(signature).isCorrect());
	
	externalSignVerify(signature);

    }

    /**
     * Tests for signing a XML file as an enveloping signature.
     * @throws Exception If the test fails.
     */
    public void testSignXmlEnveloping() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();

	final byte[ ] dataToSign = getXmlDocument();

	final byte[ ] signature = xadesSign.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA384WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING, getCertificatePrivateKey(), null, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	// validamos firma
	assertTrue(xadesSign.verifySignature(signature).isCorrect());

	externalSignVerify(signature);

    }

    /**
     * Tests for signing a binary file as an enveloped signature.
     * @throws Exception If the test fails.
     */
    public void testSignBinaryEnveloped() throws Exception {
	try {
	    new XadesSigner().sign(getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED, getCertificatePrivateKey(), null, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	    fail("No se ha lanzado la excepción por firma enveloped sobre datos binarios");
	} catch (final SigningException e) {}

    }

    /**
     * Tests for signing a XML file as an enveloped signature.
     * @throws Exception If the test fails.
     */
    public void testSignXmlEnveloped() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();

	final byte[ ] signature = xadesSign.sign(getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED, getCertificatePrivateKey(), getDataFormatParams(), false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	// validamos firma
	assertTrue(xadesSign.verifySignature(signature).isCorrect());
	externalSignVerify(signature);
    }

    /**
     * Tests for signing a binary file as a detached signature.
     * @throws Exception If the test fails.
     */
    public void testSignBinaryDetached() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();

	final byte[ ] signature = xadesSign.sign(getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, getCertificatePrivateKey(), getDataFormatParams(), false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	// validamos firma
	assertTrue(xadesSign.verifySignature(signature).isCorrect());
	externalSignVerify(signature);

    }

    /**
     * Tests for signing a XML file as a detached signature.
     * @throws Exception If the test fails.
     */
    public void testSignXmlDetached() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();

	final byte[ ] signature = xadesSign.sign(getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, getCertificatePrivateKey(), null, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	// validamos firma
	assertTrue(xadesSign.verifySignature(signature).isCorrect());
	externalSignVerify(signature);

    }
    
    /**
     * Tests for signing a XML file as a detached signature with a ECC certificate.
     * @throws Exception If the test fails.
     */
    public void testSignECCXmlDetached() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();

	final byte[ ] signature = xadesSign.sign(getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA256, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, getCertificateECCPrivateKey(), null, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	
	// validamos firma
	assertTrue(xadesSign.verifySignature(signature).isCorrect());
	externalSignVerify(signature);
	System.out.println("\n-->>FIRMA RESULTANTE : \n" + new String(Base64CoderCommons.encodeBase64(signature)));

    }

    /**
     * Tests for signing as an externally detached signature.
     * @throws Exception If the test fails.
     */
    public void testSignExternallyDetached() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();

	// Creamos listado de propiedades adicionales que incluirá el objeto
	// manifest con todas las referencias externas.
	final Properties extraParams = new Properties();
	final ReferenceData rd = new ReferenceData("http://www.w3.org/2000/09/xmldsig#sha1", "zyjp8GJOX69990Kkqw8ioPXGExk=");
	final String xPath = "self::text()[ancestor-or-self::node()=/Class/e[1]]";
	final TransformData transform = new TransformData("http://www.w3.org/2000/09/xmldsig#base64", null);
	final TransformData transform2 = new TransformData("http://www.w3.org/TR/1999/REC-xpath-19991116", Collections.singletonList(xPath));
	final List<TransformData> transformList = new ArrayList<TransformData>(2);
	transformList.add(transform);
	transformList.add(transform2);
	rd.setTransforms(transformList);
	rd.setId("idAttribute");
	rd.setType("typeAttribute");
	rd.setUri("uriAttribute");
	final List<ReferenceData> rdlist = Collections.singletonList(rd);
	extraParams.put(SignatureConstants.MF_REFERENCES_PROPERTYNAME, rdlist);

	final byte[ ] signature = xadesSign.sign(null, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_EXTERNALLY_DETACHED, getCertificatePrivateKey(), extraParams, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);

	// validamos firma
	assertTrue(xadesSign.verifySignature(signature).isCorrect());
	externalSignVerify(signature);

    }

    /**
     * Tests for signing a binary file as an enveloping signature with SHA-512.
     * @throws Exception If the test fails.
     */
    public void testSignOtherAlgorithms() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();
	final byte[ ] dataToSign = getTextDocument();
	final byte[ ] signature = xadesSign.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING, getCertificatePrivateKey(), null, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	// validamos firma
	assertTrue(xadesSign.verifySignature(signature).isCorrect());
	externalSignVerify(signature);
    }

    /**
     * Tests for signing a XML file as an enveloping signature with signature policies.
     * @throws Exception If the test fails.
     */
    public void testSignWithPolicy() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();
	final byte[ ] dataToSign = getXmlDocument();

	final Properties optionalParams = getDataFormatParams();
	optionalParams.putAll(getPolicyParams());

	final byte[ ] signature = xadesSign.sign(dataToSign, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING, getCertificatePrivateKey(), optionalParams, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	// validamos firma
	assertTrue(xadesSign.verifySignature(signature).isCorrect());
	externalSignVerify(signature);
    }

    /**
     * Method that obtains a set of properties needed for generating tests of signatures with signature policies.
     * @return an object that represents the properties.
     */
    private Properties getPolicyParams() {
	final Properties policyParams = new Properties();
	policyParams.put(SignatureProperties.XADES_CLAIMED_ROLE_PROP, "emisor");
	return policyParams;
    }

    /**
     * Method that obtains a set of properties related to the signed data object.
     * @return an object that represents the properties.
     */
    private Properties getDataFormatParams() {
	final Properties dataFormatProp = new Properties();
	dataFormatProp.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "Texto plano");
	dataFormatProp.put(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP, "utf-8");
	dataFormatProp.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, "text/plain");
	return dataFormatProp;
    }

    /**
     * Tests for {@link XadesSigner#coSign(byte[], byte[], String, java.security.KeyStore.PrivateKeyEntry, Properties, boolean, String, String)} with invalid
     * values.
     * @throws Exception If the test fails.
     */
    public void testCoSignInvalidValues() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();
	// Argumentos inválidos.
	try {
	    xadesSign.coSign(null, null, null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (final IllegalArgumentException e) {}

	try {
	    xadesSign.coSign(new byte[ ] { }, null, null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (final IllegalArgumentException e) {}

	try {
	    xadesSign.coSign(new byte[ ] { }, new byte[ ] { }, null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (final IllegalArgumentException e) {}

	try {
	    xadesSign.coSign(new byte[ ] { }, new byte[ ] { }, "MD5", null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (final IllegalArgumentException e) {}

	// Algoritmo de firma no soportado
	try {
	    xadesSign.coSign(new byte[ ] { }, new byte[ ] { }, "MD5", getCertificatePrivateKey(), null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (final IllegalArgumentException e) {}

	// Firma a cofirmar inválida.
	try {
	    xadesSign.coSign(new byte[ ] { }, getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (final SigningException e) {}

	try {
	    xadesSign.coSign("<Sign>".getBytes(), getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (final SigningException e) {}

	try {
	    final byte[ ] eSignature = UtilsFileSystemCommons.readFile("signatures/XAdES-Invalid.xml", true);
	    xadesSign.coSign(eSignature, getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), null, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (final SigningException e) {
	    assertTrue(e.getMessage().contains("no es válida"));
	}

    }

    /**
     * Tests for generating enveloping co-signatures.
     * @throws Exception If the test fails.
     */
    public void testCoSignEnveloping() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();

	byte[ ] eSignature = UtilsFileSystemCommons.readFile("signatures/XAdES-Enveloping-Xml.xml", true);
	byte[ ] data = getXmlDocument();

	// cofirma documento xml
	byte[ ] coSignature = xadesSign.coSign(eSignature, data, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), null, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	// validación firma
	assertTrue(xadesSign.verifySignature(coSignature).isCorrect());
	externalSignVerify(coSignature);

	// cofirma documento binario
	eSignature = UtilsFileSystemCommons.readFile("signatures/XAdES-Enveloping-Binary.xml", true);
	data = getTextDocument();
	coSignature = xadesSign.coSign(eSignature, data, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), getDataFormatParams(), false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	// validación firma
	assertTrue(xadesSign.verifySignature(coSignature).isCorrect());
	externalSignVerify(coSignature);
    }
    
    /**
     * Tests for generating enveloping co-signatures with a ECC certificate.
     * @throws Exception If the test fails.
     */
    public void testCoSignECCEnveloping() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();

	byte[ ] eSignature = UtilsFileSystemCommons.readFile("signatures/XAdES-Enveloping-Xml.xml", true);
	byte[ ] data = getXmlDocument();

	// cofirma documento xml
	byte[ ] coSignature = xadesSign.coSign(eSignature, data, SignatureConstants.SIGN_ALGORITHM_SHA256, getCertificateECCPrivateKey(), null, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	// validación firma
	assertTrue(xadesSign.verifySignature(coSignature).isCorrect());
	externalSignVerify(coSignature);

	// cofirma documento binario
	eSignature = UtilsFileSystemCommons.readFile("signatures/XAdES-Enveloping-Binary.xml", true);
	data = getTextDocument();
	coSignature = xadesSign.coSign(eSignature, data, SignatureConstants.SIGN_ALGORITHM_SHA256, getCertificateECCPrivateKey(), getDataFormatParams(), false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	// validación firma
	assertTrue(xadesSign.verifySignature(coSignature).isCorrect());
	externalSignVerify(coSignature);
	System.out.println("\n-->>FIRMA RESULTANTE : \n" + new String(Base64CoderCommons.encodeBase64(coSignature)));
    }

    /**
     * Tests for generating enveloped co-signatures.
     * @throws Exception If the test fails.
     */
    public void testCoSignEnveloped() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();
	final byte[ ] eSignature = UtilsFileSystemCommons.readFile("signatures/XAdES-Enveloped.xml", true);
	final byte[ ] data = getXmlDocument();
	assertTrue(xadesSign.verifySignature(eSignature).isCorrect());

	// //cofirma documento xml
	final byte[ ] coSignature = xadesSign.coSign(eSignature, data, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, getCertificatePrivateKey(), getDataFormatParams(), false, ISignatureFormatDetector.FORMAT_XADES_BES, null);

	// validación firma
	assertTrue(xadesSign.verifySignature(coSignature).isCorrect());
	externalSignVerify(coSignature);

    }

    /**
     * Tests for generating detached co-signatures.
     * @throws Exception If the test fails.
     */
    public void testCoSignDetached() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();
	byte[ ] eSignature = UtilsFileSystemCommons.readFile("signatures/XAdES-Detached-Xml.xml", true);
	byte[ ] data = getXmlDocument();

	// cofirma documento xml
	byte[ ] coSignature = xadesSign.coSign(eSignature, data, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), null, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	// validación firma
	assertTrue(xadesSign.verifySignature(coSignature).isCorrect());
	externalSignVerify(coSignature);

	// cofirma documento binario
	eSignature = UtilsFileSystemCommons.readFile("signatures/XAdES-Detached-Binary.xml", true);
	data = getTextDocument();
	coSignature = xadesSign.coSign(eSignature, data, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), getDataFormatParams(), false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	// validación firma
	assertTrue(xadesSign.verifySignature(coSignature).isCorrect());
	externalSignVerify(coSignature);
    }

    /**
     * Tests for generating externally detached co-signatures.
     * @throws Exception If the test fails.
     */
    public void testCoSignExternallyDetached() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();
	final byte[ ] eSignature = UtilsFileSystemCommons.readFile("signatures/XAdES-Externally_Detached.xml", true);

	// cofirma documento xml
	final byte[ ] coSignature = xadesSign.coSign(eSignature, null, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), getDataFormatParams(), false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	// validación firma
	assertTrue(xadesSign.verifySignature(coSignature).isCorrect());
	externalSignVerify(coSignature);

    }
    
    /**
     * Tests for generating externally detached co-signatures with a ECC certificate.
     * @throws Exception If the test fails.
     */
    public void testCoSignExternallyECCDetached() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();
	final byte[ ] eSignature = UtilsFileSystemCommons.readFile("signatures/XAdES-Externally_Detached.xml", true);

	// cofirma documento xml
	final byte[ ] coSignature = xadesSign.coSign(eSignature, null, SignatureConstants.SIGN_ALGORITHM_SHA256, getCertificateECCPrivateKey(), getDataFormatParams(), false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	// validación firma
	assertTrue(xadesSign.verifySignature(coSignature).isCorrect());
	externalSignVerify(coSignature);

    }

    /**
     * Tests for {@link XadesSigner#counterSign(byte[], String, java.security.KeyStore.PrivateKeyEntry, Properties, boolean, String, String)} with invalid
     * values.
     * @throws Exception If the test fails.
     */
    public void testCounterSignInvalidValues() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();
	// Argumentos inválidos.
	try {
	    xadesSign.counterSign(null, null, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (final IllegalArgumentException e) {}

	try {
	    xadesSign.counterSign(new byte[0], SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, null, null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (final IllegalArgumentException e) {}

	try {
	    xadesSign.counterSign(new byte[0], "MD5withDSA", getCertificatePrivateKey(), null, false, null, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (final IllegalArgumentException e) {}

	try { // sin firma
	    xadesSign.counterSign(new byte[0], SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, getCertificatePrivateKey(), null, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (final SigningException e) {}

	try {// firma inválida
	    final byte[ ] eSignature = UtilsFileSystemCommons.readFile("signatures/XAdES-Invalid.xml", true);
	    xadesSign.counterSign(eSignature, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), null, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (final SigningException e) {
	    assertTrue(true);
	}

	try { //
	    final byte[ ] eSignature = UtilsFileSystemCommons.readFile("signatures/XAdES-Enveloping-Xml.xml", true);
	    xadesSign.counterSign(eSignature, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), getDataFormatParams(), false, SignatureFormatDetector.FORMAT_XADES_BES, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (final IllegalArgumentException e) {}

	try { //
	    final byte[ ] eSignature = xadesSign.sign(getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED, getCertificatePrivateKey(), getPolicyParams(), false, SignatureFormatDetector.FORMAT_XADES_EPES, null);
	    xadesSign.counterSign(eSignature, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), getPolicyParams(), false, SignatureFormatDetector.FORMAT_XADES_EPES, null);
	    fail(ERROR_EXCEPTION_NOT_THROWED);
	} catch (final IllegalArgumentException e) {}
    }

    /**
     * Tests for generating detached counter-signatures.
     * @throws Exception If the test fails.
     */
    public void testCounterSignDetached() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();
	final byte[ ] eSignature = UtilsFileSystemCommons.readFile("signatures/XAdES-Detached-Xml.xml", true);
	// contrafirma documento xml

	final Properties optionalParams = getDataFormatParams();
	optionalParams.putAll(getPolicyParams());
	final byte[ ] counterSign = xadesSign.counterSign(eSignature, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), optionalParams, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	// validación firma
	assertTrue(xadesSign.verifySignature(counterSign).isCorrect());
	externalSignVerify(counterSign);
    }
    
    /**
     * Tests for generating detached counter-signatures with a ECC certificate.
     * @throws Exception If the test fails.
     */
    public void testCounterSignECCDetached() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();
	final byte[ ] eSignature = UtilsFileSystemCommons.readFile("signatures/XAdES-Detached-Xml.xml", true);
	// contrafirma documento xml

	final Properties optionalParams = getDataFormatParams();
	optionalParams.putAll(getPolicyParams());
	final byte[ ] counterSign = xadesSign.counterSign(eSignature, SignatureConstants.SIGN_ALGORITHM_SHA256, getCertificateECCPrivateKey(), optionalParams, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	// validación firma
	assertTrue(xadesSign.verifySignature(counterSign).isCorrect());
	externalSignVerify(counterSign);
    }

    /**
     * Test for generating a counter-signature from a co-signature.
     * @throws Exception If the test fails.
     */
    public void testCounterSignCoSign() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();

	final byte[ ] eSignature = UtilsFileSystemCommons.readFile("signatures/XAdES-Cosign.xml", true);
	// contrafirma documento xml
	final byte[ ] counterSign = xadesSign.counterSign(eSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), getDataFormatParams(), false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	
	// validación firma
	assertTrue(xadesSign.verifySignature(counterSign).isCorrect());
	externalSignVerify(counterSign);
    }

    /**
     * Test for generating a counter-signature from a counter-signature.
     * @throws Exception If the test fails.
     */
    public void testCounterSignCounterSign() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();

	final byte[ ] eSignature = UtilsFileSystemCommons.readFile("signatures/XAdES-Countersign.xml", true);
	// contrafirma documento xml
	final byte[ ] counterSign = xadesSign.counterSign(eSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), null, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	// validación firma
	assertTrue(xadesSign.verifySignature(counterSign).isCorrect());
	externalSignVerify(counterSign);
    }

    /**
     * Test for generating a counter-signature from a counter-signature generated from a co-signature.
     * @throws Exception If the test fails.
     */
    public void testCounterSignCounterCoSign() throws Exception {
	final XadesSigner xadesSign = new XadesSigner();

	final byte[ ] eSignature = UtilsFileSystemCommons.readFile("signatures/XAdES-CoSign-CounterSign.xml", true);
	// contrafirma documento xml
	final byte[ ] counterSign = xadesSign.counterSign(eSignature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), null, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	// validación firma
	assertTrue(xadesSign.verifySignature(counterSign).isCorrect());
	externalSignVerify(counterSign);
    }

    /**
     * Method that verifies a signature via @Firma.
     * @param signature Parameter that represents the signature to verify.
     * @throws Exception If the test fails.
     */
    private void externalSignVerify(final byte[ ] signature) throws Exception {
	if (EXTERNAL_VERIFY) {
	    final String appName = "appPrueba";
	    final Map<String, Object> inParams = new HashMap<String, Object>();

	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY, appName);
	    inParams.put(DSSTagsRequest.INCLUDE_CERTIFICATE, Boolean.TRUE.toString());
	    inParams.put(DSSTagsRequest.INCLUDE_REVOCATION, Boolean.TRUE.toString());
	    inParams.put(DSSTagsRequest.REPORT_DETAIL_LEVEL, ReportDetailLevel.ALL_DETAILS);
	    inParams.put(DSSTagsRequest.RETURN_PROCESSING_DETAILS, "");
	    inParams.put(DSSTagsRequest.RETURN_READABLE_CERT_INFO, "");
	    inParams.put(DSSTagsRequest.ADDICIONAL_REPORT_OPT_SIGNATURE_TIMESTAMP, "urn:afirma:dss:1.0:profile:XSS:SignatureProperty:SignatureTimeStamp");

	    // pruebas con firmas de tipo XML
	    inParams.put(DSSTagsRequest.SIGNATURE_PTR_ATR_WHICH, "1299585056969008");
	    inParams.put(DSSTagsRequest.DOCUMENT_ATR_ID, "1299585056969008");
	    inParams.put(DSSTagsRequest.BASE64XML, new String(Base64CoderCommons.encodeBase64(signature)));

	    final String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);
	    final String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, appName);
	    final Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);
	    // validamos si el resultado ha sido satisfactorio
	    assertEquals("La firma no es válida según verificación contra la plataforma externa de @Firma", ResultProcessIds.VALID_SIGNATURE, propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor")));
	}
    }

    /**
     * Tests for generating XAdES signatures with timestamp.
     */
    public void testSignWithTimestamp() {
	final XadesSigner xadesSigner = new XadesSigner();
	final Properties policyParams = new Properties();
	policyParams.put(SignatureProperties.XADES_CLAIMED_ROLE_PROP, "emisor");

	/*
	 * Test 1: Generación de firma XAdES-T binaria enveloping
	 */
	try {
	    final byte[ ] signature = xadesSigner.sign(getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, getCertificatePrivateKey(), null, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	    final byte[ ] coSignature = xadesSigner.coSign(signature, getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, getCertificatePrivateKey(), null, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	    final byte[ ] counterSignature = xadesSigner.counterSign(coSignature, SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, getCertificatePrivateKey(), null, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	    final byte[ ] upgradedSignature = xadesSigner.upgrade(counterSignature, null);
	    final byte[ ] notUpgradedSignature = xadesSigner.upgrade(upgradedSignature, null);
	    System.out.println(Arrays.equals(upgradedSignature, notUpgradedSignature));
	    // Validamos la firma
	    final ValidationResult vr = xadesSigner.verifySignature(signature);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Generación de firma XAdES-T xml enveloping con política
	 */
	try {
	    xadesSigner.sign(getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA384WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URN");
	} catch (final Exception e) {
	    assertTrue(true);
	}

	/*
	 * Test 3: Generación de firma XAdES-T xml enveloped con política
	 */
	try {
	    final byte[ ] signature = xadesSigner.sign(getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URN");

	    // Validamos la firma
	    final ValidationResult vr = xadesSigner.verifySignature(signature);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 4: Generación de firma XAdES-T binaria detached
	 */
	try {
	    final byte[ ] signature = xadesSigner.sign(getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URN");

	    // Validamos la firma
	    final ValidationResult vr = xadesSigner.verifySignature(signature);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 5: Generación de firma XAdES-T xml detached con política
	 */
	try {
	    final byte[ ] signature = xadesSigner.sign(getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URN");

	    // Validamos la firma
	    final ValidationResult vr = xadesSigner.verifySignature(signature);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Tests for generating XAdES co-signatures with timestamp.
     */
    public void testCoSignWithTimestamp() {
	final XadesSigner xadesSigner = new XadesSigner();
	final Properties policyParams = new Properties();
	policyParams.put(SignatureProperties.XADES_CLAIMED_ROLE_PROP, "emisor");

	/*
	 * Test 1: Generación de co-firma XAdES-T con política a partir de una firma xml enveloping
	 */
	try {
	    final byte[ ] previousXMLSignature = xadesSigner.sign(getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URN");
	    final byte[ ] signature = xadesSigner.coSign(previousXMLSignature, getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URL");
	    // Validamos la firma
	    final ValidationResult vr = xadesSigner.verifySignature(signature);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Generación de co-firma XAdES-T sin política a partir de una firma xml enveloped
	 */
	try {
	    final byte[ ] previousXMLSignature = xadesSigner.sign(getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URN");
	    final byte[ ] signature = xadesSigner.coSign(previousXMLSignature, getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URL");
	    // Validamos la firma
	    final ValidationResult vr = xadesSigner.verifySignature(signature);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 3: Generación de co-firma XAdES-T sin política a partir de una firma xml detached
	 */
	try {
	    final byte[ ] previousXMLSignature = xadesSigner.sign(getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URN");
	    final byte[ ] signature = xadesSigner.coSign(previousXMLSignature, getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URL");
	    // Validamos la firma
	    final ValidationResult vr = xadesSigner.verifySignature(signature);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Tests for generating XAdES counter-signatures with timestamp.
     */
    public void testCounterSignWithTimestamp() {
	final XadesSigner xadesSigner = new XadesSigner();
	final Properties policyParams = new Properties();
	policyParams.put(SignatureProperties.XADES_CLAIMED_ROLE_PROP, "emisor");

	/*
	 * Test 1: Generación de contra-firma XAdES-T a partir de una firma xml enveloping
	 */
	try {
	    final byte[ ] signature = xadesSigner.sign(getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URN");
	    try {
		xadesSigner.counterSign(signature, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), policyParams, false, ISignatureFormatDetector.FORMAT_XADES_EPES, null);
		fail(ERROR_EXCEPTION_NOT_THROWED);
	    } catch (final IllegalArgumentException e) {}
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Generación de contra-firma XAdES-T a partir de una firma xml enveloped
	 */
	try {
	    final byte[ ] signature = xadesSigner.sign(getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URN");
	    try {
		xadesSigner.counterSign(signature, SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), policyParams, false, ISignatureFormatDetector.FORMAT_XADES_EPES, null);
		fail(ERROR_EXCEPTION_NOT_THROWED);
	    } catch (final IllegalArgumentException e) {}
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 3: Generación de contra-firma XAdES-T a partir de una firma xml detached
	 */
	try {
	    final byte[ ] signature = xadesSigner.sign(getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URN");
	    final byte[ ] counterSignature = xadesSigner.counterSign(signature, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), policyParams, false, ISignatureFormatDetector.FORMAT_XADES_EPES, null);

	    // Validamos la firma
	    final ValidationResult vr = xadesSigner.verifySignature(counterSignature);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 4: Generación de contra-firma XAdES-T a partir de una co-firma xml enveloping
	 */
	try {
	    final byte[ ] signature = xadesSigner.sign(getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URN");
	    final byte[ ] coSignature = xadesSigner.coSign(signature, getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URL");

	    try {
		xadesSigner.counterSign(coSignature, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), policyParams, false, ISignatureFormatDetector.FORMAT_XADES_EPES, null);
		fail(ERROR_EXCEPTION_NOT_THROWED);
	    } catch (final IllegalArgumentException e) {}
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 5: Generación de contra-firma XAdES-T a partir de una co-firma xml enveloped
	 */
	try {
	    final byte[ ] signature = xadesSigner.sign(getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URN");
	    final byte[ ] coSignature = xadesSigner.coSign(signature, getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA512WITHRSA, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URL");
	    try {
		xadesSigner.counterSign(coSignature, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), policyParams, false, ISignatureFormatDetector.FORMAT_XADES_EPES, null);
		fail(ERROR_EXCEPTION_NOT_THROWED);
	    } catch (final IllegalArgumentException e) {}
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 6: Generación de contra-firma XAdES-T a partir de una co-firma xml detached
	 */
	try {
	    final byte[ ] signature = xadesSigner.sign(getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URN");
	    final byte[ ] coSignature = xadesSigner.coSign(signature, getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URL");
	    final byte[ ] counterSignature = xadesSigner.counterSign(coSignature, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), policyParams, false, ISignatureFormatDetector.FORMAT_XADES_EPES, null);

	    // Validamos la firma
	    final ValidationResult vr = xadesSigner.verifySignature(counterSignature);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}

	/*
	 * Test 7: Generación de contra-firma XAdES-T a partir de una contra-firma detached
	 */
	try {
	    final byte[ ] signature = xadesSigner.sign(getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, getCertificatePrivateKey(), policyParams, true, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URN");
	    final byte[ ] counterSignature = xadesSigner.counterSign(signature, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), policyParams, false, ISignatureFormatDetector.FORMAT_XADES_EPES, null);
	    final byte[ ] counterCounterSignature = xadesSigner.counterSign(counterSignature, SignatureConstants.SIGN_ALGORITHM_SHA256WITHRSA, getCertificatePrivateKey(), policyParams, false, ISignatureFormatDetector.FORMAT_XADES_EPES, null);

	    // Validamos la firma
	    final ValidationResult vr = xadesSigner.verifySignature(counterCounterSignature);
	    assertTrue(vr.isCorrect());
	} catch (final Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Tests for {@link XadesSigner#verifySignature(byte[])}.
     */
    public void testValidate() {
	final XadesSigner xadesSigner = new XadesSigner();

	/*
	 * Test 1: Validar una firma XAdES-BES
	 */
	final byte[ ] xadesBES = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-BES.xml", true);
	assertTrue(xadesSigner.verifySignature(xadesBES).isCorrect());

	/*
	 * Test 2: Validar una firma XAdES-EPES
	 */
	final byte[ ] xadesEPES = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-EPES.xml", true);
	assertTrue(xadesSigner.verifySignature(xadesEPES).isCorrect());

	/*
	 * Test 3: Validar una firma XAdES-T
	 */
	final byte[ ] xadesT = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-T.xml", true);
	assertTrue(xadesSigner.verifySignature(xadesT).isCorrect());

	/*
	 * Test 4: Validar una firma XAdES-C
	 */
	final byte[ ] xadesC = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-C.xml", true);
	assertTrue(xadesSigner.verifySignature(xadesC).isCorrect());

	/*
	 * Test 5: Validar una firma XAdES-X1
	 */
	final byte[ ] xadesX1 = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-X1.xml", true);
	assertTrue(xadesSigner.verifySignature(xadesX1).isCorrect());

	/*
	 * Test 6: Validar una firma XAdES-X2
	 */
	final byte[ ] xadesX2 = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-X2.xml", true);
	assertTrue(xadesSigner.verifySignature(xadesX2).isCorrect());

	/*
	 * Test 7: Validar una firma XAdES-XL1
	 */
	final byte[ ] xadesXL1 = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-XL1.xml", true);
	assertTrue(xadesSigner.verifySignature(xadesXL1).isCorrect());

	/*
	 * Test 8: Validar una firma XAdES-XL2
	 */
	final byte[ ] xadesXL2 = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-XL2.xml", true);
	assertTrue(xadesSigner.verifySignature(xadesXL2).isCorrect());

	/*
	 * Test 9: Validar una firma XAdES-A
	 */
	final byte[ ] xadesA = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-A.xml", true);
	assertTrue(xadesSigner.verifySignature(xadesA).isCorrect());
    }

    /**
     * Tests for {@link XadesSigner#upgrade(byte[], List)}.
     */
    public void testUpgrade() {
	final XadesSigner xadesSigner = new XadesSigner();

	/*
	 * Test 1: Actualizar todos los firmantes de una firma XAdES-BES
	 */
	try {
	    final byte[ ] xadesBES = xadesSigner.sign(getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING, getCertificatePrivateKey(), null, false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	    final byte[ ] xadesT = xadesSigner.upgrade(xadesBES, null);
	    if (!SignatureFormatDetector.getSignatureFormat(xadesT).equals(ISignatureFormatDetector.FORMAT_XADES_T) && !SignatureFormatDetector.getSignatureFormat(xadesT).equals(ISignatureFormatDetector.FORMAT_XADES_T_LEVEL)) {
		assertTrue(false);
	    }
	    final ValidationResult vr = xadesSigner.verifySignature(xadesT);
	    assertTrue(vr.isCorrect());
	} catch (final SigningException e) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Actualizar todos los firmantes de una firma XAdES-EPES
	 */
	try {
	    final Properties policyParams = new Properties();
	    policyParams.put(SignatureProperties.XADES_CLAIMED_ROLE_PROP, "emisor");
	    final byte[ ] xadesEPES = xadesSigner.sign(getTextDocument(), SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING, getCertificatePrivateKey(), policyParams, false, ISignatureFormatDetector.FORMAT_XADES_EPES, "XML_AGE_1.9_URN");
	    final byte[ ] xadesT = xadesSigner.upgrade(xadesEPES, null);
	    if (!SignatureFormatDetector.getSignatureFormat(xadesT).equals(ISignatureFormatDetector.FORMAT_XADES_T) && !SignatureFormatDetector.getSignatureFormat(xadesT).equals(ISignatureFormatDetector.FORMAT_XADES_T_LEVEL)) {
		assertTrue(false);
	    }
	    final ValidationResult vr = xadesSigner.verifySignature(xadesT);
	    assertTrue(vr.isCorrect());
	} catch (final SigningException e) {
	    assertTrue(false);
	}

	/*
	 * Test 3: Actualizar todos los firmantes de una firma XAdES-T
	 */
	try {
	    final byte[ ] xadesT = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-T.xml", true);
	    final byte[ ] xadesTUpgrade = xadesSigner.upgrade(xadesT, null);
	    assertTrue(Arrays.equals(xadesT, xadesTUpgrade));
	} catch (final SigningException e) {
	    assertTrue(false);
	}

	/*
	 * Test 4: Actualizar un firmante que no existe de una firma XAdES-BES
	 */
	try {
	    final byte[ ] xadesBES = xadesSigner.sign(getXmlDocument(), SignatureConstants.SIGN_ALGORITHM_SHA384WITHRSA, SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING, getCertificatePrivateKey(), getDataFormatParams(), false, ISignatureFormatDetector.FORMAT_XADES_BES, null);
	    final byte[ ] certificateBytes = UtilsFileSystemCommons.readFile("serversigner.cer", true);
	    final X509Certificate certificateServerSigner2 = UtilsCertificateCommons.generateCertificate(certificateBytes);
	    final List<X509Certificate> listSigners = new ArrayList<X509Certificate>();
	    listSigners.add(certificateServerSigner2);
	    final byte[ ] upgradedSignature = xadesSigner.upgrade(xadesBES, listSigners);
	    if (!SignatureFormatDetector.getSignatureFormat(upgradedSignature).equals(ISignatureFormatDetector.FORMAT_XADES_BES) && !SignatureFormatDetector.getSignatureFormat(upgradedSignature).equals(ISignatureFormatDetector.FORMAT_XADES_B_LEVEL)) {
		assertTrue(false);
	    }
	} catch (final Exception e) {
	    assertTrue(false);
	}

    }

    /**
     * Test for methods {@link XadesSigner#getSignedData(byte[])}.
     */
    public final void testGetSignedData() {
	final XadesSigner signer = new XadesSigner();
	final byte[ ] signature = UtilsFileSystemCommons.readFile("signatures/XAdES-Cosign.xml", true);
	try {
	    signer.getSignedData(signature);
	} catch (final Exception e) {
	    assertTrue(true);
	}

    }
}
