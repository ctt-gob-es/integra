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
 * <b>File:</b><p>es.gob.afirma.signature.asic.ASiCSBaselineSigner.java.</p>
 * <b>Description:</b><p>Class that manages the generation, validation and upgrade of ASiC-S Baseline signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>27/01/2016.</p>
 * @author Gobierno de España.
 * @version 1.3, 13/04/2020.
 */
package es.gob.afirma.signature.asic;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.apache.xml.crypto.MarshalException;
import org.apache.xml.crypto.dsig.DigestMethod;
import org.apache.xml.crypto.dsig.Reference;
import org.apache.xml.crypto.dsig.Transform;
import org.apache.xml.crypto.dsig.XMLObject;
import org.apache.xml.crypto.dsig.XMLSignature;

import net.java.xades.security.xml.XMLSignatureElement;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.apache.tika.mime.MimeType;
import org.apache.tika.mime.MimeTypeException;
import org.apache.tika.mime.MimeTypes;
import org.apache.xml.security.c14n.Canonicalizer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.signature.ISignatureFormatDetector;
import es.gob.afirma.signature.OriginalSignedData;
import es.gob.afirma.signature.SignatureConstants;
import es.gob.afirma.signature.SignatureFormatDetectorASiC;
import es.gob.afirma.signature.SignatureFormatDetectorCadesPades;
import es.gob.afirma.signature.SignatureFormatDetectorXades;
import es.gob.afirma.signature.SignatureProperties;
import es.gob.afirma.signature.Signer;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.signature.cades.CAdESBaselineSigner;
import es.gob.afirma.signature.cades.CAdESSignerInfo;
import es.gob.afirma.signature.validation.SignerValidationResult;
import es.gob.afirma.signature.validation.ValidationResult;
import es.gob.afirma.signature.xades.IdRegister;
import es.gob.afirma.signature.xades.XAdESBaselineSigner;
import es.gob.afirma.signature.xades.XAdESSignerInfo;
import es.gob.afirma.utils.CryptoUtilPdfBc;
import es.gob.afirma.utils.CryptoUtilXML;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.utils.IUtilsSignature;
import es.gob.afirma.utils.UtilsResourcesCommons;
import es.gob.afirma.utils.UtilsResourcesSignOperations;
import es.gob.afirma.utils.UtilsSignatureCommons;
import es.gob.afirma.utils.UtilsSignatureOp;

/**
 * <p>Class that manages the generation, validation and upgrade of ASiC-S Baseline signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.3, 13/04/2020.
 */
public final class ASiCSBaselineSigner implements Signer {

    /**
     * Attribute that represents the hex values of the first 4 octets of the ZIP file.
     */
    private static final String ZIP_HEADER_HEX = "504B0304";

    /**
     *  Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(ASiCSBaselineSigner.class);

    /**
     * Constant attribute that represents the name of the signed file to include into the ZIP file.
     */
    private static final String SIGNED_DATA_FILENAME = "signedFile";

    /**
     * Constant attribute that represents the default extension of the document to sign.
     */
    private static final String DEFAULT_EXTENSION = ".txt";

    /**
     * Attribute that represents the signed file included into the ASiC-S signature.
     */
    private byte[ ] signedFile = null;

    /**
     * Attribute that represents the name of the signed file included into the ASiC-S signature.
     */
    private String signedFileName = null;

    /**
     * Attribute that represents the ASN.1 signature included into the ASiC-S signature.
     */
    private byte[ ] asn1Signature = null;

    /**
     * Attribute that represents the XML signed document included into the ASiC-S signature.
     */
    private byte[ ] signedXML = null;

    /**
     * Constructor method for the class ASiCSBaselineSigner.java. 
     */
    public ASiCSBaselineSigner() {
	// Añadimos el proveedor criptográfico Bouncycastle en caso de que no
	// esté incluído
	if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
	    Security.addProvider(new BouncyCastleProvider());
	}
	org.apache.xml.security.Init.init();
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#sign(byte[], java.lang.String, java.lang.String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public byte[ ] sign(byte[ ] data, String algorithm, String signatureFormat, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID, String idClient) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.ASBS_LOG038));
	OutputStream baos = null;
	OutputStream outZip = null;
	byte[ ] result = null;

	try {

	    // Comprobamos que se ha indicado el algoritmo de firma y tiene un
	    // valor admitido
	    checkInputSignatureAlgorithm(algorithm);

	    // Comprobamos que se han indicado los datos a firmar
	    GenericUtilsCommons.checkInputParameterIsNotNull(data, Language.getResIntegra(ILogConstantKeys.ASBS_LOG042));

	    // Comprobamos que se ha indicado la clave privada
	    GenericUtilsCommons.checkInputParameterIsNotNull(privateKey, Language.getResIntegra(ILogConstantKeys.ASBS_LOG043));

	    // Comprobamos que se ha introducido el formato
	    GenericUtilsCommons.checkInputParameterIsNotNull(signatureForm, Language.getResIntegra(ILogConstantKeys.ASBS_LOG044));

	    // Se crea el fichero .zip
	    baos = new ByteArrayOutputStream();
	    outZip = new ZipOutputStream(baos);

	    // Se añade el fichero que se corresponde con los datos firmados
	    String fileToSignName = addFileToSign(data, outZip);

	    // Se añade el fichero mimetype
	    addMimetypeFile(outZip);

	    // Dependiendo del formato se generará una firma ASiC-S Baseline con
	    // una
	    // firma CAdES Baseline o una XAdES Baseline

	    // Se añade la carpeta META-INF
	    ((ZipOutputStream) outZip).putNextEntry(new ZipEntry(SignatureFormatDetectorASiC.META_INF_FOLDER));
	    ((ZipOutputStream) outZip).closeEntry();

	    if (signatureForm.equals(ISignatureFormatDetector.FORMAT_CADES_B_LEVEL)) {

		// En caso de que se haya indicado que la firma sea implícita,
		// informamos de que sólo puede ser explícita.
		if (SignatureConstants.SIGN_MODE_IMPLICIT.equals(signatureFormat)) {
		    LOGGER.warn(Language.getResIntegra(ILogConstantKeys.ASBS_LOG032));
		}
		generateSignatureASiCSBaselineCAdES(data, algorithm, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, includeTimestamp, signatureForm, signaturePolicyID, outZip);

	    } else if (signatureForm.equals(ISignatureFormatDetector.FORMAT_XADES_B_LEVEL)) {

		// En caso de que se haya indicado que la firma sea distinta a
		// detached,
		// informamos de que sólo puede ser xades detached.
		if (!SignatureConstants.SIGN_FORMAT_XADES_DETACHED.equals(signatureFormat)) {
		    LOGGER.warn(Language.getResIntegra(ILogConstantKeys.ASBS_LOG030));
		}
		generateSignatureASiCSBaselineXAdES(data, algorithm, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, extraParams, includeTimestamp, signatureForm, signaturePolicyID, outZip, fileToSignName);
	    } else {
		String msg = Language.getFormatResIntegra(ILogConstantKeys.ASBS_LOG045, new Object[ ] { signatureForm });
		LOGGER.error(msg);
		throw new IllegalArgumentException(msg);
	    }

	    outZip.close();
	    baos.close();
	    result = ((ByteArrayOutputStream) baos).toByteArray();
	    // Devolvemos la firma generada
	    return result;
	} catch (IOException e) {
	    String msg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG046);
	    LOGGER.error(msg);
	    throw new IllegalArgumentException(msg, e);
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.ASBS_LOG039));

	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#coSign(byte[], byte[], java.lang.String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public byte[ ] coSign(byte[ ] signature, byte[ ] document, String algorithm, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID, String idClient) throws SigningException {
	throw new SigningException(Language.getResIntegra(ILogConstantKeys.ASBS_LOG002));
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#counterSign(byte[], java.lang.String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public byte[ ] counterSign(byte[ ] signature, String algorithm, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID, String idClient) throws SigningException {
	throw new SigningException(Language.getResIntegra(ILogConstantKeys.ASBS_LOG003));
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#sign(byte[], java.lang.String, java.lang.String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, java.lang.String, java.lang.String)
     */
    @Override
    public byte[ ] sign(byte[ ] data, String algorithm, String signatureFormat, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID) throws SigningException {
	return sign(data, algorithm, signatureFormat, privateKey, extraParams, includeTimestamp, signatureForm, signaturePolicyID, null);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#coSign(byte[], byte[], java.lang.String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, java.lang.String, java.lang.String)
     */
    @Override
    public byte[ ] coSign(byte[ ] signature, byte[ ] document, String algorithm, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID) throws SigningException {
	return coSign(signature, document, algorithm, privateKey, extraParams, includeTimestamp, signatureForm, signaturePolicyID, null);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#counterSign(byte[], java.lang.String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, java.lang.String, java.lang.String)
     */
    @Override
    public byte[ ] counterSign(byte[ ] signature, String algorithm, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID) throws SigningException {
	return counterSign(signature, algorithm, privateKey, extraParams, includeTimestamp, signatureForm, signaturePolicyID, null);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#upgrade(byte[], java.util.List, java.lang.String)
     */
    @Override
    public byte[ ] upgrade(byte[ ] signature, List<X509Certificate> listSigners, String idClient) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.ASBS_LOG004));

	InputStream is = null;
	InputStream asicsInputStream = null;
	try {
	    // Comprobamos que se ha indicado la firma a actualizar y que es de
	    // tipo ASiC-S
	    GenericUtilsCommons.checkInputParameterIsNotNull(signature, Language.getResIntegra(ILogConstantKeys.ASBS_LOG006));

	    // Obtenemos un InputStream a partir del array de bytes de entrada
	    is = new ByteArrayInputStream(signature);
	    asicsInputStream = new ZipInputStream(is);
	    byte[ ] noXMLSignature = null;
	    byte[ ] xmlSignature = null;

	    // Recorremos las entradas del fichero ZIP
	    for (ZipEntry entry = ((ZipInputStream) asicsInputStream).getNextEntry(); entry != null; entry = ((ZipInputStream) asicsInputStream).getNextEntry()) {
		// Accedemos al nombre de la entrada
		String entryName = entry.getName();

		// Si la entrada es una firma ASN.1
		if (SignatureFormatDetectorASiC.isCAdESEntry(entryName)) {
		    // Obtenemos la firma ASN.1
		    noXMLSignature = GenericUtilsCommons.getDataFromInputStream(asicsInputStream);
		}
		// Si la entrada en una firma XML
		else if (SignatureFormatDetectorASiC.isXAdESEntry(entryName)) {
		    // Obtenemos la firma XML
		    xmlSignature = GenericUtilsCommons.getDataFromInputStream(asicsInputStream);
		}
	    }
	    // Actualizamos la firma XML o ASN.1 contenida y devolvemos la firma
	    // ASiC-S completa
	    return upgradeASiCSSignature(noXMLSignature, xmlSignature, signature, listSigners);
	} catch (IOException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG011);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} finally {
	    // Cerramos recursos
	    UtilsResourcesCommons.safeCloseInputStream(asicsInputStream);
	    UtilsResourcesCommons.safeCloseInputStream(is);
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.ASBS_LOG005));
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#upgrade(byte[], java.util.List)
     */
    @Override
    public byte[ ] upgrade(byte[ ] signature, List<X509Certificate> listSigners) throws SigningException {
	return upgrade(signature, listSigners, null);
    }

    /**
     * Method that updates the signers of the XML or ASN.1 signature contained inside of an ASiC-S signature.
     * @param noXMLSignature Parameter that represents the ASN.1 signature to update.
     * @param xmlSignature Parameter that represents the XML signature to update.
     * @param asicSSignature Parameter that represents the ASiC-S signature.
     * @param listSigners Parameter that represents the list of signers of the signature to upgrade with a time-stamp.
     * @return the upgraded ASiC-S signature.
     * @throws SigningException If the method fails.
     */
    private byte[ ] upgradeASiCSSignature(byte[ ] noXMLSignature, byte[ ] xmlSignature, byte[ ] asicSSignature, List<X509Certificate> listSigners) throws SigningException {
	byte[ ] upgradedASiCSignature = null;
	// Si no hemos encontrado ninguna firma dentro lanzamos una
	// excepción
	if (noXMLSignature == null && xmlSignature == null) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG007);
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}

	// Si hemos encontrado una firma ASN.1 y XML dentro lanzamos una
	// excepción
	else if (noXMLSignature != null && xmlSignature != null) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG008);
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
	// Si hemos encontrado una firma ASN.1
	else if (noXMLSignature != null) {
	    // Instanciamos la clase que maneja firmas CAdES Baseline
	    CAdESBaselineSigner cadesSigner = new CAdESBaselineSigner();

	    // Actualizamos la firma ASN.1
	    byte[ ] upgradedASN1Signature = cadesSigner.upgrade(noXMLSignature, listSigners);

	    // Sustituimos en el fichero ZIP la antigua firma por la nueva
	    // actualizada
	    upgradedASiCSignature = replaceASN1Signature(asicSSignature, upgradedASN1Signature);

	}
	// Si hemos encontrado una firma XML
	else if (xmlSignature != null) {
	    // Instanciamos la clase que maneja firmas XAdES Baseline
	    XAdESBaselineSigner xadesSigner = new XAdESBaselineSigner();

	    // Actualizamos la firma XML
	    byte[ ] upgradedXMLSignature = xadesSigner.upgrade(xmlSignature, listSigners);

	    // Sustituimos en el fichero ZIP la antigua firma por la nueva
	    // actualizada
	    upgradedASiCSignature = replaceXMLSignature(asicSSignature, upgradedXMLSignature);
	}
	return upgradedASiCSignature;
    }

    /**
     * Method that replaces the XML signature contained inside of the ZIP file.
     * @param asicSSignature Parameter that represents the ASiC-S signature as a ZIP file.
     * @param xmlSignature Parameter that represents the XML signature to replace.
     * @return the updated ZIP file.
     * @throws SigningException If the method fails.
     */
    private byte[ ] replaceXMLSignature(byte[ ] asicSSignature, byte[ ] xmlSignature) throws SigningException {
	OutputStream outZip = null;
	OutputStream out = new ByteArrayOutputStream();
	InputStream is = null;
	InputStream asicsInputStream = null;
	try {
	    // Instanciamos la salida de bytes que representará el nuevo fichero
	    // ZIP
	    outZip = new ZipOutputStream(out);

	    // Leemos el fichero ZIP actual
	    is = new ByteArrayInputStream(asicSSignature);
	    asicsInputStream = new ZipInputStream(is);

	    // Recorremos las entradas del fichero ZIP
	    for (ZipEntry entry = ((ZipInputStream) asicsInputStream).getNextEntry(); entry != null; entry = ((ZipInputStream) asicsInputStream).getNextEntry()) {
		// Accedemos al nombre de la entrada
		String entryName = entry.getName();

		// Añadimos una entrada con el mismo nombre al nuevo fichero ZIP
		((ZipOutputStream) outZip).putNextEntry(new ZipEntry(entryName));

		// Si la entrada es la firma XML que reemplazar
		if (SignatureFormatDetectorASiC.isXAdESEntry(entryName)) {
		    // Añadimos la nueva firma ASN.1 al ZIP
		    addEntryToZip(xmlSignature, outZip);
		    ((ZipOutputStream) outZip).closeEntry();
		}
		// Si la entrada no es un directorio
		else if (!entry.isDirectory()) {
		    // Obtenemos el array de bytes que se corresponde con el
		    // contenido de la entrada
		    byte[ ] entryBytes = GenericUtilsCommons.getDataFromInputStream(asicsInputStream);

		    // Añadimos la entrada al nuevo fichero ZIP
		    addEntryToZip(entryBytes, outZip);
		    ((ZipOutputStream) outZip).closeEntry();
		}
		((ZipOutputStream) outZip).closeEntry();
	    }
	    ((ZipOutputStream) outZip).finish();
	} catch (IOException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG010);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} finally {
	    // Cerramos recursos
	    UtilsResourcesCommons.safeCloseInputStream(asicsInputStream);
	    UtilsResourcesCommons.safeCloseInputStream(is);
	    UtilsResourcesCommons.safeCloseOutputStream(out);
	    UtilsResourcesCommons.safeCloseOutputStream(outZip);
	}
	// Devolvemos el array de bytes que se corresponde con el nuevo
	// fichero ZIP
	return ((ByteArrayOutputStream) out).toByteArray();
    }

    /**
     * Method that replaces the ASN.1 signature contained inside of the ZIP file.
     * @param asicSSignature Parameter that represents the ASiC-S signature as a ZIP file.
     * @param noXMLSignature Parameter that represents the ASN.1 signature to replace.
     * @return the updated ZIP file.
     * @throws SigningException If the method fails.
     */
    private byte[ ] replaceASN1Signature(byte[ ] asicSSignature, byte[ ] noXMLSignature) throws SigningException {
	OutputStream outZip = null;
	OutputStream out = new ByteArrayOutputStream();
	InputStream is = null;
	InputStream asicsInputStream = null;
	try {
	    // Instanciamos la salida de bytes que representará el nuevo fichero
	    // ZIP
	    outZip = new ZipOutputStream(out);

	    // Leemos el fichero ZIP actual
	    is = new ByteArrayInputStream(asicSSignature);
	    asicsInputStream = new ZipInputStream(is);

	    // Recorremos las entradas del fichero ZIP
	    for (ZipEntry entry = ((ZipInputStream) asicsInputStream).getNextEntry(); entry != null; entry = ((ZipInputStream) asicsInputStream).getNextEntry()) {
		// Accedemos al nombre de la entrada
		String entryName = entry.getName();

		// Añadimos una entrada con el mismo nombre al nuevo fichero ZIP
		((ZipOutputStream) outZip).putNextEntry(new ZipEntry(entryName));

		// Si la entrada es la firma ASN.1 que reemplazar
		if (SignatureFormatDetectorASiC.isCAdESEntry(entryName)) {
		    // Añadimos la nueva firma ASN.1 al ZIP
		    addEntryToZip(noXMLSignature, outZip);
		    ((ZipOutputStream) outZip).closeEntry();
		}
		// Si la entrada no es un directorio
		else if (!entry.isDirectory()) {
		    // Obtenemos el array de bytes que se corresponde con el
		    // contenido de la entrada
		    byte[ ] entryBytes = GenericUtilsCommons.getDataFromInputStream(asicsInputStream);

		    // Añadimos la entrada al nuevo fichero ZIP
		    addEntryToZip(entryBytes, outZip);
		    ((ZipOutputStream) outZip).closeEntry();
		}
	    }
	    ((ZipOutputStream) outZip).finish();
	} catch (IOException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG009);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} finally {
	    // Cerramos recursos
	    UtilsResourcesCommons.safeCloseInputStream(asicsInputStream);
	    UtilsResourcesCommons.safeCloseInputStream(is);
	    UtilsResourcesCommons.safeCloseOutputStream(out);
	    UtilsResourcesCommons.safeCloseOutputStream(outZip);
	}
	// Devolvemos el array de bytes que se corresponde con el nuevo
	// fichero ZIP
	return ((ByteArrayOutputStream) out).toByteArray();
    }

    /**
     * Method that checks if a XML signature is detached and one of the references is associated to the signed data.
     * @param signature Parameter that represents the XML signature.
     * @param signatureId Parameter that represents the <code>Id</code> attribute of <code>ds:Signature</code> element.
     * @param validationResult Parameter that represents the information about the validation of the ASiC-S signature.
     * @throws SigningException If the validation fails.
     */
    @SuppressWarnings("unchecked")
    private void checkSignedModeAndReferencesOfXMLSignature(XMLSignature signature, String signatureId, ValidationResult validationResult) throws SigningException {
	// Obtenemos la lista de referencias de la firma
	List<Reference> listReferences = signature.getSignedInfo().getReferences();

	// Instanciamos una variable para indicar si hemos encontrado una
	// referencia a los datos firmados
	boolean hasReferenceToSignedData = false;

	// Instanciamos una lista con los identificadores de los elementos a los
	// que apuntan las referencias
	List<String> ids = new ArrayList<String>();

	// Recorremos la lista de referencias
	for (int i = 0; i < listReferences.size(); i++) {
	    // Accedemos a la referencia
	    Reference reference = listReferences.get(i);

	    // Accedemos al valor del atributo URI de la referencia
	    String uri = reference.getURI();

	    // Si la referencia posee atributo URI, incluímos su valor en la
	    // lista con los identificadores de los elementos a los que apuntan
	    // las referencias
	    if (uri != null && uri.length() > 0) {
		ids.add(uri.substring(1));
	    }
	    // Si aún no hemos encontrado
	    // la referencia a los datos firmados
	    if (!hasReferenceToSignedData) {
		// Comprobamos si el resumen indicado en la misma coincide con
		// el resumen de los datos firmados
		hasReferenceToSignedData = checkReferenceToSignedData(reference);
	    }

	    // Obtenemos las transformadas asociadas a la referencia
	    List<Transform> transforms = reference.getTransforms();

	    // Recorremos la lista de transformadas asociadas a la referencia
	    for (int j = 0; j < transforms.size(); j++) {
		// Accedemos a la transformada
		Transform transform = transforms.get(j);

		// Si el algoritmo de la transformada es el asociado a firmas
		// Enveloped
		if (transform.getAlgorithm().equals(Transform.ENVELOPED)) {
		    // Lanzamos excepción
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.ASBS_LOG024, new Object[ ] { signatureId });
		    LOGGER.error(errorMsg);
		    validationResult.setIntegrallyCorrect(false);
		    validationResult.setErrorMsg(errorMsg);
		    throw new SigningException(errorMsg);
		}
	    }

	    // Obtenemos la lista de objetos contenidos en la firma
	    List<XMLObject> xmlObjects = signature.getObjects();

	    // Recorremos la lista de objetos contenidos en la firma
	    for (int k = 0; k < xmlObjects.size(); k++) {
		XMLObject xmlObject = xmlObjects.get(k);
		// Si existe un identificador de los elementos a los que apuntan
		// las referencias que coincide con el identificador de un
		// objeto contenido en la firma
		if (ids.contains(xmlObject.getId())) {
		    // Lanzamos excepción
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.ASBS_LOG025, new Object[ ] { signatureId });
		    LOGGER.error(errorMsg);
		    validationResult.setIntegrallyCorrect(false);
		    validationResult.setErrorMsg(errorMsg);
		    throw new SigningException(errorMsg);
		}
	    }
	}
	// Si no hemos encontrado una referencia a los datos firmados lanzamos
	// una excepción
	if (!hasReferenceToSignedData) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.ASBS_LOG026, new Object[ ] { signatureId });
	    LOGGER.error(errorMsg);
	    validationResult.setIntegrallyCorrect(false);
	    validationResult.setErrorMsg(errorMsg);
	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that checks if the digest of the signed data by a XML signature matches to the digest indicated on the associated reference.
     * @param reference Parameter that represents the reference to the signed file.
     * @return a boolean that indicates if the digest of the signed data by a XML signature matches to the digest indicated on the associated reference (true) or not (false).
     * @throws SigningException If the method fails.
     */
    @SuppressWarnings("unchecked")
    private boolean checkReferenceToSignedData(Reference reference) throws SigningException {
	// Obtenemos el algoritmo de resumen usado para calcular la referencia
	DigestMethod digestMethod = reference.getDigestMethod();
	String hashAlgorithm = CryptoUtilXML.translateXmlDigestAlgorithm(digestMethod.getAlgorithm());

	// Obtenemos las transformadas usadas para calcular la referencia
	List<Transform> listTransforms = reference.getTransforms();
	try {
	    byte[ ] canonicalizedSignedData = signedFile;
	    // Recorremos la lista de transformadas usadas para calcular la
	    // referencia
	    if (listTransforms != null) {
		for (Transform transform: listTransforms) {
		    // Canonicalizamos los datos firmados
		    canonicalizedSignedData = Canonicalizer.getInstance(transform.getAlgorithm()).canonicalize(canonicalizedSignedData);
		}
	    }
	    // Calculamos el resumen de los datos firmados (y canonicalizados)
	    // usando el algoritmo
	    // indicado en la referencia
	    byte[ ] signedDataDigest = CryptoUtilPdfBc.digest(hashAlgorithm, canonicalizedSignedData);

	    // Comparamos los arrays de bytes
	    return Arrays.equals(signedDataDigest, reference.getDigestValue());
	} catch (Exception e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.ASBS_LOG027, new Object[ ] { null });
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}
    }

    /**
     * Method that checks if the <code>mimetype</code> file contained inside of the ASiC-S signature. The <code>mimetype</code> file may use "application/vnd.etsi.asic-s+zip" or the original mimetype of the
     * signed data object.
     * @param mimeTypeFile Parameter that represents the <code>mimetype</code> file.
     * @param validationResult Parameter that represents the information about the validation of the ASiC-S signature.
     * @throws SigningException If the method fails.
     */
    private void validateMimetypeFile(byte[ ] mimeTypeFile, ValidationResult validationResult) throws SigningException {
	InputStream is = null;

	try {
	    // Si el fichero ZIP contiene un fichero mimetype
	    if (mimeTypeFile != null) {
		// Accedemos al contenido del fichero mimetype
		is = new ByteArrayInputStream(mimeTypeFile);
		List<String> lines = IOUtils.readLines(is);

		// Comprobamos que el fichero mimetype contiene una única línea
		if (lines.size() > 1) {
		    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG017);
		    LOGGER.error(errorMsg);
		    validationResult.setIntegrallyCorrect(false);
		    validationResult.setErrorMsg(errorMsg);
		    throw new SigningException(errorMsg);
		}

		// Accedemos al valor del mimetype
		String mimetype = lines.get(0);

		// Comprobamos si el valor del mimetype es el asociado a firmas
		// ASiC-S, esto es, 'application/vnd.etsi.asic-s+zip'. Si no
		// posee dicho valor, deberá tener el mimetype asociado a los
		// datos firmados
		if (!mimetype.trim().equals(SignatureFormatDetectorASiC.ASIC_S_MIME_TYPE)) {
		    // Obtenemos el mimetype de los datos firmados
		    String signedDataMimetype = UtilsResourcesSignOperations.getMimeType(signedFile);

		    // Comprobamos que los mimetype coinciden
		    if (!mimetype.equals(signedDataMimetype)) {
			String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.ASBS_LOG018, new Object[ ] { mimetype, signedDataMimetype });
			LOGGER.error(errorMsg);
			validationResult.setIntegrallyCorrect(false);
			validationResult.setErrorMsg(errorMsg);
			throw new SigningException(errorMsg);
		    }
		}
	    }
	} catch (IOException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG019);
	    LOGGER.error(errorMsg, e);
	    validationResult.setIntegrallyCorrect(false);
	    validationResult.setErrorMsg(errorMsg);
	    throw new SigningException(errorMsg, e);
	} finally {
	    // Cerramos recursos
	    UtilsResourcesCommons.safeCloseInputStream(is);
	}
    }

    /**
     * Method that checks if the ZIP file contains the ASN.1 signature or the signed XML document and the signed data.
     * @param validationResult Parameter that represents the information about the validation of the ASiC-S signature.
     * @throws SigningException If the validation fails.
     */
    private void checkZIPRequiredContent(ValidationResult validationResult) throws SigningException {
	// Comprobamos que hemos encontrado la firma ASN.1 o la firma XAdES
	// dentro del fichero.
	if (asn1Signature == null && signedXML == null) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG015);
	    LOGGER.error(errorMsg);
	    validationResult.setIntegrallyCorrect(false);
	    validationResult.setErrorMsg(errorMsg);
	    throw new SigningException(errorMsg);
	}

	// Comprobamos que hemos encontrado los datos firmados dentro del
	// fichero
	if (signedFile == null) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG016);
	    LOGGER.error(errorMsg);
	    validationResult.setIntegrallyCorrect(false);
	    validationResult.setErrorMsg(errorMsg);
	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that checks if the hex value of the 4 first octets of the ZIP file has the value <code>504B0304</code>.
     * @param asicSSignature Parameter that represents the ASiC-S signature (the ZIP file).
     * @param validationResult Parameter that represents the information about the validation of the ASiC-S signature.
     * @throws SigningException If the validation fails.
     */
    private void checkHeaderZIPFile(byte[ ] asicSSignature, ValidationResult validationResult) throws SigningException {
	// Transformamos los octetos de la firma ASiC-S en hexadecimal
	String zipHeaderHex = Hex.encodeHexString(asicSSignature).toUpperCase();

	// Comprobamos que los 4 primeros octetos tienen el valor '504B0304'
	if (!zipHeaderHex.startsWith(ZIP_HEADER_HEX)) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.ASBS_LOG014, new Object[ ] { ZIP_HEADER_HEX });
	    LOGGER.error(errorMsg);

	    // Establecemos en la información asociada a la validación
	    // estructural de la
	    // firma que ésta no es correcta
	    validationResult.setIntegrallyCorrect(false);
	    validationResult.setErrorMsg(errorMsg);

	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that checks if the input signature algorithm is <code>null</code> and is allowed to use.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     */
    private void checkInputSignatureAlgorithm(String signatureAlgorithm) {
	// Comprobamos que el algoritmo de firma no es nulo
	GenericUtilsCommons.checkInputParameterIsNotNull(signatureAlgorithm, Language.getResIntegra(ILogConstantKeys.ASBS_LOG040));

	// Comprobamos que el algoritmo de firma está soportado
	if (!SignatureConstants.SIGN_ALGORITHMS_SUPPORT_CADES.containsKey(signatureAlgorithm)) {
	    String msg = Language.getFormatResIntegra(ILogConstantKeys.ASBS_LOG041, new Object[ ] { signatureAlgorithm });
	    LOGGER.error(msg);
	    throw new IllegalArgumentException(msg);
	}
    }

    /**
     * Method that generates an ASiC-S Baseline signature with a CAdES Baseline.
     * 
     * @param data Parameter that represents the data to sign.
     * @param algorithm Parameter that represents the signature algorithm.
     * @param signatureFormat Parameter that represents the signing mode.
     * The allowed value for a CAdES Baseline signature is:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_MODE_EXPLICIT}</li>
     * </ul>
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeTimestamp Parameter that indicates if the signature will include a timestamp (true) or not (false).
     * @param signatureForm Parameter that represents the signature form.
     * @param signaturePolicyID  Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * @param outZip  Parameter that represents the zip file.
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @throws SigningException If the method fails.
     */
    private void generateSignatureASiCSBaselineCAdES(byte[ ] data, String algorithm, String signatureFormat, PrivateKeyEntry privateKey, boolean includeTimestamp, String signatureForm, String signaturePolicyID, OutputStream outZip) throws SigningException {
	// Se genera y se añade la firma CAdES Baseline
	byte[ ] signature = null;
	// Generamos la firma CAdES Baseline
	try {
	    Signer signer = new CAdESBaselineSigner();
	    signature = signer.sign(data, algorithm, signatureFormat, privateKey, null, includeTimestamp, signatureForm, signaturePolicyID);

	    // se añade la firma al fichero zip
	    ZipEntry signatureZipEntry = new ZipEntry(SignatureFormatDetectorASiC.NAME_SIGNATURE_CADES_B);
	    ((ZipOutputStream) outZip).putNextEntry(signatureZipEntry);
	    addEntryToZip(signature, outZip);
	    ((ZipOutputStream) outZip).closeEntry();
	} catch (SigningException e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.ASBS_LOG050, new Object[ ] { e.getMessage() });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg, e);

	} catch (IOException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG035);
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg, e);
	}

    }

    /**
     * Method that generates an ASiC-S Baseline signature with a XAdES Baseline.
     * 
     * @param data Parameter that represents the data to sign.
     * @param algorithm Parameter that represents the signature algorithm.
     * The allowed value for a XAdES Baseline signature is:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_DETACHED}</li>
     * </ul>
     * @param signatureFormat Parameter that represents the signing mode.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param extraParams Set of extra configuration parameters.  The allowed parameters are:
     * <ul>
     * 
     * <li>{@link SignatureProperties#XADES_CLAIMED_ROLE_PROP}.</li>
     * <li>{@link SignatureProperties#XADES_POLICY_QUALIFIER_PROP}. </li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_DESCRIPTION_PROP}. </li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_MIME_PROP}. </li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_ENCODING_PROP}. </li>
     * <li>{@link SignatureProperties#XADES_CANONICALIZATION_METHOD}. </li>
     * </ul>
     * @param includeTimestamp Parameter that indicates if the signature will include a timestamp (true) or not (false).
     * @param signatureForm Parameter that represents the signature form.
     * @param signaturePolicyID  Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * @param outZip  Parameter that represents the zip file.
     * @param fileToSignName Parameter that represents the name of the file to sign.
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @throws SigningException If the method fails.
     */
    private void generateSignatureASiCSBaselineXAdES(byte[ ] data, String algorithm, String signatureFormat, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID, OutputStream outZip, String fileToSignName) throws SigningException {
	byte[ ] signature = null;

	Signer signer = new XAdESBaselineSigner();
	try {

	    // se comprueba parámetros adicionales y opcionales son los
	    // permitidos
	    if (extraParams != null && !extraParams.isEmpty()) {
		checkInputExtraParams(extraParams);
	    }
	    // se genera la firma XAdESBaseline, pero indicando que se genera
	    // para una firma ASIC
	    signature = ((XAdESBaselineSigner) signer).sign(data, algorithm, signatureFormat, privateKey, extraParams, includeTimestamp, signatureForm, signaturePolicyID, true, fileToSignName);
	    // se añade la firma al fichero zip
	    ZipEntry signatureZipEntry = new ZipEntry(SignatureFormatDetectorASiC.NAME_SIGNATURE_XADES_B);

	    ((ZipOutputStream) outZip).putNextEntry(signatureZipEntry);

	    addEntryToZip(signature, outZip);
	    ((ZipOutputStream) outZip).closeEntry();
	} catch (SigningException e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.ASBS_LOG051, new Object[ ] { e.getMessage() });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg, e);

	} catch (IOException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG034);
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg, e);
	}

    }

    /**
     * Method that adds the file to sign into the ZIP file.
     * @param data Parameter that represents the data to sign.
     * @param outZip Parameter that allows to operate with the ZIP file.
     * @return the name of the file to sign.
     * @throws SigningException If the method fails.
     */
    private String addFileToSign(byte[ ] data, OutputStream outZip) throws SigningException {
	// A partir del array de bytes que firmar determinamos qué tipo de datos
	// son y añadimos al fichero ZIP que se corresponde con la firma ASiC-S
	// un archivo que se corresponde con los datos firmados

	try {
	    // Obtenemos el mimetype de los datos a firmar
	    String mimeTypeData = UtilsResourcesSignOperations.getMimeType(data);
	    MimeTypes mimeTypes = MimeTypes.getDefaultMimeTypes();
	    MimeType mimeType = mimeTypes.forName(mimeTypeData);

	    // Obtenemos la extensión asociada al mimetype
	    String extension = mimeType.getExtension();

	    String signedFileName = null;

	    // Si no hemos encontrado la extensión
	    if (extension.isEmpty()) {
		// Usamos la extensión .txt por defecto
		signedFileName = SIGNED_DATA_FILENAME + DEFAULT_EXTENSION;
		String infoMsg = Language.getFormatResIntegra(ILogConstantKeys.ASBS_LOG047, new Object[ ] { mimeTypeData, signedFileName });
		LOGGER.info(infoMsg);
	    } else {
		signedFileName = SIGNED_DATA_FILENAME + extension;
	    }

	    ZipEntry signedFileZIPEntry = new ZipEntry(signedFileName);
	    ((ZipOutputStream) outZip).putNextEntry(signedFileZIPEntry);
	    addEntryToZip(data, outZip);
	    ((ZipOutputStream) outZip).closeEntry();

	    return signedFileName;
	} catch (MimeTypeException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG048);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (IOException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG049);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}
    }

    /**
     * Method that adds an entry to a ZIP file.
     * @param entryBytes Parameter that represents the entry to add.
     * @param asicsOutputStream Parameter that allows to write into the ZIP file.
     * @throws IOException If the method fails.
     */
    private static void addEntryToZip(byte[ ] entryBytes, OutputStream asicsOutputStream) throws IOException {
	InputStream in = new ByteArrayInputStream(entryBytes);
	try {
	    IOUtils.copy(in, asicsOutputStream);
	} finally {
	    // Cerramos recursos
	    UtilsResourcesCommons.safeCloseInputStream(in);
	}
    }

    /**
     * Method that adds the mimetype file into the ZIP file.
     * @param outZip Parameter that allows to operate with the ZIP file.
     * @throws SigningException If the method fails.
     */
    private void addMimetypeFile(OutputStream outZip) throws SigningException {
	// Creamos un fichero mimetype que incluya únicamente el texto
	// "application/vnd.etsi.asic-s+zip" y lo añadimos al fichero ZIP que se
	// corresponde con la firma ASiC-S
	try {
	    File mimetypeFile = new File(SignatureFormatDetectorASiC.MIME_TYPE_FILE);
	    FileUtils.writeStringToFile(mimetypeFile, SignatureFormatDetectorASiC.ASIC_S_MIME_TYPE);

	    ZipEntry mimetypeZIPEntry = new ZipEntry(SignatureFormatDetectorASiC.MIME_TYPE_FILE);
	    ((ZipOutputStream) outZip).putNextEntry(mimetypeZIPEntry);
	    addEntryToZip(FileUtils.readFileToByteArray(mimetypeFile), outZip);
	    ((ZipOutputStream) outZip).closeEntry();

	    // Borramos del disco el fichero creado
	    FileUtils.forceDelete(mimetypeFile);
	} catch (IOException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG044);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}
    }

    /**
     * Method that checks the properties defined are allowed.
     * 
     * @param extraParams Represents the optional input parameters.
     */
    private void checkInputExtraParams(Properties extraParams) {
	boolean enc = false;
	Iterator<Object> it = extraParams.keySet().iterator();
	while (it.hasNext() && !enc) {
	    String prop = (String) it.next();
	    if (!prop.equals(SignatureProperties.XADES_CLAIMED_ROLE_PROP) && !prop.equals(SignatureProperties.XADES_POLICY_QUALIFIER_PROP) && !prop.equals(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP) && !prop.equals(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP) && !prop.equals(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP) && !prop.equals(SignatureProperties.XADES_CANONICALIZATION_METHOD)) {
		enc = true;
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.ASBS_LOG033, new Object[ ] { prop });
		LOGGER.error(errorMsg);
		throw new IllegalArgumentException(errorMsg);
	    }
	}
    }

    /**
     * Method that validates the structure of an ASiC-S signature and the signers of the XML or ASN.1 signature contained inside it.
     * @param asicSSignature Parameter that represents the XAdES signature.
     * @return an object that contains the information about the validation result.
     */
    public ValidationResult verifySignature(byte[ ] asicSSignature) {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.ASBS_LOG012));

	// Instanciamos el objeto a devolver
	ValidationResult validationResult = new ValidationResult();
	try {
	    // Por defecto indicamos que la validación de la firma ha sido
	    // correcta
	    validationResult.setCorrect(true);

	    // Comprobamos que se ha indicado la firma a validar
	    GenericUtilsCommons.checkInputParameterIsNotNull(asicSSignature, Language.getResIntegra(ILogConstantKeys.ASBS_LOG006));

	    /*
	     * Validación de la Integridad. Se llevarán a cabo las siguientes verificaciones:
	     * 
	     * > Los 4 primeros octetos del fichero ZIP deberán tener el valor '504B0304' en hexadecimal.
	     * > El fichero ZIP deberá contener al menos dos elementos: El fichero que se corresponde con los datos firmados, y una firma (ASN.1 o XML).
	     * > Si dentro del fichero ZIP se incluye un fichero “mimetype” se comprobará que el valor indicado en dicho fichero es el asociado a firmas ASiC-S,
	     *   esto es, 'application/vnd.etsi.asic-s+zip'. Si no posee dicho valor, deberá tener el mimetype asociado al fichero firmado.
	     */
	    checkSignatureIntegrity(validationResult, asicSSignature);

	    // Si la firma es ASN.1
	    if (asn1Signature != null) {
		// Se comprobará que la firma indicada es de tipo CAdES, posee
		// al menos un firmante, y que los datos firmados se
		// corresponden con el fichero incluído dentro de la firma
		// ASiC-S Baseline como datos firmados
		validateASN1Signature(validationResult);

	    }
	    // Si la firma es XML
	    else {
		// Se comprobará que dicho documento contiene al menos una
		// firma, que el primero elemento ds:Signature posee como
		// elemento padre asic:XAdESSignatures, y que todas las firmas
		// contenidas en el documento XML son detached
		validateXMLSignature(validationResult);
	    }
	    // Actualizamos la fecha de expiración de la firma ASiC.
	    calculateExpirationDate(validationResult);
	} catch (SigningException e) {
	    validationResult.setCorrect(false);
	} finally {
	    if (!validationResult.isCorrect()) {
		// Indicamos en el log que la firma no es correcta
		LOGGER.info(Language.getResIntegra(ILogConstantKeys.ASBS_LOG001));
	    }
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.ASBS_LOG013));
	}
	// Devolvemos el objeto con la información de validación
	return validationResult;
    }

    /**
     * Method that calculates the expiration date of a ASiC signature.
     * @param validationResult ASiC signature validation result.
     */
    private void calculateExpirationDate(ValidationResult validationResult) {
	Date date = null;
	if (validationResult != null && validationResult.getListSignersValidationResults() != null) {
	    // Recuperamos la lista de resultados de los firmantes.
	    List<SignerValidationResult> signersResultList = validationResult.getListSignersValidationResults();
	    for (SignerValidationResult signersResult: signersResultList) {
		date = UtilsSignatureOp.calculateExpirationDateForValidations(signersResult, date);
	    }
	    validationResult.setExpirationDate(date);
	}
    }

    /**
     * Method that validates the XML signed document contained inside of the ASiC-S signature.
     * @param validationResult Parameter that represents the information about the validation of the ASiC-S signature.
     * @throws SigningException If the method fails.
     */
    private void validateXMLSignature(ValidationResult validationResult) throws SigningException {
	// Accedemos al documento XML
	Document xmlDocument = getDocumentFromXML(validationResult);

	// Registramos los atributos de tipo ID del documento XML
	IdRegister.registerElements(xmlDocument.getDocumentElement());

	// Comprobamos que el primer elemento del documento XML es
	// asic:XAdESSignatures
	Node firstNode = xmlDocument.getFirstChild();
	if (firstNode.getNodeType() != Node.ELEMENT_NODE || !firstNode.getLocalName().equals("XAdESSignatures") || !firstNode.getPrefix().equals("asic")) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG023);
	    LOGGER.error(errorMsg);
	    validationResult.setIntegrallyCorrect(false);
	    validationResult.setErrorMsg(errorMsg);
	    throw new SigningException(errorMsg);
	}

	// Obtenemos la lista de firmantes y
	// contra-firmantes contenidos en la firma
	List<XAdESSignerInfo> listSigners = UtilsSignatureOp.getXAdESListSigners(xmlDocument);

	// Comprobamos que exista al menos un firmante
	if (listSigners.isEmpty()) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG022);
	    LOGGER.error(errorMsg);
	    validationResult.setIntegrallyCorrect(false);
	    validationResult.setErrorMsg(errorMsg);
	    throw new SigningException(errorMsg);
	}

	// Instanciamos una lista donde ubicar la información de validación
	// de cada firmante y la asociamos al resultado final
	List<SignerValidationResult> listSignersValidationResults = new ArrayList<SignerValidationResult>();
	validationResult.setListSignersValidationResults(listSignersValidationResults);

	// Recorremos la lista de firmantes
	for (XAdESSignerInfo signer: listSigners) {
	    try {
		// Instanciamos la firma XML asociada
		XMLSignature xmlSignature = new XMLSignatureElement(signer.getElementSignature()).getXMLSignature();

		// Obtenemos el identificador de la firma
		String signatureId = signer.getId();
		signatureId = signatureId == null ? "" : signatureId;

		// Comprobamos si la firma XML es detached y si posee una
		// referencia a los datos firmados
		checkSignedModeAndReferencesOfXMLSignature(xmlSignature, signatureId, validationResult);
	    } catch (MarshalException e) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG028);
		LOGGER.error(errorMsg, e);
		validationResult.setIntegrallyCorrect(false);
		validationResult.setErrorMsg(errorMsg);
		throw new SigningException(errorMsg, e);
	    }
	    // Instanciamos la clase que gestiona la validación de firmas
	    // CAdES Baseline
	    XAdESBaselineSigner xadesBaselineSigner = new XAdESBaselineSigner();

	    // Determinamos el formato del firmante
	    String signerFormat = SignatureFormatDetectorXades.resolveSignerXAdESFormat(signer.getElementSignature());

	    // Validamos el firmante
	    SignerValidationResult signerValidationResult = xadesBaselineSigner.validateSigner(IUtilsSignature.DETACHED_SIGNATURE_MODE, signer, validationResult, null, signerFormat, false, signedFile, signedFileName);

	    // Validamos los contra-firmantes asociados al firmante
	    xadesBaselineSigner.validateCounterSigners(IUtilsSignature.DETACHED_SIGNATURE_MODE, signer, signerValidationResult, validationResult, null, signedFile, signedFileName);

	    // Añadimos la información de validación del firmante a la lista
	    // asociada
	    listSignersValidationResults.add(signerValidationResult);
	    
	 // Recuperamos el último sello de tiempo de tipo ArchiveTimestamp (en caso de existir).
	 signerValidationResult.setLastArchiveTst(UtilsSignatureOp.obtainCertificateArchiveTimestampsXAdES(signer));
	}
    }

    /**
     * Method that obtains an object as a representation of a XML document.
     * @param validationResult Parameter that represents the information about the validation of the ASiC-S signature.
     * @return an object as a representation of a XML document.
     * @throws SigningException If the method fails.
     */
    private Document getDocumentFromXML(ValidationResult validationResult) throws SigningException {
	try {
	    return UtilsSignatureCommons.getDocumentFromXML(signedXML);
	} catch (Exception e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.ASBS_LOG020, new Object[ ] { e.getMessage() });
	    LOGGER.error(errorMsg, e);
	    validationResult.setIntegrallyCorrect(false);
	    validationResult.setErrorMsg(errorMsg);
	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates the ASN.1 signature contained inside of the ASiC-S signature.
     * @param validationResult Parameter that represents the information about the validation of the ASiC-S signature.
     * @throws SigningException If the method fails.
     */
    private void validateASN1Signature(ValidationResult validationResult) throws SigningException {
	// Obtenemos el objeto SignedData de la firma ASN.1
	CMSSignedData asn1SignedData = getCMSSignedData(validationResult);

	// Comprobamos que la firma ASN.1 es explícita
	if (UtilsSignatureOp.isImplicit(asn1SignedData)) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG020);
	    LOGGER.error(errorMsg);
	    validationResult.setIntegrallyCorrect(false);
	    validationResult.setErrorMsg(errorMsg);
	    throw new SigningException(errorMsg);
	}

	// Obtenemos la lista de firmantes y contra-firmantes contenidos en
	// la firma
	List<CAdESSignerInfo> listSignersFound = UtilsSignatureOp.getCAdESListSigners(asn1SignedData);

	// Comprobamos que exista al menos un firmante
	if (listSignersFound.isEmpty()) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG001);
	    LOGGER.error(errorMsg);
	    validationResult.setIntegrallyCorrect(false);
	    validationResult.setErrorMsg(errorMsg);
	    throw new SigningException(errorMsg);
	}

	// Instanciamos una lista donde ubicar la información de validación
	// de cada firmante y la asociamos al resultado final
	List<SignerValidationResult> listSignersValidationResults = new ArrayList<SignerValidationResult>();
	validationResult.setListSignersValidationResults(listSignersValidationResults);

	// Recorremos la lista de firmantes
	for (CAdESSignerInfo signerInfo: listSignersFound) {
	    // Accedemos a la información del firmante
	    SignerInformation signerInformation = signerInfo.getSignerInformation();

	    // Obtenemos los atributos firmados
	    AttributeTable signedAttributes = signerInformation.getSignedAttributes();

	    // Si la firma contiene atributos firmados
	    if (signedAttributes != null) {
		// Accedemos al atributo message-digest
		Attribute messageDigestAttribute = signedAttributes.get(CMSAttributes.messageDigest);

		// Obtenemos el resumen de los datos firmados
		byte[ ] signatureSignedDigest = ((ASN1OctetString) messageDigestAttribute.getAttrValues().getObjectAt(0).getDERObject()).getOctets();

		// Obtenemos el algoritmo de resumen usado para calcular el
		// resumen
		// de los datos firmados
		AlgorithmIdentifier signatureDigestAlgorithmIdentifier = signerInformation.getDigestAlgorithmID();
		String digestAlgorithm = CryptoUtilPdfBc.translateAlgorithmIdentifier(signatureDigestAlgorithmIdentifier);

		// Calculamos el resumen del fichero incluído en la firma ASiC-S
		// usando el algoritmo de resumen contenido en la propia firma
		byte[ ] signedFileDigest = getSignedFileDigest(digestAlgorithm, validationResult);

		// Comprobamos que los resúmenes coincidan
		if (!Arrays.equals(signatureSignedDigest, signedFileDigest)) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.ASBS_LOG021, new Object[ ] { signerInfo.getSigningCertificate().getSubjectDN().getName(), digestAlgorithm });
		    LOGGER.error(errorMsg);
		    validationResult.setIntegrallyCorrect(false);
		    validationResult.setErrorMsg(errorMsg);
		    throw new SigningException(errorMsg);
		}
		// Instanciamos la clase que gestiona la validación de firmas
		// CAdES Baseline
		CAdESBaselineSigner cadesBaselineSigner = new CAdESBaselineSigner();

		// Primero, determinamos el formato del firmante
		String signerFormat = SignatureFormatDetectorCadesPades.resolveSignerCAdESFormat(asn1SignedData, signerInfo.getSignerInformation());

		// Validamos el firmante
		SignerValidationResult signerValidationResult = cadesBaselineSigner.validateSigner(asn1SignedData, signerInfo, validationResult, null, false, signerFormat);

		// Validamos los contra-firmantes asociados al firmante
		cadesBaselineSigner.validateCounterSigners(signerInfo, signerValidationResult, asn1SignedData, validationResult, null);

		// Añadimos la información de validación del firmante a la lista
		// asociada
		listSignersValidationResults.add(signerValidationResult);
		
		// Recuperamos el último sello de tiempo de tipo ArchiveTimestamp (en caso de existir).
		signerValidationResult.setLastArchiveTst(UtilsSignatureOp.obtainCertificateArchiveTimestamps(signerInfo.getSignerInformation().getUnsignedAttributes()));
	    }
	    // Si la firma no contiene atributos firmados
	    else {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.ASBS_LOG031, new Object[ ] { signerInfo.getSigningCertificate().getSubjectDN().getName() });
		LOGGER.error(errorMsg);
		validationResult.setIntegrallyCorrect(false);
		validationResult.setErrorMsg(errorMsg);
		throw new SigningException(errorMsg);
	    }
	}

    }

    /**
     * Method that obtains the hash computation of the signed file contained inside of the ASiC-S signature.
     * @param digestAlgorithm Parameter that represents the algorithm used in the hash computation.
     * @param validationResult Parameter that represents the information about the validation of the ASiC-S signature.
     * @return the hash value.
     * @throws SigningException If the method fails.
     */
    private byte[ ] getSignedFileDigest(String digestAlgorithm, ValidationResult validationResult) throws SigningException {
	try {
	    return CryptoUtilPdfBc.digest(digestAlgorithm, signedFile);
	} catch (Exception e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.ASBS_LOG029, new Object[ ] { e.getMessage() });
	    LOGGER.error(errorMsg, e);
	    validationResult.setIntegrallyCorrect(false);
	    validationResult.setErrorMsg(errorMsg);
	    throw new SigningException(errorMsg, e);
	}
    }

    /**
     * Method that obtains the signature message of the ASN.1 signature contained inside of the ASiC-S signature.
     * @param validationResult Parameter that represents the information about the validation of the ASiC-S signature.
     * @return the signature message.
     * @throws SigningException If the method fails.
     */
    private CMSSignedData getCMSSignedData(ValidationResult validationResult) throws SigningException {
	try {
	    return new CMSSignedData(new CMSProcessableByteArray(signedFile), asn1Signature);
	} catch (Exception e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG052);
	    LOGGER.error(errorMsg, e);
	    validationResult.setIntegrallyCorrect(false);
	    validationResult.setErrorMsg(errorMsg);
	    throw new SigningException(errorMsg, e);
	}
    }

    /**
     * Method that checks:
     * <ul>
     * <li>If the first 4 octets shall have the hex values: "50 4B 03 04".</li>
     * <li>The signature contains the signed file and an ASN.1 or XML signature.</li>
     * <li>The mimetype file contained inside of the signature is valid.</li>
     * </ul>
     * @param validationResult Parameter that contains the information related to the validation of the ASiC-S signature.
     * @param asicSSignature Parameter that represents the ASiC-S signature.
     * @throws SigningException If the validation fails.
     */
    private void checkSignatureIntegrity(ValidationResult validationResult, byte[ ] asicSSignature) throws SigningException {
	// Establecemos, por defecto, que la firma es estructuralmente correcta
	validationResult.setIntegrallyCorrect(true);

	// Comprobamos que los primeros 4 octetos del fichero ZIP deben tener el
	// siguiente valor en hexadecimal: '50 4B 03 04'
	checkHeaderZIPFile(asicSSignature, validationResult);

	// Definimos una variable para almacenar el contenido del fichero
	// mimetype
	byte[ ] mimeTypeFile = null;

	// Inicializamos las variables relacionadas con el proceso de validación
	signedFile = null;
	asn1Signature = null;
	signedXML = null;
	signedFileName = null;

	InputStream is = null;
	InputStream asicsInputStream = null;
	try {
	    // Leemos el fichero ZIP que se corresponde con la firma ASiC-S
	    is = new ByteArrayInputStream(asicSSignature);
	    asicsInputStream = new ZipInputStream(is);

	    // Recorremos las entradas del fichero ZIP
	    for (ZipEntry entry = ((ZipInputStream) asicsInputStream).getNextEntry(); entry != null; entry = ((ZipInputStream) asicsInputStream).getNextEntry()) {
		// Accedemos al nombre de la entrada
		String entryName = entry.getName();

		// Si la entrada es el fichero mimetype
		if (entryName.equals(SignatureFormatDetectorASiC.MIME_TYPE_FILE)) {
		    // Obtenemos el array de bytes que se corresponde con el
		    // fichero mimetype
		    mimeTypeFile = GenericUtilsCommons.getDataFromInputStream(asicsInputStream);
		}
		// Si la entrada es la firma ASN.1
		else if (SignatureFormatDetectorASiC.isCAdESEntry(entryName)) {
		    // Accedemos al elemento SignedData
		    asn1Signature = GenericUtilsCommons.getDataFromInputStream(asicsInputStream);

		}
		// Si la entrada es la firma XML
		else if (SignatureFormatDetectorASiC.isXAdESEntry(entryName)) {
		    signedXML = GenericUtilsCommons.getDataFromInputStream(asicsInputStream);
		}
		// Si la entrada no es un directorio, debe ser los datos
		// firmados
		else if (!entry.isDirectory()) {
		    signedFile = GenericUtilsCommons.getDataFromInputStream(asicsInputStream);
		    signedFileName = entryName;
		}
	    }
	} catch (IOException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG011);
	    LOGGER.error(errorMsg, e);
	    validationResult.setIntegrallyCorrect(false);
	    validationResult.setErrorMsg(errorMsg);
	    throw new SigningException(errorMsg, e);
	} finally {
	    // Cerramos recursos
	    UtilsResourcesCommons.safeCloseInputStream(asicsInputStream);
	    UtilsResourcesCommons.safeCloseInputStream(is);
	}

	// Comprobamos que hemos encontrado la firma ASN.1 o la firma XAdES
	// dentro del fichero, así como los datos firmados.
	checkZIPRequiredContent(validationResult);

	// Validamos el fichero mimetype, en caso de que esté incluído
	validateMimetypeFile(mimeTypeFile, validationResult);

    }

    /**
     * 
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#getSignedData(byte[])
     */
    public OriginalSignedData getSignedData(byte[ ] asicSSignature) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.ASBS_LOG036));

	// Instanciamos el objeto a devolver
	OriginalSignedData result = new OriginalSignedData();

	signedFile = null;

	InputStream is = null;
	InputStream asicsInputStream = null;
	try {
	    // Leemos el fichero ZIP que se corresponde con la firma ASiC-S
	    is = new ByteArrayInputStream(asicSSignature);
	    asicsInputStream = new ZipInputStream(is);

	    // Recorremos las entradas del fichero ZIP
	    for (ZipEntry entry = ((ZipInputStream) asicsInputStream).getNextEntry(); entry != null && signedFile == null; entry = ((ZipInputStream) asicsInputStream).getNextEntry()) {
		// Accedemos al nombre de la entrada
		String entryName = entry.getName();

		// Si la entrada no es un directorio, no es el fichero mimetype,
		// no es la firma ASN.1 y no es la firma XML debe ser los datos
		// firmados
		if (!entry.isDirectory() && !entryName.equals(SignatureFormatDetectorASiC.MIME_TYPE_FILE) && !SignatureFormatDetectorASiC.isCAdESEntry(entryName) && !SignatureFormatDetectorASiC.isXAdESEntry(entryName)) {
		    signedFile = GenericUtilsCommons.getDataFromInputStream(asicsInputStream);
		}
	    }

	    // Obtenemos la información de los datos firmados
	    result.setMimetype(UtilsResourcesSignOperations.getMimeType(signedFile));
	    result.setSignedData(signedFile);
	} catch (IOException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.ASBS_LOG011);
	    LOGGER.error(errorMsg, e);
	    return null;
	} finally {
	    // Cerramos recursos
	    UtilsResourcesCommons.safeCloseInputStream(asicsInputStream);
	    UtilsResourcesCommons.safeCloseInputStream(is);

	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.ASBS_LOG037));
	}
	return result;
    }
}
