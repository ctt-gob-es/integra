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
 * <b>File:</b><p>es.gob.afirma.signature.pades.PAdESBaselineSigner.java.</p>
 * <b>Description:</b><p>Class that manages the generation, validation and upgrade of PAdES Baseline signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>21/01/2016.</p>
 * @author Gobierno de España.
 * @version 1.3, 13/04/2020.
 */
package es.gob.afirma.signature.pades;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

import com.lowagie.text.DocumentException;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfDate;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfNumber;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignature;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.pdf.PdfString;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.signature.ISignatureFormatDetector;
import es.gob.afirma.signature.OriginalSignedData;
import es.gob.afirma.signature.SignatureConstants;
import es.gob.afirma.signature.SignatureFormatDetectorCadesPades;
import es.gob.afirma.signature.SignatureProperties;
import es.gob.afirma.signature.Signer;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.signature.cades.CAdESSignerInfo;
import es.gob.afirma.signature.cades.CMSBuilder;
import es.gob.afirma.signature.cades.P7ContentSignerParameters;
import es.gob.afirma.signature.policy.SignaturePolicyException;
import es.gob.afirma.signature.policy.SignaturePolicyManager;
import es.gob.afirma.signature.validation.ISignatureValidationTaskID;
import es.gob.afirma.signature.validation.ITimestampValidationTaskID;
import es.gob.afirma.signature.validation.PDFDocumentTimeStampDictionaryValidationResult;
import es.gob.afirma.signature.validation.PDFSignatureDictionaryValidationResult;
import es.gob.afirma.signature.validation.PDFValidationResult;
import es.gob.afirma.signature.validation.TimeStampValidationInfo;
import es.gob.afirma.signature.validation.TimestampValidationResult;
import es.gob.afirma.signature.validation.ValidationInfo;
import es.gob.afirma.utils.CryptoUtilPdfBc;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.utils.NumberConstants;
import es.gob.afirma.utils.UtilsResourcesCommons;
import es.gob.afirma.utils.UtilsResourcesSignOperations;
import es.gob.afirma.utils.UtilsSignatureOp;
import es.gob.afirma.utils.UtilsTimestampPdfBc;

/**
 * <p>Class that manages the generation, validation and upgrade of PAdES Baseline signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.3, 13/04/2020.
 */
public final class PAdESBaselineSigner implements Signer {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(PAdESBaselineSigner.class);

    /**
     * Constructor method for the class PAdESBaselineSigner.java.
     */
    public PAdESBaselineSigner() {
	// Añadimos el proveedor criptográfico Bouncycastle en caso de que no
	// esté incluído
	if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
	    Security.addProvider(new BouncyCastleProvider());
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#sign(byte[], java.lang.String, java.lang.String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public byte[ ] sign(byte[ ] data, String algorithm, String signatureFormat, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID, String idClient) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.PBS_LOG001));
	OutputStream bytesResult = new ByteArrayOutputStream();
	try {
	    // Comprobamos que se ha indicado el algoritmo de firma y tiene un
	    // valor admitido
	    checkInputSignatureAlgorithm(algorithm);

	    // Comprobamos que se han indicado los datos a firmar
	    GenericUtilsCommons.checkInputParameterIsNotNull(data, Language.getResIntegra(ILogConstantKeys.PBS_LOG005));

	    // Comprobamos que se ha indicado la clave privada
	    GenericUtilsCommons.checkInputParameterIsNotNull(privateKey, Language.getResIntegra(ILogConstantKeys.PBS_LOG006));

	    // Comprobamos que se ha indicado el formato de la firma a generar y
	    // es un formato admitido
	    checkInputSignatureForm(signatureForm);

	    // Si no se han indicado parámetros adicionales los inicializamos
	    Properties externalParams = extraParams;
	    if (externalParams == null) {
		externalParams = new Properties();
	    }

	    // En caso de que se haya indicado que la firma sea explícita,
	    // informamos de que sólo puede ser impli
	    if (SignatureConstants.SIGN_MODE_EXPLICIT.equals(signatureFormat)) {
		LOGGER.warn(Language.getResIntegra(ILogConstantKeys.PBS_LOG009));
	    }

	    // Obtenemos la cadena de certificación a partir de la clave privada
	    Certificate[ ] certificateChain = privateKey.getCertificateChain();

	    // Leemos el documento PDF original
	    PdfReader reader = new PdfReader(data);

	    // Antes de llevar a cabo la firma comprobamos el nivel de
	    // certificación asociado a la firma más reciente, en caso de
	    // existir, del documento PDF.
	    // Si la firma anterior está definida como Certified, en ese caso,
	    // no se podrán añadir más firmas al documento PDF
	    PdfReader lastRevisionReader = UtilsSignatureOp.obtainLatestRevision(reader);
	    if (lastRevisionReader != null && lastRevisionReader.getCertificationLevel() != PdfSignatureAppearance.NOT_CERTIFIED) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.PBS_LOG010);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Creamos el contenido de la firma
	    PdfStamper stp = PdfStamper.createSignature(reader, bytesResult, '\0', null, true);

	    // Iniciamos el proceso de generación de la firma PAdES
	    PdfSignatureAppearance signatureAppearance = stp.getSignatureAppearance();

	    // Se comprueba si se va a insertar rúbrica
	    if (UtilsSignatureOp.checkExtraParamsSignWithRubric(externalParams)) {
		UtilsSignatureOp.insertRubric(reader, signatureAppearance, externalParams);
	    }
	    // Establecemos como fecha de creación de la firma la fecha actual
	    signatureAppearance.setSignDate(new GregorianCalendar());

	    // Asociamos la cadena de certificación
	    signatureAppearance.setCrypto(null, certificateChain, null, PdfName.ADOBE_PPKLITE);

	    // Establecemos el valor de la clave /SubFilter como
	    // 'ETSI.CAdES.detached'.
	    PdfSignature signDictionary = new PdfSignature(PdfName.ADOBE_PPKLITE, UtilsSignatureOp.CADES_SUBFILTER_VALUE);

	    // Añadimos la entrada /M al diccionario de firma
	    signDictionary.setDate(new PdfDate(signatureAppearance.getSignDate()));
	    String signatureDictionaryName = PdfPKCS7.getSubjectFields((X509Certificate) certificateChain[0]).getField("CN");
	    signDictionary.setName(signatureDictionaryName);

	    // Comprobamos si se ha indicado en las propiedades extra la
	    // propiedad SignatureProperties.PADES_CERTIFICATION_LEVEL. Dicha
	    // propiedad
	    // indica el nivel de restricción asociado a la firma. Si posee el
	    // valor CERTIFIED_NO_CHANGES_ALLOWED indicará
	    // que la firma
	    // no admitirá que se le añadan firmas "approval" en el futuro. Si
	    // posee el valor NOT_CERTIFIED, (valor por defecto), indicará
	    // que la firma
	    // admitirá que se le añadan firmas "approval" en el futuro.
	    int certificationLevel = defineCertificationLevel(externalParams);

	    // Establecemos el nivel de certificación en la firma
	    signatureAppearance.setCertificationLevel(certificationLevel);

	    // Incluimos propiedades de la firma (si existen)
	    addPropertyToDictionary(externalParams, signDictionary);

	    // Incluímos el diccionario de firma
	    signatureAppearance.setCryptoDictionary(signDictionary);

	    // Reservamos espacio para el contenido de la clave /Contents
	    int csize = NumberConstants.INT_8000;

	    // Incluimos la clave /Contents
	    HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
	    exc.put(PdfName.CONTENTS, Integer.valueOf(csize * 2 + 2));
	    signatureAppearance.preClose(exc);

	    // Definimos una variable para crear el elemento SignedData
	    byte[ ] signedData = null;

	    // Instanciamos los parámetros que recibirá el método encargado de
	    // generar el núcleo de firma CAdES
	    P7ContentSignerParameters csp = new P7ContentSignerParameters(data, algorithm, privateKey);

	    // Instanciamos el OID asociado al atributo content-type con valor
	    Oid dataType = new Oid(PKCSObjectIdentifiers.data.getId());

	    // Obtenemos el algoritmo de resumen a partir del algoritmo de firma
	    // indicado
	    String digestAlgorithm = CryptoUtilPdfBc.getDigestAlgorithmName(algorithm);

	    // Calculamos el message-digest
	    byte[ ] messageDigest = CryptoUtilPdfBc.digest(digestAlgorithm, GenericUtilsCommons.getDataFromInputStream(signatureAppearance.getRangeStream()));
	    csp.setDigestValue(messageDigest);

	    // Incluimos en los parámetros opcionales aquél que indica que el
	    // SignedData a crear será para una firma PAdES
	    externalParams.put(SignatureConstants.SIGN_FORMAT_PADES, true);

	    // Creamos el elemento SignedData
	    CMSBuilder cmsBuilder = new CMSBuilder();
	    signedData = cmsBuilder.generateSignedData(csp, false, dataType, externalParams, includeTimestamp, signatureForm, signaturePolicyID, idClient);

	    // Incluímos la firma CAdES en el diccionario de firma
	    byte[ ] outc = new byte[csize];
	    PdfDictionary dic2 = new PdfDictionary();
	    System.arraycopy(signedData, 0, outc, 0, signedData.length);
	    dic2.put(PdfName.CONTENTS, new PdfString(outc).setHexWriting(true));
	    signatureAppearance.close(dic2);

	    // Si la firma a generar incluye política de firma, comprobamos si
	    // es
	    // válida respecto a las entradas del diccionario de firma
	    if (cmsBuilder.isEPES()) {
		SignaturePolicyManager.validateGeneratedPAdESEPESSignature(signDictionary, cmsBuilder.getPolicyID(), null, idClient);
	    }

	    // Obtenemos la firma PAdES Baseline creada
	    byte[ ] result = ((ByteArrayOutputStream) bytesResult).toByteArray();

	    // Informamos de que hemos generado la firma CAdES Baseline
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.PBS_LOG011));

	    // Escribimos la firma en el Log
	    GenericUtilsCommons.printResult(result, LOGGER);

	    // Devolvemos la firma generada
	    return result;
	} catch (IOException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.PBS_LOG012);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (DocumentException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.PBS_LOG012);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (GSSException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.PBS_LOG012);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (SignaturePolicyException e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.PBS_LOG013, new Object[ ] { e.getMessage() });
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} finally {
	    // Cerramos recursos
	    UtilsResourcesCommons.safeCloseOutputStream(bytesResult);
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.PBS_LOG002));
	}
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
     * Adds properties to signature dictionary.
     * @param externalParams optional parameters
     * @param signDictionary signature dictionary
     */
    private void addPropertyToDictionary(Properties externalParams, PdfSignature signDictionary) {
	String reason = externalParams.getProperty(SignatureProperties.PADES_REASON_PROP);
	String contact = externalParams.getProperty(SignatureProperties.PADES_CONTACT_PROP);
	String location = externalParams.getProperty(SignatureProperties.PADES_LOCATION_PROP);
	if (GenericUtilsCommons.assertStringValue(reason)) {
	    signDictionary.setReason(reason);
	}
	// Localización donde se produce la firma
	if (GenericUtilsCommons.assertStringValue(location)) {
	    signDictionary.setLocation(location);
	}

	// Contacto del firmante
	if (GenericUtilsCommons.assertStringValue(contact)) {
	    signDictionary.setContact(contact);
	}

    }

    /**
     * Method that checks if the extra properties have defined the property {@link SignatureProperties#PADES_CERTIFICATION_LEVEL} and returns the document
     * type to certified instead of simply signed.
     * @param extraParams Represents the optional input parameters.
     * @return {@link PdfSignatureAppearance#CERTIFIED_NO_CHANGES_ALLOWED} or {@link PdfSignatureAppearance#CERTIFIED_FORM_FILLING_AND_ANNOTATIONS}.
     */
    private int defineCertificationLevel(Properties extraParams) {
	// Comprobamos si se ha indicado en las propiedades extra la
	// propiedad SignatureProperties.PADES_CERTIFICATION_LEVEL. Dicha
	// propiedad
	// indica el nivel de restricción asociado a la firma. Si posee el
	// valor CERTIFIED_NO_CHANGES_ALLOWED indicará
	// que la firma
	// no admitirá que se le añadan firmas "approval" en el futuro. Si
	// posee el valor NOT_CERTIFIED, (valor por defecto), indicará
	// que la firma
	// admitirá que se le añadan firmas "approval" en el futuro.
	int certificationLevel = PdfSignatureAppearance.NOT_CERTIFIED;
	if (extraParams.getProperty(SignatureProperties.PADES_CERTIFICATION_LEVEL) != null && extraParams.getProperty(SignatureProperties.PADES_CERTIFICATION_LEVEL).equals(SignatureConstants.PDF_CERTIFIED)) {
	    certificationLevel = PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED;
	}
	return certificationLevel;
    }

    /**
     * Method that checks if the input signature algorithm is <code>null</code> and is allowed to use.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     */
    private void checkInputSignatureAlgorithm(String signatureAlgorithm) {
	// Comprobamos que el algoritmo de firma no es nulo
	GenericUtilsCommons.checkInputParameterIsNotNull(signatureAlgorithm, Language.getResIntegra(ILogConstantKeys.PBS_LOG003));

	// Comprobamos que el algoritmo de firma está soportado
	if (!SignatureConstants.SIGN_ALGORITHMS_SUPPORT_CADES.containsKey(signatureAlgorithm)) {
	    String msg = Language.getFormatResIntegra(ILogConstantKeys.PBS_LOG004, new Object[ ] { signatureAlgorithm });
	    LOGGER.error(msg);
	    throw new IllegalArgumentException(msg);
	}
    }

    /**
     * Method that checks if the input signature format is <code>null</code> and is allowed to use.
     * @param signatureForm Parameter that represents the signature format.
     */
    private void checkInputSignatureForm(String signatureForm) {
	// Comprobamos que el formato de la firma a generar no es nulo
	GenericUtilsCommons.checkInputParameterIsNotNull(signatureForm, Language.getResIntegra(ILogConstantKeys.PBS_LOG007));

	// Comprobamos que el formato de la firma a generar está
	// soportado.
	if (!signatureForm.equals(ISignatureFormatDetector.FORMAT_PADES_B_LEVEL)) {
	    String msg = Language.getFormatResIntegra(ILogConstantKeys.PBS_LOG008, new Object[ ] { signatureForm });
	    LOGGER.error(msg);
	    throw new IllegalArgumentException(msg);
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#coSign(byte[], byte[], java.lang.String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public byte[ ] coSign(byte[ ] signature, byte[ ] document, String algorithm, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID, String idClient) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.PBS_LOG033));
	OutputStream bytesResult = new ByteArrayOutputStream();
	try {
	    // Comprobamos que se han indicado los datos a firmar
	    GenericUtilsCommons.checkInputParameterIsNotNull(signature, Language.getResIntegra(ILogConstantKeys.PBS_LOG005));

	    // Comprobamos que se ha indicado el algoritmo de firma y tiene un
	    // valor admitido
	    checkInputSignatureAlgorithm(algorithm);

	    // Comprobamos que se ha indicado la clave privada
	    GenericUtilsCommons.checkInputParameterIsNotNull(privateKey, Language.getResIntegra(ILogConstantKeys.PBS_LOG006));

	    // Comprobamos que se ha indicado el formato de la firma a generar y
	    // es un formato admitido
	    checkInputSignatureForm(signatureForm);

	    // Si no se han indicado parámetros adicionales los inicializamos
	    Properties externalParams = extraParams;
	    if (externalParams == null) {
		externalParams = new Properties();
	    }

	    checkExtraParamsCoSign(externalParams);

	    // Obtenemos la cadena de certificación a partir de la clave privada
	    Certificate[ ] certificateChain = privateKey.getCertificateChain();

	    // Leemos el documento PDF original
	    PdfReader reader = new PdfReader(signature);

	    // Antes de llevar a cabo la firma comprobamos el nivel de
	    // certificación asociado a la firma más reciente, en caso de
	    // existir, del documento PDF.
	    // Si la firma anterior está definida como Certified, en ese caso,
	    // no se podrán añadir más firmas al documento PDF
	    PdfReader lastRevisionReader = UtilsSignatureOp.obtainLatestRevision(reader);
	    if (lastRevisionReader != null && lastRevisionReader.getCertificationLevel() != PdfSignatureAppearance.NOT_CERTIFIED) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.PBS_LOG010);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Creamos el contenido de la firma
	    PdfStamper stp = PdfStamper.createSignature(reader, bytesResult, '\0', null, true);

	    // Iniciamos el proceso de generación de la firma PAdES
	    PdfSignatureAppearance signatureAppearance = stp.getSignatureAppearance();

	    // Se comprueba si se va a insertar rúbrica
	    if (UtilsSignatureOp.checkExtraParamsSignWithRubric(externalParams)) {
		UtilsSignatureOp.insertRubric(reader, signatureAppearance, externalParams);
	    }
	    // Establecemos como fecha de creación de la firma la fecha actual
	    signatureAppearance.setSignDate(new GregorianCalendar());

	    // Asociamos la cadena de certificación
	    signatureAppearance.setCrypto(null, certificateChain, null, PdfName.ADOBE_PPKLITE);

	    // Establecemos el valor de la clave /SubFilter como
	    // 'ETSI.CAdES.detached'.
	    PdfSignature signDictionary = new PdfSignature(PdfName.ADOBE_PPKLITE, UtilsSignatureOp.CADES_SUBFILTER_VALUE);

	    // Añadimos la entrada /M al diccionario de firma
	    signDictionary.setDate(new PdfDate(signatureAppearance.getSignDate()));
	    String signatureDictionaryName = PdfPKCS7.getSubjectFields((X509Certificate) certificateChain[0]).getField("CN");
	    signDictionary.setName(signatureDictionaryName);

	    // Comprobamos si se ha indicado en las propiedades extra la
	    // propiedad SignatureProperties.PADES_CERTIFICATION_LEVEL. Dicha
	    // propiedad
	    // indica el nivel de restricción asociado a la firma. Si posee el
	    // valor CERTIFIED_NO_CHANGES_ALLOWED indicará
	    // que la firma
	    // no admitirá que se le añadan firmas "approval" en el futuro. Si
	    // posee el valor NOT_CERTIFIED, (valor por defecto), indicará
	    // que la firma
	    // admitirá que se le añadan firmas "approval" en el futuro.
	    int certificationLevel = defineCertificationLevel(externalParams);

	    // Establecemos el nivel de certificación en la firma
	    signatureAppearance.setCertificationLevel(certificationLevel);

	    // Incluimos propiedades de la firma (si existen)
	    addPropertyToDictionary(externalParams, signDictionary);

	    // Incluímos el diccionario de firma
	    signatureAppearance.setCryptoDictionary(signDictionary);

	    // Reservamos espacio para el contenido de la clave /Contents
	    int csize = NumberConstants.INT_8000;

	    // Incluimos la clave /Contents
	    HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
	    exc.put(PdfName.CONTENTS, Integer.valueOf(csize * 2 + 2));
	    signatureAppearance.preClose(exc);

	    // Definimos una variable para crear el elemento SignedData
	    byte[ ] signedData = null;

	    // Instanciamos los parámetros que recibirá el método encargado de
	    // generar el núcleo de firma CAdES
	    P7ContentSignerParameters csp = new P7ContentSignerParameters(signature, algorithm, privateKey);

	    // Instanciamos el OID asociado al atributo content-type con valor
	    Oid dataType = new Oid(PKCSObjectIdentifiers.data.getId());

	    // Obtenemos el algoritmo de resumen a partir del algoritmo de firma
	    // indicado
	    String digestAlgorithm = CryptoUtilPdfBc.getDigestAlgorithmName(algorithm);

	    // Calculamos el message-digest
	    byte[ ] messageDigest = CryptoUtilPdfBc.digest(digestAlgorithm, GenericUtilsCommons.getDataFromInputStream(signatureAppearance.getRangeStream()));
	    csp.setDigestValue(messageDigest);

	    // Incluimos en los parámetros opcionales aquél que indica que el
	    // SignedData a crear será para una firma PAdES
	    externalParams.put(SignatureConstants.SIGN_FORMAT_PADES, true);

	    // Creamos el elemento SignedData
	    CMSBuilder cmsBuilder = new CMSBuilder();
	    signedData = cmsBuilder.generateSignedData(csp, false, dataType, externalParams, includeTimestamp, signatureForm, signaturePolicyID, idClient);

	    // Incluímos la firma PAdES en el diccionario de firma
	    byte[ ] outc = new byte[csize];
	    PdfDictionary dic2 = new PdfDictionary();
	    System.arraycopy(signedData, 0, outc, 0, signedData.length);
	    dic2.put(PdfName.CONTENTS, new PdfString(outc).setHexWriting(true));
	    signatureAppearance.close(dic2);

	    // Si la firma a generar incluye política de firma, comprobamos si
	    // es
	    // válida respecto a las entradas del diccionario de firma
	    if (cmsBuilder.isEPES()) {
		SignaturePolicyManager.validateGeneratedPAdESEPESSignature(signDictionary, cmsBuilder.getPolicyID(), null, idClient);
	    }

	    // Obtenemos la firma PAdES Baseline creada
	    byte[ ] result = ((ByteArrayOutputStream) bytesResult).toByteArray();

	    // Informamos de que hemos generado la co-firma PAdES Baseline
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.PBS_LOG039));

	    // Escribimos la firma en el Log
	    GenericUtilsCommons.printResult(result, LOGGER);

	    // Devolvemos la firma generada
	    return result;
	} catch (IOException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.PBS_LOG041);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (DocumentException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.PBS_LOG041);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (GSSException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.PBS_LOG041);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (SignaturePolicyException e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.PBS_LOG029, new Object[ ] { e.getMessage() });
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} finally {
	    // Cerramos recursos
	    UtilsResourcesCommons.safeCloseOutputStream(bytesResult);
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.PBS_LOG034));
	}
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
     * @see es.gob.afirma.signature.Signer#counterSign(byte[], java.lang.String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public byte[ ] counterSign(byte[ ] signature, String algorithm, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID, String idClient) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.PBS_LOG035));
	OutputStream bytesResult = new ByteArrayOutputStream();
	try {
	    // Comprobamos que se han indicado los datos a firmar
	    GenericUtilsCommons.checkInputParameterIsNotNull(signature, Language.getResIntegra(ILogConstantKeys.PBS_LOG005));

	    // Comprobamos que se ha indicado el algoritmo de firma y tiene un
	    // valor admitido
	    checkInputSignatureAlgorithm(algorithm);

	    // Comprobamos que se ha indicado la clave privada
	    GenericUtilsCommons.checkInputParameterIsNotNull(privateKey, Language.getResIntegra(ILogConstantKeys.PBS_LOG006));

	    // Comprobamos que se ha indicado el formato de la firma a generar y
	    // es un formato admitido
	    checkInputSignatureForm(signatureForm);

	    // Si no se han indicado parámetros adicionales los inicializamos
	    Properties externalParams = extraParams;
	    if (externalParams == null) {
		externalParams = new Properties();
	    }

	    checkExtraParamsCounterSign(externalParams);

	    // Obtenemos la cadena de certificación a partir de la clave privada
	    Certificate[ ] certificateChain = privateKey.getCertificateChain();

	    // Leemos el documento PDF original
	    PdfReader reader = new PdfReader(signature);

	    // Antes de llevar a cabo la firma comprobamos el nivel de
	    // certificación asociado a la firma más reciente, en caso de
	    // existir, del documento PDF.
	    // Si la firma anterior está definida como Certified, en ese caso,
	    // no se podrán añadir más firmas al documento PDF
	    PdfReader lastRevisionReader = UtilsSignatureOp.obtainLatestRevision(reader);
	    if (lastRevisionReader != null && lastRevisionReader.getCertificationLevel() != PdfSignatureAppearance.NOT_CERTIFIED) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.PBS_LOG010);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Creamos el contenido de la firma
	    PdfStamper stp = PdfStamper.createSignature(reader, bytesResult, '\0', null, true);

	    // Iniciamos el proceso de generación de la firma PAdES
	    PdfSignatureAppearance signatureAppearance = stp.getSignatureAppearance();

	    // Se comprueba si se va a insertar rúbrica
	    if (UtilsSignatureOp.checkExtraParamsSignWithRubric(externalParams)) {
		UtilsSignatureOp.insertRubric(reader, signatureAppearance, externalParams);
	    }
	    // Establecemos como fecha de creación de la firma la fecha actual
	    signatureAppearance.setSignDate(new GregorianCalendar());

	    // Asociamos la cadena de certificación
	    signatureAppearance.setCrypto(null, certificateChain, null, PdfName.ADOBE_PPKLITE);

	    // Establecemos el valor de la clave /SubFilter como
	    // 'ETSI.CAdES.detached'.
	    PdfSignature signDictionary = new PdfSignature(PdfName.ADOBE_PPKLITE, UtilsSignatureOp.CADES_SUBFILTER_VALUE);

	    // Añadimos la entrada /M al diccionario de firma
	    signDictionary.setDate(new PdfDate(signatureAppearance.getSignDate()));
	    String signatureDictionaryName = PdfPKCS7.getSubjectFields((X509Certificate) certificateChain[0]).getField("CN");
	    signDictionary.setName(signatureDictionaryName);

	    // Comprobamos si se ha indicado en las propiedades extra la
	    // propiedad SignatureProperties.PADES_CERTIFICATION_LEVEL. Dicha
	    // propiedad
	    // indica el nivel de restricción asociado a la firma. Si posee el
	    // valor CERTIFIED_NO_CHANGES_ALLOWED indicará
	    // que la firma
	    // no admitirá que se le añadan firmas "approval" en el futuro. Si
	    // posee el valor NOT_CERTIFIED, (valor por defecto), indicará
	    // que la firma
	    // admitirá que se le añadan firmas "approval" en el futuro.
	    int certificationLevel = defineCertificationLevel(externalParams);

	    // Establecemos el nivel de certificación en la firma
	    signatureAppearance.setCertificationLevel(certificationLevel);

	    // Incluimos propiedades de la firma (si existen)
	    addPropertyToDictionary(externalParams, signDictionary);

	    // Incluímos el diccionario de firma
	    signatureAppearance.setCryptoDictionary(signDictionary);

	    // Reservamos espacio para el contenido de la clave /Contents
	    int csize = NumberConstants.INT_8000;

	    // Incluimos la clave /Contents
	    HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
	    exc.put(PdfName.CONTENTS, Integer.valueOf(csize * 2 + 2));
	    signatureAppearance.preClose(exc);

	    // Definimos una variable para crear el elemento SignedData
	    byte[ ] signedData = null;

	    // Instanciamos los parámetros que recibirá el método encargado de
	    // generar el núcleo de firma CAdES
	    P7ContentSignerParameters csp = new P7ContentSignerParameters(signature, algorithm, privateKey);

	    // Instanciamos el OID asociado al atributo content-type con valor
	    Oid dataType = new Oid(PKCSObjectIdentifiers.data.getId());

	    // Obtenemos el algoritmo de resumen a partir del algoritmo de firma
	    // indicado
	    String digestAlgorithm = CryptoUtilPdfBc.getDigestAlgorithmName(algorithm);

	    // Calculamos el message-digest
	    byte[ ] messageDigest = CryptoUtilPdfBc.digest(digestAlgorithm, GenericUtilsCommons.getDataFromInputStream(signatureAppearance.getRangeStream()));
	    csp.setDigestValue(messageDigest);

	    // Incluimos en los parámetros opcionales aquél que indica que el
	    // SignedData a crear será para una firma PAdES
	    externalParams.put(SignatureConstants.SIGN_FORMAT_PADES, true);

	    // Creamos el elemento SignedData
	    CMSBuilder cmsBuilder = new CMSBuilder();
	    signedData = cmsBuilder.generateSignedData(csp, false, dataType, externalParams, includeTimestamp, signatureForm, signaturePolicyID, idClient);

	    // Incluímos la firma CAdES en el diccionario de firma
	    byte[ ] outc = new byte[csize];
	    PdfDictionary dic2 = new PdfDictionary();
	    System.arraycopy(signedData, 0, outc, 0, signedData.length);
	    dic2.put(PdfName.CONTENTS, new PdfString(outc).setHexWriting(true));
	    signatureAppearance.close(dic2);

	    // Si la firma a generar incluye política de firma, comprobamos si
	    // es
	    // válida respecto a las entradas del diccionario de firma
	    if (cmsBuilder.isEPES()) {
		SignaturePolicyManager.validateGeneratedPAdESEPESSignature(signDictionary, cmsBuilder.getPolicyID(), null, idClient);
	    }

	    // Obtenemos la firma PAdES Baseline creada
	    byte[ ] result = ((ByteArrayOutputStream) bytesResult).toByteArray();

	    // Informamos de que hemos generado la co-firma PAdES Baseline
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.PBS_LOG040));

	    // Escribimos la firma en el Log
	    GenericUtilsCommons.printResult(result, LOGGER);

	    // Devolvemos la firma generada
	    return result;
	} catch (IOException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.PBS_LOG042);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (DocumentException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.PBS_LOG042);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (GSSException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.PBS_LOG042);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (SignaturePolicyException e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.PBS_LOG028, new Object[ ] { e.getMessage() });
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} finally {
	    // Cerramos recursos
	    UtilsResourcesCommons.safeCloseOutputStream(bytesResult);
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.PBS_LOG036));
	}
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
    public byte[ ] upgrade(byte[ ] pdfDocument, List<X509Certificate> listSigners, String idClient) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.PBS_LOG016));
	OutputStream out = new ByteArrayOutputStream();
	PdfStamper stamper = null;
	String errorMsg = null;
	try {
	    // Comprobamos que se ha indicado el documento PDF que actualizar
	    GenericUtilsCommons.checkInputParameterIsNotNull(pdfDocument, Language.getResIntegra(ILogConstantKeys.PBS_LOG018));

	    // Instanciamos el objeto que permite leer el documento PDF
	    errorMsg = Language.getResIntegra(ILogConstantKeys.PBS_LOG030);
	    PdfReader reader = new PdfReader(pdfDocument);

	    // Antes de llevar a cabo la actualización comprobamos el nivel de
	    // certificación asociado a la firma más reciente, en caso de
	    // existir, del documento PDF.
	    // Si la firma anterior está definida como Certified, en ese caso,
	    // no se podrán añadir más firmas al documento PDF
	    PdfReader lastRevisionReader = UtilsSignatureOp.obtainLatestRevision(reader);
	    if (lastRevisionReader != null && lastRevisionReader.getCertificationLevel() != PdfSignatureAppearance.NOT_CERTIFIED) {
		errorMsg = Language.getResIntegra(ILogConstantKeys.PBS_LOG010);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Construimos el objeto para añadir el diccionario de sello de
	    // tiempo
	    errorMsg = Language.getResIntegra(ILogConstantKeys.PBS_LOG019);
	    stamper = PdfStamper.createSignature(reader, out, '\0', null, true);

	    // Instanciamos un objeto para poder aplicar cambios al documento
	    // PDF
	    PdfSignatureAppearance sap = stamper.getSignatureAppearance();

	    // Creamos un nuevo diccionario de firma de tipo DocTimeStamp
	    PdfSignature timeStampSignature = new PdfSignature(PdfName.ADOBE_PPKLITE, UtilsSignatureOp.TST_SUBFILTER_VALUE);
	    timeStampSignature.put(PdfName.TYPE, UtilsSignatureOp.DOC_TIME_STAMP_DICTIONARY_NAME);
	    timeStampSignature.put(PdfName.V, new PdfNumber(0));
	    sap.setCryptoDictionary(timeStampSignature);

	    // Reservamos espacio para el contenido de la clave /Contents
	    Integer reservedSpace = Integer.valueOf(NumberConstants.HEX_0X6502);
	    Map<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
	    exc.put(PdfName.CONTENTS, reservedSpace);
	    errorMsg = Language.getResIntegra(ILogConstantKeys.PBS_LOG020);
	    sap.preClose((HashMap<PdfName, Integer>) exc);

	    // Obtenemos los datos que debe sellar la entidad emisora de marcas
	    // de hora (TSA)
	    InputStream s = sap.getRangeStream();
	    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
	    int nRead;
	    byte[ ] data = new byte[NumberConstants.INT_16384];
	    while ((nRead = s.read(data, 0, data.length)) != -1) {
		buffer.write(data, 0, nRead);
	    }
	    buffer.flush();
	    byte[ ] dataR = buffer.toByteArray();

	    // Obtenemos la marca de hora sobre los datos obtenidos
	    TimeStampToken tst = new CMSBuilder().generateTimestamp(dataR, idClient);

	    // Actualizamos el contenido de la clave /Contents
	    byte[ ] timestampToken = tst.getEncoded();
	    byte[ ] outc = new byte[(reservedSpace.intValue() - 2) / 2];
	    PdfDictionary dic2 = new PdfDictionary();
	    System.arraycopy(timestampToken, 0, outc, 0, timestampToken.length);
	    dic2.put(PdfName.CONTENTS, new PdfString(outc).setHexWriting(true));
	    sap.close(dic2);

	    // Devolvemos el documento PDF con el nuevo diccionario de sello de
	    // tiempo
	    return ((ByteArrayOutputStream) out).toByteArray();
	} catch (DocumentException e) {
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (IOException e) {
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} finally {
	    // Cerramos recursos
	    UtilsResourcesCommons.safeCloseOutputStream(out);
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.PBS_LOG017));
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#upgrade(byte[], java.util.List)
     */
    public byte[ ] upgrade(byte[ ] pdfDocument, List<X509Certificate> listSigners) throws SigningException {
	return upgrade(pdfDocument, listSigners, null);
    }

    /**
     * Method that verifies all the signature dictionaries and document Time-stamp dictionaries of a PDF document.
     * @param pdfDocument Parameter that represents the PDF document.
     * @return an object that contains the information about the validation result.
     */
    public PDFValidationResult verifySignature(byte[ ] pdfDocument) {
	return verifySignature(pdfDocument, null);
    }

    /**
     *
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#getSignedData(byte[])
     */
    public OriginalSignedData getSignedData(byte[ ] pdfDocument) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.PBS_LOG031));
	OriginalSignedData osd = new OriginalSignedData();
	// Comprobamos que el parámetro de entrada no es nulo
	if (pdfDocument == null) {
	    throw new SigningException(Language.getResIntegra(ILogConstantKeys.US_LOG008));
	}
	// obtenemos la primera revisión
	byte[ ] buffer = UtilsSignatureOp.obtainFirstRevision(pdfDocument);

	// guarda los datos firmados y el mimetype del documento.
	osd.setSignedData(buffer);
	osd.setMimetype(UtilsResourcesSignOperations.getMimeType(buffer));

	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.PBS_LOG032));
	return osd;
    }

    /**
     * Method that checks if the extra properties have defined the allowed properties to co-sign.
     *
     * @param extraParams Represents the optional input parameters.
    
     */
    private void checkExtraParamsCoSign(Properties extraParams) {
	boolean enc = false;
	Iterator<Object> it = extraParams.keySet().iterator();
	while (it.hasNext() && !enc) {
	    String prop = (String) it.next();
	    if (!prop.equals(SignatureProperties.PADES_CERTIFICATION_LEVEL) && !prop.equals(SignatureProperties.PADES_CONTACT_PROP) && !prop.equals(SignatureProperties.PADES_LOCATION_PROP) && !prop.equals(SignatureProperties.PADES_REASON_PROP) && !prop.equals(SignatureProperties.PADES_IMAGE) && !prop.equals(SignatureProperties.PADES_IMAGE_PAGE) && !prop.equals(SignatureProperties.PADES_LOWER_LEFT_X) && !prop.equals(SignatureProperties.PADES_LOWER_LEFT_Y) && !prop.equals(SignatureProperties.PADES_UPPER_RIGHT_X) && !prop.equals(SignatureProperties.PADES_UPPER_RIGHT_Y)) {
		enc = true;
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.PBS_LOG037, new Object[ ] { prop });
		LOGGER.error(errorMsg);
		throw new IllegalArgumentException(errorMsg);
	    }
	}
    }

    /**
     * Method that checks if the extra properties have defined the allowed properties to counter-sign .
     *
     * @param extraParams Represents the optional input parameters.
     */
    private void checkExtraParamsCounterSign(Properties extraParams) {
	boolean enc = false;
	Iterator<Object> it = extraParams.keySet().iterator();
	while (it.hasNext() && !enc) {
	    String prop = (String) it.next();
	    // CHECKSTYLE:OFF Boolean complexity needed
	    if (!prop.equals(SignatureProperties.CADES_POLICY_QUALIFIER_PROP) && !prop.equals(SignatureProperties.PADES_CERTIFICATION_LEVEL) && !prop.equals(SignatureProperties.PADES_CONTACT_PROP) && !prop.equals(SignatureProperties.PADES_LOCATION_PROP) && !prop.equals(SignatureProperties.PADES_REASON_PROP) && !prop.equals(SignatureProperties.PADES_IMAGE) && !prop.equals(SignatureProperties.PADES_IMAGE_PAGE) && !prop.equals(SignatureProperties.PADES_LOWER_LEFT_X) && !prop.equals(SignatureProperties.PADES_LOWER_LEFT_Y) && !prop.equals(SignatureProperties.PADES_UPPER_RIGHT_X) && !prop.equals(SignatureProperties.PADES_UPPER_RIGHT_Y)) {
		// CHECKSTYLE:ON
		enc = true;
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.PBS_LOG038, new Object[ ] { prop });
		LOGGER.error(errorMsg);
		throw new IllegalArgumentException(errorMsg);
	    }
	}
    }

    /**
     * Method that validates the Document Time-stamp dictionaries contained inside of a PDF document.
     * @param listTimestampDictionaries Parameter that represents the list of Document Time-stamp dictionaries to validate.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @param pdfDocument Parameter that represents the signed PDF document.
     * @param idClient Parameter that represents the client application identifier.
     */
    private void validateDocumentTimeStampDictionaries(List<PDFDocumentTimestampDictionary> listTimestampDictionaries, PDFValidationResult validationResult, byte[ ] pdfDocument, String idClient) {
	// Si el documento PDF incluye diccionarios de sello de tiempo
	if (!listTimestampDictionaries.isEmpty()) {

	    // Instanciamos una lista donde ubicar la información de
	    // validación
	    // de cada diccionario de sello de tiempo y la asociamos al
	    // resultado final
	    List<PDFDocumentTimeStampDictionaryValidationResult> listPDFTimeStampDictionariesValidationResult = new ArrayList<PDFDocumentTimeStampDictionaryValidationResult>();
	    validationResult.setListPDFDocumentTimeStampDictionariesValidationResults(listPDFTimeStampDictionariesValidationResult);

	    // Iteramos sobre la lista de diccionarios de sello de tiempo
	    // ordenada
	    // ascendentemente por revisión
	    for (int i = 0; i < listTimestampDictionaries.size(); i++) {
		PDFDocumentTimestampDictionary pdfDocumentTimeStampDictionary = listTimestampDictionaries.get(i);

		// Instanciamos una variable donde ubicar la información del
		// diccionario de sello de tiempo a validar
		PDFDocumentTimeStampDictionaryValidationResult pdfDocumentTimeStampDictionaryValidationResult = new PDFDocumentTimeStampDictionaryValidationResult();

		// Asociamos una lista donde incluir la información de las
		// validaciones que se aplicarán sobre el diccionario de sello
		// de tiempo
		pdfDocumentTimeStampDictionaryValidationResult.setListValidations(new ArrayList<TimeStampValidationInfo>());

		// Asociamos la información del certificado firmante del sello
		// de tiempo a la información del
		// diccionario de sello de tiempo a validar
		pdfDocumentTimeStampDictionaryValidationResult.setSigningCertificate(pdfDocumentTimeStampDictionary.getCertificate());

		try {
		    // Indicamos inicialmente que la validación del diccionario
		    // de sello de tiempo ha sido correcta
		    pdfDocumentTimeStampDictionaryValidationResult.setCorrect(true);

		    // Asociamos al objeto con la información de validación
		    // del diccionario de sello de tiempo su nombre
		    pdfDocumentTimeStampDictionaryValidationResult.setDictionaryName(pdfDocumentTimeStampDictionary.getName());

		    // Añadimos la información del diccionario de sello de
		    // tiempo a validar a
		    // la lista asociada
		    listPDFTimeStampDictionariesValidationResult.add(pdfDocumentTimeStampDictionaryValidationResult);

		    /*
		     * Validación Estructural Diccionario Document Time-stamp. Contemplará las siguientes verificaciones:
		     * > La clave /ByteRange del diccionario de firma deberá estar presente y su valor corresponderse con el valor del atributo message-imprint del sello de tiempo.
		     * > La clave /Cert del diccionario de firma no deberá estar presente.
		     * > La clave /Reference del diccionario de firma no deberá estar presente.
		     * > La clave /Changes del diccionario de firma no deberá estar presente.
		     * > La clave /R del diccionario de firma no deberá estar presente.
		     * > La clave /Prop_AuthTime del diccionario de firma no deberá estar presente.
		     * > La clave /Prop_AuthType del diccionario de firma no deberá estar presente.
		     * > La clave /V del diccionario de firma deberá estar presente y su valor corresponderse con el valor 0.
		     */
		    validateDocumentTimeStampDictionaryStructurally(pdfDocumentTimeStampDictionaryValidationResult, validationResult, pdfDocumentTimeStampDictionary, pdfDocument);

		    /*
		     * Validación del Instante de Firma: La fecha de generación del sello de tiempo contenido en el diccionario de firma será anterior a la fecha de validación.
		     * La fecha de validación se corresponderá con la fecha de generación del sello de tiempo contenido en el diccionario de firma de tipo Document Time-stamp
		     * incluído en el documento PDF como la revisión inmediatamente superior a la revisión del diccionario de firma de tipo Document Time-stamp
		     * que estamos procesando. En caso de que no existan ningún diccionario de firma de tipo Document Time-stamp con número de revisión mayor la
		     * fecha de validación se corresponderá con la fecha actual.
		     */
		    Date validationDate = Calendar.getInstance().getTime();
		    if (i < listTimestampDictionaries.size() - 1) {
			validationDate = listTimestampDictionaries.get(i + 1).getTimestamp().getTimeStampInfo().getGenTime();
		    }
		    validateDocumentTimeStampSigningTime(pdfDocumentTimeStampDictionaryValidationResult, validationResult, pdfDocumentTimeStampDictionary, validationDate);

		    /*
		     * Validación del Núcleo de Firma: Se comprobará que el sello de tiempo contenido en el diccionario de firma está bien formado y que sus
		     * datos sellados se corresponden con los que deberían haber sellado.
		     */
		    validateDocumentTimeStampCore(pdfDocumentTimeStampDictionaryValidationResult, validationResult, pdfDocumentTimeStampDictionary);

		    /*
		     * Validación del Certificado Firmante: Se comprobará el estado del certificado del primer firmante del sello de tiempo contenido en
		     * el diccionario de firma respecto a la fecha de validación utilizando el método de validación definido para los certificados firmantes,
		     * ya sea en el fichero integraFacade.properties (si la validación se realiza desde la fachada de firma), o bien en el fichero signer.properties
		     * (si la validación se realiza desde la interfaz Signer). La fecha de validación se corresponderá con la fecha de generación del sello de tiempo
		     * contenido en el diccionario de firma de tipo Document Time-stamp incluído en el documento PDF como la revisión inmediatamente superior a la
		     * revisión del diccionario de firma de tipo Document Time-stamp que estamos procesando. En caso de que no existan ningún diccionario de firma
		     * de tipo Document Time-stamp con número de revisión mayor la fecha de validación se corresponderá con la fecha actual. Además, se verificará
		     * que el certificado posee la extensión id-kp-timestamp.
		     */
		    validateDocumentTimeStampCertificate(pdfDocumentTimeStampDictionaryValidationResult, validationResult, pdfDocumentTimeStampDictionary, validationDate, idClient);
		} catch (Exception e) {
		    // Establecemos en la información asociada a la validación
		    // del diccionario de sello de tiempo que éste no es
		    // correcto
		    pdfDocumentTimeStampDictionaryValidationResult.setCorrect(false);

		    // Establecemos en la información asociada a la validación
		    // de la firma que ésta no es correcta
		    validationResult.setCorrect(false);
		}
	    }
	}
    }

    /**
     * Method that validates a signed PDF document.
     * @param pdfDocument Parameter that represents the signed PDF document.
     * @param idClient Parameter that represents the client application identifier.
     * @return an object that contains information about the validation of the signature, including all the signers and counter-signers contained inside it.
     */
    public PDFValidationResult verifySignature(byte[ ] pdfDocument, String idClient) {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.PBS_LOG021));
	// Instanciamos el objeto a devolver
	PDFValidationResult validationResult = new PDFValidationResult();
	try {
	    // Por defecto indicamos que la validación de la firma ha sido
	    // correcta
	    validationResult.setCorrect(true);

	    // Comprobamos que se ha indicado el documento PDF a validar
	    GenericUtilsCommons.checkInputParameterIsNotNull(pdfDocument, Language.getResIntegra(ILogConstantKeys.PBS_LOG018));

	    // Creamos una lista donde ubicar los diccionarios de firma
	    List<PDFSignatureDictionary> listSignatureDictionaries = new ArrayList<PDFSignatureDictionary>();

	    // Creamos una lista donde ubicar los diccionarios de sello de
	    // tiempo
	    List<PDFDocumentTimestampDictionary> listTimestampDictionaries = new ArrayList<PDFDocumentTimestampDictionary>();

	    // Creamos un mapa donde la clave es la revisión de un
	    // diccionario de firma y su valor es el contenido de la revisión,
	    // ordenado
	    // ascendentemente por revisión.
	    Map<Integer, InputStream> mapSignatureDictionaryRevisions = new TreeMap<Integer, InputStream>();

	    // Validación de la Integridad: Se comprobará que el documento PDF
	    // posee al menos una firma, y que el nivel de certificación del
	    // documento PDF es correcto. Esto es, que no existe ninguna
	    // revisión (diccionario de firma) que haya sido añadida al
	    // documento PDF después de que la última revisión haya sido
	    // definida como Certified
	    AcroFields af = checkSignatureIntegrity(pdfDocument, validationResult, listSignatureDictionaries, listTimestampDictionaries, mapSignatureDictionaryRevisions);

	    // Determinamos el formato de firma asociado al documento PDF y lo
	    // asociamos a la información de validación de la firma
	    validationResult.setSignatureFormat(SignatureFormatDetectorCadesPades.getSignatureFormat(pdfDocument));

	    // Instanciamos una lista donde ubicar la información de validación
	    // de cada diccionario de firma y la asociamos al resultado final
	    List<PDFSignatureDictionaryValidationResult> listPDFSignatureDictionariesValidationResult = new ArrayList<PDFSignatureDictionaryValidationResult>();
	    validationResult.setListPDFSignatureDictionariesValidationResults(listPDFSignatureDictionariesValidationResult);

	    // Validamos los diccionarios de firma
	    validateSignatureDictionaries(listSignatureDictionaries, listPDFSignatureDictionariesValidationResult, af, validationResult, listTimestampDictionaries, pdfDocument, idClient);

	    // Validamos los diccionarios de sello de tiempo
	    validateDocumentTimeStampDictionaries(listTimestampDictionaries, validationResult, pdfDocument, idClient);

	    // Indicamos en el log que la firma es correcta
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.PBS_LOG015));
	    
	    // Calculamos la fecha de expiración de la firma.
	    validationResult.setExpirationDate(UtilsSignatureOp.calculateExpirationDate(listSignatureDictionaries, listTimestampDictionaries));
	} catch (Exception e) {
	    // Establecemos en la información asociada a la validación
	    // de la firma que ésta no es correcta
	    validationResult.setCorrect(false);

	    // Indicamos en el log que la firma no es correcta
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.PBS_LOG014));
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.PBS_LOG022));
	}
	return validationResult;
    }

    /**
     * Method that checks if a PDF document contains at least one signature dictionary (or Document Time-stamp dictionary), and if if some approval signature was added to
     * the PDF document after that it was defined as certified.
     * @param pdfDocument Parameter that represents the PDF document.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @param listSignatureDictionaries Parameter that represents a list to fill with the signature dictionaries contained inside of the PDF document.
     * @param listTimestampDictionaries Parameter that represents a list to fill with the Document Time-stamp dictionaries contained inside of the PDF document.
     * @param mapSignatureDictionaryRevisions Parameter that represents a map to fill with the revisions of the PDF document. Each revision represents a signature dictionary. The key
     * is the revision number, and the value is the revision.
     * @return an object that allows to access to the fields of PDF document.
     * @throws SigningException If the method fails.
     */
    @SuppressWarnings("unchecked")
    private AcroFields checkSignatureIntegrity(byte[ ] pdfDocument, PDFValidationResult validationResult, List<PDFSignatureDictionary> listSignatureDictionaries, List<PDFDocumentTimestampDictionary> listTimestampDictionaries, Map<Integer, InputStream> mapSignatureDictionaryRevisions) throws SigningException {
	// Establecemos, por defecto, que el documento PDF es íntegramente
	// correcto
	validationResult.setIntegrallyCorrect(true);

	try {
	    // Construimos el objeto para poder leer el PDF
	    PdfReader reader = new PdfReader(pdfDocument);

	    // Instanciamos un objeto para consultar campos del PDF
	    AcroFields af = reader.getAcroFields();

	    // Obtenemos las firmas del documento, esto es, los objetos /Sig y
	    // los objetos /DocTimeStamp
	    List<String> names = af.getSignatureNames();

	    // Añadimos los valores a las listas y mapa anteriores.
	    searchSignaturesAndTimestamps(names, af, listSignatureDictionaries, listTimestampDictionaries, mapSignatureDictionaryRevisions, validationResult);

	    // Comprobamos que el documento PDF contenga al menos un diccionario
	    // de firma o un diccionario de sello de tiempo
	    if (listSignatureDictionaries.isEmpty() && listTimestampDictionaries.isEmpty()) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.PBS_LOG025);
		LOGGER.error(errorMsg);
		validationResult.setIntegrallyCorrect(false);
		validationResult.setErrorMsg(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    try {
		// Comprobamos que el nivel de certificación del documento PDF
		// es
		// correcto, es decir, que no existe ninguna revisión
		// (diccionario
		// de firma) definido
		// como Certified y al que se le hayan añadido posteriormente
		// revisiones (diccionarios de firma)
		UtilsSignatureOp.checkPDFCertificationLevel(mapSignatureDictionaryRevisions);
	    } catch (Exception e) {
		LOGGER.error(e.getMessage());
		validationResult.setIntegrallyCorrect(false);
		validationResult.setErrorMsg(e.getMessage());
		throw new SigningException(e);
	    }
	    return af;
	} catch (IOException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.PBS_LOG030);
	    LOGGER.error(errorMsg, e);
	    validationResult.setIntegrallyCorrect(false);
	    validationResult.setErrorMsg(errorMsg);
	    throw new SigningException(e);
	}
    }

    /**
     * Method that searches the signature and Document Time-stamp dictionaries contained inside of the PDF document.
     * @param names Parameter that represents a list with the signature and Document Time-stamp dictionaries contained inside of the PDF document.
     * @param af Parameter that allows to access to the fields of PDF document.
     * @param listSignatureDictionaries Parameter that represents a list to fill with the signature dictionaries contained inside of the PDF document.
     * @param listTimestampDictionaries Parameter that represents a list to fill with the Document Time-stamp dictionaries contained inside of the PDF document.
     * @param mapSignatureDictionaryRevisions Parameter that represents a map to fill with the revisions of the PDF document. Each revision represents a signature dictionary. The key
     * is the revision number, and the value is the revision.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @throws SigningException If the method fails.
     */
    private void searchSignaturesAndTimestamps(List<String> names, AcroFields af, List<PDFSignatureDictionary> listSignatureDictionaries, List<PDFDocumentTimestampDictionary> listTimestampDictionaries, Map<Integer, InputStream> mapSignatureDictionaryRevisions, PDFValidationResult validationResult) throws SigningException {
	// Recorremos las firmas
	for (String signatureName: names) {
	    // Obtenemos el diccionario
	    PdfDictionary signatureDictionary = af.getSignatureDictionary(signatureName);

	    // Determinamos el tipo de diccionario obtenido
	    String pdfType = null;
	    if (signatureDictionary.get(PdfName.TYPE) != null) {
		pdfType = signatureDictionary.get(PdfName.TYPE).toString();
	    }
	    // Determinamos el contenido de la clave SubFilter
	    String subFilter = signatureDictionary.get(PdfName.SUBFILTER).toString();
	    // Es TST
	    if (UtilsSignatureOp.isDocumentTimeStampDictionary(pdfType, subFilter)) {
		// Accedemos al contenido de la clave /Contents
		byte[ ] arrayTST = signatureDictionary.getAsString(PdfName.CONTENTS).getOriginalBytes();
		TimeStampToken tst = null;
		X509Certificate tstCertificate = null;
		// Si la clave /Contents no es nula
		if (arrayTST != null) {
		    try {
			// Accedemos al sello de tiempo
			tst = new TimeStampToken(new CMSSignedData(arrayTST));

			// Accedemos al certificado firmante del sello de tiempo
			tstCertificate = UtilsTimestampPdfBc.getSigningCertificate(tst);
		    } catch (Exception e) {
			String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.PBS_LOG023, new Object[ ] { signatureName });
			LOGGER.error(errorMsg, e);
			throw new SigningException(errorMsg, e);
		    }
		}

		// Añadimos el diccionario a la lista de diccionarios de
		// sello de tiempo
		listTimestampDictionaries.add(new PDFDocumentTimestampDictionary(signatureDictionary, signatureName, af.getRevision(signatureName), tst, tstCertificate));
	    }
	    // Es firma
	    else if (UtilsSignatureOp.isSignatureDictionary(pdfType, subFilter)) {
		// Añadimos la firma al mapa de firmas
		listSignatureDictionaries.add(new PDFSignatureDictionary(af.getRevision(signatureName), signatureDictionary, signatureName));

		// Añadimos la revisión al mapa de revisiones
		try {
		    mapSignatureDictionaryRevisions.put(af.getRevision(signatureName), af.extractRevision(signatureName));
		} catch (IOException e) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.PBS_LOG024, new Object[ ] { signatureName });
		    LOGGER.error(errorMsg, e);
		    validationResult.setIntegrallyCorrect(false);
		    validationResult.setErrorMsg(errorMsg);
		    throw new SigningException(errorMsg, e);
		}
	    }
	}
	// Ordenamos la lista donde ubicar todos los diccionarios de firma
	// ascendentemente por revisión
	Collections.sort(listSignatureDictionaries);

	// Ordenamos la lista donde ubicar todos los diccionarios de sello
	// de tiempo ordenados ascendentemente por revisión
	Collections.sort(listTimestampDictionaries);
    }

    /**
     * Method that validates the signature dictionaries contained inside of a PDF document.
     * @param listSignatureDictionaries Parameter that represents the list of signature dictionaries to validate.
     * @param listPDFSignatureDictionariesValidationResult Parameter that represents the list where to locate the results of valite each signature dictionary.
     * @param af Parameter that allows to access to the fields of PDF document.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @param listTimestampDictionaries Parameter that represents the list with the Document Time-stamp dictionaries contained inside of the PDF document.
     * @param pdfDocument Parameter that represents the signed PDF document.
     * @param idClient Parameter that represents the client application identifier.
     */
    private void validateSignatureDictionaries(List<PDFSignatureDictionary> listSignatureDictionaries, List<PDFSignatureDictionaryValidationResult> listPDFSignatureDictionariesValidationResult, AcroFields af, PDFValidationResult validationResult, List<PDFDocumentTimestampDictionary> listTimestampDictionaries, byte[ ] pdfDocument, String idClient) {
	// Iteramos sobre la lista de diccionarios de firma ordenada
	// ascendentemente por revisión
	for (PDFSignatureDictionary pdfSignatureDictionary: listSignatureDictionaries) {

	    // Instanciamos una variable donde ubicar la información del
	    // diccionario de firma a validar
	    PDFSignatureDictionaryValidationResult pdfSignatureDictionaryValidationResult = new PDFSignatureDictionaryValidationResult();

	    try {
		// Por defecto indicamos que la validación del diccionario de
		// firma ha sido correcta
		pdfSignatureDictionaryValidationResult.setCorrect(true);

		// Instanciamos una lista donde ubicar la información de las
		// validaciones aplicadas sobre el diccionario de firma
		pdfSignatureDictionaryValidationResult.setListValidations(new ArrayList<ValidationInfo>());

		// Asociamos al objeto con la información de validación
		// del diccionario de firma su nombre
		pdfSignatureDictionaryValidationResult.setDictionaryName(pdfSignatureDictionary.getName());

		// Añadimos la información del diccionario de firma a validar a
		// la lista asociada
		listPDFSignatureDictionariesValidationResult.add(pdfSignatureDictionaryValidationResult);

		// Determinamos el formato de firma asociado al diccionario de
		// firma
		String signatureFormat = SignatureFormatDetectorCadesPades.resolveSignatureDictionaryFormat(pdfSignatureDictionary);

		// Si el formato de firma es PDF no realizamos ninguna
		// validación sobre el documento
		// PDF ni sobre el firmante
		if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PDF)) {
		    validatePDFSignatureDictionary(pdfSignatureDictionaryValidationResult, pdfSignatureDictionary, af, validationResult);
		}
		// Si el formato del diccionario de firma no es PDF
		else {
		    // Obtenemos los datos firmados
		    CMSSignedData signedData = UtilsSignatureOp.getCMSSignature(pdfSignatureDictionary);

		    // Accedemos a los datos del firmante
		    CAdESSignerInfo signerInfo = getSignerFromSignature(signedData, pdfSignatureDictionaryValidationResult, validationResult, pdfSignatureDictionary);

		    // Asociamos el certificado firmante a la información de
		    // validación del diccionario de firma
		    pdfSignatureDictionaryValidationResult.setSigningCertificate(signerInfo.getSigningCertificate());

		    // Determinamos la fecha de validación para cada firma que
		    // será
		    // la fecha de generación del primer sello de tiempo
		    // contenido
		    // en un atributo
		    // signature-time-stamp de la firma CAdES o CMS. Si no
		    // contuviese
		    // dicho atributo, entonces, la fecha de validación sería la
		    // fecha de generación
		    // del sello de tiempo contenido en el primer diccionario de
		    // sello de tiempo con revisión posterior a la del
		    // diccionario
		    // de firma. Si el
		    // documento PDF no tuviera diccionarios de sello de tiempo
		    // se
		    // utilizará la fecha actual como fecha de validación
		    Date validationDate = getValidationDateForSignatureDictionary(signerInfo, pdfSignatureDictionary.getRevision(), listTimestampDictionaries);

		    // Si el diccionario de firma es PAdES-Basic
		    if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_BASIC)) {
			/*
			 * Validación Estructural PDF: Contemplará las siguientes verificaciones:
			 * > La firma CMS que constituye el núcleo de firma sólo contiene un firmante.
			 * > La clave /Contents del diccionario de firma deberá estar presente y su contenido corresponderse con una firma CMS.
			 * > La clave /ByteRange del diccionario de firma deberá estar presente y su contenido corresponderse con el resumen de la firma CMS.
			 * > La clave /SubFilter del diccionario de firma deberá estar presente y su contenido corresponderse con el valor “adbe.pkcs7.detached” o “adbe.pkcs7.sha1”.
			 * 		En el caso de que el valor sea “adbe.pkcs7.detached” se comprobará que la firma CMS contenida es explícita.
			 * 		En el caso de que el valor sea “adbe.pkcs7.sha1” se comprobará que el algoritmo de firma utilizado es SHA-1.
			 */
			validatePAdESBasicStructurally(pdfSignatureDictionaryValidationResult, pdfSignatureDictionary, pdfDocument, signedData, validationResult);

			/*
			 * Validación del Núcleo de Firma: Se comprobará que el primer firmante de la firma CMS contenida en el diccionario de firma verifica la propia
			 * firma CMS.
			 */
			validateSignatureCore(pdfSignatureDictionaryValidationResult, signerInfo, validationResult);

			/*
			 * Validación de la Información de Clave Pública: Si el primer firmante de la firma CMS posee el atributo firmado serial-number se
			 * comprobará que éste coincide con el número de serie del certificado firmante
			 */
			validateCMSKeyInfo(pdfSignatureDictionaryValidationResult, signerInfo, validationResult);

			/*
			 * Validación del Instante de Firma: Si el primer firmante de la firma CMS contenida en el diccionario de firma incluye el atributo firmado signing-time se
			 * comprobará que dicho atributo está bien formado y que la fecha contenida en el mismo es anterior a la fecha de validación. Igualmente,
			 * si el diccionario de firma incluye la clave /M validaremos que dicho campo posee un formato correcto según [PDF_Reference],
			 * sección 3.8.3 (Dates), así como que la fecha contenida no sea futura respecto a la fecha de validación. La fecha de validación en ambos casos
			 * será la fecha de generación del sello de tiempo menos reciente contenido en un atributo no firmado signature-time-stamp del primer firmante de
			 * la firma CMS contenida en el diccionario de firma. Si dicho atributo no se incluye, la fecha de validación será la fecha de generación del
			 * sello de tiempo menos reciente contenido en los diccionarios de firma de tipo Document Time-stamp que incluyese el documento PDF. Si no se incluye
			 * ningún diccionario de firma de tipo Document Time-stamp la fecha de validación será la fecha actual.
			 */
			validatePAdESBasicSigningTime(pdfSignatureDictionaryValidationResult, validationResult, signerInfo, validationDate, pdfSignatureDictionary);

			/*
			 * Validación del Certificado Firmante: Se comprobará el estado del certificado del primer firmante de la firma contenida en el diccionario de
			 * firma respecto a la fecha de validación utilizando el método de validación definido para el mismo, ya sea en el fichero integraFacade.properties
			 * (si la validación se realiza desde la fachada de firma), o bien en el fichero signer.properties (si la validación se realiza desde la interfaz Signer).
			 */
			validateSigningCertificate(pdfSignatureDictionaryValidationResult, validationResult, signerInfo, validationDate, idClient);

			/*
			 * Validación de los Atributos signature-time-stamp: Si el primer firmante de la firma CMS contenida en el diccionario de firma posee atributos
			 * signature-time-stamp se comprobará que todos ellos poseen una estructura correcta y que los sellos de tiempo que contienen están bien formados.
			 * Respecto a cada sello de tiempo se definen las siguientes tareas de validación:
			 * 		> Validación de la Firma del Sello de Tiempo: Se comprobará que la firma del sello de tiempo es correcta.
			 * 		> Validación de la Integridad del Sello de Tiempo: Se comprobará que los datos sellados son correctos.
			 * 		> Validación del Certificado Firmante del Sello de Tiempo: Se comprobará el estado del certificado firmante del sello de tiempo respecto a la fecha de
			 * 		generación del siguiente sello de tiempo, utilizando el método de validación definido para los certificados firmantes, ya sea en el fichero
			 * 		integraFacade.properties (si la validación se realiza desde la fachada de firma), o bien en el fichero signer.properties (si la validación
			 * 		se realiza desde la interfaz Signer). Cuando se esté procesando el certificado firmante del sello de tiempo más reciente (y por lo tanto el último)
			 * 		se utilizará como fecha de validación la fecha actual. Además, se verificará que el certificado posee la extensión id-kp-timestamp.
			 */
			validateSignatureTimeStampAttributes(pdfSignatureDictionaryValidationResult, validationResult, signerInfo, listTimestampDictionaries, idClient);
		    }
		    // Si el diccionario de firma es PAdES B-Level
		    else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_B_LEVEL)) {
			/*
			 * Validación Estructural PDF: Contemplará las siguientes verificaciones:
			 * > La clave /ByteRange del diccionario de firma deberá estar presente y su contenido corresponderse con el resumen de la firma CAdES.
			 * > La clave /SubFilter del diccionario de firma deberá estar presente y su valor corresponderse con “ETSI.CAdES.detached”.
			 * > El primer firmante de la firma CAdES contenida en el diccionario de firma no deberá contener el atributo firmado signing-time.
			 * > El primer firmante de la firma CAdES contenida en el diccionario de firma no deberá contener el atributo firmado content-identifier.
			 * > El primer firmante de la firma CAdES contenida en el diccionario de firma no deberá contener el atributo firmado content-hints.
			 * > El primer firmante de la firma CAdES contenida en el diccionario de firma no deberá contener el atributo firmado signer-location.
			 * > Si el primer firmante de la firma CAdES contienida en el diccionario de firma posee el atributo firmado content-type y éste tiene el valor “id-data”.
			 * > Si el primer firmante de la firma CAdES contenida en el diccionario de firma posee el atributo firmado signature-policy-id entonces no deberá poseer el
			 * atributo firmado commitment-type-indication.
			 * > El primer firmante de la firma CAdES contenida en el diccionario de firma no deberá contener el atributo no firmado counter-signature.
			 * > El primer firmante de la firma CAdES contenida en el diccionario de firma no deberá contener el atributo no firmado content-reference.
			 * > La clave /Cert del diccionario de firma no deberá estar presente.
			 */
			boolean hasSignaturePolicyId = validatePAdESBaselineStructurally(pdfSignatureDictionaryValidationResult, pdfSignatureDictionary, pdfDocument, signedData, validationResult);

			/*
			 * Validación del Núcleo de Firma: Se comprobará que el primer firmante de la firma CAdES contenida en el diccionario de firma verifica la propia
			 * firma CAdES.
			 */
			validateSignatureCore(pdfSignatureDictionaryValidationResult, signerInfo, validationResult);

			/*
			 * Validación de la Información de Clave Pública: Se comprobará que el primer firmante de la firma CAdES contenida en el diccionario de firma incluye
			 * el atributo firmado signing-certificate o el atributo firmado signing-certificate-v2, y que dicho atributo identifica al certificado del firmante.
			 * Además, en el caso de que el atributo que incluya de los dos sea signing-certificate se comprobará que el algoritmo de firma utilizado ha sido SHA-1.
			 */
			validateKeyInfo(pdfSignatureDictionaryValidationResult, validationResult, signerInfo, signedData);

			// Si el primer firmante de la firma contenida en el
			// diccionario de firma tiene el atributo
			// signature-policy-id (incluye política de firma)
			if (hasSignaturePolicyId) {
			    /*
			     * Validación de la Política de Firma: Si el primer firmante de la firma CAdES contenida en el diccionario de firma incluye el atributo
			     * firmado signature-policy-identifier se comprobará si el OID de la política de firma definida en dicho atributo coincide con el OID
			     * de la política de firma definida para firmas PDF en el fichero policy.properties, en cuyo caso, se comprobará que los datos de la
			     * firma y del firmante concreto son válidos respecto a las propiedades definidas en dicho fichero.
			     */
			    validateSignaturePolicy(pdfSignatureDictionaryValidationResult, validationResult, signerInfo, pdfSignatureDictionary, idClient);
			}

			/*
			 * Validación del Instante de Firma: Se comprobará que el diccionario de firma incluye la clave /M y que dicho campo posee un formato
			 * correcto según [PDF_Reference], sección 3.8.3 (Dates), así como que la fecha contenida no sea futura respecto a la fecha de validación.
			 * La fecha de validación será la fecha de generación del sello de tiempo menos reciente contenido en los diccionarios de firma de tipo
			 * Document Time-stamp que incluyese el documento PDF. Si no se incluye ningún diccionario de firma de tipo Document Time-stamp la fecha
			 * de validación será la fecha actual.
			 */
			validatePAdESSigningTime(pdfSignatureDictionaryValidationResult, validationResult, validationDate, pdfSignatureDictionary, true);

			/*
			 * Validación del Certificado Firmante: Se comprobará el estado del certificado del primer firmante de la firma CAdES contenida en el diccionario
			 * de firma respecto a la fecha de validación utilizando el método de validación definido para el mismo, ya sea en el fichero integraFacade.properties
			 * (si la validación se realiza desde la fachada de firma), o bien en el fichero signer.properties (si la validación se realiza desde la interfaz Signer).
			 * La fecha de validación será la fecha de generación del sello de tiempo menos reciente contenido en un atributo no firmado signature-time-stamp del
			 * primer firmante de la firma CAdES contenida en el diccionario de firma. Si dicho atributo no se incluye, la fecha de validación será la fecha de
			 * generación del sello de tiempo menos reciente contenido en los diccionarios de firma de tipo Document Time-stamp que incluyese el documento PDF.
			 * Si no se incluye ningún diccionario de firma de tipo Document Time-stamp la fecha de validación será la fecha actual.
			 */
			validateSigningCertificate(pdfSignatureDictionaryValidationResult, validationResult, signerInfo, validationDate, idClient);
		    }
		    // Si el diccionario de firma es PAdES T-Level
		    else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_T_LEVEL)) {
			/*
			 * Validación Estructural PDF: Contemplará las siguientes verificaciones:
			 * > La clave /ByteRange del diccionario de firma deberá estar presente y su contenido corresponderse con el resumen de la firma CAdES.
			 * > La clave /SubFilter del diccionario de firma deberá estar presente y su valor corresponderse con “ETSI.CAdES.detached”.
			 * > El primer firmante de la firma CAdES contenida en el diccionario de firma no deberá contener el atributo firmado signing-time.
			 * > El primer firmante de la firma CAdES contenida en el diccionario de firma no deberá contener el atributo firmado content-identifier.
			 * > El primer firmante de la firma CAdES contenida en el diccionario de firma no deberá contener el atributo firmado content-hints.
			 * > El primer firmante de la firma CAdES contenida en el diccionario de firma no deberá contener el atributo firmado signer-location.
			 * > Si el primer firmante de la firma CAdES contienida en el diccionario de firma posee el atributo firmado content-type y éste tiene el valor “id-data”.
			 * > Si el primer firmante de la firma CAdES contenida en el diccionario de firma posee el atributo firmado signature-policy-id entonces no deberá poseer el
			 * atributo firmado commitment-type-indication.
			 * > El primer firmante de la firma CAdES contenida en el diccionario de firma no deberá contener el atributo no firmado counter-signature.
			 * > El primer firmante de la firma CAdES contenida en el diccionario de firma no deberá contener el atributo no firmado content-reference.
			 * > La clave /Cert del diccionario de firma no deberá estar presente.
			 */
			boolean hasSignaturePolicyId = validatePAdESBaselineStructurally(pdfSignatureDictionaryValidationResult, pdfSignatureDictionary, pdfDocument, signedData, validationResult);

			/*
			 * Validación del Núcleo de Firma: Se comprobará que el primer firmante de la firma CAdES contenida en el diccionario de firma verifica la propia
			 * firma CAdES.
			 */
			validateSignatureCore(pdfSignatureDictionaryValidationResult, signerInfo, validationResult);

			/*
			 * Validación de la Información de Clave Pública: Se comprobará que el primer firmante de la firma CAdES contenida en el diccionario de firma incluye
			 * el atributo firmado signing-certificate o el atributo firmado signing-certificate-v2, y que dicho atributo identifica al certificado del firmante.
			 * Además, en el caso de que el atributo que incluya de los dos sea signing-certificate se comprobará que el algoritmo de firma utilizado ha sido SHA-1.
			 */
			validateKeyInfo(pdfSignatureDictionaryValidationResult, validationResult, signerInfo, signedData);

			// Si el primer firmante de la firma contenida en el
			// diccionario de firma tiene el atributo
			// signature-policy-id (incluye política de firma)
			if (hasSignaturePolicyId) {
			    /*
			     * Validación de la Política de Firma: Si el primer firmante de la firma CAdES contenida en el diccionario de firma incluye el atributo
			     * firmado signature-policy-identifier se comprobará si el OID de la política de firma definida en dicho atributo coincide con el OID
			     * de la política de firma definida para firmas PDF en el fichero policy.properties, en cuyo caso, se comprobará que los datos de la
			     * firma y del firmante concreto son válidos respecto a las propiedades definidas en dicho fichero.
			     */
			    validateSignaturePolicy(pdfSignatureDictionaryValidationResult, validationResult, signerInfo, pdfSignatureDictionary, idClient);
			}

			/*
			 * Validación del Instante de Firma: Se comprobará que el diccionario de firma incluye la clave /M y que dicho campo posee un formato
			 * correcto según [PDF_Reference], sección 3.8.3 (Dates), así como que la fecha contenida no sea futura respecto a la fecha de validación.
			 * La fecha de validación será la fecha de generación del sello de tiempo menos reciente contenido en los diccionarios de firma de tipo
			 * Document Time-stamp que incluyese el documento PDF. Si no se incluye ningún diccionario de firma de tipo Document Time-stamp la fecha
			 * de validación será la fecha actual.
			 */
			validatePAdESSigningTime(pdfSignatureDictionaryValidationResult, validationResult, validationDate, pdfSignatureDictionary, true);

			/*
			 * Validación del Certificado Firmante: Se comprobará el estado del certificado del primer firmante de la firma CAdES contenida en el diccionario
			 * de firma respecto a la fecha de validación utilizando el método de validación definido para el mismo, ya sea en el fichero integraFacade.properties
			 * (si la validación se realiza desde la fachada de firma), o bien en el fichero signer.properties (si la validación se realiza desde la interfaz Signer).
			 * La fecha de validación será la fecha de generación del sello de tiempo menos reciente contenido en un atributo no firmado signature-time-stamp del
			 * primer firmante de la firma CAdES contenida en el diccionario de firma. Si dicho atributo no se incluye, la fecha de validación será la fecha de
			 * generación del sello de tiempo menos reciente contenido en los diccionarios de firma de tipo Document Time-stamp que incluyese el documento PDF.
			 * Si no se incluye ningún diccionario de firma de tipo Document Time-stamp la fecha de validación será la fecha actual.
			 */
			validateSigningCertificate(pdfSignatureDictionaryValidationResult, validationResult, signerInfo, validationDate, idClient);

			/*
			 * Validación de los Atributos signature-time-stamp: Si el primer firmante de la firma CAdES contenida en el diccionario de firma posee atributos
			 * signature-time-stamp se comprobará que todos ellos poseen una estructura correcta y que los sellos de tiempo que contienen están bien formados.
			 * Respecto a cada sello de tiempo se definen las siguientes tareas de validación:
			 * 		> Validación de la Firma del Sello de Tiempo: Se comprobará que la firma del sello de tiempo es correcta.
			 * 		> Validación de la Integridad del Sello de Tiempo: Se comprobará que los datos sellados son correctos.
			 * 		> Validación del Certificado Firmante del Sello de Tiempo: Se comprobará el estado del certificado firmante del sello de tiempo respecto a la fecha de
			 * 		generación del siguiente sello de tiempo, utilizando el método de validación definido para los certificados firmantes, ya sea en el fichero
			 * 		integraFacade.properties (si la validación se realiza desde la fachada de firma), o bien en el fichero signer.properties (si la validación
			 * 		se realiza desde la interfaz Signer). Cuando se esté procesando el certificado firmante del sello de tiempo más reciente (y por lo tanto el último)
			 * 		se utilizará como fecha de validación la fecha actual. Además, se verificará que el certificado posee la extensión id-kp-timestamp.
			 */
			validateSignatureTimeStampAttributes(pdfSignatureDictionaryValidationResult, validationResult, signerInfo, listTimestampDictionaries, idClient);
		    }
		    // Si el diccionario de firma es PAdES-BES
		    else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_BES)) {
			/*
			 * Validación Estructural PDF: Contemplará las siguientes verificaciones:
			 * > La clave /Contents del diccionario de firma deberá estar presente y su contenido corresponderse con una firma CAdES.
			 * > La clave /ByteRange del diccionario de firma deberá estar presente y su contenido corresponderse con el resumen de la firma CAdES.
			 * > La clave /SubFilter del diccionario de firma deberá estar presente y su contenido corresponderse con el valor “ETSI.CAdES.detached”.
			 * > El primer firmante de la firma CAdES que contiene el diccionario de firma deberá tener el atributo firmado content-type con valor "id-data".
			 * > El primer firmante de la firma CAdES que contiene el diccionario de firma deberá no tener el atributo no firmado counter-signature.
			 * > El primer firmante de la firma CAdES que contiene el diccionario de firma deberá no tener el atributo no firmado content-reference.
			 * > El primer firmante de la firma CAdES que contiene el diccionario de firma deberá no tener el atributo firmado content-identifier.
			 * > El primer firmante de la firma CAdES que contiene el diccionario de firma deberá no tener el atributo firmado commitment-type-indication.
			 * > El primer firmante de la firma CAdES que contiene el diccionario de firma deberá no tener el atributo firmado signer-location.
			 * > El primer firmante de la firma CAdES que contiene el diccionario de firma deberá no tener el atributo firmado signing-time.
			 * > El primer firmante de la firma CAdES que contiene el diccionario de firma deberá no tener el atributo firmado content-hints.
			 * > La clave /Cert del diccionario de firma no deberá estar presente.
			 */
			validatePAdESEnhancedStructurally(pdfSignatureDictionaryValidationResult, pdfSignatureDictionary, pdfDocument, signedData, validationResult, false);

			/*
			 * Validación del Núcleo de Firma: Se comprobará que el primer firmante de la firma CAdES contenida en el diccionario de firma verifica la propia
			 * firma CAdES.
			 */
			validateSignatureCore(pdfSignatureDictionaryValidationResult, signerInfo, validationResult);

			/*
			 * Validación de la Información de Clave Pública: Se comprobará que el primer firmante de la firma CAdES contenida en el diccionario de firma incluye
			 * el atributo firmado signing-certificate o el atributo firmado signing-certificate-v2, y que dicho atributo identifica al certificado del firmante.
			 * Además, en el caso de que el atributo que incluya de los dos sea signing-certificate se comprobará que el algoritmo de firma utilizado ha sido SHA-1.
			 */
			validateKeyInfo(pdfSignatureDictionaryValidationResult, validationResult, signerInfo, signedData);

			/*
			 * Validación del Instante de Firma: Si el diccionario de firma incluye la clave /M validaremos que dicho campo posee un formato correcto según
			 * [PDF_Reference], sección 3.8.3 (Dates), así como que la fecha contenida no sea futura respecto a la fecha de validación. La fecha de validación
			 * será la fecha de generación del sello de tiempo menos reciente contenido en un atributo no firmado signature-time-stamp del primer firmante de
			 * la firma CAdES contenida en el diccionario de firma. Si dicho atributo no se incluye, la fecha de validación será la fecha de generación del
			 * sello de tiempo menos reciente contenido en los diccionarios de firma de tipo Document Time-stamp que incluyese el documento PDF. Si no se
			 * incluye ningún diccionario de firma de tipo Document Time-stamp la fecha de validación será la fecha actual.
			 */
			validatePAdESSigningTime(pdfSignatureDictionaryValidationResult, validationResult, validationDate, pdfSignatureDictionary, false);

			/*
			 * Validación del Certificado Firmante: Se comprobará el estado del certificado del primer firmante de la firma CAdES contenida en el diccionario
			 * de firma respecto a la fecha de validación utilizando el método de validación definido para el mismo, ya sea en el fichero integraFacade.properties
			 * (si la validación se realiza desde la fachada de firma), o bien en el fichero signer.properties (si la validación se realiza desde la interfaz Signer).
			 * La fecha de validación será la fecha de generación del sello de tiempo menos reciente contenido en un atributo no firmado signature-time-stamp del
			 * primer firmante de la firma CAdES contenida en el diccionario de firma. Si dicho atributo no se incluye, la fecha de validación será la fecha de
			 * generación del sello de tiempo menos reciente contenido en los diccionarios de firma de tipo Document Time-stamp que incluyese el documento PDF.
			 * Si no se incluye ningún diccionario de firma de tipo Document Time-stamp la fecha de validación será la fecha actual.
			 */
			validateSigningCertificate(pdfSignatureDictionaryValidationResult, validationResult, signerInfo, validationDate, idClient);

			/*
			 * Validación de los Atributos signature-time-stamp: Si el primer firmante de la firma CAdES contenida en el diccionario de firma posee atributos
			 * signature-time-stamp se comprobará que todos ellos poseen una estructura correcta y que los sellos de tiempo que contienen están bien formados.
			 * Respecto a cada sello de tiempo se definen las siguientes tareas de validación:
			 * 		> Validación de la Firma del Sello de Tiempo: Se comprobará que la firma del sello de tiempo es correcta.
			 * 		> Validación de la Integridad del Sello de Tiempo: Se comprobará que los datos sellados son correctos.
			 * 		> Validación del Certificado Firmante del Sello de Tiempo: Se comprobará el estado del certificado firmante del sello de tiempo respecto a la fecha de
			 * 		generación del siguiente sello de tiempo, utilizando el método de validación definido para los certificados firmantes, ya sea en el fichero
			 * 		integraFacade.properties (si la validación se realiza desde la fachada de firma), o bien en el fichero signer.properties (si la validación
			 * 		se realiza desde la interfaz Signer). Cuando se esté procesando el certificado firmante del sello de tiempo más reciente (y por lo tanto el último)
			 * 		se utilizará como fecha de validación la fecha actual. Además, se verificará que el certificado posee la extensión id-kp-timestamp.
			 */
			validateSignatureTimeStampAttributes(pdfSignatureDictionaryValidationResult, validationResult, signerInfo, listTimestampDictionaries, idClient);
		    }
		    // Si el diccionario de firma es PAdES-EPES
		    else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_EPES)) {
			/*
			 * Validación Estructural PAdES-EPES: Contemplará las siguientes verificaciones:
			 * > La clave /Contents del diccionario de firma deberá estar presente y su contenido corresponderse con una firma CAdES.
			 * > La clave /ByteRange del diccionario de firma deberá estar presente y su valor corresponderse con el resumen de la firma CAdES.
			 * > La clave /SubFilter del diccionario de firma deberá estar presente y su valor corresponderse con “ETSI.CAdES.detached”.
			 * > El primer firmante de la firma CAdES que contiene el diccionario de firma deberá tener el atributo firmado content-type con valor "id-data".
			 * > El primer firmante de la firma CAdES contenida en el diccionario de firma no deberá contener el atributo no firmado counter-signature.
			 * > El primer firmante de la firma CAdES contenida en el diccionario de firma no deberá contener el atributo no firmado content-reference.
			 * > El primer firmante de la firma CAdES contenida en el diccionario de firma no deberá contener el atributo firmado content-identifier.
			 * > La clave /Reason del diccionario de firma no deberá estar presente.
			 * > La clave /Cert del diccionario de firma no deberá estar presente.
			 * > El primer firmante de la firma CAdES contenida en el diccionario de firma no deberá contener el atributo firmado signer-location.
			 * > El primer firmante de la firma CAdES contenida en el diccionario de firma no deberá contener el atributo firmado signing-time.
			 * > El primer firmante de la firma CAdES contenida en el diccionario de firma no deberá contener el atributo firmado content-hints.
			 */
			validatePAdESEnhancedStructurally(pdfSignatureDictionaryValidationResult, pdfSignatureDictionary, pdfDocument, signedData, validationResult, true);

			/*
			 * Validación del Núcleo de Firma: Se comprobará que el primer firmante de la firma CAdES contenida en el diccionario de firma verifica la propia
			 * firma CAdES.
			 */
			validateSignatureCore(pdfSignatureDictionaryValidationResult, signerInfo, validationResult);

			/*
			 * Validación de la Información de Clave Pública: Se comprobará que el primer firmante de la firma CAdES contenida en el diccionario de firma incluye
			 * el atributo firmado signing-certificate o el atributo firmado signing-certificate-v2, y que dicho atributo identifica al certificado del firmante.
			 * Además, en el caso de que el atributo que incluya de los dos sea signing-certificate se comprobará que el algoritmo de firma utilizado ha sido SHA-1.
			 */
			validateKeyInfo(pdfSignatureDictionaryValidationResult, validationResult, signerInfo, signedData);

			/*
			 * Validación del Instante de Firma: Si el diccionario de firma incluye la clave /M validaremos que dicho campo posee un formato correcto según
			 * [PDF_Reference], sección 3.8.3 (Dates), así como que la fecha contenida no sea futura respecto a la fecha de validación. La fecha de validación
			 * será la fecha de generación del sello de tiempo menos reciente contenido en un atributo no firmado signature-time-stamp del primer firmante de
			 * la firma CAdES contenida en el diccionario de firma. Si dicho atributo no se incluye, la fecha de validación será la fecha de generación del
			 * sello de tiempo menos reciente contenido en los diccionarios de firma de tipo Document Time-stamp que incluyese el documento PDF. Si no se
			 * incluye ningún diccionario de firma de tipo Document Time-stamp la fecha de validación será la fecha actual.
			 */
			validatePAdESSigningTime(pdfSignatureDictionaryValidationResult, validationResult, validationDate, pdfSignatureDictionary, false);

			/*
			 * Validación de la Política de Firma: Se comprobará si el OID de la política de firma definida en el atributo firmado signature-policy-identifier
			 * para el primer firmante de la firma CAdES contenida en el diccionario de firma coincide con el OID de la política de firma definida para firmas
			 * PDF en el fichero policy.properties, en cuyo caso, se comprobará que los datos de la firma y del firmante concreto son válidos respecto a las
			 * propiedades definidas en dicho fichero.
			 */
			validateSignaturePolicy(pdfSignatureDictionaryValidationResult, validationResult, signerInfo, pdfSignatureDictionary, idClient);

			/*
			 * Validación del Certificado Firmante: Se comprobará el estado del certificado del primer firmante de la firma CAdES contenida en el diccionario
			 * de firma respecto a la fecha de validación utilizando el método de validación definido para el mismo, ya sea en el fichero integraFacade.properties
			 * (si la validación se realiza desde la fachada de firma), o bien en el fichero signer.properties (si la validación se realiza desde la interfaz Signer).
			 * La fecha de validación será la fecha de generación del sello de tiempo menos reciente contenido en un atributo no firmado signature-time-stamp del
			 * primer firmante de la firma CAdES contenida en el diccionario de firma. Si dicho atributo no se incluye, la fecha de validación será la fecha de
			 * generación del sello de tiempo menos reciente contenido en los diccionarios de firma de tipo Document Time-stamp que incluyese el documento PDF.
			 * Si no se incluye ningún diccionario de firma de tipo Document Time-stamp la fecha de validación será la fecha actual.
			 */
			validateSigningCertificate(pdfSignatureDictionaryValidationResult, validationResult, signerInfo, validationDate, idClient);

			/*
			 * Validación de los Atributos signature-time-stamp: Si el primer firmante de la firma CAdES contenida en el diccionario de firma posee atributos
			 * signature-time-stamp se comprobará que todos ellos poseen una estructura correcta y que los sellos de tiempo que contienen están bien formados.
			 * Respecto a cada sello de tiempo se definen las siguientes tareas de validación:
			 * 		> Validación de la Firma del Sello de Tiempo: Se comprobará que la firma del sello de tiempo es correcta.
			 * 		> Validación de la Integridad del Sello de Tiempo: Se comprobará que los datos sellados son correctos.
			 * 		> Validación del Certificado Firmante del Sello de Tiempo: Se comprobará el estado del certificado firmante del sello de tiempo respecto a la fecha de
			 * 		generación del siguiente sello de tiempo, utilizando el método de validación definido para los certificados firmantes, ya sea en el fichero
			 * 		integraFacade.properties (si la validación se realiza desde la fachada de firma), o bien en el fichero signer.properties (si la validación
			 * 		se realiza desde la interfaz Signer). Cuando se esté procesando el certificado firmante del sello de tiempo más reciente (y por lo tanto el último)
			 * 		se utilizará como fecha de validación la fecha actual. Además, se verificará que el certificado posee la extensión id-kp-timestamp.
			 */
			validateSignatureTimeStampAttributes(pdfSignatureDictionaryValidationResult, validationResult, signerInfo, listTimestampDictionaries, idClient);
		    }
		}
	    } catch (Exception e) {
		// Establecemos en la información asociada a la validación
		// del diccionario de firma que éste no es correcto
		pdfSignatureDictionaryValidationResult.setCorrect(false);

		// Establecemos en la información asociada a la validación
		// de la firma que ésta no es correcta
		validationResult.setCorrect(false);
	    }
	}
    }

    /**
     * Method that validates a signature dictionary with PDF form.
     * @param pdfSignatureDictionaryValidationResult Parameter that represents the information about the validation of the signature dictionary to update
     * with the result of the validation.
     * @param pdfSignatureDictionary Parameter that contains information about the signature dictionary to validate.
     * @param af Parameter that allows to access to the fields of PDF document.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     */
    private void validatePDFSignatureDictionary(PDFSignatureDictionaryValidationResult pdfSignatureDictionaryValidationResult, PDFSignatureDictionary pdfSignatureDictionary, AcroFields af, PDFValidationResult validationResult) {
	// Si el formato de firma es PDF no realizamos ninguna validación sobre
	// el documento
	// PDF ni sobre el firmante
	String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.PBS_LOG026, new Object[ ] { pdfSignatureDictionary.getName() });

	// Establecemos en la información de validación del diccionario de firma
	// que el diccionario de firma no es correcto
	PdfPKCS7 pk = af.verifySignature(pdfSignatureDictionary.getName());
	pdfSignatureDictionaryValidationResult.setCorrect(false);
	pdfSignatureDictionaryValidationResult.setErrorMsg(errorMsg);
	pdfSignatureDictionaryValidationResult.setSigningCertificate(pk.getSigningCertificate());

	// Establecemos a nivel general que la validación no ha sido correcta
	validationResult.setCorrect(false);
	if (validationResult.getErrorMsg() == null) {
	    validationResult.setErrorMsg(errorMsg);
	}
    }

    /**
     * Method that obtains information about the first signer of a CAdES/CMS signature contained inside of a PAdES signature.
     * @param signedData Parameter that represents the signature message of the CAdES signature contained inside of the signature dictionary.
     * @param pdfSignatureDictionaryValidationResult Parameter that represents the information about the validation of the signature dictionary to update
     * with the result of the validation.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @param pdfSignatureDictionary Parameter that contains information about the signature dictionary to validate.
     * @return an object that contains information about the signer.
     * @throws SigningException If the method fails.
     */
    private CAdESSignerInfo getSignerFromSignature(CMSSignedData signedData, PDFSignatureDictionaryValidationResult pdfSignatureDictionaryValidationResult, PDFValidationResult validationResult, PDFSignatureDictionary pdfSignatureDictionary) throws SigningException {
	// Obtenemos la lista de firmantes y contra-firmantes contenidos en
	// la firma
	List<CAdESSignerInfo> listSignersFound = UtilsSignatureOp.getCAdESListSigners(signedData);

	// Accedemos al primer firmante
	if (!listSignersFound.isEmpty()) {
	    CAdESSignerInfo signerInfo = listSignersFound.get(0);

	    // Verificamos que no se haya producido ningún error durante el
	    // proceso
	    if (signerInfo.getErrorMsg() != null) {
		// Establecemos, a nivel general, el error asociado a la
		// validación
		// del documento PDF como el error producido, si es que no se
		// indicó
		// previamente
		if (validationResult.getErrorMsg() == null) {
		    validationResult.setErrorMsg(signerInfo.getErrorMsg());
		}

		// Establecemos, a nivel del diccionario de firma, el error
		// asociado a la
		// validación como el error producido
		pdfSignatureDictionaryValidationResult.setErrorMsg(signerInfo.getErrorMsg());

		throw new SigningException(signerInfo.getErrorMsg());
	    }
	    return signerInfo;
	} else {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.PBS_LOG027, new Object[ ] { pdfSignatureDictionary.getName() });
	    LOGGER.error(errorMsg);

	    // Establecemos, a nivel general, el error asociado a la validación
	    // del documento PDF como el error producido, si es que no se indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(errorMsg);
	    }

	    // Establecemos, a nivel del diccionario de firma, el error asociado
	    // a la
	    // validación como el error producido
	    pdfSignatureDictionaryValidationResult.setErrorMsg(errorMsg);

	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that obtains the date to use for validating a signature dictionary.
     * <ul>
     * <li>If the first signed of the signature contained inside of the signature dictionary includes at least one <code>signature-time-stamp</code> attribute, the validation date
     * will be the generation date of the first time-stamp contained inside of the <code>signature-time-stamp</code> attribute.</li>
     * <li>If the first signed of the signature contained inside of the signature dictionary doesn't include any <code>signature-time-stamp</code> attribute, the validation date
     * will be the generation date of the time-stamp contained inside of the first Document Time-stamp dictionary added after than de signature dictionary.</li>
     * <li>If the first signed of the signature contained inside of the signature dictionary doesn't include any <code>signature-time-stamp</code> attribute and the PDF document
     * doesn't contain any Document Time-stamp dictionary added after than the signature dictionary, the validation date will be the current date.</li>
     * </ul>
     * @param signerInfo Parameter that represents the information about the first signer of the signature.
     * @param signatureDictionaryRevision Parameter that represents the revision number of the signature dictionary.
     * @param listTimestampDictionaries Parameter that represents the list with the Document Time-stamp dictionaries contained inside of the PDF document.
     * @return the validation date.
     */
    public static Date getValidationDateForSignatureDictionary(CAdESSignerInfo signerInfo, Integer signatureDictionaryRevision, List<PDFDocumentTimestampDictionary> listTimestampDictionaries) {
	// Por defecto definimos la fecha de validación como la fecha actual
	Date validationDate = Calendar.getInstance().getTime();

	// Si el firmante incluye algún sello de tiempo contenido en atributo
	// signature-time-stamp
	List<TimeStampToken> listTimeStamps = signerInfo.getListTimeStamps();
	if (listTimeStamps != null && listTimeStamps.size() > 0) {
	    // Establecemos como fecha de validación la fecha de generación del
	    // sello de
	    // tiempo menos reciente, esto es, el primero de la lista
	    validationDate = listTimeStamps.get(0).getTimeStampInfo().getGenTime();
	}
	// Si el firmante no incluye ningún atributo signature-time-stamp
	else {
	    // Recorremos la lista de diccionarios de sello de tiempo
	    int i = 0;
	    boolean found = false;
	    while (i < listTimestampDictionaries.size() && !found) {
		// Accedemos al diccionario de sello de tiempo
		PDFDocumentTimestampDictionary documentTimestamp = listTimestampDictionaries.get(i);

		// Si su número de revisión es posterior al del diccionario
		// de
		// firma
		if (signatureDictionaryRevision < documentTimestamp.getRevision()) {
		    // Accedemos a la fecha de generación del sello de
		    // tiempo y
		    // la asignamos como fecha de validación para la firma
		    // del
		    // diccionario de firma
		    validationDate = documentTimestamp.getTimestamp().getTimeStampInfo().getGenTime();
		    found = true;
		}
		i++;
	    }

	}
	return validationDate;
    }

    /**
     * Method that validates structurally a signature dictionary by PAdES-Basic signature form.
     * @param pdfSignatureDictionaryValidationResult Parameter that represents the information about the validation of the signature dictionary to update
     * with the result of the validation.
     * @param pdfSignatureDictionary Parameter that contains information about the signature dictionary to validate.
     * @param pdfDocument Parameter that represents the signed PDF document.
     * @param signedData arameter that represents the signature message of the CMS signature contained inside of the signature dictionary.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @throws SigningException If the validation fails.
     */
    private void validatePAdESBasicStructurally(PDFSignatureDictionaryValidationResult pdfSignatureDictionaryValidationResult, PDFSignatureDictionary pdfSignatureDictionary, byte[ ] pdfDocument, CMSSignedData signedData, PDFValidationResult validationResult) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	ValidationInfo validationInfo = new ValidationInfo();
	validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_PDF_STRUCTURALLY_VALIDATION);

	// Añadimos a la lista de validaciones del diccionario de firma la
	// información asociada a esta validación
	pdfSignatureDictionaryValidationResult.getListValidations().add(validationInfo);
	try {
	    // Validamos estructuralmente el diccionario de firma en base a
	    // PAdES-Basic
	    UtilsSignatureOp.validatePAdESBasicStructurally(pdfSignatureDictionary, pdfDocument, signedData);

	    // Indicamos que la validación ha sido correcta
	    validationInfo.setSucess(true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la
	    // validación
	    // del diccionario de firma como el error producido, si es que no se
	    // indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel del diccionario de firma, el error asociado
	    // a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (pdfSignatureDictionaryValidationResult.getErrorMsg() == null) {
		pdfSignatureDictionaryValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a
	    // cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that checks if the first signer of a signature associated to a PAdES signature verifies the signature.
     * @param pdfSignatureDictionaryValidationResult Parameter that represents the information about the validation of the signature dictionary to update
     * with the result of the validation.
     * @param signerInfo Parameter that represents the information about the first signer of the CMS signature.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @throws SigningException If the validation fails.
     */
    private void validateSignatureCore(PDFSignatureDictionaryValidationResult pdfSignatureDictionaryValidationResult, CAdESSignerInfo signerInfo, PDFValidationResult validationResult) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	ValidationInfo validationInfo = new ValidationInfo();
	validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_SIGNATURE_CORE_VALIDATION);

	// Añadimos a la lista de validaciones del diccionario de firma la
	// información asociada a esta validación
	pdfSignatureDictionaryValidationResult.getListValidations().add(validationInfo);
	try {
	    // Comprobamos que el firmante verifica la firma
	    UtilsSignatureOp.validateCAdESSignatureCore(signerInfo.getSignerInformation(), signerInfo.getSigningCertificate(),true);

	    // Indicamos que la validación ha sido correcta
	    validationInfo.setSucess(true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la
	    // validación
	    // del diccionario de firma como el error producido, si es que no se
	    // indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel del diccionario de firma, el error asociado
	    // a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (pdfSignatureDictionaryValidationResult.getErrorMsg() == null) {
		pdfSignatureDictionaryValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a
	    // cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that checks if the value of the signed attribute <code>SerialNumber</code> of a signature matches to the serial number of the signing certificate for the first
     * signer contained inside of a CMS signature associated to a PAdES-Basic signature.
     * @param pdfSignatureDictionaryValidationResult Parameter that represents the information about the validation of the signature dictionary to update
     * with the result of the validation.
     * @param signerInfo Parameter that represents the information about the first signer of the CMS signature.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @throws SigningException If the validation fails.
     */
    private void validateCMSKeyInfo(PDFSignatureDictionaryValidationResult pdfSignatureDictionaryValidationResult, CAdESSignerInfo signerInfo, PDFValidationResult validationResult) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	ValidationInfo validationInfo = new ValidationInfo();
	validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_PUBLIC_KEY_INFO_VALIDATION);

	// Añadimos a la lista de validaciones del diccionario de firma la
	// información asociada a esta validación
	pdfSignatureDictionaryValidationResult.getListValidations().add(validationInfo);
	try {
	    // Comprobamos que el atributo firmado serial-number coincide con el
	    // número de serie del certificado firmante
	    UtilsSignatureOp.validateCMSPublicKeyInfo(signerInfo.getSignerInformation(), pdfSignatureDictionaryValidationResult.getSigningCertificate());

	    // Indicamos que la validación ha sido correcta
	    validationInfo.setSucess(true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la
	    // validación
	    // del diccionario de firma como el error producido, si es que no se
	    // indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel del diccionario de firma, el error asociado
	    // a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (pdfSignatureDictionaryValidationResult.getErrorMsg() == null) {
		pdfSignatureDictionaryValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a
	    // cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates the signing time associated to a PAdES-Basic signature.
     * @param pdfSignatureDictionaryValidationResult Parameter that represents the information about the validation of the signature dictionary to update
     * with the result of the validation.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @param signerInfo Parameter that represents the information about the first signer of the CAdES signature.
     * @param validationDate Parameter that represents the validation date.
     * @param pdfSignatureDictionary Parameter that contains information about the signature dictionary to validate.
     * @throws SigningException If the validation fails.
     */
    private void validatePAdESBasicSigningTime(PDFSignatureDictionaryValidationResult pdfSignatureDictionaryValidationResult, PDFValidationResult validationResult, CAdESSignerInfo signerInfo, Date validationDate, PDFSignatureDictionary pdfSignatureDictionary) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	ValidationInfo validationInfo = new ValidationInfo();
	validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_SIGNING_TIME_VALIDATION);

	// Añadimos a la lista de validaciones del diccionario de firma la
	// información asociada a esta validación
	pdfSignatureDictionaryValidationResult.getListValidations().add(validationInfo);
	try {
	    /*
	     * Validación del Instante de Firma: Si el primer firmante de la firma CMS contenida en el diccionario de firma incluye el atributo firmado signing-time se
	     * comprobará que dicho atributo está bien formado y que la fecha contenida en el mismo es anterior a la fecha de validación. Igualmente,
	     * si el diccionario de firma incluye la clave /M validaremos que dicho campo posee un formato correcto según [PDF_Reference],
	     * sección 3.8.3 (Dates), así como que la fecha contenida no sea futura respecto a la fecha de validación. La fecha de validación en ambos casos
	     * será la fecha de generación del sello de tiempo menos reciente contenido en un atributo no firmado signature-time-stamp del primer firmante de
	     * la firma CMS contenida en el diccionario de firma. Si dicho atributo no se incluye, la fecha de validación será la fecha de generación del
	     * sello de tiempo menos reciente contenido en los diccionarios de firma de tipo Document Time-stamp que incluyese el documento PDF. Si no se incluye
	     * ningún diccionario de firma de tipo Document Time-stamp la fecha de validación será la fecha actual.
	     */
	    UtilsSignatureOp.validatePAdESBasicSigningTime(signerInfo.getSignerInformation(), validationDate, pdfSignatureDictionaryValidationResult.getSigningCertificate(), pdfSignatureDictionary);

	    // Indicamos que la validación ha sido correcta
	    validationInfo.setSucess(true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la
	    // validación
	    // del diccionario de firma como el error producido, si es que no se
	    // indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel del diccionario de firma, el error asociado
	    // a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (pdfSignatureDictionaryValidationResult.getErrorMsg() == null) {
		pdfSignatureDictionaryValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a
	    // cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates the signing certificate of the first signer of a CAdES signature contained inside of a PAdES signature.
     * @param pdfSignatureDictionaryValidationResult Parameter that represents the information about the validation of the signature dictionary to update
     * with the result of the validation.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @param signerInfo Parameter that represents the information about the first signer of the CAdES signature.
     * @param validationDate Parameter that represents the validation date.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the validation fails.
     */
    private void validateSigningCertificate(PDFSignatureDictionaryValidationResult pdfSignatureDictionaryValidationResult, PDFValidationResult validationResult, CAdESSignerInfo signerInfo, Date validationDate, String idClient) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	ValidationInfo validationInfo = new ValidationInfo();
	validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_SIGNING_CERTIFICATE_VALIDATION);

	// Añadimos a la lista de validaciones del diccionario de firma la
	// información asociada a esta validación
	pdfSignatureDictionaryValidationResult.getListValidations().add(validationInfo);
	try {
	    // Validamos el certificado del firmante
	    UtilsSignatureOp.validateCertificate(signerInfo.getSigningCertificate(), validationDate, false, idClient, false);

	    // Indicamos que la validación ha sido correcta
	    validationInfo.setSucess(true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la
	    // validación
	    // del diccionario de firma como el error producido, si es que no se
	    // indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel del diccionario de firma, el error asociado
	    // a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (pdfSignatureDictionaryValidationResult.getErrorMsg() == null) {
		pdfSignatureDictionaryValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a
	    // cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates the <code>signature-time-stamp</code> attributes associated to the first signer of a CAdES signature contained inside of a PAdES signature.
     * @param pdfSignatureDictionaryValidationResult Parameter that represents the information about the validation of the signature dictionary to update
     * with the result of the validation.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @param signerInfo Parameter that represents the information about the first signer of the CAdES signature.
     * @param listTimestampDictionaries Parameter that represents a list with the Document Time-stamp dictionaries contained inside of the signed PDF document.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the validation fails.
     */
    private void validateSignatureTimeStampAttributes(PDFSignatureDictionaryValidationResult pdfSignatureDictionaryValidationResult, PDFValidationResult validationResult, CAdESSignerInfo signerInfo, List<PDFDocumentTimestampDictionary> listTimestampDictionaries, String idClient) throws SigningException {
	// Si el firmante posee algún atributo signature-time-stamp
	if (signerInfo.getListTimeStamps() != null && !signerInfo.getListTimeStamps().isEmpty()) {
	    // Instanciamos el objeto que ofrece información sobre la validación
	    // llevada a cabo
	    ValidationInfo validationInfo = new ValidationInfo();
	    validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_SIGNATURE_TIME_STAMP_ATTRIBUTES_VALIDATION);
	    
	    pdfSignatureDictionaryValidationResult.setListTimestampsValidations(new ArrayList<TimestampValidationResult>());

	    // Añadimos a la lista de validaciones del diccionario de firma la
	    // información asociada a esta validación
	    pdfSignatureDictionaryValidationResult.getListValidations().add(validationInfo);

	    // Por defecto establecemos que la validación ha sido correcta
	    validationInfo.setSucess(true);

	    try {

		// Obtenemos una lista con los sellos de tiempo contenidos
		// en los
		// atributos signature-time-stamp ordenados ascendentemente
		// por fecha
		// de generación
		List<TimeStampToken> listTimestampsIntoSignatureTimeStampAtts = signerInfo.getListTimeStamps();

		// Definimos la fecha actual como fecha de validación para
		// el certificado firmante del sello de tiempo más reciente
		Date validationDateLatestSignatureTimeStamp = Calendar.getInstance().getTime();

		// Si el documento PDF incluye diccionarios de sello de tiempo,
		// la fecha de validación para el sello de tiempo contenido en
		// el atributo signature-time-stamp
		// más reciente será la fecha de generación del sello de tiempo
		// contenido en el primer diccionario de sello de tiempo
		if (!listTimestampDictionaries.isEmpty()) {
		    validationDateLatestSignatureTimeStamp = listTimestampDictionaries.get(0).getTimestamp().getTimeStampInfo().getGenTime();
		}

		// Recorremos la lista con los sellos de tiempo contenidos
		// en los
		// atributos signature-time-stamp ordenados ascendentemente
		// por fecha
		// de generación
		for (int i = 0; i < listTimestampsIntoSignatureTimeStampAtts.size(); i++) {
		    // Definimos una variable para establecer la fecha de
		    // validación del
		    // certificado firmante del sello de tiempo. Por
		    // defecto, dicha fecha será la fecha actual
		    Date validationDate = validationDateLatestSignatureTimeStamp;

		    // Si no estamos procesando el sello de tiempo más
		    // reciente
		    if (i < listTimestampsIntoSignatureTimeStampAtts.size() - 1) {
			// Establecemos como fecha de validación la fecha de
			// generación
			// del siguiente sello de tiempo
			validationDate = listTimestampsIntoSignatureTimeStampAtts.get(i + 1).getTimeStampInfo().getGenTime();
		    }

		    // Accedemos al sello de tiempo
		    TimeStampToken currentTimestamp = listTimestampsIntoSignatureTimeStampAtts.get(i);

		    // Instanciamos el objeto donde ubicar la información de
		    // validación asociada al sello de tiempo y añadimos esa
		    // información al objeto que contiene la información
		    // de validación del diccionario de firma
		    TimestampValidationResult timestampValidationResult = new TimestampValidationResult();
		    pdfSignatureDictionaryValidationResult.getListTimestampsValidations().add(timestampValidationResult);

		    // Por defecto establecemos que el sello de tiempo es
		    // correcto
		    timestampValidationResult.setCorrect(true);

		    // Instanciamos en el objeto donde ubicar la información
		    // de validación asociada al sello de tiempo una lista
		    // donde ubicar la información asociada a las
		    // validaciones
		    // levadas a cabo sobre el sello de tiempo
		    timestampValidationResult.setListValidations(new ArrayList<TimeStampValidationInfo>());

		    // Establecemos en la información de validación asociada
		    // al sello de tiempo que éste es de tipo ASN.1
		    timestampValidationResult.setXML(false);

		    // Validamos el sello de tiempo
		    validateTimeStamp(currentTimestamp, pdfSignatureDictionaryValidationResult, timestampValidationResult, validationResult, validationInfo, signerInfo, validationDate, idClient);
		}
	    } catch (Exception e) {
		// Establecemos, a nivel general, el error asociado a la
		// validación
		// de la
		// firma CAdES como el error producido, si es que no se
		// indicó
		// previamente
		if (validationResult.getErrorMsg() == null) {
		    validationResult.setErrorMsg(e.getMessage());
		}

		// Establecemos, a nivel de diccionario de firma, el error
		// asociado a la
		// validación como el error producido, si es que no se
		// indicó
		// previamente
		if (pdfSignatureDictionaryValidationResult.getErrorMsg() == null) {
		    pdfSignatureDictionaryValidationResult.setErrorMsg(e.getMessage());
		}

		// Indicamos en la información sobre la validación llevada a
		// cabo
		// que no ha sido correcta
		validationInfo.setSucess(false);
		validationInfo.setErrorMsg(e.getMessage());

		throw new SigningException(e);
	    }
	}
    }

    /**
     * Method that validates a time-stamp contained inside of the <code>signature-time-stamp</code> attribute associated to the first signer of a CAdES signature contained inside
     * of a PAdES signature.
     * @param tst Parameter that represents the time-stamp to validate.
     * @param pdfSignatureDictionaryValidationResult Parameter that represents the information about the validation of the signature dictionary to update
     * with the result of the validation.
     * @param timestampValidationResult Parameter that represents the information to update with the result of the validation of the time-stamp.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @param validationInfo Parameter that represents the information about the result of the valdation of the <code>signature-time-stamp</code> attributes associated to
     * the first signer of a CAdES signature contained inside of a PAdES signature.
     * @param signerInfo Parameter that represents the information about the first signer of the CAdES signature.
     * @param validationDate Parameter that represents the validation date.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the validation fails.
     */
    private void validateTimeStamp(TimeStampToken tst, PDFSignatureDictionaryValidationResult pdfSignatureDictionaryValidationResult, TimestampValidationResult timestampValidationResult, PDFValidationResult validationResult, ValidationInfo validationInfo, CAdESSignerInfo signerInfo, Date validationDate, String idClient) throws SigningException {
	try {
	    // Obtenemos el certificado firmante del sello de
	    // tiempo
	    X509Certificate timestampCertificate = UtilsTimestampPdfBc.getSigningCertificate(tst);

	    // Añadimos a la información de validación asociada
	    // al sello de tiempo los datos del certificado
	    // firmante del sello de tiempo
	    timestampValidationResult.setSigningCertificate(timestampCertificate);

	    // Validamos la firma del sello de tiempo
	    validateTimestampSignature(timestampValidationResult, tst);

	    // Validamos los datos firmados por el sello de
	    // tiempo
	    validateTimeStampStampedData(timestampValidationResult, tst, signerInfo);

	    // Validamos el certificado firmante del sello de
	    // tiempo
	    validateTimeStampCertificate(timestampValidationResult, timestampCertificate, validationDate, idClient);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado
	    // a la
	    // validación del documento PDF como el error producido, si es que
	    // no
	    // se indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel del diccionario de firma, el error
	    // asociado a la
	    // validación como el error producido, si es que no
	    // se indicó
	    // previamente
	    if (pdfSignatureDictionaryValidationResult.getErrorMsg() == null) {
		pdfSignatureDictionaryValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación
	    // llevada a
	    // cabo sobre los atributos signature-time-stamp
	    // que no ha sido correcta, si es que no se indicó
	    // previamente
	    validationInfo.setSucess(false);
	    if (validationInfo.getErrorMsg() == null) {
		validationInfo.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación
	    // llevada a
	    // cabo en el sello de tiempo
	    // que no ha sido correcta
	    timestampValidationResult.setCorrect(false);

	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates the signature of a time-stamp contained inside of a <code>signature-time-stamp</code> attribute associated to the first signer of a CAdES
     * signature contained inside of a PAdES signature.
     * @param timestampValidationResult Parameter that represents the information to update with the result of the validation of the time-stamp.
     * @param tst Parameter that represents the time-stamp to validate.
     * @throws SigningException If the validation fails.
     */
    private void validateTimestampSignature(TimestampValidationResult timestampValidationResult, TimeStampToken tst) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	TimeStampValidationInfo timestampValidationInto = new TimeStampValidationInfo();
	timestampValidationInto.setIdValidationTask(ITimestampValidationTaskID.ID_TIMESTAMP_SIGNATURE_VALIDATION);

	// Añadimos a la lista de validaciones del sello de tiempo la
	// información asociada a esta validación
	timestampValidationResult.getListValidations().add(timestampValidationInto);

	try {
	    // Validamos la firma del sello de tiempo
	    UtilsTimestampPdfBc.validateASN1Timestamp(tst);

	    // Indicamos que la validación ha sido correcta
	    timestampValidationInto.setSucess(true);
	} catch (Exception e) {
	    // Indicamos en la información sobre la validación llevada a cabo
	    // que no ha sido correcta
	    timestampValidationInto.setSucess(false);
	    timestampValidationInto.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that checks if the value of the messageImprint field within time-stamp token is a hash of the value indicated.
     * @param timestampValidationResult Parameter that represents the information to update with the result of the validation of the time-stamp.
     * @param tst Parameter that represents the time-stamp to validate.
     * @param signerInfo Parameter that represents the information about the first signer of the CAdES signature.
     * @throws SigningException If the validation fails.
     */
    private void validateTimeStampStampedData(TimestampValidationResult timestampValidationResult, TimeStampToken tst, CAdESSignerInfo signerInfo) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	TimeStampValidationInfo timestampValidationInto = new TimeStampValidationInfo();
	timestampValidationInto.setIdValidationTask(ITimestampValidationTaskID.ID_STAMPED_DATA_VALIDATION);

	// Añadimos a la lista de validaciones del sello de tiempo la
	// información asociada a esta validación
	timestampValidationResult.getListValidations().add(timestampValidationInto);
	try {
	    // Validamos los datos firmados por el sello de tiempo
	    UtilsTimestampPdfBc.validateTimestampMessageImprint(tst, signerInfo.getSignerInformation().getSignature());

	    // Indicamos que la validación ha sido correcta
	    timestampValidationInto.setSucess(true);
	} catch (Exception e) {
	    // Indicamos en la información sobre la validación llevada a cabo
	    // que no ha sido correcta
	    timestampValidationInto.setSucess(false);
	    timestampValidationInto.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates the signing certificate of a time-stamp contained inside a <code>signature-time-stamp</code> attribute associated to the first signer of a CAdES
     * signature contained inside of a PAdES signature.
     * @param timestampValidationResult Parameter that represents the information to update with the result of the validation of the time-stamp.
     * @param timestampCertificate Parameter that represents the signing certificate of the time-stamp.
     * @param validationDate Parameter that represents the validation date.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the validation fails.
     */
    private void validateTimeStampCertificate(TimestampValidationResult timestampValidationResult, X509Certificate timestampCertificate, Date validationDate, String idClient) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	TimeStampValidationInfo timestampValidationInto = new TimeStampValidationInfo();
	timestampValidationInto.setIdValidationTask(ITimestampValidationTaskID.ID_SIGNING_CERTIFICATE_VALIDATION);

	// Añadimos a la lista de validaciones del sello de tiempo la
	// información asociada a esta validación
	timestampValidationResult.getListValidations().add(timestampValidationInto);
	try {
	    // Validamos el certificado firmante
	    UtilsSignatureOp.validateCertificate(timestampCertificate, validationDate, false, idClient, true);

	    // Indicamos que la validación ha sido correcta
	    timestampValidationInto.setSucess(true);
	} catch (Exception e) {
	    // Indicamos en la información sobre la validación llevada a cabo
	    // que no ha sido correcta
	    timestampValidationInto.setSucess(false);
	    timestampValidationInto.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates structurally a signature dictionary by PAdES Baseline profile.
     * @param pdfSignatureDictionaryValidationResult Parameter that represents the information about the validation of the signature dictionary to update
     * with the result of the validation.
     * @param pdfSignatureDictionary Parameter that contains information about the signature dictionary to validate.
     * @param pdfDocument Parameter that represents the signed PDF document.
     * @param signedData Parameter that represents the signature message of the CAdES signature contained inside of the signature dictionary.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @return a boolean that indicates if the first signer of the signature contained inside of the signature dictionary includes <code>signature-policy-id</code>
     * attribute (true) or not (false).
     * @throws SigningException If the validation fails.
     */
    private boolean validatePAdESBaselineStructurally(PDFSignatureDictionaryValidationResult pdfSignatureDictionaryValidationResult, PDFSignatureDictionary pdfSignatureDictionary, byte[ ] pdfDocument, CMSSignedData signedData, PDFValidationResult validationResult) throws SigningException {
	boolean hasSignaturePolicyId = false;

	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	ValidationInfo validationInfo = new ValidationInfo();
	validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_PDF_STRUCTURALLY_VALIDATION);

	// Añadimos a la lista de validaciones del diccionario de firma la
	// información asociada a esta validación
	pdfSignatureDictionaryValidationResult.getListValidations().add(validationInfo);
	try {
	    // Validamos estructuralmente el diccionario de firma en base a
	    // PAdES Baseline
	    hasSignaturePolicyId = UtilsSignatureOp.validatePAdESBaselineStructurally(pdfSignatureDictionary, pdfDocument, signedData);

	    // Indicamos que la validación ha sido correcta
	    validationInfo.setSucess(true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la
	    // validación
	    // del diccionario de firma como el error producido, si es que no se
	    // indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel del diccionario de firma, el error asociado
	    // a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (pdfSignatureDictionaryValidationResult.getErrorMsg() == null) {
		pdfSignatureDictionaryValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a
	    // cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
	return hasSignaturePolicyId;
    }

    /**
     * Method that checks if the first signer of the signature contained inside of a signature dictionary includes a SigningCertificate signed attribute, or a SigningCertificateV2
     * signed attribute, and this matches to the signing certificate.
     * @param pdfSignatureDictionaryValidationResult Parameter that represents the information about the validation of the signature dictionary to update
     * with the result of the validation.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @param signerInfo Parameter that represents the information about the first signer of the CAdES signature.
     * @param signedData Parameter that represents the signature message.
     * @throws SigningException If the validation fails.
     */
    private void validateKeyInfo(PDFSignatureDictionaryValidationResult pdfSignatureDictionaryValidationResult, PDFValidationResult validationResult, CAdESSignerInfo signerInfo, CMSSignedData signedData) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	ValidationInfo validationInfo = new ValidationInfo();
	validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_PUBLIC_KEY_INFO_VALIDATION);

	// Añadimos a la lista de validaciones del diccionario de firma la
	// información asociada a esta validación
	pdfSignatureDictionaryValidationResult.getListValidations().add(validationInfo);

	try {
	    // Comprobamos que la información de clave pública del primer
	    // firmante del diccionario de firma es correcta
	    UtilsSignatureOp.validateCAdESPublicKeyInfo(signedData, signerInfo.getSignerInformation(), signerInfo.getSigningCertificate());

	    // Indicamos que la validación ha sido correcta
	    validationInfo.setSucess(true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la validación
	    // de la
	    // firma CAdES como el error producido, si es que no se indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel de diccionario de firma, el error asociado
	    // a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (pdfSignatureDictionaryValidationResult.getErrorMsg() == null) {
		pdfSignatureDictionaryValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates a CAdES signature contained inside of a PAdES-EPES signature by the signature policy defined on the properties file where to configure the validation
     * and generation of signatures with signature policies.
     * @param pdfSignatureDictionaryValidationResult Parameter that represents the information about the validation of the signature dictionary to update
     * with the result of the validation.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @param signerInfo Parameter that represents the information about the first signer of the CAdES signature.
     * @param pdfSignatureDictionary Parameter that contains information about the signature dictionary to validate.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the validation fails.
     */
    private void validateSignaturePolicy(PDFSignatureDictionaryValidationResult pdfSignatureDictionaryValidationResult, PDFValidationResult validationResult, CAdESSignerInfo signerInfo, PDFSignatureDictionary pdfSignatureDictionary, String idClient) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	ValidationInfo validationInfo = new ValidationInfo();
	validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_SIGNATURE_POLICY_VALIDATION);

	// Añadimos a la lista de validaciones del diccionario de firma la
	// información asociada a esta validación
	pdfSignatureDictionaryValidationResult.getListValidations().add(validationInfo);

	try {
	    // Validamos la política de firma asociada al firmante
	    SignaturePolicyManager.validatePAdESEPESSignature(signerInfo.getSignerInformation(), pdfSignatureDictionary.getDictionary(), null, idClient);
	    // Indicamos que la validación ha sido correcta
	    validationInfo.setSucess(true);
	} catch (SignaturePolicyException e) {
	    // Establecemos, a nivel general, el error asociado a la
	    // validación
	    // del diccionario de firma como el error producido, si es que no se
	    // indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel del diccionario de firma, el error asociado
	    // a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (pdfSignatureDictionaryValidationResult.getErrorMsg() == null) {
		pdfSignatureDictionaryValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a
	    // cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates the signing time associated to a PAdES signature.
     * @param pdfSignatureDictionaryValidationResult Parameter that represents the information about the validation of the signature dictionary to update
     * with the result of the validation.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @param validationDate Parameter that represents the validation date
     * @param pdfSignatureDictionary Parameter that contains information about the signature dictionary to validate.
     * @param isBaseline Parameter that indicates if the PAdES signature has Baseline form (true) or not (false).
     * @throws SigningException If the validation fails.
     */
    private void validatePAdESSigningTime(PDFSignatureDictionaryValidationResult pdfSignatureDictionaryValidationResult, PDFValidationResult validationResult, Date validationDate, PDFSignatureDictionary pdfSignatureDictionary, boolean isBaseline) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	ValidationInfo validationInfo = new ValidationInfo();
	validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_SIGNING_TIME_VALIDATION);

	// Añadimos a la lista de validaciones del diccionario de firma la
	// información asociada a esta validación
	pdfSignatureDictionaryValidationResult.getListValidations().add(validationInfo);
	try {
	    // Validamos el instante de firma. Si el diccionario de firma es
	    // Baseline, la clave /M deberá ser obligatoria. En otro caso será
	    // opcional.
	    UtilsSignatureOp.validatePAdESSigningTime(pdfSignatureDictionary, validationDate, isBaseline);

	    // Indicamos que la validación ha sido correcta
	    validationInfo.setSucess(true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la
	    // validación
	    // del diccionario de firma como el error producido, si es que no se
	    // indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel del diccionario de firma, el error asociado
	    // a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (pdfSignatureDictionaryValidationResult.getErrorMsg() == null) {
		pdfSignatureDictionaryValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a
	    // cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates structurally a signature dictionary by PAdES enhanced profile.
     * @param pdfSignatureDictionaryValidationResult Parameter that represents the information about the validation of the signature dictionary to update
     * with the result of the validation.
     * @param pdfSignatureDictionary Parameter that contains information about the signature dictionary to validate.
     * @param pdfDocument Parameter that represents the signed PDF document.
     * @param signedData Parameter that represents the signature message of the CAdES signature contained inside of the signature dictionary.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @param isEPES Parameter that indicates if the signature dictionary represents a PAdES-EPES signature (true) or a PAdES-BES signature (false).
     * @throws SigningException If the validation fails.
     */
    private void validatePAdESEnhancedStructurally(PDFSignatureDictionaryValidationResult pdfSignatureDictionaryValidationResult, PDFSignatureDictionary pdfSignatureDictionary, byte[ ] pdfDocument, CMSSignedData signedData, PDFValidationResult validationResult, boolean isEPES) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	ValidationInfo validationInfo = new ValidationInfo();
	validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_PDF_STRUCTURALLY_VALIDATION);

	// Añadimos a la lista de validaciones del diccionario de firma la
	// información asociada a esta validación
	pdfSignatureDictionaryValidationResult.getListValidations().add(validationInfo);
	try {
	    // Validamos estructuralmente el diccionario de firma en base a
	    // PAdES Enhanced
	    UtilsSignatureOp.validatePAdESEnhancedStructurally(pdfSignatureDictionary, pdfDocument, signedData, isEPES);

	    // Indicamos que la validación ha sido correcta
	    validationInfo.setSucess(true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la
	    // validación
	    // del diccionario de firma como el error producido, si es que no se
	    // indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel del diccionario de firma, el error asociado
	    // a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (pdfSignatureDictionaryValidationResult.getErrorMsg() == null) {
		pdfSignatureDictionaryValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a
	    // cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates if a Document Time-stamp dictionary is structurally correct.
     * @param pdfDocumentTimeStampDictionaryValidationResult Parameter that represents the information about the validation of the Document Time-stamp dictionary to update
     * with the result of the validation.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @param pdfDocumentTimeStampDictionary Parameter that contains information about the Document Time-stamp dictionary to validate.
     * @param pdfDocument Parameter that represents the signed PDF document.
     * @throws SigningException If the validation fails.
     */
    private void validateDocumentTimeStampDictionaryStructurally(PDFDocumentTimeStampDictionaryValidationResult pdfDocumentTimeStampDictionaryValidationResult, PDFValidationResult validationResult, PDFDocumentTimestampDictionary pdfDocumentTimeStampDictionary, byte[ ] pdfDocument) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	TimeStampValidationInfo validationInfo = new TimeStampValidationInfo();
	validationInfo.setIdValidationTask(ITimestampValidationTaskID.ID_PDF_STRUCTURALLY_VALIDATION);

	// Añadimos a la lista de validaciones del diccionario de sello de
	// tiempo la
	// información asociada a esta validación
	pdfDocumentTimeStampDictionaryValidationResult.getListValidations().add(validationInfo);
	try {
	    // Validamos estructuralmente el diccionario de sello de tiempo
	    UtilsSignatureOp.validateDocumentTimeStampDictionaryStructurally(pdfDocumentTimeStampDictionary, pdfDocument);

	    // Indicamos que la validación ha sido correcta
	    validationInfo.setSucess(true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la
	    // validación
	    // del diccionario de firma como el error producido, si es que no se
	    // indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel del diccionario de sello de tiempo, el
	    // error asociado
	    // a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (pdfDocumentTimeStampDictionaryValidationResult.getErrorMsg() == null) {
		pdfDocumentTimeStampDictionaryValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a
	    // cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that checks if the generation date of the time-stamp contained inside of a Document Time-stamp dictionary is previous than a validation date.
     * @param pdfDocumentTimeStampDictionaryValidationResult Parameter that represents the information about the validation of the Document Time-stamp dictionary to update
     * with the result of the validation.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @param pdfDocumentTimeStampDictionary Parameter that contains information about the Document Time-stamp dictionary to validate.
     * @param validationDate Parameter that represents the validation date.
     * @throws SigningException If the validation fails.
     */
    private void validateDocumentTimeStampSigningTime(PDFDocumentTimeStampDictionaryValidationResult pdfDocumentTimeStampDictionaryValidationResult, PDFValidationResult validationResult, PDFDocumentTimestampDictionary pdfDocumentTimeStampDictionary, Date validationDate) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	TimeStampValidationInfo validationInfo = new TimeStampValidationInfo();
	validationInfo.setIdValidationTask(ITimestampValidationTaskID.ID_SIGNING_TIME_VALIDATION);

	// Añadimos a la lista de validaciones del diccionario de sello de
	// tiempo la
	// información asociada a esta validación
	pdfDocumentTimeStampDictionaryValidationResult.getListValidations().add(validationInfo);
	try {
	    // Comprobamos que la fecha de generación del sello de tiempo
	    // contenido en el diccionario de sello de tiempo sea anterior a la
	    // fecha de validación
	    UtilsSignatureOp.validateDocumentTimeStampSigningTime(pdfDocumentTimeStampDictionary, validationDate);

	    // Indicamos que la validación ha sido correcta
	    validationInfo.setSucess(true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la
	    // validación
	    // del diccionario de firma como el error producido, si es que no se
	    // indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel del diccionario de sello de tiempo, el
	    // error asociado
	    // a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (pdfDocumentTimeStampDictionaryValidationResult.getErrorMsg() == null) {
		pdfDocumentTimeStampDictionaryValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a
	    // cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates the core of the the time-stamp contained inside of a Document Time-stamp dictionary.
     * @param pdfDocumentTimeStampDictionaryValidationResult Parameter that represents the information about the validation of the Document Time-stamp dictionary to update
     * with the result of the validation.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @param pdfDocumentTimeStampDictionary Parameter that contains information about the Document Time-stamp dictionary to validate.
     * @throws SigningException If the validation fails.
     */
    private void validateDocumentTimeStampCore(PDFDocumentTimeStampDictionaryValidationResult pdfDocumentTimeStampDictionaryValidationResult, PDFValidationResult validationResult, PDFDocumentTimestampDictionary pdfDocumentTimeStampDictionary) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	TimeStampValidationInfo validationInfo = new TimeStampValidationInfo();
	validationInfo.setIdValidationTask(ITimestampValidationTaskID.ID_TIMESTAMP_SIGNATURE_VALIDATION);

	// Añadimos a la lista de validaciones del diccionario de sello de
	// tiempo la
	// información asociada a esta validación
	pdfDocumentTimeStampDictionaryValidationResult.getListValidations().add(validationInfo);

	try {
	    // Validamos la firma del sello de tiempo
	    UtilsTimestampPdfBc.validateASN1Timestamp(pdfDocumentTimeStampDictionary.getTimestamp());

	    // Indicamos que la validación ha sido correcta
	    validationInfo.setSucess(true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la
	    // validación
	    // del diccionario de firma como el error producido, si es que no se
	    // indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel del diccionario de sello de tiempo, el
	    // error asociado
	    // a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (pdfDocumentTimeStampDictionaryValidationResult.getErrorMsg() == null) {
		pdfDocumentTimeStampDictionaryValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a
	    // cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates the signing certificate of the time-stamp contained inside of a Document Time-stamp dictionary.
     * @param pdfDocumentTimeStampDictionaryValidationResult Parameter that represents the information about the validation of the Document Time-stamp dictionary to update
     * with the result of the validation.
     * @param validationResult Parameter that represents the information about the validation of the signed PDF document.
     * @param pdfDocumentTimeStampDictionary Parameter that contains information about the Document Time-stamp dictionary to validate.
     * @param validationDate Parameter that represents the validation date.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the validation fails.
     */
    private void validateDocumentTimeStampCertificate(PDFDocumentTimeStampDictionaryValidationResult pdfDocumentTimeStampDictionaryValidationResult, PDFValidationResult validationResult, PDFDocumentTimestampDictionary pdfDocumentTimeStampDictionary, Date validationDate, String idClient) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	TimeStampValidationInfo validationInfo = new TimeStampValidationInfo();
	validationInfo.setIdValidationTask(ITimestampValidationTaskID.ID_SIGNING_CERTIFICATE_VALIDATION);

	// Añadimos a la lista de validaciones del diccionario de sello de
	// tiempo la
	// información asociada a esta validación
	pdfDocumentTimeStampDictionaryValidationResult.getListValidations().add(validationInfo);

	try {
	    // Validamos el certificado firmante
	    UtilsSignatureOp.validateCertificate(pdfDocumentTimeStampDictionary.getCertificate(), validationDate, false, idClient, true);

	    // Indicamos que la validación ha sido correcta
	    validationInfo.setSucess(true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la
	    // validación
	    // del diccionario de firma como el error producido, si es que no se
	    // indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel del diccionario de sello de tiempo, el
	    // error asociado
	    // a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (pdfDocumentTimeStampDictionaryValidationResult.getErrorMsg() == null) {
		pdfDocumentTimeStampDictionaryValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a
	    // cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }
}
