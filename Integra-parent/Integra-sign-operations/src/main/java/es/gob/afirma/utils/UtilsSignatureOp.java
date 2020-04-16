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
 * <b>File:</b><p>es.gob.afirma.utils.UtilsSignature.java.</p>
 * <b>Description:</b><p>Class that contains methods related to the manage of signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>07/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.5, 16/04/2020.
 */
package es.gob.afirma.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.NumberFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TimeZone;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.apache.log4j.Logger;
import org.apache.xml.crypto.MarshalException;
import org.apache.xml.crypto.dsig.Reference;
import org.apache.xml.crypto.dsig.XMLSignature;
import org.apache.xml.dsig.internal.dom.DOMReference;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.esf.ESFAttributes;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPUtil;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Attr;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;
import org.xml.sax.SAXException;

import com.lowagie.text.BadElementException;
import com.lowagie.text.Image;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PRTokeniser;
import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignatureAppearance;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.integraFacade.IntegraFacadeConstants;
import es.gob.afirma.integraFacade.pojo.TransformData;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.properties.IIntegraConstants;
import es.gob.afirma.properties.IntegraProperties;
import es.gob.afirma.signature.ISignatureFormatDetector;
import es.gob.afirma.signature.SignatureConstants;
import es.gob.afirma.signature.SignatureFormatDetector;
import es.gob.afirma.signature.SignatureFormatDetectorASiC;
import es.gob.afirma.signature.SignatureFormatDetectorCadesPades;
import es.gob.afirma.signature.SignatureFormatDetectorXades;
import es.gob.afirma.signature.SignatureProperties;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.signature.cades.CAdESSignerInfo;
import es.gob.afirma.signature.pades.PDFDocumentTimestampDictionary;
import es.gob.afirma.signature.pades.PDFSignatureDictionary;
import es.gob.afirma.signature.policy.SignaturePolicyException;
import es.gob.afirma.signature.policy.SignaturePolicyManager;
import es.gob.afirma.signature.validation.SignerValidationResult;
import es.gob.afirma.signature.validation.TimestampValidationResult;
import es.gob.afirma.signature.xades.ExternalFileURIDereferencer;
import es.gob.afirma.signature.xades.IXMLConstants;
import es.gob.afirma.signature.xades.IdRegister;
import es.gob.afirma.signature.xades.ReferenceData;
import es.gob.afirma.signature.xades.ReferenceDataBaseline;
import es.gob.afirma.signature.xades.XAdESSignerInfo;
import es.gob.afirma.transformers.TransformersException;
import net.java.xades.security.xml.XMLSignatureElement;
import net.java.xades.security.xml.XAdES.DataObjectFormat;
import net.java.xades.security.xml.XAdES.DataObjectFormatImpl;
import net.java.xades.security.xml.XAdES.ObjectIdentifier;
import net.java.xades.security.xml.XAdES.ObjectIdentifierImpl;

/**
 * <p>Class that contains methods related to the manage of signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.5, 16/04/2020.
 */
@SuppressWarnings("unchecked")
public final class UtilsSignatureOp implements IUtilsSignature {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(UtilsSignatureOp.class);

    /**
     *  Constant attribute that represents the value for the key <i>SubFilter</i> of the signature dictionary for a
     *  PAdES Enhanced signature.
     */
    public static final PdfName CADES_SUBFILTER_VALUE = new PdfName("ETSI.CAdES.detached");

    /**
     *  Constant attribute that represents the value for the key <i>SubFilter</i> of a Document Time-stamp dictionary.
     */
    public static final PdfName TST_SUBFILTER_VALUE = new PdfName("ETSI.RFC3161");

    /**
     * Constant attribute that represents the value to identify the type of a Document Time-stamp.
     */
    public static final PdfName DOC_TIME_STAMP_DICTIONARY_NAME = new PdfName("DocTimeStamp");

    /**
     * Constant attribute that represents the value to identify the <i>DSS</i> entry in a PDF's Catalog.
     */
    public static final PdfName DSS_DICTIONARY_NAME = new PdfName("DSS");

    /**
     * Constant attribute that represents the OID of the <code>archive-time-stamp-v3</code> attribute.
     */
    private static final DERObjectIdentifier ID_ARCHIVE_TIME_STAMP_V3 = new ASN1ObjectIdentifier("0.4.0.1733.2.4");

    /**
     * Constant attribute that represents the local name of a ASN.1 archiveTimestamp.
     */
    private static final String LOCAL_NAME_ARCHIVE_TIMESTAMP_ASN1 = "EncapsulatedTimeStamp";

    /**
     * Constant attribute that represents the local name of a XML archiveTimestamp.
     */
    private static final String LOCAL_NAME_ARCHIVE_TIMESTAMP_XML = "XMLTimeStamp";

    /**
     * Constructor method for the class SignatureUtils.java.
     */
    private UtilsSignatureOp() {
    }

    /**
     * Method that validates the passed in certificate as being of the correct type to be used for time stamping. To be valid it must have an <code>ExtendedKeyUsage</code>
     * extension which has a key purpose identifier of "id-kp-timeStamping".
     * @param certificate Parameter that represents the certificate to check.
     * @param isTimestampCertificate Parameter that indicates if the certificate is the signing certificate of a time-stamp (true) or not (false).
     * @throws SigningException If the certificate fails on one of the check points.
     */
    private static void validateKeyUsageTimestampCertificate(X509Certificate certificate, boolean isTimestampCertificate) throws SigningException {
	// Comprobamos si el certificado firmante del sello de tiempo incluye la
	// extensión id-kp-timestamping
	try {
	    if (isTimestampCertificate) {
		TSPUtil.validateCertificate(certificate);
	    }
	} catch (TSPValidationException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG238);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}
    }

    /**
     * Method that validates the validity period of a certificate and the revocation status
     * of a certificate (if the validation level for the certificates is defined with the value {@link IntegraFacadeConstants#VALIDATION_LEVEL_COMPLETE}).
     * If the validation level for the certificates is defined with the value {@link IntegraFacadeConstants#VALIDATION_LEVEL_COMPLETE} the validation of
     * the revocation status will be via OCSP.
     * @param certificate Parameter that represents the certificate to validate.
     * @param validationDate Parameter that represents the validation date.
     * @param isUpgradeOperation Parameter that indicates if the origin operation is an upgrade signature operation (true) or not (false).
     * @param idClient Parameter that represents the client application identifier.
     * @param isTimestampCertificate Parameter that indicates if the certificate is the signing certificate of a time-stamp (true) or not (false).
     * @throws SigningException If the certificate isn't valid or the method fails.
     */
    public static void validateCertificate(X509Certificate certificate, Date validationDate, boolean isUpgradeOperation, String idClient, boolean isTimestampCertificate) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG042));
	try {
	    // Comprobamos que el certificado no es nulo
	    GenericUtilsCommons.checkInputParameterIsNotNull(certificate, Language.getResIntegra(ILogConstantKeys.US_LOG002));

	    String validationLevelStr = null;

	    String propertiesName = IIntegraConstants.PROPERTIES_FILE;

	    Properties integraProperties = new IntegraProperties().getIntegraProperties(idClient);
	    // Rescatamos del archivo de propiedades el
	    // nivel de validación para el certificado.
	    validationLevelStr = (String) integraProperties.get(IntegraFacadeConstants.KEY_CERTIFICATE_VALIDATION_LEVEL);

	    // Si no se ha indicado nivel de validación
	    // en el archivo de propiedades, lanzamos una excepción
	    if (validationLevelStr == null || validationLevelStr.isEmpty()) {
		String msg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG001, new Object[ ] { propertiesName });
		LOGGER.error(msg);
		throw new SigningException(msg);
	    }

	    // Comprobamos que el nivel de validación posee un valor correcto
	    int validationLevel = IUtilsSignature.VALIDATION_LEVEL_SIMPLE;
	    try {
		validationLevel = Integer.parseInt(validationLevelStr);
	    } catch (NumberFormatException e) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG003, new Object[ ] { validationLevelStr, propertiesName });
		LOGGER.error(errorMsg, e);
		throw new SigningException(errorMsg, e);
	    }
	    // Si se ha indicado el modo de validación 0 (Sin Validación)
	    if (validationLevel == IUtilsSignature.VALIDATION_LEVEL_NONE) {
		// Si la operación que se está llevando a cabo no es de
		// actualización
		if (!isUpgradeOperation) {
		    // Si no estamos validando el certificado firmante de un
		    // sello de tiempo
		    if (!isTimestampCertificate) {
			// Informamos de que no llevaremos a cabo operación de
			// validación sobre el certificado
			LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG090, new Object[ ] { validationLevelStr, propertiesName }));
		    }
		    // Si estamos validando el certificado firmante de un sello
		    // de tiempo
		    else {
			// Comprobamos que el certificado firmante contiene la
			// extensión id-kp-timestamping
			validateKeyUsageTimestampCertificate(certificate, isTimestampCertificate);
		    }
		} else {
		    // Informamos de que llevaremos a cabo operación de
		    // validación simple sobre el certificado
		    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG091, new Object[ ] { validationLevelStr, propertiesName }));

		    // Validamos el periodo de validez del certificado.
		    // Comprobamos que
		    // la validez del certificado en sí mismo
		    UtilsSignatureCommons.checkValityPeriod(certificate, validationDate);

		    // Comprobamos que el certificado firmante contiene la
		    // extensión id-kp-timestamping, en caso de ser el
		    // certificado firmante de un sello de tiempo
		    validateKeyUsageTimestampCertificate(certificate, isTimestampCertificate);
		}
	    }
	    // Si se ha indicado el modo de validación 1 (Validación Simple)
	    else if (validationLevel == IUtilsSignature.VALIDATION_LEVEL_SIMPLE) {
		// Informamos de que llevaremos a cabo operación de validación
		// simple sobre el certificado
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG091, new Object[ ] { validationLevelStr, propertiesName }));

		// Validamos el periodo de validez del certificado. Comprobamos
		// que
		// la validez del certificado en sí mismo
		UtilsSignatureCommons.checkValityPeriod(certificate, validationDate);

		// Comprobamos que el certificado firmante contiene la extensión
		// id-kp-timestamping, en caso de ser el certificado firmante de
		// un sello de tiempo
		validateKeyUsageTimestampCertificate(certificate, isTimestampCertificate);
	    }
	    // Si se ha indicado el modo de validación 2 (Validación Completa)
	    else if (validationLevel == IUtilsSignature.VALIDATION_LEVEL_COMPLETE) {
		// Informamos de que llevaremos a cabo operación de validación
		// completa sobre el certificado
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG092, new Object[ ] { validationLevelStr, propertiesName }));

		// Validamos el periodo de validez del certificado. Comprobamos
		// que
		// la validez del certificado en sí mismo
		UtilsSignatureCommons.checkValityPeriod(certificate, validationDate);

		// Comprobamos que el certificado firmante contiene la extensión
		// id-kp-timestamping, en caso de ser el certificado firmante de
		// un sello de tiempo
		validateKeyUsageTimestampCertificate(certificate, isTimestampCertificate);

		// Validación del certificado a través del servicio OCSP de
		// validación de certificado de @Firma, u otra plataforma
		UtilsSignatureOCSP.validateCertificateViaOCSP(certificate, validationDate, idClient);
	    }
	    // Si se ha indicado el modo de validación no reconocido
	    else {
		// Lanzamos una excepción
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG003, new Object[ ] { validationLevelStr, propertiesName });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG043));
	}
    }

    /**
     * Method that obtains the signature dictionary with major review.
     * @param reader Parameter that represents the reader for the PDF document.
     * @return the signature dictionary with major review.
     */
    public static PDFSignatureDictionary obtainLatestSignatureFromPDF(PdfReader reader) {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG044));
	try {
	    // Comprobamos que el parámetro de entrada no es nulo
	    GenericUtilsCommons.checkInputParameterIsNotNull(reader, Language.getResIntegra(ILogConstantKeys.US_LOG008));

	    // Instanciamos la variable a devolver
	    PDFSignatureDictionary dictionary = null;
	    // Instanciamos un contador de revisión
	    int revision = -1;
	    // Instanciamos un objeto para leer las firmas
	    AcroFields af = reader.getAcroFields();
	    // Obtenemos la lista de firmas del documento PDF
	    List<String> listSignatures = af.getSignatureNames();
	    // Recorremos la lista de firmas obtenidas
	    for (int i = 0; i < listSignatures.size(); i++) {
		// Metemos en una variable el nombre de la firma
		String signatureName = listSignatures.get(i);
		// Obtenemos el diccionario de firma asociado
		PdfDictionary signatureDictionary = af.getSignatureDictionary(signatureName);
		// Determinamos el tipo de diccionario obtenido
		String pdfType = null;
		if (signatureDictionary.get(PdfName.TYPE) != null) {
		    pdfType = signatureDictionary.get(PdfName.TYPE).toString();
		}
		String pdfSubFilter = signatureDictionary.get(PdfName.SUBFILTER).toString();
		// Si el tipo de diccionario obtenido es un diccionario de firma
		// y
		// no un diccionario de tipo Document Time-stamp
		if (!pdfSubFilter.equalsIgnoreCase(new PdfName("ETSI.RFC3161").toString()) && (pdfType == null || pdfType.equalsIgnoreCase(PdfName.SIG.toString()))) {
		    // Comparamos el número de revisión de la firma con el que
		    // tenemos, si es mayor, actualizamos variables
		    int actuallyRevision = af.getRevision(signatureName);
		    if (actuallyRevision > revision) {
			revision = actuallyRevision;
			dictionary = new PDFSignatureDictionary(actuallyRevision, signatureDictionary, signatureName);
		    }
		}
	    }
	    return dictionary;
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG045));
	}

    }

    //
    /**
     * Method that indicates whether a signature dictionary refers to a PDF or PAdES-Basic signature (true) or to a PAdES-BES or PAdES-EPES signature (false).
     * @param pdfDic Parameter that represents the signature dictionary.
     * @return a boolean that indicates whether a signature dictionary refers to a PDF or PAdES-Basic signature (true) or to a PAdES-BES or PAdES-EPES
     * signature (false).
     */
    public static boolean isNotPAdESEnhancedPDF(PdfDictionary pdfDic) {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG046));
	try {
	    PdfName subFilterValue = (PdfName) pdfDic.get(PdfName.SUBFILTER);
	    if (!subFilterValue.equals(CADES_SUBFILTER_VALUE)) {
		return true;
	    }
	    return false;
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG047));
	}
    }

    /**
     * Method that obtains the <code>SignedData</code> contained inside of a signature dictionary of a PDF document.
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @return an object that represents the <code>SignedData</code>.
     * @throws SigningException If the method fails.
     */
    public static CMSSignedData getCMSSignature(PDFSignatureDictionary signatureDictionary) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG048));
	try {
	    // Comprobamos que los parámetros de entrada no son nulos
	    GenericUtilsCommons.checkInputParameterIsNotNull(signatureDictionary, Language.getResIntegra(ILogConstantKeys.US_LOG007));

	    // Metemos en una variable el contenido de la clave
	    // /Contents, o
	    // lo que es lo mismo, la firma
	    byte[ ] contents = signatureDictionary.getDictionary().getAsString(PdfName.CONTENTS).getOriginalBytes();
	    try {
		// Obtenemos los datos firmados
		CMSSignedData signedData = new CMSSignedData(contents);

		// Comprobamos que la firma tiene al menos un firmante
		if (signedData.getSignerInfos().getSigners().size() == 0) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG015, new Object[ ] { signatureDictionary.getName() });
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
		// Devolvemos los datos firmados
		return signedData;
	    } catch (CMSException e) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG009, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg, e);
		throw new SigningException(errorMsg, e);
	    }
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG049));
	}
    }

    /**
     * Method that indicates whether the signature includes the original document (true) or not (false).
     * @param cmsSignedData Parameter that represents the pkcs7-signature message.
     * @return a boolean that indicates whether the signature includes the original document (true) or not (false).
     */
    public static boolean isImplicit(CMSSignedData cmsSignedData) {
	/*
	 * Firma explícita: El documento original no se incluye en la firma.
	 * Firma implícita: El documento original está incluído en la firma.
	 */
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG050));
	// Por defecto indicamos que la firma es explícita
	boolean result = false;
	ContentInfo contentInfo = cmsSignedData.getContentInfo();
	SignedData signedData = SignedData.getInstance(contentInfo.getContent());
	if (signedData.getEncapContentInfo() != null && signedData.getEncapContentInfo().getContent() != null) {
	    // Si la firma contiene los datos originales, es implícita
	    result = true;
	}
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG051));
	return result;
    }

    /**
     * Method that compares two bytes arrays and indicates if the hash of each is equals (true) or not (false).
     * @param pdfArrayByteRange Parameter that represents the exact byte range for the digest calculation.
     * @param messageDigestSignature Parameter that represents the message digest algorithm.
     * @param pdfDocument Parameter that represents the first bytes array to compare.
     * @param hashSignature Parameter that represents the second bytes array to compare.
     * @return a boolean that indicates if the hash of each is equals (true) or not (false).
     */
    public static boolean equalsHash(PdfArray pdfArrayByteRange, MessageDigest messageDigestSignature, byte[ ] pdfDocument, byte[ ] hashSignature) {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG052));
	boolean res = false;
	int i0, i1;
	int f0, f1;
	i0 = pdfArrayByteRange.getAsNumber(0).intValue();
	i1 = pdfArrayByteRange.getAsNumber(1).intValue();
	f0 = pdfArrayByteRange.getAsNumber(2).intValue();
	f1 = pdfArrayByteRange.getAsNumber(NumberConstants.INT_3).intValue();
	messageDigestSignature.update(pdfDocument, i0, i1);
	messageDigestSignature.update(pdfDocument, f0, f1);
	byte[ ] hashDocument = messageDigestSignature.digest();
	if (Arrays.equals(hashDocument, hashSignature)) {
	    res = true;
	}
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG053));
	return res;
    }

    /**
     * The ISO 32000-1 specifies in section 12.8.3.3.1:
     * - adbe.pkcs7.detached: The original signed message digest over the document’s byte range shall
     *   be incorporated as the normal PKCS#7 SignedData field. No data shall be encapsulated in the
     *   PKCS#7 SignedData field.
     * - adbe.pkcs7.sha1: The SHA1 digest of the document’s byte range shall be encapsulated in the
     *   PKCS#7 SignedData field with ContentInfo of type Data. The digest of that SignedData shall
     *   be incorporated as the normal PKCS#7 digest.
     * This method checks if that conditions are valid.
     * @param dictionarySignature Parameter that represents the signature dictionary.
     * @param signedData Parameter that represents the signed data.
     * @throws SigningException If one of the conditiones isn't valid.
     */
    public static void checkSubFilterConditionsISO320001(PDFSignatureDictionary dictionarySignature, CMSSignedData signedData) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG054));
	try {
	    // Inicialmente se considera que no cumple las condiciones.
	    boolean result = false;

	    // Determinamos el contenido de la clave /SubFilter.
	    String subFilter = dictionarySignature.getDictionary().get(PdfName.SUBFILTER).toString();

	    // Si el subfilter es adbe.pkcs7.detached.
	    if (subFilter.equals(PdfName.ADBE_PKCS7_DETACHED.toString())) {
		result = !isImplicit(signedData);
		// Si el subfilter es adbe.pkcs7.sha1.
	    } else if (subFilter.equals(PdfName.ADBE_PKCS7_SHA1.toString())) {
		// Accedemos al firmante
		SignerInformation signerInformation = ((List<SignerInformation>) signedData.getSignerInfos().getSigners()).iterator().next();
		result = signedData.getSignedContentTypeOID().equals(PKCSObjectIdentifiers.data) && signerInformation.getDigestAlgOID().equals(OIWObjectIdentifiers.idSHA1);
	    }
	    if (!result) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG035, new Object[ ] { dictionarySignature.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG055));
	}
    }

    /**
     * Method that validates the mandatory attributes for a PAdES enhanced signature. The method verifies that:
     * <ul>
     * <li>The <i>content-type</i> attribute cannot be null and must have the value <code>id-data</code>.</li>
     * <li>The entry with the key <i>Cert</i> in the signature dictionary isn't used.</li>
     * </ul>
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @param signedData Parameter that represents the signed data.
     * @throws SigningException If the validation fails.
     */
    public static void validatePAdESEnhancedMandatoryAttributes(PDFSignatureDictionary signatureDictionary, CMSSignedData signedData) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG058));
	try {
	    // Comprobamos que los parámetros de entrada no son nulos
	    GenericUtilsCommons.checkInputParameterIsNotNull(signatureDictionary, Language.getResIntegra(ILogConstantKeys.US_LOG007));
	    GenericUtilsCommons.checkInputParameterIsNotNull(signedData, Language.getResIntegra(ILogConstantKeys.US_LOG019));

	    /*
	     * Validación 1: La firma debe ser explícita.
	     */
	    if (isImplicit(signedData)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG108, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Accedemos al firmante
	    SignerInformation signerInformation = ((List<SignerInformation>) signedData.getSignerInfos().getSigners()).iterator().next();

	    // Obtenemos el conjunto de atributos firmados
	    AttributeTable signedAttr = signerInformation.getSignedAttributes();

	    // Validación 2: El atributo content-type debe estar y tener el
	    // valor
	    // "id-data"
	    checkContentTypeAttributeForPAdESSignature(signedAttr, signatureDictionary.getName());

	    // Validación 3: La clave /Cert del diccionario de firma no debe
	    // estar
	    // presente
	    if (signatureDictionary.getDictionary().getAsName(PdfName.CERT) != null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG018, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG059));
	}
    }

    /**
     * Method that validates the optional unsigned attributes for a PAdES enhanced signature. The method verifies that:
     * <ul>
     * <li>The <i>counter-signature</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * <li>The <i>content-reference</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * </ul>
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @param unsignedAttr Parameter that represents the unsigned attributes of the signature.
     * @throws SigningException If the validation fails.
     */
    private static void validatePAdESEnhancedOptionalUnsignedAttributes(PDFSignatureDictionary signatureDictionary, AttributeTable unsignedAttr) throws SigningException {
	// Si existen atributos no firmados
	if (unsignedAttr != null) {
	    // Validación 1: El atributo counter-signature no debe usarse
	    if (unsignedAttr.get(PKCSObjectIdentifiers.pkcs_9_at_counterSignature) != null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG020, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    // Validación 2: El atributo content-reference no debe usarse
	    if (unsignedAttr.get(PKCSObjectIdentifiers.id_aa_contentReference) != null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG021, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	}
    }

    /**
     * Method that validates the optional attributes for a PAdES enhanced signature. The method verifies that:
     * <ul>
     * <li>The <i>counter-signature</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * <li>The <i>content-reference</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * <li>The <i>content-identifier</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * <li>The <i>Reason</i> key isn't present in the signature dictionary if the signature has PAdES-EPES profile.</li>
     * <li>The <i>commitment-type-indication</i> attribute isn't used if the signature has PAdES-BES profile.</li>
     * <li>The <i>signer-location</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * <li>The <i>signing-time</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * <li>The <i>content-hints</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * </ul>
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @param signedAttr Parameter that represents the signed attributes of the signature.
     * @param unsignedAttr Parameter that represents the unsigned attributes of the signature.
     * @param isEPES Parameter that indicates if the signature has PAdES-EPES profile (true) or PAdES-BES profile (false).
     * @throws SigningException If the validation fails.
     */
    private static void validatePAdESEnhancedOptionalAttributes(PDFSignatureDictionary signatureDictionary, AttributeTable signedAttr, AttributeTable unsignedAttr, boolean isEPES) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG060));
	try {
	    // Validamos los atributos no firmados
	    validatePAdESEnhancedOptionalUnsignedAttributes(signatureDictionary, unsignedAttr);

	    // Validación 3: El atributo content-identifier no debe usarse
	    if (signedAttr.get(PKCSObjectIdentifiers.id_aa_contentIdentifier) != null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG022, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    // Si la firma es PAdES-EPES
	    if (isEPES) {
		// Validación 4: La clave /Reason no debe estar presente para
		// PAdES-EPES
		if (signatureDictionary.getDictionary().getAsName(PdfName.REASON) != null) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG023, new Object[ ] { signatureDictionary.getName() });
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
	    }
	    // Si la firma es PAdES-BES
	    else {
		// Validación 4: El atributo commitment-type-indication no debe
		// usarse para PAdES-BES
		if (signedAttr.get(PKCSObjectIdentifiers.id_aa_ets_commitmentType) != null) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG024, new Object[ ] { signatureDictionary.getName() });
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
	    }
	    // Validación 5: El atributo signer-location no debe usarse
	    if (signedAttr.get(PKCSObjectIdentifiers.id_aa_ets_signerLocation) != null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG025, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    // Validación 6: El atributo firmado signing-time no debe usarse
	    if (signedAttr.get(PKCSObjectIdentifiers.pkcs_9_at_signingTime) != null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG026, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    // Validación 7: El atributo firmado content-hints no debe usarse
	    if (signedAttr.get(PKCSObjectIdentifiers.id_aa_contentHint) != null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG027, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG061));
	}
    }

    /**
     * Method that validates the optional attributes for a PAdES signature. The method verifies that:
     * <ul>
     * <li>The <i>counter-signature</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * <li>The <i>content-reference</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * <li>The <i>content-identifier</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * <li>The <i>Reason</i> key isn't present in the signature dictionary if the signature has PAdES-EPES profile.</li>
     * <li>The <i>commitment-type-indication</i> attribute isn't used if the signature has PAdES-BES profile.</li>
     * <li>The <i>signer-location</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * <li>The <i>signing-time</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * <li>The <i>content-hints</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * <li>If the signature dictionary has /M entry that entry must be a date with a valid format by PDF Reference and
     * that date must be before of the validation date if the signature has PAdES-Basic, PAdES-EPES or PAdES-BES profile.</li>
     * </ul>
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @param signedData Parameter that represents the signed data.
     * @param isEPES Parameter that indicates if the signature has PAdES-EPES profile (true) or PAdES-BES profile (false).
     * @param isBasic Parameter that indicates if the signature has PAdES-Basic profile (true) or PAdES Enhanced profile (false).
     * @throws SigningException If the validation fails.
     */
    public static void validatePAdESOptionalAttributes(PDFSignatureDictionary signatureDictionary, CMSSignedData signedData, boolean isEPES, boolean isBasic) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG062));
	try {
	    // Comprobamos que los parámetros de entrada no son nulos
	    GenericUtilsCommons.checkInputParameterIsNotNull(signatureDictionary, Language.getResIntegra(ILogConstantKeys.US_LOG007));
	    GenericUtilsCommons.checkInputParameterIsNotNull(signedData, Language.getResIntegra(ILogConstantKeys.US_LOG019));

	    // Accedemos al firmante
	    SignerInformation signerInformation = ((List<SignerInformation>) signedData.getSignerInfos().getSigners()).iterator().next();

	    // Obtenemos el conjunto de atributos firmados
	    AttributeTable signedAttr = signerInformation.getSignedAttributes();

	    // Obtenemos el conjunto de atributos no firmados
	    AttributeTable unsignedAttr = signerInformation.getUnsignedAttributes();

	    // Si la firma no es PAdES-Basic
	    if (!isBasic) {
		// Validamos los atributos opcionales para las firmas PAdES
		// enhanced
		validatePAdESEnhancedOptionalAttributes(signatureDictionary, signedAttr, unsignedAttr, isEPES);
	    }
	    // Validación 8: Si el diccionario de firma posee la entrada /M
	    // validaremos que dicho campo posee un formato correcto
	    // según PDF Reference, sección 3.8.3 (Dates), así como que la fecha
	    // contenida no sea futura
	    if (signatureDictionary.getDictionary().get(PdfName.M) != null) {
		String mTimeStr = signatureDictionary.getDictionary().getAsString(PdfName.M).toString();
		Date mTime = parseToPDFDate(mTimeStr);
		// Si la fecha contenida en la entrada /M no tiene el formato
		// adecuado
		if (mTime == null) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG028, new Object[ ] { signatureDictionary.getName() });
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
		// Si la fecha contenida en la entrada /M es posterior a la
		// fecha
		// actual
		Calendar cal = Calendar.getInstance();
		if (mTime.after(cal.getTime())) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG029, new Object[ ] { signatureDictionary.getName() });
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
	    }
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG063));
	}
    }

    /**
     * Method that returns a Date from a string representing a PDF Date conform to the ASN.1 date format. This consists of
     *  D:YYYYMMDDHHmmSSOHH'mm' where everything before and after YYYY is optional.
     * @param value Parameter that represents the PDF Date.
     * @return a wellformed Date if the input param is valid, or null in another case.
     */
    // CHECKSTYLE:OFF Cyclomatic complexity needed
    private static Date parseToPDFDate(String value) {
	// CHECKSTYLE:ON
	// Inicializamos variables
	int year = 0;
	int month = 0;
	int day = 0;
	int hour = 0;
	int minute = 0;
	int second = 0;

	String yearStr = null;
	String monthStr = null;
	String dayStr = null;
	String hourStr = null;
	String minuteStr = null;
	String secondStr = null;
	String timezoneminuteStr = null;

	char timezonechar = '?'; // +, -, o Z
	int timezonehour = 0;
	int timezoneminute = 0;

	Calendar cal = null;

	// Verificación 1: el valor de entrada no puede ser nulo
	String str = value;
	if (str == null) {
	    return null;
	}
	// Verificación 2: el valor de entrada debe tener, como mínimo 6
	// caracteres, esto es, formato D:YYYY
	str = str.trim();
	if (str.length() < NumberConstants.INT_6) {
	    return null;
	}
	int datestate = 0;
	int charidx = 0;
	try {
	    wloop : while (charidx < str.length()) {
		// Para parsear la fecha se utilizará una variable por cada
		// componente de la fecha
		switch (datestate) {
		    // Verificación 3: el valor de entrada debe comenzar por
		    // "D:"
		    case 0:
			if ("D:".equals(str.substring(charidx, charidx + 2))) {
			    charidx += 2;
			} else {
			    return null;
			}
			datestate = 1;
			break;
		    // Verificación 4: El año debe tener 4 cifras (0000-9999)
		    case 1:
			yearStr = str.substring(charidx, charidx + NumberConstants.INT_4);
			year = Integer.parseInt(yearStr);
			charidx += NumberConstants.INT_4;
			if (year < 0 || year > NumberConstants.INT_9999) {
			    return null;
			}
			datestate = 2;
			break;
		    // Verificación 5: El mes debe tener 2 cifras (01-12)
		    case 2:
			monthStr = str.substring(charidx, charidx + 2);
			if (!monthStr.startsWith("Z") && !monthStr.startsWith("-") && !monthStr.startsWith("+")) {
			    month = Integer.parseInt(monthStr);
			    charidx += 2;
			    if (month < 1 || month > NumberConstants.INT_12) {
				return null;
			    }
			} else {
			    monthStr = null;
			}
			datestate = NumberConstants.INT_3;
			break;
		    // Verificación 6: El día debe tener 2 cifras (01-31)
		    case NumberConstants.INT_3:
			dayStr = str.substring(charidx, charidx + 2);
			if (!dayStr.startsWith("Z") && !dayStr.startsWith("-") && !dayStr.startsWith("+")) {
			    day = Integer.parseInt(dayStr);
			    if (day < 1 || day > NumberConstants.INT_31) {
				return null;
			    }
			    charidx += 2;
			} else {
			    dayStr = null;
			}
			datestate = NumberConstants.INT_4;
			break;
		    // Verificación 7: La hora debe tener 2 cifras (00-23)
		    case NumberConstants.INT_4:
			hourStr = str.substring(charidx, charidx + 2);
			if (!hourStr.startsWith("Z") && !hourStr.startsWith("-") && !hourStr.startsWith("+")) {
			    hour = Integer.parseInt(hourStr);
			    charidx += 2;
			    if (hour < 0 || hour > NumberConstants.INT_23) {
				return null;
			    }
			} else {
			    hourStr = null;
			}
			datestate = NumberConstants.INT_5;
			break;
		    // Verificación 8: El minuto debe tener 2 cifras (00-59)
		    case NumberConstants.INT_5:
			minuteStr = str.substring(charidx, charidx + 2);
			if (!minuteStr.startsWith("Z") && !minuteStr.startsWith("-") && !minuteStr.startsWith("+")) {
			    minute = Integer.parseInt(minuteStr);
			    charidx += 2;
			    if (minute < 0 || minute > NumberConstants.INT_59) {
				return null;
			    }
			} else {
			    minuteStr = null;
			}
			datestate = NumberConstants.INT_6;
			break;
		    // Verificación 9: El segundo debe tener 2 cifras (00-59)
		    case NumberConstants.INT_6:
			secondStr = str.substring(charidx, charidx + 2);
			if (!secondStr.startsWith("Z") && !secondStr.startsWith("-") && !secondStr.startsWith("+")) {
			    second = Integer.parseInt(secondStr);
			    charidx += 2;
			    if (second < 0 || second > NumberConstants.INT_59) {
				return null;
			    }
			} else {
			    secondStr = null;
			}
			datestate = NumberConstants.INT_7;
			break;
		    // Verificación 10: La zona horaria debe tener 1 carácter
		    // válido
		    // ('+', '-', o 'Z')
		    case NumberConstants.INT_7:
			timezonechar = str.charAt(charidx);
			if (timezonechar != 'Z' && timezonechar != '+' && timezonechar != '-') {
			    return null;
			}
			charidx++;
			datestate = NumberConstants.INT_8;
			break;
		    // Verificación 11: La hora que va tras la zona horaria debe
		    // tener 2 cifras (00-23) si y sólo si
		    // la zona horaria no tiene el carácter 'Z'
		    case NumberConstants.INT_8:
			if (timezonechar == '+' || timezonechar == '-') {
			    timezonehour = Integer.parseInt(str.substring(charidx, charidx + 2));
			    if (timezonehour < 0 || timezonehour > NumberConstants.INT_23) {
				return null;
			    }
			    if (timezonechar == '-') {
				timezonehour = -timezonehour;
			    }
			    // Verificación 12: La hora que va tras la zona
			    // horaria debe acabar en comilla simple
			    if (!str.substring(charidx + 2, charidx + NumberConstants.INT_3).equals("'")) {
				return null;
			    }
			    charidx += 2;
			}
			datestate = NumberConstants.INT_9;
			break;
		    // Verificación 13: El minuto que va tras la zona horaria
		    // debe tener 2 cifras (00-59) si y sólo si
		    // la zona horaria no tiene el carácter 'Z'
		    case NumberConstants.INT_9:
			if (timezonechar == '+' || timezonechar == '-') {
			    if (str.charAt(charidx) == '\'') {
				timezoneminuteStr = str.substring(charidx + 1, charidx + NumberConstants.INT_3);
				if (timezoneminuteStr.length() != 2) {
				    return null;
				}
				timezoneminute = Integer.parseInt(timezoneminuteStr);
			    }
			    if (timezoneminute < 0 || timezoneminute > NumberConstants.INT_59) {
				return null;
			    }
			    if (timezonechar == '-') {
				timezoneminute = -timezoneminute;
			    }
			}
			break wloop;
		}
	    }
	    // Verificación 14: El día debe ser válido para el mes obtenido
	    if (yearStr != null && monthStr != null && dayStr != null) {

		// Mes con 28 o 29 días
		if (month == 2) {
		    GregorianCalendar gc = new GregorianCalendar();
		    // Año bisiesto
		    if (gc.isLeapYear(year)) {
			if (day > NumberConstants.INT_29) {
			    return null;
			}
		    }
		    // Año no bisiesto
		    else {
			if (day > NumberConstants.INT_28) {
			    return null;
			}
		    }
		}
		// Meses con 30 días
		// CHECKSTYLE:OFF Bolean complexity needed
		else if ((month == NumberConstants.INT_4 || month == NumberConstants.INT_6 || month == NumberConstants.INT_9 || month == NumberConstants.INT_11) && day > NumberConstants.INT_30) {
		    // CHECKSTYLE:ON
		    return null;
		}
	    }
	    // Verificación 15: El número de campos rescatados debe ser al menos
	    // 2
	    if (datestate < 2) {
		return null;
	    }
	}
	// Si se produce alguna excepción durante el proceso de asignación de
	// fechas entendemos que la fecha no está bien formada
	// y por tanto no es correcta.
	catch (Exception e) {
	    return null;
	}
	// Construimos el objeto TimeZone que representará la zona horaria si se
	// especifica zona horaria.
	if (timezonechar != '?') {
	    String tzStr = "GMT";
	    if (timezonechar == 'Z') {
		tzStr += "+0000";
	    } else {
		tzStr += timezonechar;
		NumberFormat nfmt = NumberFormat.getInstance();
		nfmt.setMinimumIntegerDigits(2);
		nfmt.setMaximumIntegerDigits(2);
		tzStr += nfmt.format(timezonehour);
		tzStr += nfmt.format(timezoneminute);
	    }
	    TimeZone tz = TimeZone.getTimeZone(tzStr);

	    // Usamos el objeto TimeZone para crear un objeto Calendar con la
	    // fecha teniendo en cuenta que los meses en Java comienzan en 0.
	    cal = Calendar.getInstance(tz);
	}
	// Si no se especifica zona horaria
	else {
	    cal = Calendar.getInstance();
	}
	if (month == 0) {
	    month = 1;
	}
	cal.setTimeInMillis(0);
	cal.set(year, month - 1, day, hour, minute, second);
	return cal.getTime();
    }

    /**
     * Method that obtains the structure of a certificate from a certificates store.
     * @param certificatesStore Parameter that represents the certificates store.
     * @param signerId Parameter that represents the identifier of the signer used to find the certificate.
     * @return an object that represents the structure of the certificate.
     */
    public static X509CertificateHolder getX509CertificateHolderBySignerId(Store certificatesStore, SignerId signerId) {
	if (certificatesStore != null && certificatesStore.getMatches(null) != null && signerId != null) {
	    for (Iterator<?> iterator = certificatesStore.getMatches(null).iterator(); iterator.hasNext();) {
		X509CertificateHolder cert = (X509CertificateHolder) iterator.next();
		if (signerId.match(cert)) {
		    return cert;
		}
	    }
	}
	return null;
    }

    //
    /**
     * Method that validates the signer of a signature contained inside of a PDF document.
     * @param signedData Parameter that represents the signed data.
     * @param signerInformation Parameter that represents the signer information.
     * @param pdfSignatureDictionary Parameter that represents the PDF signature dictionary.
     * @param validationDate Parameter that represents the validation date.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the validation fails.
     */
    public static void validatePDFSigner(CMSSignedData signedData, SignerInformation signerInformation, PdfDictionary pdfSignatureDictionary, Date validationDate, String idClient) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG064));
	Date vd = validationDate;
	try {
	    // Comprobamos que se han indicado parámetros de entrada
	    GenericUtilsCommons.checkInputParameterIsNotNull(signedData, Language.getResIntegra(ILogConstantKeys.US_LOG019));
	    GenericUtilsCommons.checkInputParameterIsNotNull(signerInformation, Language.getResIntegra(ILogConstantKeys.US_LOG032));

	    // Obtenemos la estructura del certificado firmante
	    X509CertificateHolder x509CertificateHolder = getX509CertificateHolderBySignerId(signedData.getCertificates(), signerInformation.getSID());
	    if (x509CertificateHolder == null) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG031);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    // Si no se ha indicado fecha de validación, se establecerá ésta
	    // como la fecha actual
	    if (validationDate == null) {
		vd = Calendar.getInstance().getTime();
	    }

	    // Obtenemos el sello de tiempo (en caso de que la firma
	    // contenga sello de tiempo)
	    TimeStampToken tst = UtilsTimestampPdfBc.getTimeStampToken(signerInformation);

	    // Si la firma contiene sello de tiempo
	    if (tst != null) {
		// Establecemos la fecha de validación como la fecha del
		// sello de tiempo
		if (validationDate == null) {
		    vd = tst.getTimeStampInfo().getGenTime();
		}

		// Llevamos a cabo la validación del sello de tiempo
		UtilsTimestampPdfBc.validateASN1Timestamp(tst);
	    }

	    String errorMsg = null;
	    try {
		errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG031);
		// Validamos el certificado firmante
		validateCertificate(new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder), vd, false, idClient, false);
	    } catch (CertificateException e) {
		LOGGER.error(errorMsg, e);
		throw new SigningException(errorMsg, e);
	    }
	    // Comprobamos si la firma es EPES, es decir, si tiene el elemento
	    // firmado SignaturePolicyIdentifier
	    if (SignatureFormatDetectorCadesPades.hasSignaturePolicyIdentifier(signerInformation)) {
		// Validamos la política de firma asociada al firmante
		try {
		    SignaturePolicyManager.validatePAdESEPESSignature(signerInformation, pdfSignatureDictionary, null, idClient);
		} catch (SignaturePolicyException e) {
		    errorMsg = e.getMessage();
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg, e);
		}
	    }
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG065));
	}
    }

    /**
     * Method that obtains a list with the principal information related to the signers of a CAdES signature.
     * @param signedData Parameter that represents the signed data.
     * @return a list with the principal information related to the signers of a CAdES signature.
     */
    public static List<CAdESSignerInfo> getCAdESListSigners(CMSSignedData signedData) {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG068));
	try {
	    // Comprobamos que se han indicado parámetros de entrada
	    GenericUtilsCommons.checkInputParameterIsNotNull(signedData, Language.getResIntegra(ILogConstantKeys.US_LOG019));

	    // Instanciamos la variable a devolver
	    List<CAdESSignerInfo> listResult = new ArrayList<CAdESSignerInfo>();

	    // Obtenemos la lista con todos los firmantes contenidos en la firma
	    SignerInformationStore signerInformationStore = signedData.getSignerInfos();
	    if (signerInformationStore != null) {
		List<SignerInformation> listSignersSignature = (List<SignerInformation>) signerInformationStore.getSigners();
		if (listSignersSignature != null) {
		    // Recorremos la lista de firmantes
		    for (SignerInformation signerInformation: listSignersSignature) {
			CAdESSignerInfo signerInfo = new CAdESSignerInfo();
			listResult.add(signerInfo);
			processCAdESSignerInfos(signedData, signerInformation, signerInfo);
		    }
		}
	    }
	    return listResult;
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG069));
	}
    }

    /**
     * Method that fills the principal information related to a signer of a CAdES signature with the information about a signer.
     * @param signedData Parameter that represents the signed data.
     * @param si Parameter that represents the signer of the CAdES signature.
     * @param signerInfo Parameter that represents the principal information related to the signer to fill.
     */
    private static void processCAdESSignerInfos(CMSSignedData signedData, SignerInformation si, CAdESSignerInfo signerInfo) {
	// Asociamos los datos del firmante
	signerInfo.setSignerInformation(si);

	// Obtenemos el certificado firmante
	X509Certificate signingCertificate = null;
	try {
	    signingCertificate = getSigningCertificate(signedData, si);
	} catch (SigningException e) {
	    signerInfo.setErrorMsg(e.getMessage());
	}

	try {
	    // Accedemos al conjunto de atributos no firmados del firmante
	    AttributeTable unsignedAttrs = signerInfo.getSignerInformation().getUnsignedAttributes();

	    // Si el firmante tiene atributos no firmados
	    if (unsignedAttrs != null) {
		// Accedemos a todos los atributos signature-time-stamp
		ASN1EncodableVector signatureTimeStampattributes = unsignedAttrs.getAll(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);

		// Si el firmante incluye algún atributo signature-time-stamp
		if (signatureTimeStampattributes.size() > 0) {
		    // Obtenemos la lista de sellos de tiempo contenidos en los
		    // atributos signature-time-stamp, ordenados ascendentemente
		    // por fecha de generación, en el caso de que el firmante
		    // contenga dichos atributos
		    signerInfo.setListTimeStamps(UtilsTimestampPdfBc.getOrderedTimeStampTokens(signatureTimeStampattributes));
		}

	    }
	} catch (SigningException e) {
	    signerInfo.setErrorMsg(e.getMessage());
	}

	// Asociamos el certificado firmante a los datos del firmante
	signerInfo.setSigningCertificate(signingCertificate);

	// Obtenemos el conjunto de contra-firmas
	SignerInformationStore sis = si.getCounterSignatures();
	if (sis != null) {
	    Iterator<SignerInformation> siIt = sis.getSigners().iterator();
	    // Recorremos la lista de contra-firmas
	    while (siIt.hasNext()) {
		// Procesamos el conjunto de contra-firmas
		SignerInformation siCounter = siIt.next();
		CAdESSignerInfo signerInfoCounter = new CAdESSignerInfo();
		List<CAdESSignerInfo> listCounterSigners = signerInfo.getListCounterSigners() != null ? signerInfo.getListCounterSigners() : new ArrayList<CAdESSignerInfo>();
		signerInfo.setListCounterSigners(listCounterSigners);
		listCounterSigners.add(signerInfoCounter);
		processCAdESSignerInfos(signedData, siCounter, signerInfoCounter);
	    }
	}

    }

    /**
     * Method that obtains the singing certificate of a signer of a signature.
     * @param signedData Parameter that represents the signed data.
     * @param signerInformation Parameter that represents the information about the signer of the signature.
     * @return an object that represents the signing certificate.
     * @throws SigningException If the certificate hasn't could be retrieved.
     */
    public static X509Certificate getSigningCertificate(CMSSignedData signedData, SignerInformation signerInformation) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG074));
	try {
	    // Obtenemos el conjunto de certificados de la firma
	    Store store = signedData.getCertificates();

	    // Obtenemos el certificado firmante
	    Collection<X509CertificateHolder> certCollection = store.getMatches(signerInformation.getSID());
	    Iterator<X509CertificateHolder> certIt = certCollection.iterator();
	    X509CertificateHolder certHolder = certIt.next();
	    return new JcaX509CertificateConverter().getCertificate(certHolder);
	} catch (CertificateException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG031);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG075));
	}
    }

    /**
     * Method that obtains the revision of the signature dictionary most recent.
     * @param reader Parameter that represents the reader for the PDF document.
     * @return an input stream that represents the revision, or <code>null</code> if the PDF document doesn't contain any signature dictionary.
     * @throws SigningException If cannot access to some revision.
     */
    public static PdfReader obtainLatestRevision(PdfReader reader) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG044));
	String signatureName = null;
	// Instanciamos la variable a devolver
	PdfReader latestRevision = null;
	try {
	    // Comprobamos que el parámetro de entrada no es nulo
	    GenericUtilsCommons.checkInputParameterIsNotNull(reader, Language.getResIntegra(ILogConstantKeys.US_LOG008));

	    // Instanciamos un contador de revisiones
	    int revision = -1;
	    // Instanciamos un objeto para leer las firmas
	    AcroFields af = reader.getAcroFields();
	    // Obtenemos la lista de firmas del documento PDF
	    List<String> listSignatures = af.getSignatureNames();
	    // Recorremos la lista de firmas obtenidas
	    for (int i = 0; i < listSignatures.size(); i++) {
		// Metemos en una variable el nombre de la firma
		signatureName = listSignatures.get(i);
		// Obtenemos el diccionario de firma asociado
		PdfDictionary signatureDictionary = af.getSignatureDictionary(signatureName);
		// Determinamos el tipo de diccionario obtenido
		String pdfType = null;
		if (signatureDictionary.get(PdfName.TYPE) != null) {
		    pdfType = signatureDictionary.get(PdfName.TYPE).toString();
		}
		String pdfSubFilter = signatureDictionary.get(PdfName.SUBFILTER).toString();
		// Si el tipo de diccionario obtenido es un diccionario de firma
		// y
		// no un diccionario de tipo Document Time-stamp
		if (!pdfSubFilter.equalsIgnoreCase(new PdfName("ETSI.RFC3161").toString()) && (pdfType == null || pdfType.equalsIgnoreCase(PdfName.SIG.toString()))) {
		    // Comparamos el número de revisión de la firma con el que
		    // tenemos, si es mayor, actualizamos variables
		    int actuallyRevision = af.getRevision(signatureName);
		    if (actuallyRevision > revision) {
			revision = actuallyRevision;
			latestRevision = new PdfReader(af.extractRevision(signatureName));
		    }
		}
	    }
	} catch (IOException e) {
	    throw new SigningException(Language.getFormatResIntegra(ILogConstantKeys.US_LOG081, new Object[ ] { signatureName }), e);
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG045));
	}
	return latestRevision;
    }

    /**
     * Method that validates if some approval signature was added to a PDF document after that it was defined as certified.
     * @param mapRevisions Parameter that represents a map with the revisions of the PDF document. Each revision represents a signature dictionary. The key
     * is the revision number, and the value is the revision.
     * @throws SigningException If the method fails or some approval signature was added to a PDF document after that it was defined as certified.
     */
    public static void checkPDFCertificationLevel(Map<Integer, InputStream> mapRevisions) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG080));
	try {
	    // Comprobamos que los parámetros de entrada son válidos
	    GenericUtilsCommons.checkInputParameterIsNotNull(mapRevisions, Language.getResIntegra(ILogConstantKeys.US_LOG078));

	    // Incialmente suponemos que ninguna revisión es certified, es
	    // decir, admite firmas posteriores
	    boolean isCertified = false;

	    // Recorremos el mapa de revisiones ordenado ascendentemente
	    Iterator<InputStream> it = mapRevisions.values().iterator();
	    while (it.hasNext()) {
		InputStream is = it.next();

		// Accedemos a la revisión
		PdfReader revision = new PdfReader(is);

		// Si para la revisión anterior se definió el documento PDF como
		// certified, entonces, esta revisión no debería haberse
		// incluído, por lo que
		// se lanzaría una excepción
		if (isCertified) {
		    throw new SigningException(Language.getResIntegra(ILogConstantKeys.US_LOG041));
		}

		// Comprobamos el nivel de certificación para esa revisión
		if (revision.getCertificationLevel() != PdfSignatureAppearance.NOT_CERTIFIED) {
		    isCertified = true;
		}
	    }
	} catch (IOException e) {
	    throw new SigningException(Language.getResIntegra(ILogConstantKeys.US_LOG004), e);
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG079));
	}
    }

    /**
     * Method that obtains a list with the principal information related to the signers of a XAdES signature.
     * @param doc Parameter that represents the XML document.
     * @return a list with the principal information related to the signers of a XAdES signature.
     */
    public static List<XAdESSignerInfo> getXAdESListSigners(Document doc) {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG066));
	try {
	    // Comprobamos que se han indicado parámetros de entrada
	    // Comprobamos que se ha indicado el documento XML firmado
	    GenericUtilsCommons.checkInputParameterIsNotNull(doc, Language.getResIntegra(ILogConstantKeys.US_LOG037));

	    // Instanciamos la variable a devolver
	    List<XAdESSignerInfo> listResult = new ArrayList<XAdESSignerInfo>();

	    // Obtenemos la lista de firmas contenidas en el documento XML
	    NodeList nlSignature = doc.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_SIGNATURE);
	    if (nlSignature != null) {
		// Recorremos la lista de firmantes
		for (int i = 0; i < nlSignature.getLength(); i++) {
		    Element signatureNode = (Element) nlSignature.item(i);
		    if (signatureNode.getParentNode() == null || !IXMLConstants.ELEMENT_COUNTER_SIGNATURE.equals(signatureNode.getParentNode().getLocalName()) && !IXMLConstants.ELEMENT_XML_TIMESTAMP.equals(signatureNode.getParentNode().getLocalName()) && !IXMLConstants.ELEMENT_TIMESTAMP.equals(signatureNode.getParentNode().getLocalName())) {
			XAdESSignerInfo signerInfo = new XAdESSignerInfo();
			listResult.add(signerInfo);
			try {
			    signerInfo.setSignature(new org.apache.xml.security.signature.XMLSignature(signatureNode, ""));
			    signerInfo.setElementSignature(signatureNode);
			    signerInfo.setId(signatureNode.getAttribute(IXMLConstants.ATTRIBUTE_ID));
			    processXMLSignature(signerInfo, signatureNode);
			} catch (org.apache.xml.security.signature.XMLSignatureException e) {
			    signerInfo.setErrorMsg(Language.getResIntegra(ILogConstantKeys.US_LOG040));
			} catch (org.apache.xml.security.exceptions.XMLSecurityException e) {
			    signerInfo.setErrorMsg(Language.getResIntegra(ILogConstantKeys.US_LOG040));
			}
		    }
		}
	    }

	    return listResult;
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG067));
	}
    }

    /**
     * Method that obtains the list of <code>ds:Signature</code> elements, as signatures, contained inside of a XML document.
     * @param doc Parameter that represents the XML document.
     * @return a list with the <code>ds:Signature</code> elements.
     */
    public static List<Element> getListSignatures(Document doc) {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG093));

	// Instanciamos la lista a devolver
	List<Element> listSignatureElements = new ArrayList<Element>();

	try {
	    // Comprobamos que se han indicado los parámetros de entrada
	    // Comprobamos que se ha indicado el documento XML firmado
	    GenericUtilsCommons.checkInputParameterIsNotNull(doc, Language.getResIntegra(ILogConstantKeys.US_LOG037));

	    // Obtenemos la lista de elementos ds:Signature contenidos en el
	    // documento XML
	    NodeList nlSignature = doc.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_SIGNATURE);
	    if (nlSignature != null) {
		// Recorremos la lista de elementos ds:Signature
		for (int i = 0; i < nlSignature.getLength(); i++) {
		    Element signatureNode = (Element) nlSignature.item(i);
		    // Comprobamos que el elemento ds:Signature no haga
		    // referencia a un sello de tiempo XML
		    if (signatureNode.getParentNode() == null || !IXMLConstants.ELEMENT_XML_TIMESTAMP.equals(signatureNode.getParentNode().getLocalName()) && !IXMLConstants.ELEMENT_TIMESTAMP.equals(signatureNode.getParentNode().getLocalName())) {
			// Añadimos el elemento a la lista que devolver
			listSignatureElements.add(signatureNode);
		    }
		}
	    }

	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG094));
	}
	return listSignatureElements;
    }

    /**
     * Method that checks if a signer of a XAdES signature contains the ArchiveTimeStamp element and updates the information about the signer with that.
     * @param qualifyingProperties Parameter that represents the QualifyingProperties element of the XAdES signature.
     * @param signerInfo Parameter that represents the information about the signer of the XAdES signature.
     */
    private static void setHasArchiveTimeStamp(Node qualifyingProperties, XAdESSignerInfo signerInfo) {
	NodeList archiveTimeStamps = ((Element) qualifyingProperties).getElementsByTagNameNS(IXMLConstants.XADES_1_4_1_NAMESPACE, IXMLConstants.ELEMENT_ARCHIVE_TIMESTAMP);
	if (archiveTimeStamps != null && archiveTimeStamps.getLength() > 0) {
	    signerInfo.setHasArchiveTimeStampElement(true);
	} else {
	    archiveTimeStamps = ((Element) qualifyingProperties).getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_ARCHIVE_TIMESTAMP);
	    if (archiveTimeStamps != null && archiveTimeStamps.getLength() > 0) {
		signerInfo.setHasArchiveTimeStampElement(true);
	    }
	}
    }

    /**
     * Method that fills the principal information related to a signer of a XAdES signature with the time-stamps contained inside of the <code>xades:SignatureTimeStamp</code> elements.
     * @param qualifyingProperties Parameter that represents the QualifyingProperties element of the XAdES signature.
     * @param signerInfo Parameter that represents the information about the signer of the XAdES signature.
     */
    private static void setTimestamps(Node qualifyingProperties, XAdESSignerInfo signerInfo) {
	try {
	    // Recorremos la lista de elementos hijos del elemento
	    // xades:QualifyingProperties buscando el elemento
	    // xades:UnsignedProperties
	    Element unsignedPropertiesElement = UtilsXML.getChildElement((Element) qualifyingProperties, IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES, signerInfo.getId(), false);

	    // Si hemos encontrado el elemento xades:UnsignedProperties
	    if (unsignedPropertiesElement != null) {
		// Recorremos la lista de elementos hijos del elemento
		// xades:UnsignedProperties buscando el elemento
		// xades:UnsignedSignatureProperties
		Element unsignedSignaturePropertiesElement = UtilsXML.getChildElement(unsignedPropertiesElement, IXMLConstants.ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES, signerInfo.getId(), false);

		// Si hemos encontrado el elemento
		// xades:UnsignedSignatureProperties
		if (unsignedSignaturePropertiesElement != null) {
		    // Obtenemos la lista de elementos hijos
		    // xades:SignatureTimeStamp
		    List<Element> listSignatureTimeStampElements = UtilsXML.getChildElements(unsignedSignaturePropertiesElement, IXMLConstants.ELEMENT_SIGNATURE_TIMESTAMP);

		    // Definimos una lista donde ubicar la información asociada
		    // a
		    // los sellos de tiempo contenidos en los elementos
		    // xades:SignatureTimeStamp
		    List<XAdESTimeStampType> listSignatureTimeStamps = new ArrayList<XAdESTimeStampType>();

		    // Recorremos la lista de elementos xades:SignatureTimeStamp
		    for (int i = 0; i < listSignatureTimeStampElements.size() && signerInfo.getErrorMsg() == null; i++) {
			// Accedemos al elemento xades:SignatureTimeStamp
			Element signatureTimeStampElement = (Element) listSignatureTimeStampElements.get(i);

			// Accedemos al atributo Id del elemento
			// xades:SignatureTimeStamp
			String signatureTimeStampId = signatureTimeStampElement.getAttribute(IXMLConstants.ATTRIBUTE_ID);

			// Comprobamos de qué tipo es el sello de tiempo
			// contenido
			if (signatureTimeStampElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_ENCAPSULATED_TIMESTAMP).item(0) != null) {
			    // Sello de tiempo ASN.1
			    String encodedTST = signatureTimeStampElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_ENCAPSULATED_TIMESTAMP).item(0).getTextContent();

			    // Obtenemos el sello de tiempo
			    TimeStampToken timestamp = null;
			    try {
				timestamp = new TimeStampToken(new CMSSignedData(Base64.decode(encodedTST)));

				// Añadimos a la información del firmante la
				// información relacionada con el sello de
				// tiempo
				XAdESTimeStampType xadesTimeStampType = new XAdESTimeStampType();
				xadesTimeStampType.setId(signatureTimeStampId);
				xadesTimeStampType.setTimestampGenerationDate(timestamp.getTimeStampInfo().getGenTime());
				xadesTimeStampType.setTstCertificate(UtilsTimestampPdfBc.getSigningCertificate(timestamp));
				xadesTimeStampType.setAsn1Timestamp(timestamp);
				xadesTimeStampType.setCanonicalizationAlgorithm(getCanonicalizationMethod(signatureTimeStampElement));
				listSignatureTimeStamps.add(xadesTimeStampType);
			    } catch (Exception e) {
				// Sello de tiempo ASN.1 incorrecto
				signerInfo.setErrorMsg(Language.getFormatResIntegra(ILogConstantKeys.US_LOG176, new Object[ ] { signatureTimeStampId }));
			    }
			} else if (signatureTimeStampElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_XML_TIMESTAMP).item(0) != null) {
			    // Sello de tiempo XML
			    Element timeStampElement = (Element) signatureTimeStampElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_XML_TIMESTAMP).item(0);

			    // Accedemos al elemento dss:Timestamp
			    // Element timeStampElement = (Element)
			    // xmlTimeStampElement.getElementsByTagNameNS(DSSConstants.OASIS_CORE_1_0_NS,
			    // IXMLConstants.ELEMENT_TIMESTAMP).item(0);
			    // if (timeStampElement == null) {
			    // // Sello de tiempo mal formado
			    // signerInfo.setErrorMsg(Language.getFormatResIntegra(ILogConstantKeys.US_LOG177,
			    // new Object[ ] { signatureTimeStampId }));
			    // } else {

			    try {
				// Añadimos a la información del firmante la
				// información relacionada con el sello de
				// tiempo
				XAdESTimeStampType xadesTimeStampType = new XAdESTimeStampType();
				xadesTimeStampType.setId(signatureTimeStampId);
				xadesTimeStampType.setTimestampGenerationDate(UtilsTimestampXML.getGenTimeXMLTimestamp((Element) UtilsXML.getChildNodesByLocalNames(timeStampElement, "Timestamp").item(0)));
				xadesTimeStampType.setTstCertificate(UtilsTimestampXML.getCertificateFromXMLTimestamp(timeStampElement));
				xadesTimeStampType.setXmlTimestamp(timeStampElement);
				xadesTimeStampType.setCanonicalizationAlgorithm(getCanonicalizationMethod(signatureTimeStampElement));
				listSignatureTimeStamps.add(xadesTimeStampType);
			    } catch (Exception e) {
				// Sello de tiempo mal formado
				signerInfo.setErrorMsg(Language.getFormatResIntegra(ILogConstantKeys.US_LOG177, new Object[ ] { signatureTimeStampId }));
			    }
			    // }

			} else {
			    signerInfo.setErrorMsg(Language.getFormatResIntegra(ILogConstantKeys.US_LOG178, new Object[ ] { signatureTimeStampId }));
			}
		    }
		    // Si hemos procesado elementos xades:SignatureTimeStamp
		    // encontrando sellos de tiempo, ordenamos la lista con
		    // información de todos los elementos
		    // xades:SignatureTimeStamp ascendentemente por fecha de
		    // generación del sello de tiempo contenido y asociamos esa
		    // lista a la información del firmante
		    if (!listSignatureTimeStamps.isEmpty()) {
			Collections.sort(listSignatureTimeStamps);
			signerInfo.setListTimeStamps(listSignatureTimeStamps);
		    }
		}
	    }
	} catch (SigningException e) {
	    // Esta excepción nunca se lanzará
	}
    }

    /**
     * Method that obtains the canonicalization algorithm from <code>ds:CanonicalizationMethod</code> element contained inside of <code>SignatureTimeStamp</code> element.
     * @param signatureTimeStampElement Parameter that represents <code>SignatureTimeStamp</code> element.
     * @return the canonicalization algorithm or <code>null</code> if <code>ds:CanonicalizationMethod</code> element doesn't exist.
     */
    private static String getCanonicalizationMethod(Element signatureTimeStampElement) {
	String canonicalizationAlgorithm = null;
	NodeList childNodes = signatureTimeStampElement.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_CANONICALIZATION_METHOD);
	int i = 0;
	while (i < childNodes.getLength() && canonicalizationAlgorithm == null) {
	    Node currentNode = childNodes.item(i);
	    if (currentNode.getNodeType() == Node.ELEMENT_NODE) {
		// Accedemos al algoritmo de canonicalización
		canonicalizationAlgorithm = ((Element) currentNode).getAttributeNode(IXMLConstants.ATTRIBUTE_ALGORITHM).getNodeValue();
	    }
	    i++;
	}
	return canonicalizationAlgorithm;
    }

    /**
     * Method that obtains all the counter signers of a signer and fills the principal information related to each counter signer..
     *@param qualifyingProperties Parameter that represents the QualifyingProperties element of the XAdES signature.
     * @param signerInfo Parameter that represents the signer of the XAdES signature.
     */
    private static void processXMLCounterSigners(Node qualifyingProperties, XAdESSignerInfo signerInfo) {
	// Obtenemos el conjunto de contrafirmas
	NodeList counterNodes = ((Element) qualifyingProperties).getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_COUNTER_SIGNATURE);
	if (counterNodes != null && counterNodes.getLength() > 0) {
	    List<XAdESSignerInfo> listCounterSigners = new ArrayList<XAdESSignerInfo>();
	    signerInfo.setListCounterSigners(listCounterSigners);
	    for (int i = 0; i < counterNodes.getLength(); i++) {
		NodeList counterSigNodeList = counterNodes.item(i).getChildNodes();
		for (int j = 0; j < counterSigNodeList.getLength(); j++) {
		    if (counterSigNodeList.item(j).getNodeType() == Node.ELEMENT_NODE) {
			Element signatureNode = (Element) counterSigNodeList.item(j);
			XAdESSignerInfo signerInfoCounter = new XAdESSignerInfo();
			listCounterSigners.add(signerInfoCounter);
			try {
			    signerInfoCounter.setSignature(new org.apache.xml.security.signature.XMLSignature(signatureNode, ""));
			    signerInfoCounter.setElementSignature(signatureNode);
			    signerInfoCounter.setId(signatureNode.getAttribute(IXMLConstants.ATTRIBUTE_ID));
			} catch (Exception e) {
			    signerInfo.setErrorMsg(Language.getResIntegra(ILogConstantKeys.US_LOG040));
			}
			processXMLSignature(signerInfoCounter, signatureNode);
		    }
		}
	    }
	}
    }

    /**
     * Method that fills the principal information related to a signer of a XAdES signature with the information about a signer.
     * @param signerInfo Parameter that represents the signer of the XAdES signature.
     * @param signatureNode Parameter that represents the signature node.
     */
    private static void processXMLSignature(XAdESSignerInfo signerInfo, Element signatureNode) {
	// Accedemos al conjunto de nodos hijos del nodo Signature
	NodeList nl = signatureNode.getChildNodes();

	// Instanciamos variables
	Element qualifyingProperties = null;

	// Recorremos la lista de nodos hijos del nodo Signature
	for (int i = 0; i < nl.getLength(); i++) {
	    Node child = nl.item(i);
	    // Comprobamos que el elemento hijo sea un nodo y que no sea el
	    // elemento KeyInfo
	    if (child.getNodeType() == Node.ELEMENT_NODE && child.getLocalName().equals(IXMLConstants.ELEMENT_OBJECT)) {
		NodeList childsObject = child.getChildNodes();
		int j = 0;
		while (qualifyingProperties == null && j < childsObject.getLength()) {
		    if (childsObject.item(j).getNodeType() == Node.ELEMENT_NODE && childsObject.item(j).getLocalName().equals(IXMLConstants.ELEMENT_QUALIFIYING_PROPERTIES)) {
			qualifyingProperties = (Element) childsObject.item(j);
		    }
		    j++;
		}
	    }
	}
	// Si hemos accedido al elemento QualifyingProperties
	if (qualifyingProperties != null) {
	    try {
		// Asociamos el elemento QualifyingProperties
		signerInfo.setQualifyingPropertiesElement(qualifyingProperties);

		// Recorremos la lista de elementos hijos del elemento
		// xades:QualifyingProperties buscando el elemento
		// obligatorio xades:SignedProperties
		Element signedPropertiesElement = UtilsXML.getChildElement(signerInfo.getQualifyingPropertiesElement(), IXMLConstants.ELEMENT_SIGNED_PROPERTIES, signerInfo.getId(), true);

		// Recuperamos el elemento obligatorio
		// xades:SignedSignatureProperties
		Element signedSignaturePropertiesElement = UtilsXML.getChildElement(signedPropertiesElement, IXMLConstants.ELEMENT_SIGNED_SIGNATURE_PROPERTIES, signerInfo.getId(), true);

		// Recuperamos el certificado firmante y lo asociamos a la
		// información del firmante
		signerInfo.setSigningCertificate(retrieveSigningCertificateOfXMLSigner(signedSignaturePropertiesElement, signerInfo.getId(), signerInfo.getElementSignature()));

		// Comprobamos si el firmante posee el elemento ArchiveTimeStamp
		setHasArchiveTimeStamp(qualifyingProperties, signerInfo);

		// Asociamos los sellos de tiempo contenidos en los elementos
		// xades:SignatureTimeStamp, ordenados ascendentemente por fecha
		// de
		// generación, en caso de existir
		setTimestamps(qualifyingProperties, signerInfo);

		// Procesamos el conjunto de contrafirmas
		processXMLCounterSigners(qualifyingProperties, signerInfo);
	    } catch (Exception e) {
		// Sello de tiempo ASN.1 incorrecto
		signerInfo.setErrorMsg(e.getMessage());
	    }
	}
    }

    /**
     * Method that validates the signer of a XAdES signature.
     * @param xmlSignature Parameter that represents the XAdES signature.
     * @param signingCertificate Parameter that represents the signing certificate
     * @param tst Parameter that represents the RFC 3161 timestamp associated to the signer.
     * @param xmlTst Parameter that represents the XML timestamp associated to the signer.
     * @param signingMode Parameter that represents the signing mode of the XAdES signature. The possible values are:
     * <ul>
     * <li>{@link IUtilsSignature#DETACHED_SIGNATURE_MODE}</li>
     * <li>{@link IUtilsSignature##ENVELOPED_SIGNATURE_MODE}</li>
     * <li>{@link IUtilsSignature##ENVELOPING_SIGNATURE_MODE}</li>
     * </ul>
     * @param signedFile Parameter that represents the file signed by the XML signature when the signed data isn't included into the signed XML document.
     * @param signedFileName Parameter that represents the name of the file signed by the XML signature when the signed data isn't included into the signed XML document.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the validation fails.
     */
    public static void validateXAdESSigner(org.apache.xml.security.signature.XMLSignature xmlSignature, X509Certificate signingCertificate, TimeStampToken tst, Element xmlTst, String signingMode, byte[ ] signedFile, String signedFileName, String idClient) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG070));
	try {
	    // Comprobamos que se ha indicado la firma XML
	    GenericUtilsCommons.checkInputParameterIsNotNull(xmlSignature, Language.getResIntegra(ILogConstantKeys.US_LOG039));

	    // Comprobamos que se ha indicado el certificado firmante
	    GenericUtilsCommons.checkInputParameterIsNotNull(signingCertificate, Language.getResIntegra(ILogConstantKeys.US_LOG002));

	    // Definimos la fecha de validación para el certificado como la
	    // fecha
	    // actual
	    Date validationDate = Calendar.getInstance().getTime();

	    // Si hay un sello de tiempo ASN.1 asociado
	    if (tst != null) {
		// Establecemos la fecha de validación como la fecha del
		// sello de tiempo
		validationDate = tst.getTimeStampInfo().getGenTime();

		// Llevamos a cabo la validación del sello de tiempo
		UtilsTimestampXML.validateASN1Timestamp(tst);
	    }
	    // Si hay un sello de tiempo XML asociado
	    else if (xmlTst != null) {
		// Establecemos la fecha de validación como la fecha del
		// sello de tiempo
		validationDate = UtilsTimestampXML.getGenTimeXMLTimestamp(xmlTst);

		// Llevamos a cabo la validación del sello de tiempo
		UtilsTimestampXML.validateXMLTimestamp(xmlTst);
	    }

	    // Validamos el certificado firmante
	    validateCertificate(signingCertificate, validationDate, false, idClient, false);

	    // Accedemos al elemento KeyInfo
	    KeyInfo keyInfo = xmlSignature.getKeyInfo();

	    if (keyInfo != null) {
		try {
		    // Antes de validar la firma comprobamos si se ha indicado
		    // el fichero externo y su nombre, representando los datos
		    // firmados. En ese caso, deberemos añadir un elemento para
		    // procesar
		    // ese fichero firmado que no está incluido en la firma
		    if (signedFile != null && signedFileName != null) {
			ExternalFileURIDereferencer ext = new ExternalFileURIDereferencer(signedFile, signedFileName);
			xmlSignature.addResourceResolver(ext);
		    }
		    // Validamos la firma usando el certificado firmante
		    if (!xmlSignature.checkSignatureValue(signingCertificate)) {
			String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG030);
			LOGGER.error(errorMsg);
			throw new SigningException(errorMsg);
		    }
		} catch (org.apache.xml.security.signature.XMLSignatureException e) {
		    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG033);
		    LOGGER.error(errorMsg, e);
		    throw new SigningException(errorMsg, e);
		}
	    } else {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG040);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    // Comprobamos si la firma es EPES, es decir, si tiene el elemento
	    // firmado SignaturePolicyIdentifier
	    Element dsSignature = xmlSignature.getElement();
	    if (SignatureFormatDetectorXades.hasSignaturePolicyIdentifier(dsSignature)) {
		// Validamos la política de firma asociada al firmante
		try {
		    SignaturePolicyManager.validateXAdESEPESSignature(dsSignature, null, signingMode, idClient);
		} catch (SignaturePolicyException e) {
		    String errorMsg = e.getMessage();
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg, e);
		}
	    }

	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG071));
	}
    }

    /**
     * Method that adds a certificate to a certificates store.
     * @param certificates Parameter that represents the certificates store.
     * @param certificate Parameter that represents the certificate to add.
     * @return the upgraded certificates store.
     * @throws SigningException If the method fails.
     */
    public static Store addCertificateToStore(Store certificates, X509Certificate certificate) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG095));
	try {
	    // Comprobamos que se ha indicado el almacén de certificados
	    GenericUtilsCommons.checkInputParameterIsNotNull(certificates, Language.getResIntegra(ILogConstantKeys.US_LOG097));

	    // Comprobamos que se ha indicado el certificado que añadir
	    GenericUtilsCommons.checkInputParameterIsNotNull(certificate, Language.getResIntegra(ILogConstantKeys.US_LOG002));

	    Collection<X509CertificateHolder> certAuxCol = certificates.getMatches(null);
	    certAuxCol.add(new X509CertificateHolder(certificate.getEncoded()));
	    return new JcaCertStore(certAuxCol);
	} catch (Exception e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG098);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG096));
	}
    }

    /**
     * Method that obtains the CAdES structure of an ASN.1 signature.
     * @param signature Parameter that represents the ASN.1 signature.
     * @return an object that represents the CAdES structure.
     * @throws SigningException If the method fails.
     */
    public static CMSSignedData getCMSSignedData(byte[ ] signature) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG100));
	try {
	    // Comprobamos que se ha indicado la firma
	    GenericUtilsCommons.checkInputParameterIsNotNull(signature, Language.getResIntegra(ILogConstantKeys.US_LOG039));

	    return new CMSSignedData(signature);
	} catch (CMSException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG099);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG101));
	}
    }

    /**
     * Method that indicates whether a pdf dictionary is a document Time-stamp dictionary (true) or not (false).
     * @param pdfType Parameter that represents the value of /Type entry.
     * @param subFilter Parameter that represents the value of /SubFilter entry.
     * @return a boolean that indicates whether a pdf dictionary is a document Time-stamp dictionary (true) or not (false).
     */
    public static boolean isDocumentTimeStampDictionary(String pdfType, String subFilter) {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG102));
	try {
	    if (subFilter.equals(TST_SUBFILTER_VALUE.toString()) && (pdfType == null || pdfType != null && pdfType.equals(DOC_TIME_STAMP_DICTIONARY_NAME.toString()))) {
		return true;
	    }
	    return false;
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG103));
	}
    }

    /**
     * Method that indicates whether a pdf dictionary is a signature dictionary (true) or not (false).
     * @param pdfType Parameter that represents the value of /Type entry.
     * @param subFilter Parameter that represents the value of /SubFilter entry.
     * @return a boolean that indicates whether a pdf dictionary is a signature dictionary (true) or not (false).
     */
    public static boolean isSignatureDictionary(String pdfType, String subFilter) {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG104));
	try {
	    if ((pdfType == null || pdfType != null && pdfType.equals(PdfName.SIG.toString())) && !subFilter.equals(TST_SUBFILTER_VALUE.toString())) {
		return true;
	    }
	    return false;
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG105));
	}
    }

    /**
     * Method that checks, for the signature contained inside of a signature dictionary of a PDF document, if the signature contains the <code>content-type</code> attribute and it has the value "id-data".
     * @param signedAttr Parameter that represents the signed attributes of the CAdES signature contained inside of the signature dictionary.
     * @param signatureName Parameter that represents the name of the signature dictionary.
     * @throws SigningException If the validation fails.
     */
    private static void checkContentTypeAttributeForPAdESSignature(AttributeTable signedAttr, String signatureName) throws SigningException {
	Attribute contentTypeAttribute = signedAttr.get(PKCSObjectIdentifiers.pkcs_9_at_contentType);
	if (contentTypeAttribute == null) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG016, new Object[ ] { signatureName });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	} else if (!contentTypeAttribute.getAttrValues().getObjectAt(0).getDERObject().equals(PKCSObjectIdentifiers.data)) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG017, new Object[ ] { signatureName });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that checks, for the signature contained inside of a signature dictionary of a PDF document:
     * <ul>
     * <li>If the SignedData field is explicit.</li>
     * <li>If the signature contains the <code>content-type</code> attribute and it has the value "id-data".</li>
     * <li>If the signature dictionary doesn't contain <code>/Cert</code> entry.</li>
     * <li>If the signature dictionary contain the signing time inside of <code>/M</code> entry and it's after than the validation date.</li>
     * </ul>
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @param signedData Parameter that represents the signed data.
     * @param validationDate Parameter that represents the date defined for validating the signature. If this values is <code>null</code> the validation date will be the current date.
     * @throws SigningException If the validation fails.
     */
    public static void validatePAdESBaselineMandatoryAttributes(PDFSignatureDictionary signatureDictionary, CMSSignedData signedData, Date validationDate) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG106));
	try {
	    // Comprobamos que se han indicado los datos del diccionario de
	    // firma que contiene la firma PAdES Baseline
	    GenericUtilsCommons.checkInputParameterIsNotNull(signatureDictionary, Language.getResIntegra(ILogConstantKeys.US_LOG007));
	    GenericUtilsCommons.checkInputParameterIsNotNull(signedData, Language.getResIntegra(ILogConstantKeys.US_LOG019));

	    // Comprobamos si se ha indicado la fecha de validación, en caso
	    // contrario, la establecemos como la fecha actual
	    Date vDate = validationDate;
	    if (vDate == null) {
		vDate = Calendar.getInstance().getTime();
	    }

	    /*
	     * Validación 1: La firma debe ser explícita.
	     */
	    if (isImplicit(signedData)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG108, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Accedemos al firmante
	    SignerInformation signerInformation = ((List<SignerInformation>) signedData.getSignerInfos().getSigners()).iterator().next();

	    // Obtenemos el conjunto de atributos firmados
	    AttributeTable signedAttr = signerInformation.getSignedAttributes();

	    /*
	     * Validación 2: El atributo content-type no puede ser nulo y debe tener el valor "id-data".
	     */
	    checkContentTypeAttributeForPAdESSignature(signedAttr, signatureDictionary.getName());

	    /*
	     * Validación 3: La clave /Cert del diccionario de firma no debe usarse.
	     */
	    if (signatureDictionary.getDictionary().getAsName(PdfName.CERT) != null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG018, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    /*
	     * Validación 4: La clave /M del diccionario de firma no puede ser nula y debe contener la fecha de firma en formato UTC.
	     */
	    if (signatureDictionary.getDictionary().get(PdfName.M) == null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG109, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    } else {
		// Accedemos al contenido de la clave /M
		String mTimeStr = signatureDictionary.getDictionary().getAsString(PdfName.M).toString();

		// Comprobamos que el formato de la fecha es correcto
		Date mTime = parseToPDFDate(mTimeStr);
		if (mTime == null) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG110, new Object[ ] { signatureDictionary.getName() });
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
		// Comprobamos que la fecha contenida en la clave /M es anterior
		// a
		// la fecha de validación
		Calendar cal = Calendar.getInstance();
		cal.setTime(vDate);
		if (mTime.after(vDate)) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG110, new Object[ ] { signatureDictionary.getName() });
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}

	    }
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG107));
	}

    }

    /**
     * Method that checks, for the signature contained inside of a signature dictionary of a PDF document:
     * <ul>
     * <li>If the signature doesn't contain the <code>counter-signature</code> attribute.</li>
     * <li>If the signature doesn't contain the <code>content-reference</code> attribute.</li>
     * </ul>
     * @param signerInformation Parameter that represents the information about the signer of the CAdES signature contained inside of the signature dictionary.
     * @param signatureName Parameter that represents the name of the signature dictionary.
     * @throws SigningException If the validation fails.
     */
    private static void validatePAdESBaselineOptionalUnsignedAttributes(SignerInformation signerInformation, String signatureName) throws SigningException {
	// Obtenemos el conjunto de atributos no firmados
	AttributeTable unsignedAttr = signerInformation.getUnsignedAttributes();

	if (unsignedAttr != null) {
	    /*
	     * Validación 1: El atributo counter-signature no debe usarse.
	     */
	    if (unsignedAttr.get(PKCSObjectIdentifiers.pkcs_9_at_counterSignature) != null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG020, new Object[ ] { signatureName });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    /*
	     * Validación 2: El atributo content-reference no debe usarse.
	     */
	    if (unsignedAttr.get(PKCSObjectIdentifiers.id_aa_contentReference) != null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG021, new Object[ ] { signatureName });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	}
    }

    /**
     * Method that checks, for the signature contained inside of a signature dictionary of a PDF document:
     * <ul>
     * <li>If the signature doesn't contain the <code>signing-time</code> attribute.</li>
     * <li>If the signature doesn't contain the <code>counter-signature</code> attribute.</li>
     * <li>If the signature doesn't contain the <code>content-reference</code> attribute.</li>
     * <li>If the signature doesn't contain the <code>content-identifier</code> attribute.</li>
     * <li>If the signature doesn't contain the <code>content-hints</code> attribute.</li>
     * <li>If the signature doesn't contain the <code>commitment-type-indication</code> attribute.</li>
     * <li>If the signature doesn't contain the <code>signer-location</code> attribute.</li>
     * </ul>
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @param signedData Parameter that represents the signed data.
     * @throws SigningException If the validation fails.
     */
    public static void validatePAdESBaselineOptionalAttributes(PDFSignatureDictionary signatureDictionary, CMSSignedData signedData) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG112));
	try {
	    // Comprobamos que se han indicado los datos del diccionario de
	    // firma que contiene la firma PAdES Baseline
	    GenericUtilsCommons.checkInputParameterIsNotNull(signatureDictionary, Language.getResIntegra(ILogConstantKeys.US_LOG007));
	    GenericUtilsCommons.checkInputParameterIsNotNull(signedData, Language.getResIntegra(ILogConstantKeys.US_LOG019));

	    // Accedemos al firmante
	    SignerInformation signerInformation = ((List<SignerInformation>) signedData.getSignerInfos().getSigners()).iterator().next();

	    // Validamos los atributos no firmados, esto es, que los atributos
	    // counter-signature y content-reference no se usen
	    validatePAdESBaselineOptionalUnsignedAttributes(signerInformation, signatureDictionary.getName());

	    // Obtenemos el conjunto de atributos firmados
	    AttributeTable signedAttr = signerInformation.getSignedAttributes();

	    /*
	     * Validación 1: El atributo signing-time no debe usarse.
	     */
	    if (signedAttr.get(PKCSObjectIdentifiers.pkcs_9_at_signingTime) != null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG026, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    /*
	     * Validación 2: El atributo content-identifier no debe usarse.
	     */
	    if (signedAttr.get(PKCSObjectIdentifiers.id_aa_contentIdentifier) != null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG022, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    /*
	     * Validación 3: El atributo content-hints no debe usarse.
	     */
	    if (signedAttr.get(PKCSObjectIdentifiers.id_aa_contentHint) != null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG027, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    /*
	     * Validación 4: El atributo commitment-type-indication no debe usarse si la firma no contiene el atributo signature-policy-id.
	     */
	    if (signedAttr.get(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId) == null && signedAttr.get(PKCSObjectIdentifiers.id_aa_ets_commitmentType) != null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG024, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    /*
	     * Validación 5: El atributo signer-location no debe usarse.
	     */
	    if (signedAttr.get(PKCSObjectIdentifiers.id_aa_ets_signerLocation) != null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG025, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG113));
	}

    }

    /**
     * Method that obtains a <code>Signature</code> element from a XML document.
     * @param document Parameter that represents the XML document.
     * @param signatureId Parameter that represents the attribute <code>Id</code> of the element to obtain.
     * @return an objects that represents the <code>Signature</code> element, or <code>null</code>.
     * @throws SigningException If the element is <code>null</code>.
     */
    public static Element getXMLSignatureById(Document document, String signatureId) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG114));

	try {
	    // Comprobamos que se ha indicado el documento XML
	    // Comprobamos que se ha indicado el documento XML firmado
	    GenericUtilsCommons.checkInputParameterIsNotNull(document, Language.getResIntegra(ILogConstantKeys.US_LOG037));

	    // Comprobamos que se ha indicado el identificador de la firma a
	    // obtener
	    GenericUtilsCommons.checkInputParameterIsNotNull(signatureId, Language.getResIntegra(ILogConstantKeys.US_LOG116));

	    NodeList listSignatures = document.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_SIGNATURE);
	    Element dsSignature = null;
	    int i = 0;
	    while (dsSignature == null && i < listSignatures.getLength()) {
		if (((Element) listSignatures.item(i)).getAttribute(IXMLConstants.ATTRIBUTE_ID).equals(signatureId)) {
		    dsSignature = (Element) listSignatures.item(i);
		}
		i++;
	    }
	    return dsSignature;

	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG115));
	}
    }

    /**
     * Method that obtains the signature mode of a signed XML document.
     * @param xmlDocument Parameter that represents the signed XML document.
     * @return four possible values:
     * <ul>
     * <li>{@link SignatureConstants#SIGN_FORMAT_XADES_ENVELOPING}</li>
     * <li>{@link SignatureConstants#SIGN_FORMAT_XADES_ENVELOPED}</li>
     * <li>{@link SignatureConstants#SIGN_FORMAT_XADES_DETACHED}</li>
     * <li>{@link SignatureConstants#SIGN_FORMAT_XADES_EXTERNALLY_DETACHED}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    public static String getTypeOfXMLSignature(Document xmlDocument) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG117));
	try {
	    // Comprobamos que se ha indicado el documento XML firmado
	    GenericUtilsCommons.checkInputParameterIsNotNull(xmlDocument, Language.getResIntegra(ILogConstantKeys.US_LOG037));

	    // Accedemos al nodo raíz
	    String rootName = xmlDocument.getDocumentElement().getNodeName();

	    // Si el nodo raíz es ds:Signature, entonces es una firma
	    // XAdES Enveloping
	    if (rootName.equalsIgnoreCase(IXMLConstants.DS_SIGNATURE_NODE_NAME) || rootName.equals(IXMLConstants.ROOT_COSIGNATURES_TAG)) {
		return SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING;
	    } else {
		// Si contiene un nodo <ds:Manifest> es una firma XAdES
		// Externally
		// Detached
		NodeList signatureNodeLs = xmlDocument.getElementsByTagName(IXMLConstants.MANIFEST_TAG_NAME);
		if (signatureNodeLs.getLength() > 0) {
		    return SignatureConstants.SIGN_FORMAT_XADES_EXTERNALLY_DETACHED;
		}

		NodeList signsList = xmlDocument.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_SIGNATURE);
		if (signsList.getLength() == 0) {
		    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG119);
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
		// Si contiene alguna referencia con la URI "" se trata de una
		// firma
		// XAdES Enveloped
		Node signatureNode = signsList.item(0);
		XMLSignature xmlSignature;
		try {
		    xmlSignature = new XMLSignatureElement((Element) signatureNode).getXMLSignature();
		} catch (MarshalException e) {
		    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG120);
		    LOGGER.error(errorMsg, e);
		    throw new SigningException(errorMsg, e);
		}
		// Tomamos las referencias de la firma
		List<Reference> references = xmlSignature.getSignedInfo().getReferences();

		// Buscamos la referencia con URI=""
		for (int i = 0; i < references.size(); i++) {
		    if (references.get(i).getURI().isEmpty()) {
			return SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED;
		    }
		}
		return SignatureConstants.SIGN_FORMAT_XADES_DETACHED;
	    }
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG118));
	}
    }

    /**
     * Method that obtains the original data from a signed XML document.
     * @param xmlDocument Parameter that represents the signed XML document.
     * @return the original unsigned data.
     * @throws SigningException If the method fails.
     */
    public static byte[ ] getOriginalDataFromSignedXMLDocument(Document xmlDocument) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG121));
	try {
	    // Comprobamos que se ha indicado el documento XML firmado
	    GenericUtilsCommons.checkInputParameterIsNotNull(xmlDocument, Language.getResIntegra(ILogConstantKeys.US_LOG037));

	    byte[ ] result = null;
	    // Obtención de cualquiera de las firmas para obtener el documento
	    // original.
	    NodeList signNodeList = xmlDocument.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_SIGNATURE);
	    if (signNodeList.getLength() == 0) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG119);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    // Se selecciona la primera firma.
	    Element signatureNode = (Element) signNodeList.item(0);
	    // registro de los id de los nodos
	    IdRegister.registerElements(signatureNode);

	    XMLSignature xmlSign;
	    try {
		xmlSign = new XMLSignatureElement((Element) signatureNode).getXMLSignature();
	    } catch (MarshalException e) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG123);
		LOGGER.error(errorMsg, e);
		throw new SigningException(errorMsg, e);
	    }

	    // Obtención de la referencia del documento original.
	    List<?> references = xmlSign.getSignedInfo().getReferences();
	    XMLSignatureInput xmlObjectInput = null;
	    for (Object tmp: references) {
		Reference ref = (Reference) tmp;
		Attr uriAttr = (Attr) ((DOMReference) ref).getHere();
		ResourceResolver res;
		try {
		    res = ResourceResolver.getInstance(uriAttr, null);
		    xmlObjectInput = res.resolve(uriAttr, null);
		} catch (ResourceResolverException e) {
		    continue;
		}

		Node dsObject = xmlObjectInput.getSubNode();
		if ("ds:Object".equals(dsObject.getNodeName()) && !IXMLConstants.ELEMENT_QUALIFIYING_PROPERTIES.equals(dsObject.getFirstChild().getLocalName())) {
		    NodeList nodeListObject = dsObject.getChildNodes();
		    if (nodeListObject.getLength() == 1) {
			Node children = dsObject.getFirstChild();
			result = transformNode(children);
		    } else {
			StringBuffer buffer = new StringBuffer();
			for (int i = 0; i < nodeListObject.getLength(); i++) {
			    Node children = nodeListObject.item(i);
			    byte[ ] nodeValue = transformNode(children);
			    if (nodeValue != null) {
				buffer.append(new String(nodeValue));
			    }
			}
			result = buffer.toString().getBytes();
		    }
		    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG124, new Object[ ] { new String(result) }));
		    return result;
		}
	    }
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG125));
	    return result;
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG122));
	}

    }

    /**
     * Method that obtains the content of a node as a String.
     * @param node Parameter that represents the node to process.
     * @return the content of a node as a String.
     * @throws SigningException If the method fails.
     */
    private static byte[ ] transformNode(Node node) throws SigningException {
	try {
	    if (node.getNodeType() == Node.TEXT_NODE || node.getNodeType() == Node.CDATA_SECTION_NODE) {
		String textValue = ((Text) node).getData();
		return textValue == null ? null : textValue.getBytes();
	    } else if (node.getNodeType() == Node.ELEMENT_NODE) {
		return UtilsXML.transformDOMtoString((Element) node, true).getBytes();
	    } else {
		return null;
	    }
	} catch (TransformersException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG123);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}
    }

    /**
     * Method that composes and obtains a XML document with the root node &lt;ROOT_COSIGNATURES&gt; for adding new cosigns
     * over that (on enveloping signature mode). If the received signature is wrapped in this element, the element is returned without
     * modifications. In another case, the wrapper is created and the sign is added, if isn't null.
     * @param xmlDocument Parameter that represents the XML signature. It can be <code>null</code>.
     * @param dBFactory Parameter that represents a factory for building XML documents.
     * @return a XML document with the root node &lt;ROOT_COSIGNATURES&gt; and the signature as a children node.
     * @throws SigningException If the method fails.
     */
    public static Document composeCoSignaturesDocument(Document xmlDocument, DocumentBuilderFactory dBFactory) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG126));
	try {
	    // Comprobamos que se ha indicado la factoría de documentos XML
	    GenericUtilsCommons.checkInputParameterIsNotNull(dBFactory, Language.getResIntegra(ILogConstantKeys.US_LOG128));

	    Document newDocument = null;
	    if (xmlDocument != null) {
		if (xmlDocument.getFirstChild().getNodeName().equals(IXMLConstants.ROOT_COSIGNATURES_TAG)) {
		    return xmlDocument;
		}
		newDocument = dBFactory.newDocumentBuilder().parse(new ByteArrayInputStream(new String("<" + IXMLConstants.ROOT_COSIGNATURES_TAG + "/>").getBytes()));
		Node tempNode = newDocument.importNode(xmlDocument.getFirstChild(), true);
		newDocument.getFirstChild().appendChild(tempNode);
	    } else {
		newDocument = dBFactory.newDocumentBuilder().parse(new ByteArrayInputStream(new String("<" + IXMLConstants.ROOT_COSIGNATURES_TAG + "/>").getBytes()));
	    }

	    return newDocument;
	} catch (SAXException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG129);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (IOException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG129);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (ParserConfigurationException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG129);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}

	finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG127));
	}
    }

    /**
     * Method that appends a XML document to certain signed XML document.
     * @param xmlDocument Parameter that represents the signed XML document.
     * @param documentToAppend Parameter that represents the XML document to append to the signed XML document.
     * @throws SigningException If the method fails.
     */
    public static void appendXMLDocument(Document xmlDocument, Document documentToAppend) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG130));
	try {
	    // Comprobamos que se ha indicado el documento XML firmado
	    GenericUtilsCommons.checkInputParameterIsNotNull(xmlDocument, Language.getResIntegra(ILogConstantKeys.US_LOG037));

	    // Si se ha indicado el documento XML que añadir
	    if (documentToAppend != null) {
		Node tempNode = xmlDocument.importNode(documentToAppend.getFirstChild(), true);
		xmlDocument.getFirstChild().appendChild(tempNode);
	    }
	} catch (DOMException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG129);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG131));
	}
    }

    /**
     * Method that obtains the value of the attribute <code>Id</code> of the <code>Content</code> node of the wrapper, or an empty String if the signed XML document doesn't contain that attribute
     * (wrapper signed on enveloped mode).
     * @param xmlDocument Parameter that represents the signed XML document.
     * @return the value of the attribute <code>Id</code> of the <code>Content</code> node of the wrapper, or an empty String if the signed XML document doesn't contain that attribute
     * (wrapper signed on enveloped mode).
     * @throws SigningException If the method fails.
     */
    public static String getSignedElementIdValue(Document xmlDocument) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG132));
	try {
	    // Comprobamos que se ha indicado el documento XML firmado
	    GenericUtilsCommons.checkInputParameterIsNotNull(xmlDocument, Language.getResIntegra(ILogConstantKeys.US_LOG037));

	    NodeList nodes = xmlDocument.getElementsByTagName(IXMLConstants.CONTENT_TAG);
	    if (nodes.getLength() != 1) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG134);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    NamedNodeMap attributes = nodes.item(0).getAttributes();
	    for (int i = 0; i < attributes.getLength(); i++) {
		Node attribute = attributes.item(i);
		if (IXMLConstants.ATTRIBUTE_ID.equalsIgnoreCase(attribute.getNodeName())) {
		    return attribute.getNodeValue();
		}
	    }
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG135);
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG133));
	}
    }

    /**
     * Method that defines the <code>AFIRMA</code> node as root node of a signed XML document.
     * @param xmlDocument Parameter that represents the signed XML document.
     * @param dBFactory Parameter that represents a factory for building XML documents.
     * @return the updated signed XML document.
     * @throws SigningException If the method fails.
     */
    public static Document insertAfirmaRootNode(Document xmlDocument, DocumentBuilderFactory dBFactory) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG136));
	try {
	    // Comprobamos que se ha indicado el documento XML firmado
	    GenericUtilsCommons.checkInputParameterIsNotNull(xmlDocument, Language.getResIntegra(ILogConstantKeys.US_LOG037));

	    // Comprobamos que se ha indicado la factoría de documentos XML
	    GenericUtilsCommons.checkInputParameterIsNotNull(dBFactory, Language.getResIntegra(ILogConstantKeys.US_LOG128));

	    // Crea un nuevo documento con la raiz "AFIRMA"
	    Document docAfirma = dBFactory.newDocumentBuilder().newDocument();
	    Element rootAfirma = docAfirma.createElement(IXMLConstants.AFIRMA_TAG);

	    // Inserta el documento pasado por parametro en el nuevo documento
	    rootAfirma.appendChild(docAfirma.adoptNode(xmlDocument.getDocumentElement()));
	    docAfirma.appendChild(rootAfirma);

	    return docAfirma;
	} catch (ParserConfigurationException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG129);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG137));
	}
    }

    /**
     * Method that obtains from a root element the list of <code>ds:Signature</code> elements to add <code>xades:CounterSignature</code> element.
     * The method only obtains the signature element withouth any signature element child.
     * @param rootElement Parameter that represents the root element of the XML document.
     * @return a list with the <code>ds:Signature</code> elements to add <code>xades:CounterSignature</code> element.
     */
    public static List<Element> getListSignaturesToCounterSign(Element rootElement) {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG138));
	try {
	    // Comprobamos que se ha indicado el elemento raíz
	    GenericUtilsCommons.checkInputParameterIsNotNull(rootElement, Language.getResIntegra(ILogConstantKeys.US_LOG140));

	    // Instanciamos una lista donde ubicar los elementos que no
	    // contengan
	    // contrafirmas o subnodos de firma y que además no sean sellos de
	    // tiempo
	    List<Element> listSignaturesToCounterSign = new ArrayList<Element>();

	    // Obtenemos el conjunto de firmas
	    NodeList signList = rootElement.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_SIGNATURE);
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.XS_LOG052, new Object[ ] { signList.getLength() }));
	    for (int i = 0; i < signList.getLength(); i++) {
		Element signElement = (Element) signList.item(i);

		// Comprobamos que la firma no haga referencia a la firma de un
		// sello de tiempo XML
		if (!IXMLConstants.ELEMENT_XML_TIMESTAMP.equals(signElement.getParentNode().getLocalName()) && !IXMLConstants.ELEMENT_TIMESTAMP.equals(signElement.getParentNode().getLocalName())) {
		    // Obtenemos el conjunto de firmas contenidas dentro de la
		    // firma
		    NodeList childSignatures = signElement.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_SIGNATURE);

		    // Si el elemento ds:Signature no tiene a su vez más nodos
		    // ds:Signature hijos, o bien, si tiene elementos
		    // ds:Signature hijos pero dichos elementos tienen como
		    // padre un
		    // elemento XMLTimeStamp
		    if (childSignatures.getLength() == 0) {
			// Añadimos el elemento a la lista de firmas a las que
			// añadir la
			// contrafirma
			listSignaturesToCounterSign.add(signElement);
		    } else {
			boolean enc = false;
			int j = 0;
			while (!enc && j < childSignatures.getLength()) {
			    Element signatureNode = (Element) childSignatures.item(j);
			    if (!IXMLConstants.ELEMENT_XML_TIMESTAMP.equals(signatureNode.getParentNode().getLocalName()) && !IXMLConstants.ELEMENT_TIMESTAMP.equals(signatureNode.getParentNode().getLocalName())) {
				enc = true;
			    }
			    j++;
			}
			if (!enc) {
			    // Añadimos el elemento a la lista de firmas a las
			    // que
			    // añadir la
			    // contrafirma
			    listSignaturesToCounterSign.add(signElement);
			}
		    }
		}
	    }
	    return listSignaturesToCounterSign;
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG139));
	}
    }

    /**
     * Method that obtains an element from a XML document.
     * @param parentNode Parameter that represents the parent node of the element to retrieve.
     * @param nodeName Parameter that represents the name of the element to retrieve.
     * @param namespaceURI Parameter that represents the namespace URI of the element to match on. The special value "*" matches all namespaces.
     * @param isRequired Parameter that indicates if the element to retrieve is required (true) or not (false).
     * @return an object that represents the XML element.
     * @throws SigningException If the XML document doesn't contain the required element.
     */
    public static Element retrieveNode(Element parentNode, String nodeName, String namespaceURI, boolean isRequired) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG141));
	try {
	    // Comprobamos que se ha indicado el elemento padre
	    GenericUtilsCommons.checkInputParameterIsNotNull(parentNode, Language.getResIntegra(ILogConstantKeys.US_LOG143));

	    // Comprobamos que se ha indicado el nombre del elemento
	    GenericUtilsCommons.checkInputParameterIsNotNull(nodeName, Language.getResIntegra(ILogConstantKeys.US_LOG144));

	    // Comprobamos que se ha indicado la URI del espacio de nombres al
	    // que pertenece el elemento
	    GenericUtilsCommons.checkInputParameterIsNotNull(namespaceURI, Language.getResIntegra(ILogConstantKeys.US_LOG145));

	    Element element = null;
	    NodeList nodeList = parentNode.getElementsByTagNameNS(namespaceURI, nodeName);
	    if (nodeList.getLength() == 0) {
		if (isRequired) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG146, new Object[ ] { nodeName });
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
	    } else {
		element = (Element) nodeList.item(0);
	    }
	    return element;
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG142));
	}
    }

    /**
     * Method that indicates if the signature is an XMLTimeStamp element by the OASIS-DSS specifications (true) or not (false).
     * @param eSignature Parameter that represents the XML signature.
     * @return a boolean that indicates if the signature is an XMLTimeStamp element by the OASIS-DSS specifications (true) or not (false).
     */
    public static boolean isDSSTimestamp(Node eSignature) {
	Node parent = eSignature.getParentNode();
	if (parent != null) {
	    return parent.getNodeName().substring(parent.getNodeName().indexOf(":") + 1).equals("XMLTimeStamp");
	}
	return false;
    }

    /**
     * Method that obtains the first revision of the signature dictionary.
     * 
     * @param pdfDocument Parameter that represents the PDF document.
     * @return an input stream that represents the revision, or <code>null</code> if the PDF document doesn't contain any signature dictionary.
     * @throws SigningException exception if any error
     */
    public static byte[ ] obtainFirstRevision(byte[ ] pdfDocument) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG149));
	String signatureName = null;
	byte[ ] buffer = null;
	try {

	    PdfReader reader = new PdfReader(pdfDocument);
	    // Instanciamos un objeto para leer las firmas
	    AcroFields af = reader.getAcroFields();

	    // Se obtiene el número total de revisiones
	    int totalRevisions = af.getTotalRevisions();

	    if (totalRevisions == 1) {
		// si solo hay una revisión, solo existe una firma
		// tenemos que buscar el trailer original
		buffer = getPreviousRevisionByTrailer(pdfDocument);
	    } else if (totalRevisions > 1) {
		// si el número de revisiones es mayor que 1, existen varias
		// firmas
		// Obtenemos la lista de firmas obtenidas.
		List<String> listSignatures = af.getSignatureNames();
		// recorremos la lista de firmas obtenidas
		for (int i = 0; i < listSignatures.size(); i++) {
		    // se guarda en una variable el nombre de la firma
		    signatureName = listSignatures.get(i);
		    // Se obtiene el diccionario de firma asociado
		    PdfDictionary signatureDictionary = af.getSignatureDictionary(signatureName);
		    // Se determina el tipo de diccionario obtenido
		    String pdfType = null;
		    if (signatureDictionary.get(PdfName.TYPE) != null) {
			pdfType = signatureDictionary.get(PdfName.TYPE).toString();
		    }
		    String pdfSubFilter = signatureDictionary.get(PdfName.SUBFILTER).toString();
		    // si el tipo de diccionario obtenido es un diccionario de
		    // firma
		    // y no un diccionario de tipo Document Time-Stamp
		    if (!pdfSubFilter.equalsIgnoreCase(new PdfName("ETSI.RFC3161").toString()) && (pdfType == null || pdfType.equalsIgnoreCase(PdfName.SIG.toString()))) {
			// se compara el número de revisión de la firma con el
			// que
			// tenemos, si es menor, actualizamos las variables
			int actuallyRevision = af.getRevision(signatureName);
			if (actuallyRevision < totalRevisions) {
			    totalRevisions = actuallyRevision;

			    buffer = getRevisionBySignature(af, signatureName);
			    // Buscamos el trailer anterior para obtener el
			    // documento
			    // original
			    buffer = getPreviousRevisionByTrailer(buffer);
			    // buffer = getRevisionBySignature(af,
			    // signatureName);
			}
		    }
		}
	    }
	} catch (IOException e) {
	    throw new SigningException(Language.getFormatResIntegra(ILogConstantKeys.US_LOG081, new Object[ ] { signatureName }), e);
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG150));
	}
	return buffer;
    }

    /**
     * 
     * Gets the previous document by locating the previous trailer.
     * 
     * @param signedDocument PDF document
     * @return byte array containing the previous document
     * @throws IOException if fails reading th document
     */
    private static byte[ ] getPreviousRevisionByTrailer(byte[ ] signedDocument) throws IOException {
	byte buffer[] = null;
	// Utilizamos el PRTokeniser que nos permitirá posicionarnos y leer del
	// fichero
	PRTokeniser rFile = new PRTokeniser(signedDocument);
	PdfReader reader = new PdfReader(signedDocument);
	// Obtenemos la sección Trailer
	PdfDictionary trailer = reader.getTrailer();
	// En la sección Trailer buscamos una entrada /Prev que nos indicará
	// la localización exacta de la Sección Cross-reference anterior
	if (trailer.getAsNumber(PdfName.PREV) != null) {
	    int pos = trailer.getAsNumber(PdfName.PREV).intValue();
	    // En posFinal almacenamos el la posición final del Trailer original
	    int posFinal = 0;
	    // Nos colocamos en la Sección Cross-reference anterior para buscar
	    // el final del Trailer
	    rFile.seek(pos);
	    int j = 0;
	    boolean encontrado = false;
	    do {
		j = rFile.read();
		// El final del Trailer viene delimitado por la cadena %%EOF
		if (j == '%') {
		    StringBuffer outBuf = new StringBuffer();
		    outBuf.append((char) j);
		    for (int n = 0; n < NumberConstants.INT_4; n++) {
			j = rFile.read();
			outBuf.append((char) j);
		    }
		    if ("%%EOF".equals(outBuf.toString())) {
			encontrado = true;
			posFinal = rFile.getFilePointer();
		    }
		}
	    }
	    while (j != -1 && !encontrado);

	    if (j == -1) {
		// error
	    }
	    buffer = new byte[posFinal];
	    // El documento original consta de todo el contenido desde la
	    // posición 0
	    // hasta el final del primer trailer
	    System.arraycopy(signedDocument, 0, buffer, 0, posFinal);
	}

	return buffer;
    }

    /**
     * Gets the revision asigned to the signature identifier.
     * 
     * @param fields AcroFields
     * @param signatureName signature identifier
     * @return Array of Bytes containing the revision
     * @throws IOException throws if fails extracting or reading the document
     */
    private static byte[ ] getRevisionBySignature(AcroFields fields, String signatureName) throws IOException {
	byte buffer[] = null;
	ByteArrayOutputStream baos = null;
	InputStream ip = null;
	try {
	    ip = fields.extractRevision(signatureName);
	    byte[ ] tempBuf = new byte[NumberConstants.INT_2048];
	    baos = new ByteArrayOutputStream();
	    int num = 0;
	    while ((num = ip.read(tempBuf)) > 0) {

		baos.write(tempBuf, 0, num);
	    }
	    buffer = baos.toByteArray();
	    baos.close();

	    return buffer;
	} catch (IOException e) {
	    throw e;
	} finally {
	    if (baos != null) {
		try {
		    baos.close();
		} catch (IOException e) {
		    throw e;
		} finally {
		    if (ip != null) {
			ip.close();
		    }
		}
	    } else {
		if (ip != null) {
		    ip.close();
		}
	    }
	}
    }

    /**
     * Method that checks if the signature includes a rubric.
     * 
     * @param externalParams Represents the optional input parameters.
     * @return boolean true if the signature includes rubric.
     */
    public static boolean checkExtraParamsSignWithRubric(Properties externalParams) {
	boolean rubric = false;
	byte[ ] image = null;
	String imageB64 = externalParams.getProperty(SignatureProperties.PADES_IMAGE);

	if (!GenericUtilsCommons.assertStringValue(imageB64)) {
	    // se comprueba si la imagen viene dada como byte[]
	    image = (byte[ ]) externalParams.get(SignatureProperties.PADES_IMAGE);
	}

	String imagePage = externalParams.getProperty(SignatureProperties.PADES_IMAGE_PAGE);
	String lowerLeftX = externalParams.getProperty(SignatureProperties.PADES_LOWER_LEFT_X);
	String lowerLeftY = externalParams.getProperty(SignatureProperties.PADES_LOWER_LEFT_Y);
	String upperRightX = externalParams.getProperty(SignatureProperties.PADES_UPPER_RIGHT_X);
	String upperRightY = externalParams.getProperty(SignatureProperties.PADES_UPPER_RIGHT_Y);
	if (GenericUtilsCommons.assertStringValue(imagePage) && GenericUtilsCommons.assertStringValue(lowerLeftX) && GenericUtilsCommons.assertStringValue(lowerLeftY) && GenericUtilsCommons.assertStringValue(upperRightX) && GenericUtilsCommons.assertStringValue(upperRightY)) {
	    if (image != null) {
		rubric = true;
	    } else if (GenericUtilsCommons.assertStringValue(imageB64)) {
		rubric = true;
	    }
	}
	return rubric;
    }

    /**
     * Method that inserts the rubric in a document.
     * @param reader Parameter representing the PDF to be signed.
     * @param signatureAppearance Parameter that represents the appearances that form a signature.
     * @param externalParams Represents the optional input parameters.
     * @throws SigningException If the method fails.
     */
    public static void insertRubric(PdfReader reader, PdfSignatureAppearance signatureAppearance, Properties externalParams) throws SigningException {

	try {
	    byte[ ] image = null;
	    // se obtiene los parametros relacionados con la rúbrica.
	    String pathImage = externalParams.getProperty(SignatureProperties.PADES_IMAGE);

	    if (!GenericUtilsCommons.assertStringValue(pathImage)) {
		// se comprueba si la imagen viene dada como byte[]
		image = (byte[ ]) externalParams.get(SignatureProperties.PADES_IMAGE);
	    }

	    int imagePage = Integer.parseInt(externalParams.getProperty(SignatureProperties.PADES_IMAGE_PAGE));
	    int lowerLeftX = Integer.parseInt(externalParams.getProperty(SignatureProperties.PADES_LOWER_LEFT_X));
	    int lowerLeftY = Integer.parseInt(externalParams.getProperty(SignatureProperties.PADES_LOWER_LEFT_Y));
	    int upperRightX = Integer.parseInt(externalParams.getProperty(SignatureProperties.PADES_UPPER_RIGHT_X));
	    int upperRightY = Integer.parseInt(externalParams.getProperty(SignatureProperties.PADES_UPPER_RIGHT_Y));

	    // cargamos imagen dependiendo del cómo venga especificada (array de
	    // byte o ruta donde se encuentra)
	    Image img = obtainRubric(image, pathImage);
	    // Loading Signature Image in Signature Appearance
	    signatureAppearance.setImage(img);

	    // numero de páginas que tiene el documento
	    int numPages = reader.getNumberOfPages();

	    if (imagePage == -1) {
		// se firma en la última página.
		signatureAppearance.setVisibleSignature(new Rectangle(lowerLeftX, lowerLeftY, upperRightX, upperRightY), numPages, null);
	    } else if (imagePage <= numPages) {

		signatureAppearance.setVisibleSignature(new Rectangle(lowerLeftX, lowerLeftY, upperRightX, upperRightY), imagePage, null);
	    } else {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG151);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	} catch (NumberFormatException e) {
	    LOGGER.error(e);
	    throw new SigningException(e);
	}
    }

    /**
     * Method that obtains an instance of the object Image with the image to be inserted into the document.
     * 
     * @param image Parameter that represents the image in a byte array.
     * @param imagePath Parameter that represent the path where the image is located.
     * @return Image.
     * @throws SigningException If the method fails.
     */
    private static Image obtainRubric(byte[ ] image, String imagePath) throws SigningException {
	Image img = null;
	try {
	    if (image != null) {
		// comprobamos que el formato sea permitido
		String mimetype = UtilsResourcesSignOperations.getMimeType(image).toUpperCase();
		if (!mimetype.contains("JPEG") && !mimetype.contains("PNG") && !mimetype.contains("GIF") && !mimetype.contains("BMP")) {
		    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG152);
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}

		img = Image.getInstance(image);

	    } else {
		// comprobamos que el formato sea el permitido
		String pathImageB64 = new String(Base64.decode(imagePath)).toUpperCase();
		if (!pathImageB64.endsWith("JPEG") && !pathImageB64.endsWith("PNG") && !pathImageB64.endsWith("GIF") && !pathImageB64.endsWith("BMP")) {
		    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG152);
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
		img = Image.getInstance(new String(Base64.decode(imagePath)));
	    }
	} catch (BadElementException e) {
	    LOGGER.error(e);
	    throw new SigningException(e);
	} catch (MalformedURLException e) {
	    LOGGER.error(e);
	    throw new SigningException(e);
	} catch (IOException e) {
	    LOGGER.error(e);
	    throw new SigningException(e);
	}
	return img;
    }

    /**
     * Method that validates the CAdES signature core associated to a signer.
     * @param signerInformation Parameter that represents the information about the signer.
     * @param signingCertificate Parameter that represents the certificate of the signer.
     * @param isPadesSignature Parameter that indicates if the signature is contained inside of a signature dictionary (true) or not (false).
     * @throws SigningException If the validation fails.
     */
    public static void validateCAdESSignatureCore(SignerInformation signerInformation, X509Certificate signingCertificate, boolean isPadesSignature) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG153));
	try {
	    // Comprobamos que se ha indicado la información asociada al
	    // firmante
	    GenericUtilsCommons.checkInputParameterIsNotNull(signerInformation, Language.getResIntegra(ILogConstantKeys.US_LOG032));

	    // Comprobamos que se ha indicado el certificado firmante
	    GenericUtilsCommons.checkInputParameterIsNotNull(signingCertificate, Language.getResIntegra(ILogConstantKeys.US_LOG002));

	    boolean signatureValid = false;
	    if (!isPadesSignature) {
		try {
		    // Validamos la información del firmante delegando en
		    // Bouncycastle
		    SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder().build(signingCertificate);
		    signatureValid = signerInformation.verify(signerInformationVerifier);
		} catch (OperatorCreationException e) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG073, new Object[ ] { signingCertificate.getSubjectDN().getName() });
		    LOGGER.error(errorMsg, e);
		    throw new SigningException(errorMsg, e);
		} catch (CMSException e) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG072, new Object[ ] { signingCertificate.getSubjectDN().getName() });
		    LOGGER.error(errorMsg, e);
		    throw new SigningException(errorMsg, e);
		}
	    }

	    try {
		// Si el firmante no es válido según bouncycastle intentamos
		// llevar a cabo la validación manual
		if (!signatureValid) {
		    ASN1EncodableVector vectorSignedAttributes = signerInformation.getSignedAttributes().toASN1EncodableVector();
		    Signature signatureValidator = Signature.getInstance(signerInformation.getEncryptionAlgOID(), BouncyCastleProvider.PROVIDER_NAME);
		    signatureValidator.initVerify(signingCertificate);
		    signatureValidator.update(new DERSet(vectorSignedAttributes).getDEREncoded());
		    signatureValid = signatureValidator.verify(signerInformation.getSignature());
		    if (!signatureValid) {
			String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG072, new Object[ ] { signingCertificate.getSubjectDN().getName() });
			LOGGER.error(errorMsg);
			throw new SigningException(errorMsg);
		    }
		}
	    } catch (Exception e) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG072, new Object[ ] { signingCertificate.getSubjectDN().getName() });
		LOGGER.error(errorMsg, e);
		throw new SigningException(errorMsg, e);
	    }
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG155, new Object[ ] { signingCertificate.getSubjectDN().getName() }));
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG154));
	}
    }

    /**
     * Method that checks if the signer includes a <code>SigningCertificate</code> signed attribute, or a <code>SigningCertificateV2</code> signed attribute,
     * and this matches to the signing certificate.
     * @param signedData Parameter that represents the signed data.
     * @param signerInformation Parameter that represents the information about the signer.
     * @param signingCertificate Parameter that represents the signing certificate.
     * @throws SigningException If the validation fails.
     */
    public static void validateCAdESPublicKeyInfo(CMSSignedData signedData, SignerInformation signerInformation, X509Certificate signingCertificate) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG156));
	try {
	    // Comprobamos que se han indicado los datos firmados
	    GenericUtilsCommons.checkInputParameterIsNotNull(signedData, Language.getResIntegra(ILogConstantKeys.US_LOG158));

	    // Comprobamos que se ha indicado la información del firmante
	    GenericUtilsCommons.checkInputParameterIsNotNull(signerInformation, Language.getResIntegra(ILogConstantKeys.US_LOG032));

	    // Comprobamos que se ha indicado el certificado firmante
	    GenericUtilsCommons.checkInputParameterIsNotNull(signingCertificate, Language.getResIntegra(ILogConstantKeys.US_LOG002));

	    // Accedemos al conjunto de atributos firmados
	    AttributeTable signedAttrs = signerInformation.getSignedAttributes();

	    // Definimos un valor que indica si el certificado firmante se
	    // incluye en el atributo firmado SigningCertificate (true)
	    // o en el atributo firmado SigningCertificateV2 (false)
	    boolean isSigningCertificate = true;

	    // Accedemos al atributo SigningCertificate
	    Attribute attSigningCertificate = signedAttrs.get(PKCSObjectIdentifiers.id_aa_signingCertificate);

	    // Si el atributo SigningCertificate es nulo obtenemos el atributo
	    // SigningCertificateV2
	    if (attSigningCertificate == null) {
		isSigningCertificate = false;
		attSigningCertificate = signedAttrs.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
	    }

	    // Si el certificado firmante no se ha incluído en los atributos
	    // firmados, devolvemos error
	    if (attSigningCertificate == null) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG159);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    // Si el certificado firmante se ha incluído en los atributos
	    // firmados
	    else {
		LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.US_LOG160, new Object[ ] { signingCertificate.getSubjectDN().getName() }));

		// Si el certificado firmante se incluye en el atributo firmado
		// SigningCertificate
		if (isSigningCertificate) {
		    // Obtenemos el objeto SigningCertificate
		    SigningCertificate signingCertificatev1 = SigningCertificate.getInstance(attSigningCertificate.getAttrValues().getObjectAt(0));

		    // Comprobamos que el algoritmo usado para codificar los
		    // datos haya sido SHA-1
		    if (signingCertificatev1.getCerts()[0].getCertHash().length != NumberConstants.INT_20) {
			String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG161, new Object[ ] { signingCertificate.getSubjectDN().getName() });
			LOGGER.error(errorMsg);
			throw new SigningException(errorMsg);
		    } else {
			// Comprobamos que el certificado indicado en el
			// atributo firmando SigningCertificate coincide con el
			// certificado firmante
			ESSCertID essCertID = signingCertificatev1.getCerts()[0];

			// Obtenemos el hash asociado al certificado
			// incluído en el atributo firmado
			// SigningCertificate
			byte[ ] signingCertificateV1Hash = essCertID.getCertHash();

			// Obtenemos el hash del certificado firmante
			MessageDigest md = MessageDigest.getInstance(ICryptoUtil.HASH_ALGORITHM_SHA1, BouncyCastleProvider.PROVIDER_NAME);
			byte[ ] signingCertificateHash = md.digest(signingCertificate.getEncoded());

			// Comprobamos que los hash coincidan
			if (!Arrays.equals(signingCertificateV1Hash, signingCertificateHash)) {
			    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG162, new Object[ ] { signingCertificate.getSubjectDN().getName() });
			    LOGGER.error(errorMsg);
			    throw new SigningException(errorMsg);
			} else {
			    // Informamos de que la validación ha sido
			    // correcta
			    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG163, new Object[ ] { signingCertificate.getSubjectDN().getName() }));
			}
		    }
		}
		// Si el certificado firmante se incluye en el atributo firmado
		// SigningCertificateV2
		else {
		    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.US_LOG164, new Object[ ] { signingCertificate.getSubjectDN().getName() }));

		    // Obtenemos el objeto SigningCertificateV2
		    SigningCertificateV2 signingCertificatev2 = SigningCertificateV2.getInstance(attSigningCertificate.getAttrValues().getObjectAt(0));

		    // Comprobamos que el certificado indicado en el atributo
		    // firmando SigningCertificateV2 coincide con el certificado
		    // firmante
		    ESSCertIDv2 essCertID = signingCertificatev2.getCerts()[0];

		    // Obtenemos el hash asociado al certificado incluído en
		    // el atributo firmado SigningCertificateV2
		    byte[ ] signingCertificateV2Hash = essCertID.getCertHash();

		    // Obtenemos el algoritmo de hash utilizado en el atributo
		    // firmado SigningCertificateV2
		    AlgorithmIdentifier ai2 = essCertID.getHashAlgorithm();
		    String hashAlgorithm = CryptoUtilPdfBc.translateAlgorithmIdentifier(ai2);

		    // Obtenemos el hash del certificado firmante
		    MessageDigest md = MessageDigest.getInstance(hashAlgorithm, new BouncyCastleProvider());
		    byte[ ] signingCertificateHash = md.digest(signingCertificate.getEncoded());

		    // Comprobamos que los hash coincidan
		    if (!Arrays.equals(signingCertificateV2Hash, signingCertificateHash)) {
			String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG165, new Object[ ] { signingCertificate.getSubjectDN().getName() });
			LOGGER.error(errorMsg);
			throw new SigningException(errorMsg);
		    } else {
			// Informamos de que la validación ha sido correcta
			LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.US_LOG166, new Object[ ] { signingCertificate.getSubjectDN().getName() }));
		    }
		}
	    }
	} catch (NoSuchAlgorithmException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG167);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (NoSuchProviderException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG167);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (CertificateEncodingException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG167);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG157));
	}
    }

    /**
     * Method that validates if the signing time of a signature is previous than certain date.
     * @param signedData Parameter that represents the signed data.
     * @param signerInformation Parameter that represents the information about the signer.
     * @param isRequired Parameter that indicates if the <code>SigningTime</code> attribute shall be included as a signed attribute for the signer (true) or not (false).
     * @param validationDate Parameter that represents the validation date.
     * @param signingCertificate Parameter that represents the signing certificate.
     * @throws SigningException If the validation fails.
     */
    public static void validateCAdESSigningTime(CMSSignedData signedData, SignerInformation signerInformation, boolean isRequired, Date validationDate, X509Certificate signingCertificate) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG168));
	try {
	    // Comprobamos que se han indicado los datos firmados
	    GenericUtilsCommons.checkInputParameterIsNotNull(signedData, Language.getResIntegra(ILogConstantKeys.US_LOG158));

	    // Comprobamos que se ha indicado la información del firmante
	    GenericUtilsCommons.checkInputParameterIsNotNull(signerInformation, Language.getResIntegra(ILogConstantKeys.US_LOG032));

	    // Comprobamos que se ha indicado la fecha de validación
	    GenericUtilsCommons.checkInputParameterIsNotNull(validationDate, Language.getResIntegra(ILogConstantKeys.US_LOG204));

	    // Comprobamos que se ha indicado el certificado firmante
	    GenericUtilsCommons.checkInputParameterIsNotNull(signingCertificate, Language.getResIntegra(ILogConstantKeys.US_LOG002));

	    // Accedemos al conjunto de atributos firmados
	    AttributeTable signedAttrs = signerInformation.getSignedAttributes();

	    // Accedemos al atributo SigningTime
	    Attribute attSigningTime = signedAttrs.get(PKCSObjectIdentifiers.pkcs_9_at_signingTime);

	    // Si el firmante carece del atributo SigningTime
	    if (attSigningTime == null) {
		// Si el atributo SigningTime es obligatorio
		if (isRequired) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG170, new Object[ ] { signingCertificate.getSubjectDN().getName() });
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
		// Si el atributo SigningTime es opcional
		else {
		    // Consideramos la validación como correcta pues no se puede
		    // validar dicho atributo
		    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG170, new Object[ ] { signingCertificate.getSubjectDN().getName() }));
		}
	    }
	    // Si el firmante posee el atributo SigningTime
	    else {

		// Llevamos a cabo la validación del atributo SigningTime
		checkSigningTime(attSigningTime, signingCertificate, validationDate);
	    }
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG169));
	}
    }

    /**
     * Method that validates if the signing time is before to the current date plus the time gap.
     * @param attSigningTime Parameter that represents the <code>SigningTime</code> attribute.
     * @param signingCertificate Parameter that represents the signing certificate.
     * @param validationDate Parameter that represents the validation date.
     * @throws SigningException If the validation fails.
     */
    private static void checkSigningTime(Attribute attSigningTime, X509Certificate signingCertificate, Date validationDate) throws SigningException {
	try {
	    Date signingTimeDate = null;
	    // Accedemos a la fecha de generación de la firma
	    DEREncodable signingTime = attSigningTime.getAttrValues().getObjectAt(0);
	    if (signingTime instanceof ASN1UTCTime) {
		signingTimeDate = ((ASN1UTCTime) signingTime).getDate();
	    } else if (signingTime instanceof ASN1GeneralizedTime) {
		signingTimeDate = ((ASN1GeneralizedTime) signingTime).getDate();
	    } else {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG171, new Object[ ] { signingTime.getClass().getName(), signingCertificate.getSubjectDN().getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG172, new Object[ ] { signingCertificate.getSubjectDN().getName(), signingTimeDate.toString() }));

	    if (signingTimeDate.after(validationDate)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG173, new Object[ ] { signingTimeDate.toString(), signingCertificate.getSubjectDN().getName(), validationDate.toString() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.US_LOG174, new Object[ ] { signingCertificate.getSubjectDN().getName() }));
	} catch (ParseException e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG175, new Object[ ] { signingCertificate.getSubjectDN().getName() });
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}
    }

    /**
     * Method that validates the XAdES signature core associated to a signer.
     * @param qualifyingPropertiesElement Parameter that represents <code>xades:QualifyingProperties</code> element.
     * @param signatureId Parameter that represents the value of <code>Id</code> attribute of <code>ds:Signature</code> element.
     * @param signatureElement Parameter that represents <code>ds:Signature</code> element.
     * @param xmlSignature Parameter that represents the XML signature.
     * @param signedFile Parameter that represents the file signed by the XML signature when the signed data isn't included into the signed XML document.
     * @param signedFileName Parameter that represents the name of the file signed by the XML signature when the signed data isn't included into the signed XML document.
     * @param signingCertificate Parameter that represents the signing certificate.
     * @param signedSignaturePropertiesElement Parameter that represents <code>xades:SignedSignatureProperties</code> element.
     * @param signedPropertiesElement Parameter that represents <code>xades:SignedProperties</code> element.
     * @param isBaseline Parameter that indicates if the signature to validate has Baseline form (true) or not (false).
     * @param isCounterSignature Parameter that indicates if the signature to validate is a countersignature (true) or not (false).
     * @throws SigningException If the validation fails.
     */
    public static void validateXAdESSignatureCore(Element qualifyingPropertiesElement, String signatureId, Element signatureElement, org.apache.xml.security.signature.XMLSignature xmlSignature, byte[ ] signedFile, String signedFileName, X509Certificate signingCertificate, Element signedSignaturePropertiesElement, Element signedPropertiesElement, boolean isBaseline, boolean isCounterSignature) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG179));
	/*
	 * Validación del Núcleo de Firma: Se realizarán las siguientes verificaciones (en el caso de que la firma no sea Baseline):
	 * > Se comprobará que la versión de XAdES es 1.3.2 o superior.
	 * > Se comprobará que el elemento xades:QualifyingProperties está presente y se encuentra correctamente formado.
	 * > Se comprobará que el elemento xades:SignedSignatureProperties tiene una estructura correcta.
	 * > Se comprobará que existe una referencia que apunta al elemento xades:SignedProperties.
	 * > Se comprobará que el firmante verifica la firma.
	 * 
	 * Mientras que en el caso de que la firma sea Baseline:
	 * > Se comprobará que la versión de XAdES es 1.3.2 o superior.
	 * > Se comprobará que el firmante verifica la firma.
	 * > Se verificará que el elemento xades:QualifyingProperties está presente y se encuentra correctamente formado.
	 * > Se comprobará que el elemento xades:SignedSignatureProperties tiene una estructura correcta.
	 * > Se verificará que se incluye, al menos, un elemento xades:DataObjectFormat, y por cada uno de ellos, que está correctamente formado y que tiene asociada una
	 *   referencia que no apunta hacia el elemento xades:SignedProperties.
	 * > Se comprobará que existe una referencia que apunta al elemento xades:SignedProperties.
	 */
	try {
	    // Comprobamos que se ha indicado el elemento
	    // xades:QualifyingProperties
	    GenericUtilsCommons.checkInputParameterIsNotNull(qualifyingPropertiesElement, Language.getResIntegra(ILogConstantKeys.US_LOG190));

	    // Comprobamos que se ha indicado el elemento ds:Signature
	    GenericUtilsCommons.checkInputParameterIsNotNull(signatureElement, Language.getResIntegra(ILogConstantKeys.US_LOG191));

	    // Comprobamos que se ha indicado la firma XML
	    GenericUtilsCommons.checkInputParameterIsNotNull(xmlSignature, Language.getResIntegra(ILogConstantKeys.US_LOG039));

	    // comprobamos que se ha indicado el certificado firmante
	    GenericUtilsCommons.checkInputParameterIsNotNull(signingCertificate, Language.getResIntegra(ILogConstantKeys.US_LOG002));

	    // Comprobamos que se ha indicado el elemento
	    // xades:SignedProperties
	    GenericUtilsCommons.checkInputParameterIsNotNull(signedPropertiesElement, Language.getResIntegra(ILogConstantKeys.US_LOG199));

	    // Comprobamos que se ha indicado el elemento
	    // xades:SignedSignatureProperties
	    GenericUtilsCommons.checkInputParameterIsNotNull(signedSignaturePropertiesElement, Language.getResIntegra(ILogConstantKeys.US_LOG200));

	    // Comprobamos que el espacio de nombres está soportado (XAdES
	    // v1.3.2 o XAdES v.1.4.1)
	    checkXAdESNamespace(signatureId, signatureElement);

	    // Comprobamos que el elemento xades:QualifiyingProperties posea el
	    // atributo Target y que éste apunta hacia la firma
	    String target = qualifyingPropertiesElement.getAttribute(IXMLConstants.ATTRIBUTE_TARGET);
	    if (target == null || target.isEmpty()) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG181, new Object[ ] { signatureId });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    if (!target.substring(1).equals(signatureId)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG205, new Object[ ] { signatureId });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Comprobamos que el orden de los elementos hijos del
	    // elemento xades:SignedSignatureProperties es correcto
	    // conforme al esquema (xsd) de XAdES
	    checkSignedSignaturePropertiesElementsOrder(signedSignaturePropertiesElement, signatureId);

	    // Comprobamos que la firma incluye una referencia al
	    // elemento xades:SignedProperties
	    checkReferenceToSignedProperties(xmlSignature, signatureId, signedPropertiesElement);

	    // Validamos la estructura del elemento xades:DataObjectFormat, si
	    // la firma es Baseline
	    if (isBaseline) {
		checkDataObjectFormatStructure(signatureId, signedPropertiesElement, xmlSignature, isCounterSignature);
	    }

	    // Comprobamos que el firmante verifica la firma
	    checkXAdESSigner(xmlSignature, signedFile, signedFileName, signingCertificate, signatureId);

	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG196, new Object[ ] { signatureId }));
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG180));
	}
    }

    /**
     * Method that validates the structure of <code>xades:DataObjectFormat</code> elements.
     * @param signatureId Parameter that represents the value of <code>Id</code> attribute of <code>ds:Signature</code> element.
     * @param signedPropertiesElement Parameter that represents <code>xades:SignedProperties</code> element.
     * @param xmlSignature Parameter that represents the XML signature.
     * @param isCounterSignature Parameter that indicates if the signature to validate is a countersignature (true) or not (false).
     * @throws SigningException If the validation fails.
     */
    private static void checkDataObjectFormatStructure(String signatureId, Element signedPropertiesElement, org.apache.xml.security.signature.XMLSignature xmlSignature, boolean isCounterSignature) throws SigningException {
	// Accedemos al elemento xades:SignedDataObjectProperties
	Element signedDataObjectPropertiesElement = UtilsXML.getChildElement(signedPropertiesElement, IXMLConstants.ELEMENT_SIGNED_DATA_OBJECT_PROPERTIES, signatureId, true);

	// Instanciamos la lista de elementos xades:DataObjectFormat
	List<Element> listDataObjectFormatElements = new ArrayList<Element>();

	// Obtenemos la lista de hijos del elemento
	// xades:SignedDataObjectProperties
	NodeList childNodes = signedDataObjectPropertiesElement.getChildNodes();

	// Recorremos la lista de hijos del elemento
	// xades:SignedDataObjectProperties
	for (int i = 0; i < childNodes.getLength(); i++) {
	    // Accedemos al elemento hijo
	    Node childElement = childNodes.item(i);

	    // Si el elemento es xades:DataObjectFormat lo añadimos a la lista
	    // asociada
	    if (childElement.getNodeType() == Node.ELEMENT_NODE && childElement.getLocalName().equals(IXMLConstants.ELEMENT_DATA_OBJECT_FORMAT)) {
		listDataObjectFormatElements.add((Element) childElement);
	    }
	}
	// Comprobamos que existe al menos un elemento xades:DataObjectFormat
	if (listDataObjectFormatElements.isEmpty()) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG206, new Object[ ] { signatureId });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
	// Recorremos la lista de elementos xades:DataObjectFormat
	for (Element dataObjectFormatElement: listDataObjectFormatElements) {
	    // Verificamos que el elemento xades:DataObjectFormat posee como
	    // hijo un elemento xades:MimeType
	    Element mimeTypeElement = UtilsXML.getChildElement(dataObjectFormatElement, IXMLConstants.ELEMENT_MIME_TYPE, signatureId, false);
	    if (mimeTypeElement == null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG207, new Object[ ] { signatureId });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Accedemos al atributo ObjectReference que es obligatorio
	    String objectReference = dataObjectFormatElement.getAttribute(IXMLConstants.ATTRIBUTE_OBJECT_REFERENCE);

	    if (objectReference == null || objectReference.isEmpty()) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG208, new Object[ ] { signatureId });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Obtenemos el valor del atributo Id del elemento
	    // xades:SignedProperties
	    String idSignedProperties = signedPropertiesElement.getAttribute(IXMLConstants.ATTRIBUTE_ID);

	    // Recorremos la lista de referencias buscando aquella apuntada por
	    // el atributo ObjectReference
	    findReferenceFromDataObjectFormat(xmlSignature, objectReference, idSignedProperties, signatureId, isCounterSignature);
	}
    }

    /**
     * Method that checks if the mandatory <code>ObjectReference</code> attribute of <code>xades:DataObjectFormat</code> element reference the <code>ds:Reference</code> element
     * of the <code>ds:Signature</code> corresponding with the data object qualified by this property or if there is a manifest reference by each data object format.
     * @param xmlSignature Parameter that represents the XML signature.
     * @param objectReference Parameter that represents the value of <code>ObjectReference</code> attribute.
     * @param idSignedProperties Parameter that represents the value of <code>Id</code> attribute of <code>xades:SignedProperties</code> element.
     * @param signatureId Parameter that represents the value of <code>Id</code> attribute of <code>ds:Signature</code> element.
     * @param isCounterSignature parameter that indicates if the signature to validate is a countersignature (true) or not (false).
     * @throws SigningException If the validation fails.
     */
    private static void findReferenceFromDataObjectFormat(org.apache.xml.security.signature.XMLSignature xmlSignature, String objectReference, String idSignedProperties, String signatureId, boolean isCounterSignature) throws SigningException {
	try {
	    // Recorremos la lista de referencias buscando aquella apuntada por
	    // el atributo ObjectReference
	    boolean found = false;
	    for (int i = 0; !found && i < xmlSignature.getSignedInfo().getLength(); i++) {
		// Accedemos a la referencia
		org.apache.xml.security.signature.Reference ref = xmlSignature.getSignedInfo().item(i);

		// Comprobamos si el Id de la referencia coincide con el valor
		// del atributo ObjectReference del elemento
		// xades:DataObjectFormat
		if (ref.getId() != null && ref.getId().equals(objectReference.substring(1))) {
		    // Indicamos que hemos encontrado la referencia
		    found = true;

		    // Verificamos que dicha referencia no apunta al elemento
		    // xades:SignedProperties, es decir, que el valor del
		    // atributo URI de la referencia no coincide con el valor
		    // del atributo Id
		    // del elemento xades:SignedProperties
		    if (ref.getURI() != null && !ref.getURI().isEmpty() && ref.getURI().substring(1).equals(idSignedProperties)) {
			String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG209, new Object[ ] { signatureId });
			LOGGER.error(errorMsg);
			throw new SigningException(errorMsg);
		    }
		}
	    }
	    // Si no hemos encontrado ninguna referencia
	    if (!found) {
		// Comprobamos si al menos existe un dataObjectFormat por cada
		// reference del manifest.
		findManifestReferenceFromDataObjectFormat(xmlSignature, objectReference, isCounterSignature);
	    }
	} catch (org.apache.xml.security.exceptions.XMLSecurityException e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG188, new Object[ ] { signatureId });
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}
    }

    /**
     * Method that checks if there is any manifest reference with a identifier who matches with the data object format object reference.
     * @param xmlSignature XML signature.
     * @param objectReference Object reference of the data object format to find.
     * @param isCounterSignature Parameter that indicates if the signature to verify is a countersignature (true) or not (false).
     * @throws SigningException if there is not possible to find any manifest reference that matches with the data object format.
     */
    private static void findManifestReferenceFromDataObjectFormat(org.apache.xml.security.signature.XMLSignature xmlSignature, String objectReference, boolean isCounterSignature) throws SigningException {
	String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG210, new Object[ ] { xmlSignature.getId(), objectReference.substring(1) });

	// Recuperamos el elemento Manifest de la firma.
	Element object = UtilsXML.getChildElement(xmlSignature.getElement(), IXMLConstants.ELEMENT_OBJECT, null, false);
	while (!object.getFirstChild().getNodeName().equals(IXMLConstants.MANIFEST_TAG_NAME)) {
	    if (object.getNextSibling() != null && object.getNextSibling() instanceof Element) {
		object = (Element) object.getNextSibling();
	    } else if (isCounterSignature) {
		// En caso de que la firma a validar sea un contrafirmante, las
		// referencia del manifest ya han sido validadas previamente
		// durante la firma principal, por lo que no es necesario volver
		// a realizar dicha validación.
		return;
	    } else {
		// Si no ha sido posible encontrar el elemento Manifest en la
		// firma, ésta se considerará inválida, ya que el elemento data
		// object format es obligatorio y debe estar asociado a una
		// referencia de la firma y, puesto que previamente se ha
		// comprobado si existía una referencia en el signedInfo con un
		// identificador asociado al data object format, la firma se
		// considera inválida.
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	}
	Element manifestElem = (Element) object.getFirstChild();

	// Recorremos las referencias del manifest para poder acceder a sus
	// identificadores.
	Element reference = (Element) manifestElem.getFirstChild();
	String referenceId = null;
	while (reference != null) {
	    // accedemos al atributo Id.
	    referenceId = reference.getAttribute(IXMLConstants.ATTRIBUTE_ID);
	    // Si el identificador coincide con el del dataObjectFormat,
	    // terminamos la busqueda.
	    if (referenceId != null && referenceId.equals(objectReference.substring(1))) {
		return;
	    }
	    // Si no coincide, continuamos con la siguiente referencia del
	    // manifest.
	    else if (reference.getNextSibling() != null) {
		reference = (Element) reference.getNextSibling();
	    } else {
		reference = null;
	    }
	}

	// Si llegamos a este punto, es que no se ha encontrado ninguna
	// referencia en el manifest con un identificador igual al del
	// dataObjectFormat que buscamos, y por tanto, consideramos que la
	// firma es inválida (ya que previamente se ha buscado si existe una
	// referencia en el signedInfo que coincida con el identificador
	// buscado).
	LOGGER.error(errorMsg);
	throw new SigningException(errorMsg);
    }

    /**
     * Method that extracts the public key from the certificate and verifies if the signature is valid by re-digesting all References, comparing those against the stored
     * DigestValues and then checking to see if the Signatures match on the SignedInfo.
     * @param xmlSignature Parameter that represents the XML signature.
     * @param signedFile Parameter that represents the file signed by the XML signature when the signed data isn't included into the signed XML document.
     * @param signedFileName Parameter that represents the name of the file signed by the XML signature when the signed data isn't included into the signed XML document.
     * @param signingCertificate Parameter that represents the signing certificate.
     * @param signatureId Parameter that represents the value of <code>Id</code> attribute of <code>ds:Signature</code> element.
     * @throws SigningException If the validation fails.
     */
    private static void checkXAdESSigner(org.apache.xml.security.signature.XMLSignature xmlSignature, byte[ ] signedFile, String signedFileName, X509Certificate signingCertificate, String signatureId) throws SigningException {
	// Accedemos al elemento KeyInfo
	KeyInfo keyInfo = xmlSignature.getKeyInfo();

	if (keyInfo != null) {
	    try {
		// Antes de validar la firma comprobamos si se ha indicado
		// el fichero externo y su nombre, representando los datos
		// firmados. En ese caso, deberemos añadir un elemento para
		// procesar
		// ese fichero firmado que no está incluido en la firma
		if (signedFile != null && signedFileName != null) {
		    ExternalFileURIDereferencer ext = new ExternalFileURIDereferencer(signedFile, signedFileName);
		    xmlSignature.addResourceResolver(ext);
		}
		// Validamos la firma usando el certificado firmante
		if (!xmlSignature.checkSignatureValue(signingCertificate)) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG030, new Object[ ] { signatureId });
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
	    } catch (org.apache.xml.security.signature.XMLSignatureException e) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG033, new Object[ ] { signatureId });
		LOGGER.error(errorMsg, e);
		throw new SigningException(errorMsg, e);
	    }
	} else {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG040, new Object[ ] { signatureId });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that checks if a XML signature contains a reference to <code>xades:SignedProperties</code> element.
     * @param xmlSignature Parameter that represents the XML signature.
     * @param signatureId Parameter that represents the value of <code>Id</code> attribute of <code>ds:Signature</code> element.
     * @param signedPropertiesElement Parameter that represents <code>xades:SignedProperties</code> element.
     * @throws SigningException If the validation fails.
     */
    private static void checkReferenceToSignedProperties(org.apache.xml.security.signature.XMLSignature xmlSignature, String signatureId, Element signedPropertiesElement) throws SigningException {
	try {
	    // Accedemos al atributo Id del elemento xades:SignedProperties
	    String idSP = signedPropertiesElement.getAttribute(IXMLConstants.ATTRIBUTE_ID);

	    // Recorremos la lista de referencias buscando la que apunta al
	    // elemento
	    // xades:SignedProperties
	    boolean finded = false;
	    for (int index = 0; !finded && index < xmlSignature.getSignedInfo().getLength(); index++) {
		// Accedemos a la referencia
		org.apache.xml.security.signature.Reference ref = xmlSignature.getSignedInfo().item(index);

		// Si el valor del atributo URI de la refefencia coincide con el
		// valor del atributo Id del elemento xades:SignedProperties
		if (ref.getURI().length() > 0 && idSP.equals(ref.getURI().substring(1))) {
		    // Indicamos que hemos encontrado la refefencia al elemento
		    // xades:SignedProperties
		    finded = true;

		    // Obtenemos el valor del atributo Type de la referencia
		    String type = ref.getType();

		    // Si el valor del atributo Type de la referencia no está
		    // asociado al elemento xades:SignedProperties lanzamos una
		    // excepción
		    if (type == null || type.isEmpty() || !type.equals("http://uri.etsi.org/01903#SignedProperties")) {
			String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG187, new Object[ ] { signatureId });
			LOGGER.error(errorMsg);
			throw new SigningException(errorMsg);
		    }

		}
	    }
	    // Si no hemos encontrado la referencia hacia el elemento
	    // xades:SignedProperties lanzamos una excepción
	    if (!finded) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG186, new Object[ ] { idSP, signatureId });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	} catch (org.apache.xml.security.exceptions.XMLSecurityException e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG188, new Object[ ] { signatureId });
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}

    }

    /**
     * Method that checks if the namespace of a XML signature is associated to XAdES v1.3.2 or XAdES v1.4.1.
     * @param signatureId Parameter that represents the value of <code>Id</code> attribute of <code>ds:Signature</code> element.
     * @param signatureElement Parameter that represents <code>ds:Signature</code> element.
     * @throws SigningException If the validation fails.
     */
    private static void checkXAdESNamespace(String signatureId, Element signatureElement) throws SigningException {
	// Por defecto, una firma XAdES tendrá como espacio de nombres el de
	// XMLDSig
	String namespace = XMLSignature.XMLNS;

	try {
	    // Comprobamos si la firma posee algún elemento de tipo
	    // xadesv141:ArchiveTimeStamp
	    NodeList ats = UtilsXML.getChildNodesByLocalNames(signatureElement, "Object/QualifyingProperties/UnsignedProperties/UnsignedSignatureProperties/ArchiveTimeStamp");

	    if (ats.getLength() > 0 && ats.item(0).getNamespaceURI().equalsIgnoreCase(IXMLConstants.XADES_1_4_1_NAMESPACE)) {
		namespace = IXMLConstants.XADES_1_4_1_NAMESPACE;
	    } else {
		// Comprobamos si la firma posee algún elemento de tipo
		// xadesv141:TimeStampValidationData
		ats = UtilsXML.getChildNodesByLocalNames(signatureElement, "Object/QualifyingProperties/UnsignedProperties/UnsignedSignatureProperties/TimeStampValidationData");
		if (ats.getLength() > 0 && ats.item(0).getNamespaceURI().equalsIgnoreCase(IXMLConstants.XADES_1_4_1_NAMESPACE)) {
		    namespace = IXMLConstants.XADES_1_4_1_NAMESPACE;
		} else {
		    namespace = extractXAdESNoV141Namespace(signatureElement);
		}
	    }
	} catch (Exception e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG185, new Object[ ] { signatureId });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg, e);
	}
	// Comprobamos que el espacio de nombres sea el de XAdES v1.3.2 o
	// v.1.4.1
	if (!namespace.equals(IXMLConstants.XADES_1_4_1_NAMESPACE) && !namespace.equals(IXMLConstants.XADES_1_3_2_NAMESPACE)) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG184, new Object[ ] { signatureId, namespace });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Auxiliar method for {@link #extractXAdESNamespace(Node)}. It obtains the namespace of a XML signature which namespace isn't for XAdES 1.4.1.
     * @param signatureElement Parameter that represents <code>ds:Signature</code> element.
     * @return the associated namespace.
     * @throws XPathExpressionException If the method fails.
     */
    private static String extractXAdESNoV141Namespace(Element signatureElement) throws XPathExpressionException {
	// Por defecto, una firma XAdES tendrá como espacio de nombres el de
	// XMLDSig.
	String ns = XMLSignature.XMLNS;
	NodeList qp = UtilsXML.getChildNodesByLocalNames(signatureElement, "Object/QualifyingProperties");
	if (qp.getLength() > 0) {
	    ns = qp.item(0).getNamespaceURI();
	    if (ns == null) {
		NamedNodeMap nnm = qp.item(0).getAttributes();
		for (int i = 0; i < nnm.getLength(); i++) {
		    String attrName = nnm.item(i).getNodeName();
		    if (attrName.equals("xmlns")) {
			ns = nnm.item(i).getNodeValue();
		    } else if (attrName.equals("xmlns:xades")) {
			ns = nnm.item(i).getNodeValue();
		    } else if (attrName.equals("xmlns:xs")) {
			ns = nnm.item(i).getNodeValue();
		    }
		}
	    }
	}
	return ns;
    }

    /**
     * Method that checks if the child elements of <code>xades:SignedSignatureProperties</code> element have a correct structure.
     * @param signedSignaturePropertiesElement Parameter that represents <code>xades:SignedSignatureProperties</code> element.
     * @param signatureId Parameter that represents the value of <code>Id</code> attribute of <code>ds:Signature</code> element.
     * @throws SigningException If the validation fails.
     */
    private static void checkSignedSignaturePropertiesElementsOrder(Element signedSignaturePropertiesElement, String signatureId) throws SigningException {
	/*
	 * Comprobamos que la estructura del elemento SignedSignatureProperties es la siguiente:
	 * <xsd:complexType name="SignedSignaturePropertiesType">
	 * 		<xsd:sequence>
	 * 			<xsd:element name="SigningTime" type="xsd:dateTime" minOccurs="0"/>
	 * 			<xsd:element name="SigningCertificate" type="CertIDListType" minOccurs="0"/>
	 * 			<xsd:element name="SignaturePolicyIdentifer" type="SignaturePolicyIdentifierType" minOccurs="0"/>
	 * 			<xsd:element name="SignatureProductionPlace" type="SignatureProductionPlaceType" minOccurs="0"/>
	 * 			<xsd:element name="SignerRole" type="SignerRoleType" minOccurs="0"/>
	 * 		</xsd:sequence>
	 * 		<xsd:attribute name="Id" type="xsd:ID" use="optional"/>
	 * </xsd:complexType>
	 */
	// Definimos para cada elemento una variable
	// que representa su posición en la lista de
	// hijos
	Integer signingTimePos = null;
	Integer signingCertificatePos = null;
	Integer signaturePolicyIdentiferPos = null;
	Integer signatureProductionPlacePos = null;
	Integer signerRolePos = null;

	// Accedemos a los hijos del elemento xades:SignedSignatureProperties
	NodeList signedSignaturePropertiesNodeList = signedSignaturePropertiesElement.getChildNodes();

	// Almacenamos la posición de cada uno de
	// los hijos dentro de la lista de hijos
	for (int i = 0; i < signedSignaturePropertiesNodeList.getLength(); i++) {
	    Element element = (Element) signedSignaturePropertiesNodeList.item(i);
	    String elementName = element.getLocalName();
	    if (elementName.equals(IXMLConstants.ELEMENT_SIGNING_TIME)) {
		signingTimePos = i;
	    } else if (elementName.equals(IXMLConstants.ELEMENT_SIGNING_CERTIFICATE)) {
		signingCertificatePos = i;
	    } else if (elementName.equals(IXMLConstants.ELEMENT_SIGNATURE_POLICY_IDENTIFIER)) {
		signaturePolicyIdentiferPos = i;
	    } else if (elementName.equals(IXMLConstants.ELEMENT_SIGNATURE_PRODUCTION_PLACE)) {
		signatureProductionPlacePos = i;
	    } else if (elementName.equals(IXMLConstants.ELEMENT_SIGNER_ROLE)) {
		signerRolePos = i;
	    }
	}
	// Metemos en una lista las posiciones de
	// los elementos en el orden en que deberían
	// encontrarse, sólo si dicho elemento
	// no es nulo
	List<Integer> listPositions = getPositionsList(signingTimePos, signingCertificatePos, signaturePolicyIdentiferPos, signatureProductionPlacePos, signerRolePos);
	boolean correctOrder = true;
	int i = 0;
	Integer previousValue = -1;

	// Recorremos las posiciones de los
	// elementos de manera que si se encuentra
	// uno cuyo elemento anterior posee una
	// posición
	// mayor, entonces, el orden no es el
	// correcto.
	while (correctOrder && i < listPositions.size()) {
	    Integer currentValue = listPositions.get(i);
	    if (previousValue > currentValue) {
		correctOrder = false;
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG183, new Object[ ] { signatureId });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    } else {
		previousValue = currentValue;
	    }
	    i++;
	}
    }

    /**
     * Method that obtains a list with the positions of each child elements of <code>xades:SignedSignatureProperties</code> element.
     * @param signingTimePos Parameter that represents the position as child of <code>xades:SigningTime</code> element. If the element ins't a child, this
     * value will be <code>null</code>.
     * @param signingCertificatePos Parameter that represents the position as child of <code>xades:SigningCertificate</code> element. If the element ins't
     * a child, this value will be <code>null</code>.
     * @param signaturePolicyIdentiferPos Parameter that represents the position as child of <code>xades:SignaturePolicyIdentifer</code> element. If the
     * element ins't a child, this value will be <code>null</code>.
     * @param signatureProductionPlacePos Parameter that represents the position as child of <code>xades:SignatureProductionPlace</code> element. If the
     * element ins't a child, this value will be <code>null</code>.
     * @param signerRolePos Parameter that represents the position as child of <code>xades:SignerRole</code> element. If the element ins't a child, this
     * value will be <code>null</code>.
     * @return a list with the positions of each child elements of <code>xades:SignedSignatureProperties</code> element.
     */
    private static List<Integer> getPositionsList(Integer signingTimePos, Integer signingCertificatePos, Integer signaturePolicyIdentiferPos, Integer signatureProductionPlacePos, Integer signerRolePos) {
	List<Integer> listPositions = new ArrayList<Integer>();
	if (signingTimePos != null) {
	    listPositions.add(signingTimePos);
	}
	if (signingCertificatePos != null) {
	    listPositions.add(signingCertificatePos);
	}
	if (signaturePolicyIdentiferPos != null) {
	    listPositions.add(signaturePolicyIdentiferPos);
	}
	if (signatureProductionPlacePos != null) {
	    listPositions.add(signatureProductionPlacePos);
	}
	if (signerRolePos != null) {
	    listPositions.add(signerRolePos);
	}
	return listPositions;
    }

    /**
     * Method that retrieves the signing certificate of a signer contained inside of a XML signature.
     * @param signedSignaturePropertiesElement Parameter that represents <code>xades:SignedSignatureProperties</code> element.
     * @param signatureId Parameter that represents the value of <code>Id</code> attribute of <code>ds:Signature</code> element.
     * @param signatureElement Parameter that represents <code>ds:Signature</code> element.
     * @return an object that represents the signing certificate.
     * @throws SigningException If the method fails of the certificate cannot be retrieved.
     */
    public static X509Certificate retrieveSigningCertificateOfXMLSigner(Element signedSignaturePropertiesElement, String signatureId, Element signatureElement) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG239));
	try {
	    // Comprobamos que se ha indicado el elemento
	    // xades:SignedSignatureProperties
	    GenericUtilsCommons.checkInputParameterIsNotNull(signedSignaturePropertiesElement, Language.getResIntegra(ILogConstantKeys.US_LOG200));

	    // Comprobamos que se ha indicado el elemento ds:Signature
	    GenericUtilsCommons.checkInputParameterIsNotNull(signatureElement, Language.getResIntegra(ILogConstantKeys.US_LOG191));

	    // Recorremos la lista de elementos hijos del elemento
	    // xades:SignedSignatureProperties buscando el elemento
	    // xades:SigningCertificate
	    Element signingCertificateElement = UtilsXML.getChildElement(signedSignaturePropertiesElement, IXMLConstants.ELEMENT_SIGNING_CERTIFICATE, signatureId, true);

	    // Accedemos al elemento xades:Cert
	    Element certElement = UtilsXML.getChildElement(signingCertificateElement, IXMLConstants.ELEMENT_CERT, signatureId, true);

	    // Accedemos al primer elemento xades:CertDigest
	    Element certDigestElement = UtilsXML.getChildElement(certElement, IXMLConstants.ELEMENT_CERT_DIGEST, signatureId, true);

	    // Accedemos al elemento ds:DigestMethod
	    Element digestMethodElement = UtilsXML.getChildElement(certDigestElement, IXMLConstants.ELEMENT_DIGEST_METHOD, signatureId, true);

	    // Accedemos al atributo Algorithm del elemento ds:DigestMethod
	    String xmlHashAlg = digestMethodElement.getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM);
	    if (xmlHashAlg == null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG189, new Object[ ] { signatureId });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    // Establecemos el valor del algoritmo de hash
	    String signingCertificateHashAlgorithm = CryptoUtilXML.translateXmlDigestAlgorithm(xmlHashAlg);

	    // Accedemos al elemento ds:DigestValue
	    Element digestValueElement = UtilsXML.getChildElement(certDigestElement, IXMLConstants.ELEMENT_DIGEST_VALUE, signatureId, true);

	    // Obtenemos el valor del resumen del certificado firmante
	    String signingCertificateDigest = digestValueElement.getTextContent();

	    // Accedemos al elemento ds:KeyInfo
	    Element keyInfoElement = UtilsXML.getChildElement(signatureElement, IXMLConstants.ELEMENT_KEY_INFO, signatureId, true);

	    // Accedemos al elemento ds:X509Data
	    Element x509DataElement = UtilsXML.getChildElement(keyInfoElement, IXMLConstants.ELEMENT_X509_DATA, signatureId, true);

	    // Accedemos a la lista de elementos ds:X509Certificate
	    NodeList x509CertificateNodeList = x509DataElement.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_X509_CERTIFICATE);

	    // Comprobamos que existe al menos un certificado
	    if (x509CertificateNodeList.getLength() == 0) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG192, new Object[ ] { signatureId });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Instanciamos un mapa donde ubicar los certificados incluidos
	    // en
	    // ds:KeyInfo/ds:X509Data. La clave será el resumen en Base64
	    // del
	    // certificado
	    Map<String, X509Certificate> mapCertificatesIntoKeyInfo = new HashMap<String, X509Certificate>();

	    try {
		// Recorremos la lista de certificados
		for (int i = 0; i < x509CertificateNodeList.getLength(); i++) {
		    if (x509CertificateNodeList.item(i).getNodeType() == Node.ELEMENT_NODE) {
			// Accedemos al elemento ds:X509Certificate
			Element x509CertificateElement = (Element) x509CertificateNodeList.item(i);

			// Obtenemos el certificado codificado en Base64
			String encodedCert = x509CertificateElement.getTextContent();

			// Obtenemos el certificado como tal
			X509Certificate cert = UtilsCertificateCommons.generateCertificate(Base64.decode(encodedCert));

			// Añadimos al mapa una entrada
			mapCertificatesIntoKeyInfo.put(new String(Base64.encode(CryptoUtilPdfBc.digest(signingCertificateHashAlgorithm, cert.getEncoded()))), cert);
		    }
		}
	    } catch (Exception e) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG193, new Object[ ] { signatureId });
		LOGGER.error(errorMsg, e);
		throw new SigningException(errorMsg, e);
	    }
	    // Extraemos del mapa aquél certificado cuyo resumen coincide
	    // con el
	    // resumen del certificado firmante
	    X509Certificate signingCertificate = mapCertificatesIntoKeyInfo.remove(signingCertificateDigest);

	    // Comprobamos que hemos encontrado el certificado firmante
	    if (signingCertificate == null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG194, new Object[ ] { signatureId });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    return signingCertificate;
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG240));
	}
    }

    /**
     * Method that validates if the public key information contained inside of a XML signature is valid.
     * @param signatureId Parameter that represents the value of <code>Id</code> attribute of <code>ds:Signature</code> element.
     * @param signatureElement Parameter that represents <code>ds:Signature</code> element.
     * @param xmlSignature Parameter that represents the XML signature.
     * @param isBaseline Parameter that indicates if the XML signature has Baseline form (true) or not (false).
     * @param isCounterSignature Parameter that indicates if the element to validate is a signer (false) or a counter-signer (true).
     * @throws SigningException If the validation fails.
     */
    public static void validateXAdESPublicKeyInfo(String signatureId, Element signatureElement, org.apache.xml.security.signature.XMLSignature xmlSignature, boolean isBaseline, boolean isCounterSignature) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG156));
	try {

	    // Comprobamos que se ha indicado el elemento ds:Signature
	    GenericUtilsCommons.checkInputParameterIsNotNull(signatureElement, Language.getResIntegra(ILogConstantKeys.US_LOG191));

	    // Comprobamos que se ha indicado la firma XML
	    GenericUtilsCommons.checkInputParameterIsNotNull(xmlSignature, Language.getResIntegra(ILogConstantKeys.US_LOG039));

	    // Accedemos al elemento ds:KeyInfo
	    Element keyInfoElement = UtilsXML.getChildElement(signatureElement, IXMLConstants.ELEMENT_KEY_INFO, signatureId, true);

	    // Comprobamos que existe una referencia al elemento ds:KeyInfo, si
	    // la firma no es Baseline ni es una contra-firma
	    if (!isBaseline && !isCounterSignature) {
		validateProtectionKeyInfo(xmlSignature, keyInfoElement, signatureId);
	    }

	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG197, new Object[ ] { signatureId }));
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG157));
	}
    }

    /**
     * Method that checks if a XML signature contains a reference associated to <code>ds:KeyInfo</code> element.
     * @param xmlSignature Parameter that represents the XML signature.
     * @param keyInfoElement Parameter that represents <code>ds:KeyInfo</code> element.
     * @param signatureId Parameter that represents the value of <code>Id</code> attribute of <code>ds:Signature</code> element.
     * @throws SigningException If the validation fails.
     */
    private static void validateProtectionKeyInfo(org.apache.xml.security.signature.XMLSignature xmlSignature, Element keyInfoElement, String signatureId) throws SigningException {
	/*
	 * Comprobamos que la información de clave pública del elemento KeyInfo haya sido protegida en el cálculo de la firma digital, esto es,
	 * que exista un elemento Reference cuya URI apunte al elemento KeyInfo
	 */
	try {
	    // Accedemos al atributo Id del elemento ds:KeyInfo
	    String keyInfoIdAttribute = keyInfoElement.getAttribute(IXMLConstants.ATTRIBUTE_ID);

	    boolean found = false;

	    // Si hemos encontrado el atributo Id
	    if (keyInfoIdAttribute != null) {
		// Recorremos la lista de referencias

		for (int index = 0; !found && index < xmlSignature.getSignedInfo().getLength(); index++) {
		    // Accedemos a la referencia
		    org.apache.xml.security.signature.Reference ref = xmlSignature.getSignedInfo().item(index);

		    // Obtenemos la URI de la referencia
		    String uri = null;
		    if (ref.getURI() != null && ref.getURI().length() >= 1) {
			uri = ref.getURI().substring(1);
		    }

		    // Comprobamos si la URI de la referencia apunta al
		    // elemento KeyInfo
		    if (uri != null && uri.equals(keyInfoIdAttribute)) {
			// Indicamos que la hemos encontrado
			found = true;
		    }
		}
	    }
	    if (!found) {
		// Si no hemos encontrado ninguna referencia al elemento
		// ds:KeyInfo lanzamos una excepción
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG195, new Object[ ] { signatureId });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	} catch (org.apache.xml.security.exceptions.XMLSecurityException e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG188, new Object[ ] { signatureId });
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}
    }

    /**
     * Method that validates if the signing time of a XML signature is previous than certain validation date.
     * @param signedSignaturePropertiesElement Parameter that represents <code>xades:SignedSignatureProperties</code> element.
     * @param isRequired Parameter that indicates if the XML signature must contain <code>xades:SigningTime</code> element (true) or not (false).
     * @param signatureId Parameter that represents the value of <code>Id</code> attribute of <code>ds:Signature</code> element.
     * @param validationDate Parameter that represents the validation date.
     * @throws SigningException if the validation fails.
     */
    public static void validateXAdESSigningTime(Element signedSignaturePropertiesElement, boolean isRequired, String signatureId, Date validationDate) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG168));
	try {
	    // Comprobamos que se ha indicado el elemento
	    // xades:SignedSignatureProperties
	    GenericUtilsCommons.checkInputParameterIsNotNull(signedSignaturePropertiesElement, Language.getResIntegra(ILogConstantKeys.US_LOG200));

	    // Comprobamos que se ha indicado la fecha de validación
	    GenericUtilsCommons.checkInputParameterIsNotNull(validationDate, Language.getResIntegra(ILogConstantKeys.US_LOG204));

	    // Accedemos al elemento xades:SigningTime
	    Element signingTimeElement = UtilsXML.getChildElement(signedSignaturePropertiesElement, IXMLConstants.ELEMENT_SIGNING_TIME, signatureId, false);

	    // Si el firmante carece del elemento xades:SigningTime
	    if (signingTimeElement == null) {
		// Si el elemento xades:SigningTime es obligatorio
		if (isRequired) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG198, new Object[ ] { signatureId });
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
		// Si el atributo SigningTime es opcional
		else {
		    // Consideramos la validación como correcta pues no se puede
		    // validar dicho atributo
		    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG198, new Object[ ] { signatureId }));
		}
	    }
	    // Si el firmante posee el atributo SigningTime
	    else {
		Date signingTimeDate = null;

		// Accedemos a la fecha de generación de la firma
		String signingTimeStr = signingTimeElement.getTextContent();
		try {
		    signingTimeDate = getUTCDate(signingTimeStr);

		    // Si la fecha de generación es posterior a la fecha
		    // de validación
		    if (signingTimeDate.after(validationDate)) {
			String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG201, new Object[ ] { signingTimeStr, signatureId, validationDate.toString() });
			LOGGER.error(errorMsg);
			throw new SigningException(errorMsg);
		    }
		    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG202, new Object[ ] { signatureId }));
		} catch (ParseException e) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG203, new Object[ ] { signatureId, signingTimeStr });
		    LOGGER.error(errorMsg, e);
		    throw new SigningException(errorMsg, e);
		}
	    }
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG169));
	}

    }

    /**
     * Method that obtains a date from a string with <code>UTC</code> format.
     * @param utcDate Parameter that represents the string with <code>UTC</code> format.
     * @return the date.
     * @throws ParseException If the method fails.
     */
    private static Date getUTCDate(String utcDate) throws ParseException {
	String[ ] t = utcDate.split("T");
	String pattern = "yyyy";
	String dateStr = null;
	dateStr = t[0].substring(0, NumberConstants.INT_4);
	if (t[0].length() > NumberConstants.INT_6) {
	    dateStr = dateStr + t[0].substring(NumberConstants.INT_5, NumberConstants.INT_7);
	    pattern = pattern + "MM";
	    if (t[0].length() > NumberConstants.INT_9) {
		dateStr = dateStr + t[0].substring(NumberConstants.INT_8, NumberConstants.INT_10);
		pattern = pattern + "dd";
	    }
	}
	if (t.length == 2) {
	    String offSet = null;
	    if (t[1].indexOf('Z') > -1) {
		t[1] = t[1].substring(0, t[1].indexOf('Z'));
		offSet = "+0000";
	    } else if (t[1].indexOf('-') > -1) {
		offSet = t[1].substring(t[1].indexOf('-')).replaceAll(":", "");
		t[1] = t[1].substring(0, t[1].indexOf('-'));
	    } else if (t[1].indexOf('+') > -1) {
		offSet = t[1].substring(t[1].indexOf('+')).replaceAll(":", "");
		t[1] = t[1].substring(0, t[1].indexOf('+'));
	    }
	    if (t[1].length() > 1) {
		dateStr = dateStr + t[1].substring(0, 2);
		pattern = pattern + "HH";
		if (t[1].length() > NumberConstants.INT_4) {
		    dateStr = dateStr + t[1].substring(NumberConstants.INT_3, NumberConstants.INT_5);
		    pattern = pattern + "mm";
		    if (t[1].length() > NumberConstants.INT_7) {
			dateStr = dateStr + t[1].substring(NumberConstants.INT_6, NumberConstants.INT_8);
			pattern = pattern + "ss";
			if (t[1].length() > NumberConstants.INT_9) {
			    pattern = pattern + ".SSS";
			    t[1] = t[1].substring(NumberConstants.INT_8);
			    for (int i = t[1].length(); i < NumberConstants.INT_4; i++) {
				t[1] = t[1] + "0";
			    }
			    dateStr = dateStr + t[1].substring(0, NumberConstants.INT_4);
			}
		    }
		}
		if (offSet != null) {
		    pattern = pattern + "Z";
		    dateStr = dateStr + offSet;
		}
	    }
	}
	SimpleDateFormat sdf = new SimpleDateFormat(pattern);
	return sdf.parse(dateStr);
    }

    /**
     * Method that validates the structure of a signature dictionary by PAdES-Basic signature form. The validations to execute will be:
     * <ul>
     * <li>Check if the CMS signature contains only one signer.</li>
     * <li>/Contents key of the signature dictionary is required and the content matches to the CMS signature.</li>
     * <li>/ByteRange key of the signature dictionary is required and the content matches to the digest of the CMS signature.</li>
     * <li>/SubFilter key of the signature dictionary has "adbe.pkcs7.detached" or "adbe.pkcs7.sha1" value.</li>
     * </ul>
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @param pdfDocument Parameter that represents the PDF document.
     * @param signedData Parameter that represents the signature message.
     * @throws SigningException If the validation fails.
     */
    public static void validatePAdESBasicStructurally(PDFSignatureDictionary signatureDictionary, byte[ ] pdfDocument, CMSSignedData signedData) throws SigningException {
	/*
	 * Validación Estructural PAdES-Basic. Contemplará las siguientes verificaciones:
	 * > La firma CMS que constituye el núcleo de firma sólo contiene un firmante.
	 * > La clave /Contents del diccionario de firma deberá estar presente y su contenido corresponderse con una firma CMS.
	 * > La clave /ByteRange del diccionario de firma deberá estar presente y su contenido corresponderse con el resumen de la firma CMS.
	 * > La clave /SubFilter del diccionario de firma deberá estar presente y su contenido corresponderse con el valor “adbe.pkcs7.detached” o “adbe.pkcs7.sha1”.
	 * 		En el caso de que el valor sea “adbe.pkcs7.detached” se comprobará que la firma CMS contenida es explícita.
	 * 		En el caso de que el valor sea “adbe.pkcs7.sha1” se comprobará que el algoritmo de firma utilizado es SHA-1.
	 */
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG211));
	try {
	    // Comprobamos que se ha indicado el diccionario de firma
	    GenericUtilsCommons.checkInputParameterIsNotNull(signatureDictionary, Language.getResIntegra(ILogConstantKeys.US_LOG007));

	    // Comprobamos que se ha indicado el documento PDF
	    GenericUtilsCommons.checkInputParameterIsNotNull(pdfDocument, Language.getResIntegra(ILogConstantKeys.US_LOG008));

	    // Comprobamos que se ha indicado el contenido de la firma
	    GenericUtilsCommons.checkInputParameterIsNotNull(signedData, Language.getResIntegra(ILogConstantKeys.US_LOG019));

	    // Accedemos a la firma, que debe encontrarse dentro de la clave
	    // /Contents del diccionario de firma
	    byte[ ] signature = signatureDictionary.getDictionary().getAsString(PdfName.CONTENTS).getOriginalBytes();

	    // Comprobamos que el contenido de la clave /Contents no es nulo
	    if (signature == null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG010, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Comprobamos que la clave /ByteRange no es nula
	    PdfArray pdfArrayByteRange = signatureDictionary.getDictionary().getAsArray(PdfName.BYTERANGE);
	    if (pdfArrayByteRange == null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG011, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Verficicamos que la firma posee un único firmante
	    checkPAdESSignersNumber(signedData, signatureDictionary);

	    // Accedemos al valor de la clave /SubFilter
	    PdfName subFilterValue = (PdfName) signatureDictionary.getDictionary().get(PdfName.SUBFILTER);

	    // Si el valor de la clave /SubFilter es "adbe.pkcs7.detached"
	    if (subFilterValue.equals(PdfName.ADBE_PKCS7_DETACHED)) {
		// Comprobamos que la firma es explícita
		if (isImplicit(signedData)) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG213, new Object[ ] { signatureDictionary.getName(), PdfName.ADBE_PKCS7_DETACHED.toString() });
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
	    }
	    // Si el valor de la clave /SubFilter es "adbe.pkcs7.sha1"
	    else if (subFilterValue.equals(PdfName.ADBE_PKCS7_SHA1)) {
		// Accedemos al firmante
		SignerInformation signerInformation = ((List<SignerInformation>) signedData.getSignerInfos().getSigners()).iterator().next();

		// Comprobamos que la firma incluye el resumen en SHA-1 de los
		// datos firmados
		if (!signedData.getSignedContentTypeOID().equals(PKCSObjectIdentifiers.data) && signerInformation.getDigestAlgOID().equals(OIWObjectIdentifiers.idSHA1)) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG214, new Object[ ] { signatureDictionary.getName(), PdfName.ADBE_PKCS7_SHA1.toString() });
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}

	    }

	    // Comprobamos que el resumen de la firma coincide con el
	    // resumen
	    // indicado por el valor de la clave /ByteRange.
	    checkSignatureDigesthMatchesByteRangeValue(signatureDictionary, pdfDocument, pdfArrayByteRange, signedData);

	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG216, new Object[ ] { signatureDictionary.getName() }));
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG212));
	}
    }

    /**
     * Method that checks if a signature contained inside of a signature dictionary contains only one signer.
     * @param signedData Parameter that represents the signature message.
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @throws SigningException If the signature contains more than one signer.
     */
    private static void checkPAdESSignersNumber(CMSSignedData signedData, PDFSignatureDictionary signatureDictionary) throws SigningException {
	// Verficicamos que la firma posee un único firmante
	if (signedData.getSignerInfos().getSigners().size() > 1) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG012, new Object[ ] { signatureDictionary.getName() });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that checks if the digest of a signature included inside of a signature dictionary matches with the value included on /ByteRange entry
     * of a signature dictionary.
     * @param signatureDictionary Parameter that represents the information about the signature dictionary.
     * @param pdfDocument Parameter that represents the PDF document.
     * @param pdfArrayByteRange Parameter that represents the content of /ByteRange entry.
     * @param signedData Parameter that represents the signature message.
     * @throws SigningException If the digest of the signature doesn't match with the value included on /ByteRange entry of the signature dictionary.
     */
    private static void checkSignatureDigesthMatchesByteRangeValue(PDFSignatureDictionary signatureDictionary, byte[ ] pdfDocument, PdfArray pdfArrayByteRange, CMSSignedData signedData) throws SigningException {
	MessageDigest messageDigestSignature = null;
	byte[ ] hashSignature = null;
	try {
	    // Accedemos al firmante
	    SignerInformation signerInformation = ((List<SignerInformation>) signedData.getSignerInfos().getSigners()).iterator().next();

	    // Obtenemos el algoritmo de resumen usado para la
	    // firma
	    AlgorithmIdentifier hashAlgorithmSignature = signerInformation.getDigestAlgorithmID();

	    // Obtenemos el MessageDigest asociado a la firma
	    AttributeTable signedAttr = signerInformation.getSignedAttributes();
	    Attribute attrMessageDigest = signedAttr.get(CMSAttributes.messageDigest);

	    DERObject hashObj = attrMessageDigest.getAttrValues().getObjectAt(0).getDERObject();
	    hashSignature = ((ASN1OctetString) hashObj).getOctets();

	    messageDigestSignature = MessageDigest.getInstance(hashAlgorithmSignature.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);

	    // Si la firma es implícita, el hash de la firma
	    // coincide con el contenido de los datos firmados
	    if (isImplicit(signedData)) {
		hashSignature = signedData.getEncoded();
	    }
	} catch (Exception e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG215, new Object[ ] { signatureDictionary.getName() });
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}
	// Comparamos ambos arrays de bytes
	if (!equalsHash(pdfArrayByteRange, messageDigestSignature, pdfDocument, hashSignature)) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG013, new Object[ ] { signatureDictionary.getName() });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that checks if the value of the signed attribute <code>SerialNumber</code> of a signature matches to the serial number of the signing certificate.
     * @param signerInformation Parameter that represents the information about the signer.
     * @param signingCertificate Parameter that represents the signing certificate.
     * @throws SigningException If the validation fails.
     */
    public static void validateCMSPublicKeyInfo(SignerInformation signerInformation, X509Certificate signingCertificate) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG156));
	try {
	    // Comprobamos que se ha indicado la información del firmante
	    GenericUtilsCommons.checkInputParameterIsNotNull(signerInformation, Language.getResIntegra(ILogConstantKeys.US_LOG032));

	    // Comprobamos que se ha indicado el certificado firmante
	    GenericUtilsCommons.checkInputParameterIsNotNull(signingCertificate, Language.getResIntegra(ILogConstantKeys.US_LOG002));

	    // Accedemos al conjunto de atributos firmados
	    AttributeTable signedAttrs = signerInformation.getSignedAttributes();

	    // Accedemos al atributo SerialNumber
	    Attribute attSerialNumber = signedAttrs.get(BCStyle.SERIALNUMBER);

	    // Si el firmante contiene el atributo SerialNumber
	    if (attSerialNumber != null) {
		// Obtenemos el valor del número de serie
		String serialNumber = attSerialNumber.getAttrValues().getObjectAt(0).toString();

		// Obtenemos el número de serie del certificado firmante
		String signingCertificateSerialNumber = signingCertificate.getSerialNumber().toString();

		// Comprobamos que coincidan
		if (serialNumber.equals(signingCertificateSerialNumber)) {
		    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG217, new Object[ ] { signingCertificateSerialNumber, signingCertificate.getSubjectDN().getName() }));
		} else {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG218, new Object[ ] { serialNumber, signingCertificateSerialNumber, signingCertificate.getSubjectDN().getName() });
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
	    }
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG157));
	}
    }

    /**
     * Method that validates the signing time of a PAdES-Basic signature.
     * @param signerInformation Parameter that represents the information about the first signer of the signature.
     * @param validationDate Parameter that represents the validation date.
     * @param signingCertificate Parameter that represents the signing certificate.
     * @param signatureDictionary Parameter that represents the information about the signature dictionary.
     * @throws SigningException If the validation fails.
     */
    public static void validatePAdESBasicSigningTime(SignerInformation signerInformation, Date validationDate, X509Certificate signingCertificate, PDFSignatureDictionary signatureDictionary) throws SigningException {
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
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG219));
	try {
	    // Comprobamos que se ha indicado la información del firmante
	    GenericUtilsCommons.checkInputParameterIsNotNull(signerInformation, Language.getResIntegra(ILogConstantKeys.US_LOG032));

	    // Comprobamos que se ha indicado la fecha de validación
	    GenericUtilsCommons.checkInputParameterIsNotNull(validationDate, Language.getResIntegra(ILogConstantKeys.US_LOG204));

	    // Comprobamos que se ha indicado el certificado firmante
	    GenericUtilsCommons.checkInputParameterIsNotNull(signingCertificate, Language.getResIntegra(ILogConstantKeys.US_LOG002));

	    // Comprobamos que se ha indicado el diccionario de firma
	    GenericUtilsCommons.checkInputParameterIsNotNull(signatureDictionary, Language.getResIntegra(ILogConstantKeys.US_LOG007));

	    // Accedemos al conjunto de atributos firmados
	    AttributeTable signedAttrs = signerInformation.getSignedAttributes();

	    // Accedemos al atributo SigningTime
	    Attribute attSigningTime = signedAttrs.get(PKCSObjectIdentifiers.pkcs_9_at_signingTime);

	    // Si el firmante posee el atributo SigningTime
	    if (attSigningTime != null) {
		// Llevamos a cabo la validación del atributo SigningTime
		checkSigningTime(attSigningTime, signingCertificate, validationDate);
	    }
	    // Si el diccionario de firma posee la entrada /M
	    // validaremos que dicho campo posee un formato correcto
	    // según PDF Reference, sección 3.8.3 (Dates), así como que la fecha
	    // contenida no sea futura
	    if (signatureDictionary.getDictionary().get(PdfName.M) != null) {
		String mTimeStr = signatureDictionary.getDictionary().getAsString(PdfName.M).toString();
		Date mTime = parseToPDFDate(mTimeStr);
		// Si la fecha contenida en la entrada /M no tiene el formato
		// adecuado
		if (mTime == null) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG028, new Object[ ] { signatureDictionary.getName() });
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
		// Si la fecha contenida en la entrada /M es posterior a la
		// fecha de validación
		if (mTime.after(validationDate)) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG029, new Object[ ] { signatureDictionary.getName() });
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
	    }
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG221, new Object[ ] { signatureDictionary.getName() }));
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG220));
	}
    }

    /**
     * Method that checks if a signature dictionary is valid against PAdES Enhanced profile.
     * @param signatureDictionary Parameter that represents the information about the signature dictionary.
     * @param pdfDocument Parameter that represents the signed PDF document.
     * @param signedData Parameter that represents the signature message of the signature contained inside of the signature dictionary.
     * @param isEPES Parameter that indicates if the signature dictionary represents a PAdES-EPES signature (true) or a PAdES-BES signature (false).
     * @throws SigningException If the validation fails.
     */
    public static void validatePAdESEnhancedStructurally(PDFSignatureDictionary signatureDictionary, byte[ ] pdfDocument, CMSSignedData signedData, boolean isEPES) throws SigningException {
	/*
	 * Validación Estructural PAdES-BES. Contemplará las siguientes verificaciones:
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
	 * 
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
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG222));
	try {
	    // Comprobamos que se ha indicado el diccionario de firma
	    GenericUtilsCommons.checkInputParameterIsNotNull(signatureDictionary, Language.getResIntegra(ILogConstantKeys.US_LOG007));

	    // Comprobamos que se ha indicado el documento PDF
	    GenericUtilsCommons.checkInputParameterIsNotNull(pdfDocument, Language.getResIntegra(ILogConstantKeys.US_LOG008));

	    // Comprobamos que se ha indicado el contenido de la firma
	    GenericUtilsCommons.checkInputParameterIsNotNull(signedData, Language.getResIntegra(ILogConstantKeys.US_LOG019));

	    // Accedemos a la firma, que debe encontrarse dentro de la clave
	    // /Contents del diccionario de firma
	    byte[ ] signature = signatureDictionary.getDictionary().getAsString(PdfName.CONTENTS).getOriginalBytes();

	    // Comprobamos que el contenido de la clave /Contents no es nulo
	    if (signature == null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG010, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Comprobamos que la clave /ByteRange no es nula
	    PdfArray pdfArrayByteRange = signatureDictionary.getDictionary().getAsArray(PdfName.BYTERANGE);
	    if (pdfArrayByteRange == null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG011, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Verificamos que la firma posee un único firmante
	    checkPAdESSignersNumber(signedData, signatureDictionary);

	    // Accedemos al valor de la clave /SubFilter
	    PdfName subFilterValue = (PdfName) signatureDictionary.getDictionary().get(PdfName.SUBFILTER);

	    // Si el valor de la clave /SubFilter no es "ETSI.CAdES.detached"
	    if (!subFilterValue.equals(CADES_SUBFILTER_VALUE)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG224, new Object[ ] { signatureDictionary.getName(), subFilterValue.toString() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Accedemos al primer firmante
	    SignerInformation signerInformation = ((List<SignerInformation>) signedData.getSignerInfos().getSigners()).iterator().next();

	    // Accedemos al conjunto de atributos no firmados
	    AttributeTable unsignedAttrs = signerInformation.getUnsignedAttributes();

	    // Si el firmante presenta atributos no firmados
	    if (unsignedAttrs != null) {
		// Comprobamos que el firmante no contiene el atributo
		// counter-signature
		checkPAdESUnsignedAttribute(unsignedAttrs, PKCSObjectIdentifiers.pkcs_9_at_counterSignature, signatureDictionary.getName(), "counter-signature");

		// Comprobamos que el firmante no contiene el atributo
		// content-reference
		checkPAdESUnsignedAttribute(unsignedAttrs, PKCSObjectIdentifiers.id_aa_contentReference, signatureDictionary.getName(), "content-reference");
	    }

	    // Accedemos al conjunto de atributos firmados
	    AttributeTable signedAttrs = signerInformation.getSignedAttributes();

	    // Comprobamos que el firmante contiene el atributo content-type y
	    // que éste tiene el valor "id-data"
	    Attribute contentTypeAttribute = signedAttrs.get(PKCSObjectIdentifiers.pkcs_9_at_contentType);
	    if (contentTypeAttribute == null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG016, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    } else if (!contentTypeAttribute.getAttrValues().getObjectAt(0).getDERObject().equals(PKCSObjectIdentifiers.data)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG017, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Comprobamos que el diccionario de firma no contiene la clave
	    // /Cert
	    if (signatureDictionary.getDictionary().getAsName(PdfName.CERT) != null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG018, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Comprobamos que el firmante no contiene el atributo
	    // content-identifier
	    checkPAdESSignedAttribute(signedAttrs, PKCSObjectIdentifiers.id_aa_contentIdentifier, signatureDictionary.getName(), "content-identifier");

	    // Si la firma es PAdES-EPES
	    if (isEPES) {
		// Comprobamos que el diccionario de firma no contiene la clave
		// /Reason
		if (signatureDictionary.getDictionary().getAsName(PdfName.REASON) != null) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG023, new Object[ ] { signatureDictionary.getName() });
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
	    }
	    // Si la firma es PAdES-BES
	    else {
		// Comprobamos que el firmante no contiene el atributo
		// commitment-type-indication
		checkPAdESSignedAttribute(signedAttrs, PKCSObjectIdentifiers.id_aa_ets_commitmentType, signatureDictionary.getName(), "commitment-type-indication");
	    }

	    // Comprobamos que el firmante no contiene el atributo
	    // signer-location
	    checkPAdESSignedAttribute(signedAttrs, PKCSObjectIdentifiers.id_aa_ets_signerLocation, signatureDictionary.getName(), "signer-location");

	    // Comprobamos que el firmante no contiene el atributo signing-time
	    checkPAdESSignedAttribute(signedAttrs, PKCSObjectIdentifiers.pkcs_9_at_signingTime, signatureDictionary.getName(), "signing-time");

	    // Comprobamos que el firmante no contiene el atributo content-hints
	    checkPAdESSignedAttribute(signedAttrs, PKCSObjectIdentifiers.id_aa_contentHint, signatureDictionary.getName(), "content-hints");

	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG227, new Object[ ] { signatureDictionary.getName() }));
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG223));
	}
    }

    /**
     * Method that checks if a signed attribute isn't null for the first signer of a signature contained inside of a signature dictionary.
     * @param signedAttrs Parameter that represents the signed attributes.
     * @param attributeOID Parameter that represents the OID of the signed attribute to check.
     * @param signatureDictionaryName Parameter that represents the name of the signature dictionary.
     * @param attributeName Parameter that represents the name of the signed attribute to check.
     * @throws SigningException If the signed attributes isn't present.
     */
    private static void checkPAdESSignedAttribute(AttributeTable signedAttrs, ASN1ObjectIdentifier attributeOID, String signatureDictionaryName, String attributeName) throws SigningException {
	if (signedAttrs.get(attributeOID) != null) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG226, new Object[ ] { signatureDictionaryName, attributeName });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that checks if an unsigned attribute isn't null for the first signer of a signature contained inside of a signature dictionary.
     * @param unsignedAttrs Parameter that represents the unsigned attributes.
     * @param attributeOID Parameter that represents the OID of the unsigned attribute to check.
     * @param signatureDictionaryName Parameter that represents the name of the signature dictionary.
     * @param attributeName Parameter that represents the name of the unsigned attribute to check.
     * @throws SigningException If the signed attributes isn't present.
     */
    private static void checkPAdESUnsignedAttribute(AttributeTable unsignedAttrs, ASN1ObjectIdentifier attributeOID, String signatureDictionaryName, String attributeName) throws SigningException {
	if (unsignedAttrs.get(attributeOID) != null) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG225, new Object[ ] { signatureDictionaryName, attributeName });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that validates if the signature dictionary has /M entry that entry must be a date with a valid format by PDF Referente and
     * that date must be before of the validation date.
     * @param signatureDictionary Parameter that represents the information about the signature dictionary.
     * @param validationDate Parameter that represents the validation date.
     * @param isRequired Parameter that indicates if the /M is required for the signature dictionary (true) or not (false).
     * @throws SigningException If the validation fails.
     */
    public static void validatePAdESSigningTime(PDFSignatureDictionary signatureDictionary, Date validationDate, boolean isRequired) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG228));
	try {
	    // Comprobamos que se ha indicado el diccionario de firma
	    GenericUtilsCommons.checkInputParameterIsNotNull(signatureDictionary, Language.getResIntegra(ILogConstantKeys.US_LOG007));

	    // Comprobamos que se ha indicado la fecha de validación
	    GenericUtilsCommons.checkInputParameterIsNotNull(validationDate, Language.getResIntegra(ILogConstantKeys.US_LOG204));

	    // Si el diccionario de firma contiene la entrada /M
	    if (signatureDictionary.getDictionary().get(PdfName.M) != null) {
		// Accedemos a la fecha almacenada en la entrada /M
		String mTimeStr = signatureDictionary.getDictionary().getAsString(PdfName.M).toString();
		Date mTime = parseToPDFDate(mTimeStr);

		// Comprobamos que la fecha contenida en la entrada /M tiene el
		// formato adecuado
		if (mTime == null) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG028, new Object[ ] { signatureDictionary.getName() });
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}

		// Comprobamos que la fecha contenida en la entrada /M es
		// posterior a la fecha de validación
		if (mTime.after(validationDate)) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG029, new Object[ ] { signatureDictionary.getName() });
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
	    }
	    // Si el diccionario de firma no contiene la entrada /M y es
	    // requerida
	    else if (isRequired) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG109, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG229));
	}
    }

    /**
     * Method that validates for a Document Time-stamp dictionary:
     * <ul>
     * <li>The <i>ByteRange</i> entry of the Document Time-stamp dictionary isn't null.</li>
     * <li>The <i>ByteRange</i> entry represents the exact byte range for the digest calculation.</li>
     * <li>The entry with the key <i>Cert</i> in the Document Time-stamp dictionary isn't used.</li>
     * <li>The entry with the key <i>Reference</i> in the Document Time-stamp dictionary isn't used.</li>
     * <li>The entry with the key <i>Changes</i> in the Document Time-stamp dictionary isn't used.</li>
     * <li>The entry with the key <i>R</i> in the Document Time-stamp dictionary isn't used.</li>
     * <li>The entry with the key <i>Prop_AuthTime</i> in the Document Time-stamp dictionary isn't used.</li>
     * <li>The entry with the key <i>Prop_AuthType</i> in the Document Time-stamp dictionary isn't used.</li>
     * <li>The entry with the key <i>V</i> in the Document Time-stamp dictionary, if present, has the value: 0.</li>
     * </ul>
     * @param pdfDocumentTimestampDictionary Parameter that represents the information about the Document Time-stamp dictionary.
     * @param pdfDocument Parameter that represents the PDF document.
     * @throws SigningException If the validation fails.
     */
    public static void validateDocumentTimeStampDictionaryStructurally(PDFDocumentTimestampDictionary pdfDocumentTimestampDictionary, byte[ ] pdfDocument) throws SigningException {
	/*
	 * Validación Estructural Diccionario Document Time-stamp. Contemplará las siguientes verificaciones:
	 * > La clave /ByteRange del diccionario de sello de tiempo deberá estar presente y su valor corresponderse con el valor del atributo message-imprint del sello de tiempo.
	 * > La clave /Cert del diccionario de sello de tiempo no deberá estar presente.
	 * > La clave /Reference del diccionario de sello de tiempo no deberá estar presente.
	 * > La clave /Changes del diccionario de sello de tiempo no deberá estar presente.
	 * > La clave /R del diccionario de sello de tiempo no deberá estar presente.
	 * > La clave /Prop_AuthTime del diccionario de sello de tiempo no deberá estar presente.
	 * > La clave /Prop_AuthType del diccionario de sello de tiempo no deberá estar presente.
	 * > La clave /V del diccionario de sello de tiempo deberá estar presente y su valor corresponderse con el valor 0.
	 */
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG230));
	try {
	    // Comprobamos que se ha indicado el diccionario de sello de tiempo
	    GenericUtilsCommons.checkInputParameterIsNotNull(pdfDocumentTimestampDictionary, Language.getResIntegra(ILogConstantKeys.US_LOG232));

	    // Comprobamos que se ha indicado el documento PDF
	    GenericUtilsCommons.checkInputParameterIsNotNull(pdfDocument, Language.getResIntegra(ILogConstantKeys.US_LOG008));

	    // Comprobamos que la clave /ByteRange del diccionario de sello de
	    // tiempo está presente y su valor corresponderse con el valor del
	    // atributo message-imprint del sello de tiempo
	    validateDocumentTimeStampDictionaryByteRangeKey(pdfDocumentTimestampDictionary, pdfDocument);

	    // Comprobamos que el diccionario de sello de tiempo no contiene la
	    // clave /Cert
	    checkKeyForDocumentTimeStampDictionary(pdfDocumentTimestampDictionary, PdfName.CERT);

	    // Comprobamos que el diccionario de sello de tiempo no contiene la
	    // clave /Reference
	    checkKeyForDocumentTimeStampDictionary(pdfDocumentTimestampDictionary, PdfName.REFERENCE);

	    // Comprobamos que el diccionario de sello de tiempo no contiene la
	    // clave /Changes
	    checkKeyForDocumentTimeStampDictionary(pdfDocumentTimestampDictionary, new PdfName("Changes"));

	    // Comprobamos que el diccionario de sello de tiempo no contiene la
	    // clave /R
	    checkKeyForDocumentTimeStampDictionary(pdfDocumentTimestampDictionary, PdfName.R);

	    // Comprobamos que el diccionario de sello de tiempo no contiene la
	    // clave /Prop_AuthTime
	    checkKeyForDocumentTimeStampDictionary(pdfDocumentTimestampDictionary, new PdfName("Prop_AuthTime"));

	    // Comprobamos que el diccionario de sello de tiempo no contiene la
	    // clave /Prop_AuthType
	    checkKeyForDocumentTimeStampDictionary(pdfDocumentTimestampDictionary, new PdfName("Prop_AuthType"));

	    // Comprobamos que el diccionario de sello de tiempo contiene la
	    // clave /V
	    if (pdfDocumentTimestampDictionary.getDictionary().getAsName(PdfName.V) != null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG233, new Object[ ] { pdfDocumentTimestampDictionary.getName(), PdfName.V.toString() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Comprobamos que el valor asociado a la clave /V es 0
	    if (!pdfDocumentTimestampDictionary.getDictionary().get(PdfName.V).toString().equalsIgnoreCase("0")) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG234, new Object[ ] { pdfDocumentTimestampDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG057, new Object[ ] { pdfDocumentTimestampDictionary.getName() }));
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG231));
	}
    }

    /**
     *  Method that validates for a Document Time-stamp dictionary:
     *  <ul>
     * <li>The <i>ByteRange</i> entry of the Document Time-stamp dictionary isn't null.</li>
     * <li>The <i>ByteRange</i> entry represents the exact byte range for the digest calculation.</li>
     * </ul>
     * @param pdfDocumentTimestampDictionary Parameter that represents the information about the Document Time-stamp dictionary.
     * @param pdfDocument Parameter that represents the PDF document.
     * @throws SigningException If the validation fails.
     */
    private static void validateDocumentTimeStampDictionaryByteRangeKey(PDFDocumentTimestampDictionary pdfDocumentTimestampDictionary, byte[ ] pdfDocument) throws SigningException {
	try {
	    // Accedemos al sello de tiempo contenido en el diccionario de sello
	    // de tiempo
	    TimeStampToken tst = pdfDocumentTimestampDictionary.getTimestamp();

	    // Comprobamos que el diccionario de sello de tiempo contiene la
	    // clave /ByteRange
	    PdfArray pdfArrayByteRange = pdfDocumentTimestampDictionary.getDictionary().getAsArray(PdfName.BYTERANGE);
	    if (pdfArrayByteRange == null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG233, new Object[ ] { pdfDocumentTimestampDictionary.getName(), PdfName.BYTERANGE.toString() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Obtenemos el algoritmo de hash usado para calcular el resumen del
	    // sello de tiempo
	    AlgorithmIdentifier hATST = tst.getTimeStampInfo().getHashAlgorithm();

	    // Obtenemos el MessageDigest asociado
	    MessageDigest md = MessageDigest.getInstance(CryptoUtilPdfBc.translateAlgorithmIdentifier(hATST));

	    // Comprobamos que el contenido de la clave /ByteRange se
	    // corresponde con el valor del atributo message-imprint del sello
	    // de tiempo
	    if (!equalsHash(pdfArrayByteRange, md, pdfDocument, tst.getTimeStampInfo().getMessageImprintDigest())) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG235, new Object[ ] { pdfDocumentTimestampDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	} catch (NoSuchAlgorithmException e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG056, new Object[ ] { pdfDocumentTimestampDictionary.getName() });
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}
    }

    /**
     * Method that checks if a Document Time-stamp dictionary contains a key.
     * @param pdfDocumentTimestampDictionary Parameter that represents the information about the Document Time-stamp dictionary.
     * @param keyName Parameter that represents the key to check.
     * @throws SigningException If the Document Time-stamp dictionary doesn't include the key.
     */
    private static void checkKeyForDocumentTimeStampDictionary(PDFDocumentTimestampDictionary pdfDocumentTimestampDictionary, PdfName keyName) throws SigningException {
	if (pdfDocumentTimestampDictionary.getDictionary().getAsName(keyName) != null) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG236, new Object[ ] { pdfDocumentTimestampDictionary.getName(), keyName.toString() });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that checks if the generation date of a time-stamp contained inside of a Document Time-stamp dictionary is previous than a validation date.
     * @param pdfDocumentTimeStampDictionary Parameter that represents the information about the Document Time-stamp dictionary.
     * @param validationDate Parameter that represents the validation date.
     * @throws SigningException If the generation date of a time-stamp contained inside of a Document Time-stamp dictionary is after than the validation date.
     */
    public static void validateDocumentTimeStampSigningTime(PDFDocumentTimestampDictionary pdfDocumentTimeStampDictionary, Date validationDate) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG182));
	try {
	    // Comprobamos que se ha indicado el diccionario de sello de tiempo
	    GenericUtilsCommons.checkInputParameterIsNotNull(pdfDocumentTimeStampDictionary, Language.getResIntegra(ILogConstantKeys.US_LOG232));

	    // Comprobamos que se ha indicado la fecha de validación
	    GenericUtilsCommons.checkInputParameterIsNotNull(validationDate, Language.getResIntegra(ILogConstantKeys.US_LOG204));

	    if (pdfDocumentTimeStampDictionary.getTimestamp().getTimeStampInfo().getGenTime().after(validationDate)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG147, new Object[ ] { pdfDocumentTimeStampDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG148));
	}
    }

    /**
     * Method that checks if a signature dictionary is valid against PAdES Baseline profile.
     * @param signatureDictionary Parameter that represents the information about the signature dictionary.
     * @param pdfDocument Parameter that represents the signed PDF document.
     * @param signedData Parameter that represents the signature message of the signature contained inside of the signature dictionary.
     * @return a boolean that indicates if the first signer of the signature contained inside of the signature dictionary includes <code>signature-policy-id</code>
     * attribute (true) or not (false).
     * @throws SigningException If the validation fails.
     */
    public static boolean validatePAdESBaselineStructurally(PDFSignatureDictionary signatureDictionary, byte[ ] pdfDocument, CMSSignedData signedData) throws SigningException {
	boolean hasSignaturePolicyId = false;
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
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG111));
	try {
	    // Comprobamos que se ha indicado el diccionario de firma
	    GenericUtilsCommons.checkInputParameterIsNotNull(signatureDictionary, Language.getResIntegra(ILogConstantKeys.US_LOG007));

	    // Comprobamos que se ha indicado el documento PDF
	    GenericUtilsCommons.checkInputParameterIsNotNull(pdfDocument, Language.getResIntegra(ILogConstantKeys.US_LOG008));

	    // Comprobamos que se ha indicado el contenido de la firma
	    GenericUtilsCommons.checkInputParameterIsNotNull(signedData, Language.getResIntegra(ILogConstantKeys.US_LOG019));

	    // Accedemos a la firma, que debe encontrarse dentro de la clave
	    // /Contents del diccionario de firma
	    byte[ ] signature = signatureDictionary.getDictionary().getAsString(PdfName.CONTENTS).getOriginalBytes();

	    // Comprobamos que el contenido de la clave /Contents no es nulo
	    if (signature == null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG010, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Comprobamos que la clave /ByteRange no es nula
	    PdfArray pdfArrayByteRange = signatureDictionary.getDictionary().getAsArray(PdfName.BYTERANGE);
	    if (pdfArrayByteRange == null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG011, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Verificamos que la firma posee un único firmante
	    checkPAdESSignersNumber(signedData, signatureDictionary);

	    // Accedemos al valor de la clave /SubFilter
	    PdfName subFilterValue = (PdfName) signatureDictionary.getDictionary().get(PdfName.SUBFILTER);

	    // Si el valor de la clave /SubFilter no es "ETSI.CAdES.detached"
	    if (!subFilterValue.equals(CADES_SUBFILTER_VALUE)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG224, new Object[ ] { signatureDictionary.getName(), subFilterValue.toString() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Accedemos al primer firmante
	    SignerInformation signerInformation = ((List<SignerInformation>) signedData.getSignerInfos().getSigners()).iterator().next();

	    // Accedemos al conjunto de atributos firmados
	    AttributeTable signedAttrs = signerInformation.getSignedAttributes();

	    // Comprobamos que el firmante no contiene el atributo signing-time
	    checkPAdESSignedAttribute(signedAttrs, PKCSObjectIdentifiers.pkcs_9_at_signingTime, signatureDictionary.getName(), "signing-time");

	    // Comprobamos que el firmante no contiene el atributo
	    // content-identifier
	    checkPAdESSignedAttribute(signedAttrs, PKCSObjectIdentifiers.id_aa_contentIdentifier, signatureDictionary.getName(), "content-identifier");

	    // Comprobamos que el firmante no contiene el atributo content-hints
	    checkPAdESSignedAttribute(signedAttrs, PKCSObjectIdentifiers.id_aa_contentHint, signatureDictionary.getName(), "content-hints");

	    // Comprobamos que el firmante no contiene el atributo
	    // signer-location
	    checkPAdESSignedAttribute(signedAttrs, PKCSObjectIdentifiers.id_aa_ets_signerLocation, signatureDictionary.getName(), "signer-location");

	    // Comprobamos que el firmante contiene el atributo content-type y
	    // que éste tiene el valor "id-data"
	    Attribute contentTypeAttribute = signedAttrs.get(PKCSObjectIdentifiers.pkcs_9_at_contentType);
	    if (contentTypeAttribute == null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG016, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    } else if (!contentTypeAttribute.getAttrValues().getObjectAt(0).getDERObject().equals(PKCSObjectIdentifiers.data)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG017, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Si el firmante contiene el atributo signature-policy-id
	    if (signedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId) != null) {
		hasSignaturePolicyId = true;

		// Comprobamos que el firmante no contiene el atributo
		// commitment-type-indication
		checkPAdESSignedAttribute(signedAttrs, PKCSObjectIdentifiers.id_aa_ets_commitmentType, signatureDictionary.getName(), "commitment-type-indication");
	    }

	    // Accedemos al conjunto de atributos no firmados
	    AttributeTable unsignedAttrs = signerInformation.getUnsignedAttributes();

	    // Si el firmante presenta atributos no firmados
	    if (unsignedAttrs != null) {
		// Comprobamos que el firmante no contiene el atributo
		// counter-signature
		checkPAdESUnsignedAttribute(unsignedAttrs, PKCSObjectIdentifiers.pkcs_9_at_counterSignature, signatureDictionary.getName(), "counter-signature");

		// Comprobamos que el firmante no contiene el atributo
		// content-reference
		checkPAdESUnsignedAttribute(unsignedAttrs, PKCSObjectIdentifiers.id_aa_contentReference, signatureDictionary.getName(), "content-reference");
	    }

	    // Comprobamos que el diccionario de firma no contiene la clave
	    // /Cert
	    if (signatureDictionary.getDictionary().getAsName(PdfName.CERT) != null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.US_LOG018, new Object[ ] { signatureDictionary.getName() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG227, new Object[ ] { signatureDictionary.getName() }));

	    return hasSignaturePolicyId;
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG038));
	}
    }

    /**
     * Auxiliary method that calculate the expiration date of a validation or update response. 
     * The expiration date will be the closer expiration date between every signer and/or timestamp of the signature.
     * @param signerValidationResult Result of the signature validation/update.
     * @param currentDate The current closest expiration date.
     * @return the expiration date of the signature.
     */
    public static Date calculateExpirationDateForValidations(SignerValidationResult signerValidationResult, Date currentDate) {
	Date date = currentDate;
	boolean hasArchiveTimeStamp = false;
	boolean hasTimeStamp = false;
	X509Certificate archiveTimestampCert = signerValidationResult.getLastArchiveTst();

	// Si el firmante está protegido por sellos de tiempo de tipo
	// archiveTimeStamp, la caducidad vendrá definida por la fecha de
	// expiración del certificado firmante del sello de tiempo
	// archiveTimeStamp.
	if (archiveTimestampCert != null) {
	    date = closestExpirationDate(archiveTimestampCert.getNotAfter(), currentDate);
	    hasArchiveTimeStamp = true;
	}

	// Si el firmante está protegido por sellos de tiempo, la caducidad
	// vendrá definida por la fecha de expiración del certificado del último
	// sello de tiempo.
	List<TimestampValidationResult> timestamps = signerValidationResult.getListTimestampsValidations();
	if (!hasArchiveTimeStamp && !checkIsNullOrEmpty(timestamps)) {
	    date = closestExpirationDate(calculateExpirationDateTimestamps(timestamps), date);
	    hasTimeStamp = true;
	}

	// Si no tiene sellos de tiempo, la caducidad vendrá determinada por la
	// fecha de expiración del certificado firmante.
	X509Certificate signerCert = signerValidationResult.getSigningCertificate();
	if (!hasArchiveTimeStamp && !hasTimeStamp && signerCert != null) {
	    date = closestExpirationDate(signerCert.getNotAfter(), date);
	}

	// Además, si el firmante no tiene sellos de tiempo archiveTimestamp y
	// tiene contrafirmas, buscamos la caducidad de los contrafirmantes.
	List<SignerValidationResult> counterSigners = signerValidationResult.getListCounterSignersValidationsResults();
	if (!hasArchiveTimeStamp && !checkIsNullOrEmpty(counterSigners)) {
	    for (SignerValidationResult counterSigner: counterSigners) {
		date = closestExpirationDate(calculateExpirationDateForValidations(counterSigner, date), date);
	    }
	}

	return date;

    }

    /**
     * Auxiliary method that checks two dates and returns the one whose date is closest to the current date.
     * @param date1 Date to compare.
     * @param date2 Date to compare.
     * @return the closest date to the current one.
     */
    private static Date closestExpirationDate(Date date1, Date date2) {
	if (date1 == null && date2 != null) {
	    return date2;
	}
	if (date2 == null && date1 != null) {
	    return date1;
	}
	if (date1 == null && date2 == null) {
	    return null;
	}
	return date1.before(date2) ? date1 : date2;
    }

    /**
     * Auxiliary method that gets the expiration date from a list of timestamp.
     * @param timestamps List of timestamp validations to check.
     * @return The expiration date of the the timestamp with a the closest expiration date.
     */
    private static Date calculateExpirationDateTimestamps(List<TimestampValidationResult> timestamps) {
	Date date = null;
	if (timestamps != null && !timestamps.isEmpty()) {

	    // Si sólo existe un sello de tiempo, devolvemos su fecha de
	    // expiración, que vendrá determinada por la fecha de expiración del
	    // certificado firmante del sello de tiempo.
	    if (timestamps.size() == 1) {
		date = timestamps.get(0).getSigningCertificate().getNotAfter();
	    }

	    // Si hay más de un sello de tiempo, nos quedamos con aquel que
	    // tenga una fecha de expiración más próxima.
	    if (timestamps.size() > 1) {
		for (TimestampValidationResult timestamp: timestamps) {
		    date = closestExpirationDate(timestamp.getSigningCertificate().getNotAfter(), date);
		}
	    }
	}
	return date;
    }

    /**
     * Auxiliary method that gets the expiration date from a list of timestamp.
     * @param timestamps List of timestamp to check.
     * @return  The expiration date of the the timestamp with a the closest expiration date.
     * @throws SigningException if is not possible to calculate the expiration date of the timestamps.
     */
    private static Date calculateExpirationDateTimestamps2(List<TimeStampToken> timestamps) throws SigningException {
	Date date = null;
	try {
	    if (timestamps != null && !timestamps.isEmpty()) {

		// Si sólo existe un sello de tiempo, devolvemos su fecha de
		// expiración, que vendrá determinada por la fecha de expiración
		// del certificado firmante del sello de tiempo.
		if (timestamps.size() == 1) {
		    date = UtilsTimestampXML.getSigningCertificate(timestamps.get(0)).getNotAfter();
		}

		// Si hay más de un sello de tiempo, nos quedamos con aquel que
		// tenga una fecha de expiración más próxima.
		if (timestamps.size() > 1) {
		    for (TimeStampToken timestamp: timestamps) {
			date = closestExpirationDate(UtilsTimestampXML.getSigningCertificate(timestamp).getNotAfter(), date);
		    }
		}
	    }
	} catch (SigningException e) {
	    LOGGER.error(Language.getResIntegra(ILogConstantKeys.US_LOG244), e);
	    throw e;
	}
	return date;
    }

    /**
     * Method that gets the last archive timestamp certificate from the the list of archive timestamps of a signature.
     * @param unsignedAttributes Unsigned attributes of the signature.
     * @return the signing certificate if the last archive timestamp.
     */
    public static X509Certificate obtainCertificateArchiveTimestamps(AttributeTable unsignedAttributes) {
	List<TimeStampToken> archiveTimestampsList = new ArrayList<>();
	X509Certificate closestCert = null;

	if (unsignedAttributes != null) {
	    try {

		// Recuperamos la lista de sellos de tiempo archiveTimestamp.
		ASN1EncodableVector archiveTrst = unsignedAttributes.getAll(ESFAttributes.archiveTimestamp);
		if (archiveTrst.size() > 0) {
		    archiveTimestampsList = UtilsTimestampPdfBc.getOrderedTimeStampTokens(archiveTrst);

		    // Nos quedamos con el último sello de tiempo de la lista,
		    // ya que es éste quien determina la fecha de expiración del
		    // conjunto de sellos de tiempo archivetimestamp.
		    TimeStampToken lastTst = archiveTimestampsList.get(archiveTimestampsList.size() - 1);

		    // Obtenemos la fecha de expiración del certificado firmante
		    // del último sello de tiempo.
		    closestCert = UtilsTimestampPdfBc.getSigningCertificate(lastTst);
		}

		// Recuperamos la lista de sellos de tiempo archiveTimestamp V2.
		ASN1EncodableVector archiveTrstV2 = unsignedAttributes.getAll(ESFAttributes.archiveTimestampV2);
		if (archiveTrstV2.size() > 0) {
		    archiveTimestampsList = UtilsTimestampPdfBc.getOrderedTimeStampTokens(archiveTrstV2);

		    // Nos quedamos con el último sello de tiempo de la lista,
		    // ya que es éste quien determina la fecha de expiración del
		    // conjunto de sellos de tiempo archivetimestamp.
		    TimeStampToken lastTst = archiveTimestampsList.get(archiveTimestampsList.size() - 1);

		    // Obtenemos la fecha de expiración del certificado firmante
		    // del último sello de tiempo.
		    X509Certificate lastTstCert = UtilsTimestampPdfBc.getSigningCertificate(lastTst);
		    closestCert = closestExpirationCertificate(lastTstCert, closestCert);
		}

		// Recuperamos la lista de sellos de tiempo archiveTimestamp V3.
		ASN1EncodableVector archiveTrstV3 = unsignedAttributes.getAll(ID_ARCHIVE_TIME_STAMP_V3);
		if (archiveTrstV3.size() > 0) {
		    archiveTimestampsList = UtilsTimestampPdfBc.getOrderedTimeStampTokens(archiveTrstV3);

		    // Nos quedamos con el último sello de tiempo de la lista,
		    // ya que es éste quien determina la fecha de expiración del
		    // conjunto de sellos de tiempo archivetimestamp.
		    TimeStampToken lastTst = archiveTimestampsList.get(archiveTimestampsList.size() - 1);

		    // Obtenemos la fecha de expiración del certificado firmante
		    // del último sello de tiempo.
		    X509Certificate lastTstCert = UtilsTimestampPdfBc.getSigningCertificate(lastTst);
		    closestCert = closestExpirationCertificate(lastTstCert, closestCert);
		}

	    } catch (SigningException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.US_LOG241), e);
	    }
	}
	return closestCert;
    }

    /**
     * Auxiliary method that checks which certificate has an expiration date closest to the current date.
     * @param cert1 Certificate to compare.
     * @param cert2 Certificate to compare.
     * @return the certificarte with a closest expiration date of the certificates.
     */
    private static X509Certificate closestExpirationCertificate(X509Certificate cert1, X509Certificate cert2) {
	if (cert1 == null && cert2 == null) {
	    return null;
	}
	if (cert1 == null && cert2 != null) {
	    return cert2;
	}
	if (cert1 != null && cert2 == null) {
	    return cert1;
	}
	return cert1.getNotAfter().before(cert2.getNotAfter()) ? cert1 : cert2;
    }

    /**
     * Method that calculates the expiration date of a signature.
     * @param signature Signature to analyze.
     * @return the expiration date, that is, the date in which the signature will be invalid, or null if its not possible to determinate the date.
     */
    public static Date getExpirationDate(byte[ ] signature) {
	Date res = null;
	if (signature != null) {
	    try {
		// Detectamos el formato de la firma.
		String signatureFormat = SignatureFormatDetector.getSignatureFormat(signature);

		// Si el formato es CAdES.
		if (isCAdES(signatureFormat)) {

		    // Obtenemos la firma CAdES.
		    CMSSignedData signedData = getCMSSignedData(signature);
		    // Obtenemos la información del firmante.
		    SignerInformationStore signerInformationStore = signedData.getSignerInfos();
		    // Obtenemos la lista con todos los firmantes contenidos en
		    // la firma
		    List<SignerInformation> listSignersSignature = (List<SignerInformation>) signerInformationStore.getSigners();
		    // Calculamos la fecha de expiración de la firma.
		    return calculateExpirationDate(signedData, listSignersSignature);
		}

		// Si el formato es XAdES.
		if (isXAdES(signatureFormat)) {

		    // Accedemos al documento XML firmado.
		    Document doc = UtilsSignatureCommons.getDocumentFromXML(signature);
		    // Recuperamos la lista de firmantes.
		    List<XAdESSignerInfo> signers = UtilsSignatureOp.getXAdESListSigners(doc);
		    return calculateExpirationDate(signers, null);
		}

		// Si el formato es PAdES.
		if (isPAdES(signatureFormat)) {

		    // Construimos el objeto para poder leer el PDF
		    PdfReader reader = new PdfReader(signature);
		    // Instanciamos un objeto para consultar campos del PDF
		    AcroFields af = reader.getAcroFields();
		    // Inicializamos las listas donde se almacenarán los
		    // diccionarios.
		    List<PDFSignatureDictionary> signatureDictionaries = new ArrayList<>();
		    List<PDFDocumentTimestampDictionary> timestampDictionaries = new ArrayList<>();
		    // Recuperamos la lista de diccionarios de firma y
		    // sellos de tiempo.
		    obtainListOfDictionaries(reader, af, timestampDictionaries, signatureDictionaries);
		    // Calculamos la fecha de expiración.
		    return calculateExpirationDate(signatureDictionaries, timestampDictionaries);
		}

		// Si el formato es ASiC-S Baseline.
		if (isASiCSBaselineSignatureFormat(signatureFormat)) {
		    // Procesamos la firma ASiC-S.
		    return getASiCExpirationDate(signature);
		}
	    } catch (SigningException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.US_LOG245), e);
	    } catch (IOException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.US_LOG246));
	    }
	}
	return res;
    }

    /**
     * Auxiliary method that calculate the expiration date of a ASiC signature.
     * @param signature ASiC signature to process.
     * @return the expiration date of the signature.
     * @throws IOException if there is some problem with the signature extraction from the ZIP.
     * @throws SigningException if there is some problem with the signature processing.
     */
    private static Date getASiCExpirationDate(byte[ ] signature) throws IOException, SigningException {
	byte[ ] asn1Signature = null;
	byte[ ] signedXML = null;
	InputStream is = new ByteArrayInputStream(signature);
	InputStream asicsInputStream = new ZipInputStream(is);

	// Recorremos las entradas del fichero ZIP
	for (ZipEntry entry = ((ZipInputStream) asicsInputStream).getNextEntry(); entry != null; entry = ((ZipInputStream) asicsInputStream).getNextEntry()) {
	    // Accedemos al nombre de la entrada
	    String entryName = entry.getName();

	    // Si la entrada es la firma ASN.1
	    if (SignatureFormatDetectorASiC.isCAdESEntry(entryName)) {
		// Accedemos al elemento SignedData
		asn1Signature = GenericUtilsCommons.getDataFromInputStream(asicsInputStream);

	    }

	    // Si la entrada es la firma XML
	    else if (SignatureFormatDetectorASiC.isXAdESEntry(entryName)) {
		signedXML = GenericUtilsCommons.getDataFromInputStream(asicsInputStream);
	    }
	}

	Date date = null;
	// Si la firma es CAdES.
	if (asn1Signature != null) {
	    // Obtenemos la firma CAdES.
	    CMSSignedData signedData = getCMSSignedData(asn1Signature);
	    // Obtenemos la información del firmante.
	    SignerInformationStore signerInformationStore = signedData.getSignerInfos();
	    // Obtenemos la lista con todos los firmantes contenidos
	    // en
	    // la firma
	    List<SignerInformation> listSignersSignature = (List<SignerInformation>) signerInformationStore.getSigners();
	    // Calculamos la fecha de expiración de la firma.
	    date = calculateExpirationDate(signedData, listSignersSignature);
	}

	// Si la firma es XAdES.
	if (signedXML != null) {
	    // Accedemos al documento XML firmado.
	    Document doc = UtilsSignatureCommons.getDocumentFromXML(signedXML);
	    // Recuperamos la lista de firmantes.
	    List<XAdESSignerInfo> signers = UtilsSignatureOp.getXAdESListSigners(doc);
	    date = closestExpirationDate(calculateExpirationDate(signers, null), date);
	}
	return date;

    }

    /**
     * Auxiliary method that check if the signature format detected is PAdES.
     * @param signatureFormat Signature format detected.
     * @return <i>True</i> if the signature format is PAdES, or <i>False</i> in other cases.
     */
    private static boolean isPAdES(String signatureFormat) {
	return isPAdESSignatureFormat(signatureFormat) || isPAdESBaselineSignatureFormat(signatureFormat);
    }

    /**
     * Auxiliary method that check if the signature format detected is XAdES.
     * @param signatureFormat Signature format detected.
     * @return <i>True</i> if the signature format is XAdES, or <i>False</i> in other cases.
     */
    private static boolean isXAdES(String signatureFormat) {
	return isXAdESSignatureFormat(signatureFormat) || isXAdESBaselineSignatureFormat(signatureFormat);
    }

    /**
     * Auxiliary method that check if the signature format detected is CAdES.
     * @param signatureFormat Signature format detected.
     * @return <i>True</i> if the signature format is CAdES, or <i>False</i> in other cases.
     */
    private static boolean isCAdES(String signatureFormat) {
	return isCAdESSignatureFormat(signatureFormat) || isCAdESBaselineSignatureFormat(signatureFormat);
    }

    /**
     * Method that indicates if the format of a signature is related to CAdES signature format.
     * @param signatureFormat Parameter that represents the signature format to process.
     * @return a boolean that indicates if the format of a signature is related to CAdES signature format (true) or not (false).
     */
    private static boolean isCAdESSignatureFormat(String signatureFormat) {
	if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_BES)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_EPES)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_T)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_C)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_X1)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_X2)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_XL1)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_XL2)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_A)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that indicates if the format of a signature is related to CAdES Baseline signature format.
     * @param signatureFormat Parameter that represents the signature format to process.
     * @return a boolean that indicates if the format of a signature is related to CAdES Baseline signature format (true) or not (false).
     */
    private static boolean isCAdESBaselineSignatureFormat(String signatureFormat) {
	if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_B_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_T_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_LT_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_LTA_LEVEL)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that indicates if the format of a signature is related to XAdES signature format.
     * @param signatureFormat Parameter that represents the signature format to process.
     * @return a boolean that indicates if the format of a signature is related to XAdES signature format (true) or not (false).
     */
    private static boolean isXAdESSignatureFormat(String signatureFormat) {
	if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_BES)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_EPES)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_T)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_C)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_X1)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_X2)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_XL1)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_XL2)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_A)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that indicates if the format of a signature is related to XAdES Baseline signature format.
     * @param signatureFormat Parameter that represents the signature format to process.
     * @return a boolean that indicates if the format of a signature is related to XAdES Baseline signature format (true) or not (false).
     */
    private static boolean isXAdESBaselineSignatureFormat(String signatureFormat) {
	if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_B_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_T_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_LT_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_LTA_LEVEL)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that indicates if the format of a signature is related to PAdES signature format.
     * @param signatureFormat Parameter that represents the signature format to process.
     * @return a boolean that indicates if the format of a signature is related to PAdES signature format (true) or not (false).
     */
    private static boolean isPAdESSignatureFormat(String signatureFormat) {
	if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_BASIC)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_BES)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_EPES)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_LTV)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that indicates if the format of a signature is related to PAdES Baseline signature format.
     * @param signatureFormat Parameter that represents the signature format to process.
     * @return a boolean that indicates if the format of a signature is related to PAdES Baseline signature format (true) or not (false).
     */
    private static boolean isPAdESBaselineSignatureFormat(String signatureFormat) {
	if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_B_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_T_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_LT_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_LTA_LEVEL)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that indicates if the format of a signature is related to ASiC-S Baseline signature format.
     * @param signatureFormat Parameter that represents the signature format to process.
     * @return a boolean that indicates if the format of a signature is related to ASiC-S Baseline signature format (true) or not (false).
     */
    private static boolean isASiCSBaselineSignatureFormat(String signatureFormat) {
	if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_ASIC_S_B_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_ASIC_S_T_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_ASIC_S_LT_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_ASIC_S_LTA_LEVEL)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that calculates the expiration date of a given signature.
     * @param signedData CMS signed Data.
     * @param listSignersSignature Signers information.
     * @return the expiration date of the signature.
     */
    private static Date calculateExpirationDate(CMSSignedData signedData, List<SignerInformation> listSignersSignature) {
	if (signedData == null) {
	    return null;
	}
	Date date = null;

	try {

	    // Recorremos la lista de firmantes.
	    for (SignerInformation signer: listSignersSignature) {

		// Comprobamos si tiene sellos de tiempo de tipo
		// archiveTimestamp.
		// Si tiene sellos de tiempo archiveTimestamp, la fecha de
		// expiración será definida por la caducidad del certificado
		// firmante del último sello de tiempo arcvhiveTimestamp.
		X509Certificate lastArchiveTstCert = obtainCertificateArchiveTimestamps(signer.getUnsignedAttributes());
		if (lastArchiveTstCert != null) {
		    date = closestExpirationDate(lastArchiveTstCert.getNotAfter(), date);
		    continue;
		}

		// Comprobamos si tiene sellos de tiempo. Si tiene sellos de
		// tiempo, la fecha de expiración vendrá definida por la fecha
		// de caducidad del certificado firmante con una fecha de
		// caducidad más próxima a la fecha actual.
		boolean hasTimestamps = false;
		List<TimeStampToken> timestamps = obtainCertificateTimestamps(signer.getUnsignedAttributes());
		if (!checkIsNullOrEmpty(timestamps)) {
		    date = closestExpirationDate(calculateExpirationDateTimestamps2(timestamps), date);
		    hasTimestamps = true;
		}

		// Si la firma no tiene sellos de tiempo, la fecha de caducidad
		// puede venir definida por el certificado firmante.
		X509Certificate signingCert = getSigningCertificate(signedData, signer);
		if (!hasTimestamps && signingCert != null) {
		    date = closestExpirationDate(signingCert.getNotAfter(), date);
		}

		// Comprobamos si existen contrafirmantes. Si existen
		// contrafirmantes, verificamos si la fecha de caducidad de
		// algún contrafirmante es más próxima que la del firmante
		// principal. En ese caso, actualizamos la fecha de expiración
		// global.
		SignerInformationStore counterSignatures = signer.getCounterSignatures();
		if (!checkIsNullOrEmpty(counterSignatures)) {
		    Iterator<?> it = counterSignatures.getSigners().iterator();
		    while (it.hasNext()) {
			SignerInformation counterSigner = (SignerInformation) it.next();
			date = closestExpirationDate(calculateExpirationDate(signedData, Arrays.asList(counterSigner)), date);
		    }

		}
	    }
	} catch (SigningException e) {
	    LOGGER.error(Language.getResIntegra(ILogConstantKeys.US_LOG243));
	}
	return date;
    }

    /**
     * Method that calculates the expiration date of a XAdES signature.
     * @param signers List of signer.
     * @param currentDate Current closest expiration date.
     * @return the closest expiration date of the signature.
     */
    private static Date calculateExpirationDate(List<XAdESSignerInfo> signers, Date currentDate) {
	Date date = currentDate;
	if (!checkIsNullOrEmpty(signers)) {

	    // Recorremos la lista de firmantes. Por cada firmante...
	    X509Certificate archiveTstCert = null;
	    List<XAdESTimeStampType> tstList = null;
	    List<XAdESSignerInfo> counterSigners = null;
	    for (XAdESSignerInfo signer: signers) {
		// Recuperamos los sellos de tiempo archiveTimestamp (en caso de
		// que tenga).
		archiveTstCert = obtainCertificateArchiveTimestampsXAdES(signer);
		if (archiveTstCert != null) {
		    date = closestExpirationDate(archiveTstCert.getNotAfter(), date);
		    continue;
		}

		// Recuperamos los sellos de tiempo timestamp (en caso de que
		// tenga).
		tstList = signer.getListTimeStamps();
		boolean hasTst = false;
		if (!checkIsNullOrEmpty(tstList)) {
		    date = closestExpirationDate(tstList.get(tstList.size() - 1).getTstCertificate().getNotAfter(), date);
		    hasTst = true;
		}

		// Si el firmante no tiene ningún tipo de sello de tiempo, la
		// fecha de expiración será la del certificado firmante.
		if (!hasTst) {
		    date = closestExpirationDate(signer.getSigningCertificate().getNotAfter(), date);
		}

		// Comprobamos si tiene contrafirmantes...
		counterSigners = signer.getListCounterSigners();
		if (!checkIsNullOrEmpty(counterSigners)) {
		    date = closestExpirationDate(calculateExpirationDate(counterSigners, date), date);
		}

	    }
	}
	return date;

    }

    /**
     * Method that obtains the list of timestamp of type <i>signature-time-stamp</i> from the unsigned attributes of a signature.
     * @param unsignedAttributes Unsigned attributes set of the signature to analyze.
     * @return a list with the timestamp of the signature.
     * @throws SigningException if it is not possible to obtain the timestamps.
     */
    private static List<TimeStampToken> obtainCertificateTimestamps(AttributeTable unsignedAttributes) throws SigningException {
	List<TimeStampToken> res = null;
	try {
	    if (unsignedAttributes != null) {
		// Accedemos a todos los atributos signature-time-stamp
		ASN1EncodableVector signatureTimeStampattributes = unsignedAttributes.getAll(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);

		// Si el firmante incluye algún atributo signature-time-stamp
		if (signatureTimeStampattributes.size() > 0) {
		    // Obtenemos la lista de sellos de tiempo contenidos en los
		    // atributos signature-time-stamp, ordenados ascendentemente
		    // por fecha de generación, en el caso de que el firmante
		    // contenga dichos atributos
		    res = UtilsTimestampPdfBc.getOrderedTimeStampTokens(signatureTimeStampattributes);
		}
	    }
	} catch (SigningException e) {
	    LOGGER.error(Language.getResIntegra(ILogConstantKeys.US_LOG242), e);
	    throw e;
	}
	return res;
    }

    /**
     * Auxiliary method that checks if a list is null or empty.
     * @param value List to check.
     * @return <i>True</i> if the list is null or empty, and <i>False</i> if not.
     */
    private static boolean checkIsNullOrEmpty(List<?> value) {
	return value == null || value.isEmpty() ? true : false;
    }

    /**
     * Auxliary method that checks if a given signer information store is null or empty.
     * @param value Object to check.
     * @return <i>True</i> if the signer information store is null or empty, and <i>False</i> if not.
     */
    private static boolean checkIsNullOrEmpty(SignerInformationStore value) {
	return value == null || value.size() < 1 ? true : false;
    }

    /**
     * Auxiliary method that checks if a NodeList is null or empty.
     * @param value NodeList to check.
     * @return <i>True</i> if the object is null or empty, and <i>False</i> if not.
     */
    private static boolean checkIsNullOrEmpty(NodeList value) {
	return value == null || value.getLength() < 1;
    }

    /**
     * Method that obtains the signing certificate of the last archiveTimestamp of a XAdES signature.
     * @param signerInfo Unsigned properties element of the signer.
     * @return the X509Certificate of the last archiveTimestamp or null of there is not one archiveTimestamp.
     */
    public static X509Certificate obtainCertificateArchiveTimestampsXAdES(XAdESSignerInfo signerInfo) {
	X509Certificate cert = null;

	// Si hemos encontrado el elemento xades:UnsignedProperties
	if (signerInfo != null) {

	    try {

		// Obtenemos el elemento unsignedPropertiesElement.
		Element unsignedPropertiesElement = UtilsXML.getChildElement((Element) signerInfo.getQualifyingPropertiesElement(), IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES, signerInfo.getId(), false);

		if (unsignedPropertiesElement != null) {

		    // Obtenemos el elemento unsignedSignaturePropertiesElement.
		    Element unsignedSignaturePropertiesElement = UtilsXML.getChildElement(unsignedPropertiesElement, IXMLConstants.ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES, signerInfo.getId(), false);

		    // Buscamos si existen archiveTimestamps v1.4.1 o v1.3.2.
		    NodeList archiveTimeStamps = unsignedSignaturePropertiesElement.getElementsByTagNameNS(IXMLConstants.XADES_1_4_1_NAMESPACE, IXMLConstants.ELEMENT_ARCHIVE_TIMESTAMP);
		    if (checkIsNullOrEmpty(archiveTimeStamps)) {
			archiveTimeStamps = unsignedSignaturePropertiesElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_ARCHIVE_TIMESTAMP);
		    }
		    if (!checkIsNullOrEmpty(archiveTimeStamps)) {
			// Recuperamos el último archiveTimeStamp.
			X509Certificate signingCert = null;
			Node archiveTst = obtainLastArchiveTimestampNode(archiveTimeStamps);
			// Recuperamos el certificado firmante del último sello
			// de tiempo archiveTimestamp.
			if (archiveTst != null) {
			    signingCert = getTstSigningCertificateFromNode(archiveTst);
			    if (cert == null || signingCert.getNotAfter().before(cert.getNotAfter())) {
				cert = signingCert;
			    }
			}
		    }
		}
	    } catch (SigningException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.US_LOG247), e);
	    }
	}

	return cert;
    }

    /**
     * Method that obtains the node that represents the last archiveTimestamp of the signature, that is, the archiveTimestamp that is not protected by another one.
     * @param archiveTimeStampsNodeList List of archiveTimestamp nodes to analyze.
     * @return a node that represents the last archiveTimestamp.
     */
    private static Node obtainLastArchiveTimestampNode(NodeList archiveTimeStampsNodeList) {
	Node res = null;
	if (!checkIsNullOrEmpty(archiveTimeStampsNodeList)) {
	    Node archiveTstNode = null;
	    Node tstNode = null;
	    TimeStampToken tst = null;
	    Date xmlTstDate = null;

	    try {
		// recorremos la lista de archiveTimestamp.
		for (int i = 0; i < archiveTimeStampsNodeList.getLength(); i++) {
		    archiveTstNode = archiveTimeStampsNodeList.item(i);

		    res = obtainLastArchiveTimestampNodeAux(archiveTstNode, tstNode, tst, res, xmlTstDate);
		}
	    } catch (TSPException | IOException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.US_LOG248), e);
	    } catch (CMSException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.US_LOG249), e);
	    } catch (XPathExpressionException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.US_LOG250), e);
	    } catch (ParseException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.US_LOG251), e);
	    }
	}
	return res;
    }

    /**
     * Auxiliary method created to reduce the cyclomatic complexity.
     * @param archiveTstNode Node that contains the archiveTimestamps list.
     * @param tstNode Node that represents a archiveTimestamp.
     * @param tst Timestamp token of a given archiveTimestamp.
     * @param res Local result variable.
     * @param xmlTstDate Local expiration date of the timestamp.
     * @return the node of the last archiveTimestamp of the signature.
     * @throws TSPException if it is not possible to create the timestamp token of the archiveTimestamp.
     * @throws IOException if it is not possible to create the timestamp token of the archiveTimestamp.
     * @throws CMSException if it is not possible to create the CMS signed data of the node.
     * @throws XPathExpressionException  if it is not possible to find  the creation time element of the archiveTimestamp.
     * @throws ParseException if it is not possible to parse the creation date of the timestamp.  
     */
    private static Node obtainLastArchiveTimestampNodeAux(Node archiveTstNode, Node tstNode, TimeStampToken tst, Node res, Date xmlTstDate) throws TSPException, IOException, CMSException, XPathExpressionException, ParseException {
	Node result = res;
	Node tstNodeAux = tstNode;
	TimeStampToken tstAux = tst;
	Date xmlTstDateAux = xmlTstDate;
	// Recorremos los nodos hijos del archiveTimestamp.
	for (int e = 0; e < archiveTstNode.getChildNodes().getLength(); e++) {
	    tstNodeAux = archiveTstNode.getChildNodes().item(e);

	    // Si el sello de tiempo es de tipo ASN.1...
	    if (tstNodeAux.getLocalName().equals(LOCAL_NAME_ARCHIVE_TIMESTAMP_ASN1)) {
		String nodeValBase64 = tstNodeAux.getTextContent();
		// Recuperamos el sello de tiempo ASN.1.
		TimeStampToken localTst = new TimeStampToken(new CMSSignedData(Base64.decode(nodeValBase64)));

		// Si el sello de tiempo recuperado tiene una fecha
		// de generación anterior al sello de tiempo
		// actualmente almacenado, lo actualizamos.
		if (tstAux == null || localTst.getTimeStampInfo().getGenTime().after(tstAux.getTimeStampInfo().getGenTime())) {
		    tstAux = localTst;
		    result = archiveTstNode;
		}
		break;
	    } else if (tstNodeAux.getLocalName().equals(LOCAL_NAME_ARCHIVE_TIMESTAMP_XML)) {
		NodeList creationTimeNode = UtilsXML.getChildNodesByLocalNames(tstNodeAux, "Timestamp/Signature/Object/TstInfo/CreationTime");
		if (creationTimeNode != null) {
		    String creationDateTst = creationTimeNode.item(0).getTextContent();
		    Date localDate = new SimpleDateFormat("yyyy-mm-dd'T'hh:mm:ss.SSSXXX").parse(creationDateTst);
		    if (xmlTstDateAux == null || localDate.before(xmlTstDateAux)) {
			xmlTstDateAux = localDate;
			result = archiveTstNode;
		    }
		}
		break;
	    }
	}
	return result;
    }

    /**
     * Auxiliary method that gets the signing certificate of a timeStamp in a XAdES signature.
     * @param node ArchiveTimestamp node of the XML signature.
     * @return the signing certificate of the archiveTimestamp node.
     */
    private static X509Certificate getTstSigningCertificateFromNode(Node node) {
	X509Certificate res = null;

	if (node != null) {
	    try {

		NodeList children = node.getChildNodes();
		Node child = null;
		for (int i = 0; i < children.getLength(); i++) {
		    child = children.item(i);
		    TimeStampToken tst = null;
		    // Si es un sello de tiempo de tipo ASN.1...
		    if (child.getLocalName().equals(LOCAL_NAME_ARCHIVE_TIMESTAMP_ASN1)) {
			String nodeValBase64 = child.getTextContent();
			// Recuperamos el sello de tiempo ASN.1.
			tst = new TimeStampToken(new CMSSignedData(Base64.decode(nodeValBase64)));
			res = UtilsTimestampXML.getSigningCertificate(tst);
			break;
		    }
		    // Si es un sello de tiempo de tipo XML...
		    else if (child.getLocalName().equals(LOCAL_NAME_ARCHIVE_TIMESTAMP_XML)) {
			// Accedemos al elemento X509Certificate del sello de
			// tiempo XML.
			NodeList x509CertNodeList = UtilsXML.getChildNodesByLocalNames(child, "Timestamp/Signature/KeyInfo/X509Data/X509Certificate");

			// Si se ha recuperado correctamente el elemento,
			// transformamos el valor del nodo en un certificado
			// X509Certificate.
			if (!checkIsNullOrEmpty(x509CertNodeList)) {
			    String certBase64 = x509CertNodeList.item(0).getTextContent();
			    byte encodedCert[] = Base64.decode(certBase64);
			    ByteArrayInputStream inputStream = new ByteArrayInputStream(encodedCert);
			    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			    res = (X509Certificate) certFactory.generateCertificate(inputStream);
			    break;
			}
		    }
		}
	    } catch (TSPException | IOException | CMSException
		    | XPathExpressionException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.US_LOG252), e);
	    } catch (SigningException | CertificateException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.US_LOG253), e);
	    }
	}
	return res;
    }

    /**
     * Method that calculates the expiration date of a PAdES signature, that is, the moment in which the signature will become invalid.
     * @param signatureDictionaries Signature dictionaries from the PAdES signature.
     * @param timestampDictionaries Timestamp dictionaries from the PAdES signature.
     * @return the expiration date of the signature.
     */
    public static Date calculateExpirationDate(List<PDFSignatureDictionary> signatureDictionaries, List<PDFDocumentTimestampDictionary> timestampDictionaries) {
	Date expirationDate = null;
	PDFSignatureDictionary lastSignatureDictionary = null;
	PDFDocumentTimestampDictionary lastTimestampDictionary = null;

	try {

	    // Recuperamos el último diccionario de firma (el diccionario
	    // generado más recientemente).
	    if (!checkIsNullOrEmpty(signatureDictionaries)) {
		lastSignatureDictionary = (PDFSignatureDictionary) getLastDictionary(signatureDictionaries);
	    }

	    // Recuperamos el último diccionario de sello de tiempo (el
	    // diccionario generado más recientemente).
	    if (!checkIsNullOrEmpty(timestampDictionaries)) {
		lastTimestampDictionary = (PDFDocumentTimestampDictionary) getLastDictionary(timestampDictionaries);
	    }

	    // Nos quedamos con el diccionario que haya sido generado más
	    // recientemente.
	    Object lastDictionary = getLastDictionary(lastSignatureDictionary, lastTimestampDictionary);

	    // Si el diccionario es de firma, comprobamos si la firma tiene
	    // sellos de tiempo, en caso de tenerlos, la fecha de expiración
	    // vendrá determinada por la fecha de expiración del certificado
	    // firmante del último sello de tiempo, sino, la fecha la
	    // determinará la fecha de expiración del certificado firmante.
	    if (lastDictionary instanceof PDFSignatureDictionary) {
		CMSSignedData signature = getCMSSignature((PDFSignatureDictionary) lastDictionary);
		expirationDate = calculateExpirationDate(signature, (List<SignerInformation>) signature.getSignerInfos().getSigners());
	    }
	    // Si el diccionario es de sello de tiempo, la fecha de expiración
	    // vendrá determinada por el certificado firmante del sello de
	    // tiempo.
	    else if (lastDictionary instanceof PDFDocumentTimestampDictionary) {
		PDFDocumentTimestampDictionary tstDic = (PDFDocumentTimestampDictionary) lastDictionary;
		expirationDate = tstDic.getCertificate().getNotAfter();
	    }
	} catch (SigningException e) {
	    LOGGER.error(Language.getResIntegra(ILogConstantKeys.US_LOG254), e);
	}

	return expirationDate;
    }

    /**
     * Auxiliary method that obtains the last dictionary from a list of them. 
     * The last dictionary will be the dictionary with the greatest revision number.
     * @param dictionariesList List of PDF dictionaries to check. It can be of two types: 
     * PDFSignatureDictionary or PDFDocumentTimestampDictionary.
     * @return the last signature dictionary if the parameter is a list of signature dictionary, 
     * the last timestamp signature if the parameter is a list of timestamp dictionaries or 
     * null if the list is null, empty or it's not a valid dictionary list.
     */
    private static Object getLastDictionary(List<?> dictionariesList) {
	// Si la lista no es nula ni está vacía, procesamos los diccionarios
	// recibidos.
	if (!checkIsNullOrEmpty(dictionariesList)) {

	    // Si la lista de diccionarios es de firma...
	    if (dictionariesList.get(0) instanceof PDFSignatureDictionary) {
		PDFSignatureDictionary res = null;
		List<PDFSignatureDictionary> signatureDictionaries = (List<PDFSignatureDictionary>) dictionariesList;
		// Recorremos la lista de diccionarios y nos quedamos con aquel
		// que tenga una revisión mayor.
		for (PDFSignatureDictionary signatureDictionary: signatureDictionaries) {
		    if (res == null) {
			res = signatureDictionary;
		    } else {
			res = res.getRevision() < signatureDictionary.getRevision() ? signatureDictionary : res;
		    }
		}
		return res;

		// Si la lista de diccionarios es de sellos de tiempo...
	    } else if (dictionariesList.get(0) instanceof PDFDocumentTimestampDictionary) {
		PDFDocumentTimestampDictionary res = null;
		List<PDFDocumentTimestampDictionary> timestampDictionaries = (List<PDFDocumentTimestampDictionary>) dictionariesList;
		// Recorremos la lista de diccionarios y nos quedamos con aquel
		// que tenga una revisión mayor.
		for (PDFDocumentTimestampDictionary timestampDictionary: timestampDictionaries) {
		    if (res == null) {
			res = timestampDictionary;
		    } else {
			res = res.getRevision() < timestampDictionary.getRevision() ? timestampDictionary : res;
		    }
		}
		return res;
	    }

	}
	return null;
    }

    /**
     * Auxiliary method that checks a signature PDF dictionary and a timestamp PDF dictionary and choose which one is older (has a generation date closest to the current date).
     * @param signatureDictionary Signature PDF dictionary.
     * @param timestampDictionary Timestamp PDF dictionary.
     * @return a dictionary which is the older of both.
     */
    private static Object getLastDictionary(PDFSignatureDictionary signatureDictionary, PDFDocumentTimestampDictionary timestampDictionary) {
	if (signatureDictionary != null && timestampDictionary == null) {
	    return signatureDictionary;
	}
	if (signatureDictionary == null && timestampDictionary != null) {
	    return timestampDictionary;
	}
	if (signatureDictionary != null && timestampDictionary != null) {
	    return signatureDictionary.getRevision() > timestampDictionary.getRevision() ? signatureDictionary : timestampDictionary;
	}
	return null;
    }

    /**
     * Auxiliary method that finds the signature and timestamp dictionaries from a PDF signature.
     * @param reader PDF reader of the signature.
     * @param af Object that allows to access to the field of the signature. 
     * @param listTimestampDictionaries List where the timestamp dictionaries will be stored.
     * @param listSignatureDictionaries List where the signature dictionaries will be stored.
     * @throws SigningException if it's not possible to access to the timestamp of a timestamp dictionary.
     */
    private static void obtainListOfDictionaries(PdfReader reader, AcroFields af, List<PDFDocumentTimestampDictionary> listTimestampDictionaries, List<PDFSignatureDictionary> listSignatureDictionaries) throws SigningException {
	List<String> names = af.getSignatureNames();
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
			String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.PS_LOG011, new Object[ ] { signatureName });
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
     * Method that parse a manifest and signedDataObjectProperties element into a list of ReferenceDataBaseline objects.
     * @param manifestNode Node Element that represents the manifest node.
     * @param signedDataObjectPropertiesNode Element taht represents the signed data object properties node.
     * @return a list with the elements data parse into a list of reference data baseline objects.
     * @throws SigningException if the signature is invalid, that is, the elements has a invalid structure or the data are not correct.
     */
    public static List<ReferenceDataBaseline> fromNodeListToReferenceDataBaselineList(Node manifestNode, Node signedDataObjectPropertiesNode) throws SigningException {
	// Instanciamos las listas que necesitaremos para realizar la operación.
	List<ReferenceDataBaseline> res = new ArrayList<ReferenceDataBaseline>();
	List<ReferenceData> manifestReferencesList = new ArrayList<ReferenceData>();
	List<DataObjectFormat> dataObjectFormatList = new ArrayList<DataObjectFormat>();
	// Accedemos a los primeros elementos necesarios.
	Element referenceNode = (Element) manifestNode.getFirstChild();
	Element dataObjectFormatNode = (Element) signedDataObjectPropertiesNode.getFirstChild();

	// Recuperamos la lista de referencias del manifest.
	String id, type, uri, digestAlgorithm, digestValue;
	while (referenceNode != null) {
	    // Recuperamos los valores del nodo.
	    id = referenceNode.getAttribute(IXMLConstants.ATTRIBUTE_ID);
	    type = referenceNode.getAttribute(IXMLConstants.ATTRIBUTE_TYPE);
	    uri = referenceNode.getAttribute(IXMLConstants.ATTRIBUTE_URI);
	    digestAlgorithm = UtilsXML.getChildElement(referenceNode, IXMLConstants.ELEMENT_DIGEST_METHOD, null, true).getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM);
	    digestValue = UtilsXML.getChildElement(referenceNode, IXMLConstants.ELEMENT_DIGEST_VALUE, null, true).getTextContent();
	    List<TransformData> transforms = getTransformsElementsFromManifestReference(referenceNode);
	    // Creamos una nueva instancia de ReferenceData.
	    ReferenceData reference = new ReferenceData(digestAlgorithm, digestValue);
	    reference.setId(id);
	    reference.setType(type);
	    reference.setUri(uri);
	    reference.setTransforms(transforms);

	    // Añadimos a la lista la nueva referencia.
	    manifestReferencesList.add(reference);

	    // Continuamos con el siguiente reference.
	    if (referenceNode.getNextSibling() != null) {
		referenceNode = (Element) referenceNode.getNextSibling();
	    } else {
		referenceNode = null;
	    }
	}

	// Recuperamos la lista de dataObjectFormat.
	String reference, description, encoding, mimetype;
	Element temp = null;
	while (dataObjectFormatNode != null) {
	    // Recuperamos los valores del nodo.
	    reference = dataObjectFormatNode.getAttribute(IXMLConstants.ATTRIBUTE_OBJECT_REFERENCE);
	    temp = UtilsXML.getChildElement(dataObjectFormatNode, IXMLConstants.ELEMENT_DESCRIPTION, null, true);
	    description = temp != null ? temp.getTextContent() : null;
	    temp = UtilsXML.getChildElement(dataObjectFormatNode, IXMLConstants.ELEMENT_ENCODING, null, false);
	    encoding = temp != null ? temp.getTextContent() : null;
	    temp = UtilsXML.getChildElement(dataObjectFormatNode, IXMLConstants.ELEMENT_MIME_TYPE, null, true);
	    mimetype = temp != null ? temp.getTextContent() : null;
	    ObjectIdentifier objIdentifier = parseObjectIdentifier(dataObjectFormatNode);

	    // Creamos una nueva instancia de DataObjectFormat.
	    DataObjectFormat dataObj = new DataObjectFormatImpl(description, objIdentifier, mimetype, encoding, reference);

	    // Añadimos a la lista el nuevo dataObjectFormat.
	    dataObjectFormatList.add(dataObj);

	    // Continuamos con el siguiente elemento.
	    if (dataObjectFormatNode.getNextSibling() != null) {
		dataObjectFormatNode = (Element) dataObjectFormatNode.getNextSibling();
	    } else {
		dataObjectFormatNode = null;
	    }
	}

	// Creamos los objetos referenceDataBaseline a partir de las listas
	// anteriores.
	matchManifestAndDataObjectsLists(manifestReferencesList, dataObjectFormatList, res);

	return res;
    }

    /**
     * Auxiliary method that create a list of ReferenceDataBaseline object from a manifest reference list and a data object format list.
     * @param manifestReferencesList List that represents the set of references of the manifest in the XML signature.
     * @param dataObjectFormatList List that represents the set of data object format in the XML signature.
     * @param res List where the new references will be stored.
     * @throws SigningException if the signature is invalid, that is, if there exists some manifest reference without a data object format associated.
     */
    private static void matchManifestAndDataObjectsLists(List<ReferenceData> manifestReferencesList, List<DataObjectFormat> dataObjectFormatList, List<ReferenceDataBaseline> res) throws SigningException {
	if (!checkIsNullOrEmpty(manifestReferencesList) && !checkIsNullOrEmpty(dataObjectFormatList)) {
	    String id = null;
	    for (ReferenceData rd: manifestReferencesList) {
		DataObjectFormat dataObjectFormat = null;
		id = rd.getId();
		for (DataObjectFormat dof: dataObjectFormatList) {
		    if (id.equals(dof.getObjectReference().substring(1))) {
			dataObjectFormat = dof;
			break;
		    }
		}
		if (dataObjectFormat != null) {
		    ReferenceDataBaseline rdb = new ReferenceDataBaseline(rd.getDigestMethodAlg(), rd.getDigestValue());
		    rdb.setId(id);
		    rdb.setTransforms(rd.getTransforms());
		    rdb.setType(rd.getType());
		    rdb.setUri(rd.getUri());
		    rdb.setDataFormatDescription(dataObjectFormat.getDescription());
		    rdb.setDataFormatEncoding(dataObjectFormat.getEncoding());
		    rdb.setDataFormatMimeType(dataObjectFormat.getMimeType());
		    res.add(rdb);
		} else {
		    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG257);
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
	    }
	}

    }

    /**
     * Auxiliarty method that parses the objectIdentifier element to an object.
     * @param dataObjectFormatNode Element that represents the objectIdentifier.
     * @return a new object that represents the objectIdentifier element or null if the element doesn't exist.
     */
    private static ObjectIdentifier parseObjectIdentifier(Element dataObjectFormatNode) {
	ObjectIdentifier objIdentifier = null;
	if (dataObjectFormatNode != null) {
	    Element objectIdentifierNode;
	    try {
		objectIdentifierNode = UtilsXML.getChildElement(dataObjectFormatNode, IXMLConstants.ELEMENT_OBJECT_IDENTIFIER, null, false);

		if (objectIdentifierNode != null) {
		    String identifier = null, description;
		    ArrayList<String> documentationReferences = null;
		    Element temp = null;
		    try {
			// Recuperamos los valores del nodo.
			identifier = objectIdentifierNode.getAttribute(IXMLConstants.ATTRIBUTE_IDENTIFIER);
			temp = UtilsXML.getChildElement(objectIdentifierNode, IXMLConstants.ELEMENT_DESCRIPTION, null, false);
			description = temp != null ? temp.getTextContent() : null;
			temp = UtilsXML.getChildElement(objectIdentifierNode, IXMLConstants.ELEMENT_DOCUMENTATION_REFERENCES, null, false);
			if (temp != null && temp.getFirstChild() != null) {
			    Element documentationReferenceNode = (Element) temp.getFirstChild();
			    documentationReferences = new ArrayList<String>();
			    while (documentationReferenceNode != null) {
				documentationReferences.add(documentationReferenceNode.getTextContent());
				if (documentationReferenceNode.getNextSibling() != null) {
				    documentationReferenceNode = (Element) documentationReferenceNode.getNextSibling();
				} else {
				    documentationReferenceNode = null;
				}
			    }
			}

			// Asignamos el valor del ObjectIdentifier.
			objIdentifier = new ObjectIdentifierImpl("OIDAsURI", identifier, description, documentationReferences);
		    } catch (SigningException e) {
			LOGGER.info(Language.getResIntegra(ILogConstantKeys.US_LOG256));
		    }
		}
	    } catch (SigningException e) {
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.US_LOG255, new Object[ ] { IXMLConstants.ELEMENT_OBJECT_IDENTIFIER, dataObjectFormatNode.getLocalName() }));
	    }
	}
	return objIdentifier;

    }

    /**
     * Auxiliary method that obtains a list of transform object from a manifest reference element.
     * @param referenceNode Manifest reference element.
     * @return a list with the TransformData object found in the reference element or null if there is no one.
     */
    private static List<TransformData> getTransformsElementsFromManifestReference(Element referenceNode) {
	List<TransformData> res = null;
	try {
	    if (referenceNode != null) {
		Element transforms = UtilsXML.getChildElement(referenceNode, IXMLConstants.ELEMENT_TRANSFORMS, null, false);
		if (transforms != null && transforms.getFirstChild() != null) {
		    Element transform = (Element) transforms.getFirstChild();
		    String algorithm = null;
		    List<Element> xpaths = null;
		    res = new ArrayList<TransformData>();
		    while (transform != null) {
			algorithm = transform.getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM);
			xpaths = UtilsXML.getChildElements(transform, IXMLConstants.ELEMENT_XPATH);
			TransformData transformObj = new TransformData(algorithm, parseXPathElements(xpaths));
			res.add(transformObj);
			if (transform.getNextSibling() != null) {
			    transform = (Element) transform.getNextSibling();
			} else {
			    transform = null;
			}
		    }
		}
	    }
	} catch (SigningException e) {
	    LOGGER.warn(Language.getFormatResIntegra(ILogConstantKeys.US_LOG255, new Object[ ] { IXMLConstants.ELEMENT_TRANSFORMS, referenceNode.getLocalName() }));
	}
	return res;
    }

    /**
     * Auxiliary method that obtains a list of xPaths from a transform element of a XML signature.
     * @param xPaths list of XPath elements.
     * @return a list with the xpath element values or null if the list is null or empty.
     */
    private static List<String> parseXPathElements(List<Element> xPaths) {
	List<String> res = null;
	if (xPaths != null && !xPaths.isEmpty()) {
	    res = new ArrayList<String>();
	    for (Element xPath: xPaths) {
		res.add(xPath.getTextContent());
	    }
	}
	return res;
    }

}
