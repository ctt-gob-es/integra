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
 * <b>File:</b><p>es.gob.afirma.signature.cades.SignedDataBuilder.java.</p>
 * <b>Description:</b><p>Class that manages the generation of CMS elements as defined on RFC 3852.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>13/09/2011.</p>
 * @author Gobierno de España.
 * @version 1.3, 21/03/2017.
 */
package es.gob.afirma.signature.cades;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.esf.ESFAttributes;
import org.bouncycastle.asn1.ess.ContentHints;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.ietf.jgss.Oid;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.integraFacade.IntegraFacadeConstants;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.properties.IIntegraConstants;
import es.gob.afirma.properties.IntegraProperties;
import es.gob.afirma.signature.ISignatureFormatDetector;
import es.gob.afirma.signature.SignatureConstants;
import es.gob.afirma.signature.SignatureFormatDetector;
import es.gob.afirma.signature.SignatureProperties;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.signature.policy.ISignPolicyConstants;
import es.gob.afirma.signature.policy.SignaturePolicyException;
import es.gob.afirma.signature.policy.SignaturePolicyManager;
import es.gob.afirma.utils.CryptoUtilPdfBc;
import es.gob.afirma.utils.DSSConstants;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.utils.ICryptoUtil;
import es.gob.afirma.utils.IUtilsSignature;
import es.gob.afirma.utils.IUtilsTimestamp;
import es.gob.afirma.utils.UtilsResourcesCommons;
import es.gob.afirma.utils.UtilsSignatureOp;
import es.gob.afirma.utils.UtilsTimestampOcspRfc3161;
import es.gob.afirma.utils.UtilsTimestampPdfBc;
import es.gob.afirma.utils.UtilsTimestampWS;

/**
 * <p>Class that manages the generation of CMS elements as defined on RFC 3852.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.3, 21/03/2017.
 */
public final class CMSBuilder {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(CMSBuilder.class);

    /**
     * Attribute that indicates if the signature has EPES form (true) or not (false).
     */
    private boolean isEPES = false;

    /**
     * Attribute that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     */
    private String policyID = null;

    /**
     * <p>Enumeration class that represents different types of SignerInfo objects.</p>
     * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
     * @version 1.0, 27/01/2012.
     */
    enum SignerInfoTypes {
	/**Enum that represents type used for counter-signatures (signatures in parallels).*/
	COUNTERSIGNATURE,
	/**Enum that represents type used for co-signatures (signatures in serial).*/
	COSIGNATURE
    };

    /**
     * Method that calculates the ContentInfo.
     * @param includeContent Parameter that indicates whether the document content is included in the signature (true) or is only referenced (false).
     * @param dataType Parameter that represents the type of the content to sign.
     * @param parameters Parameters related to the signature.
     * @return an object that represents the ContentInfo.
     * @throws SigningException If the method fails.
     */
    private ContentInfo createContentInto(boolean includeContent, Oid dataType, P7ContentSignerParameters parameters) throws SigningException {
	ContentInfo encInfo = null;
	ASN1ObjectIdentifier contentTypeOID = new ASN1ObjectIdentifier(dataType.toString());

	if (includeContent) {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.CMSB_LOG003));
	    OutputStream bOut = new ByteArrayOutputStream();
	    byte[ ] content2 = parameters.getContent();
	    CMSProcessable msg = new CMSProcessableByteArray(content2);
	    try {
		msg.write(bOut);
		encInfo = new ContentInfo(contentTypeOID, new DEROctetString(((ByteArrayOutputStream) bOut).toByteArray()));
	    } catch (IOException ex) {
		throw new SigningException(Language.getResIntegra(ILogConstantKeys.CMSB_LOG004), ex);
	    } catch (CMSException e) {
		throw new SigningException(Language.getResIntegra(ILogConstantKeys.CMSB_LOG004), e);
	    } finally {
		UtilsResourcesCommons.safeCloseOutputStream(bOut);
	    }

	} else {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.CMSB_LOG005));
	    encInfo = new ContentInfo(contentTypeOID, null);
	}
	return encInfo;
    }

    /**
     *<p> Builds a signedData object used in CAdES signatures. SignedData is defined in the
     * <a href="http://tools.ietf.org/html/rfc3852">rfc3852</a>:<br>
     * <code><pre>
     * id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
         us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }
    
      SignedData ::= SEQUENCE {
        version CMSVersion,
        digestAlgorithms DigestAlgorithmIdentifiers,
        encapContentInfo EncapsulatedContentInfo,
        certificates [0] IMPLICIT CertificateSet OPTIONAL,
        crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
        signerInfos SignerInfos }
    
    </pre></code></p>
     * @param parameters parameters used in the signature.
     * @param includeContent indicates whether the document content is included in the signature or is only referenced.
     * @param dataType type of content to sign.
     * @param extraParams optional parameters.
     * @param includeTimestamp Parameter that indicates if the signature will have a timestamp (true) or not (false).
     * @return a sinedData object.
     * @param signatureForm Parameter that represents the signature form.
     * The allowed values for CAdES signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_CADES_BES}</li>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_CADES_EPES}</li>
     * </ul>
     * The allowed values for PAdES signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_PADES_BES}</li>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_PADES_EPES}</li>
     * </ul>
     * @param signaturePolicyID Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException in error case.
     */
    @SuppressWarnings("restriction")
    public byte[ ] generateSignedData(final P7ContentSignerParameters parameters, final boolean includeContent, final Oid dataType, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID, String idClient) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.CMSB_LOG001));
	if (GenericUtilsCommons.checkNullValues(parameters, dataType)) {
	    throw new IllegalArgumentException(Language.getResIntegra(ILogConstantKeys.CMSB_LOG002));
	}
	Properties optionalParams = extraParams;
	if (optionalParams == null) {
	    optionalParams = new Properties();
	}

	try {
	    // 1. VERSION
	    // la version se mete en el constructor del signedData y es 1

	    // 2. DIGESTALGORITM
	    // buscamos que tipo de algoritmo de digest es y lo codificamos con
	    // su OID

	    final ASN1EncodableVector digestAlgs = new ASN1EncodableVector();

	    String digestAlgorithm = SignatureConstants.SIGN_ALGORITHMS_SUPPORT_CADES.get(parameters.getSignatureAlgorithm());

	    final sun.security.x509.AlgorithmId digestAlgorithmId = sun.security.x509.AlgorithmId.get(digestAlgorithm);

	    AlgorithmIdentifier digAlgId = makeAlgId(digestAlgorithmId.getOID().toString(), digestAlgorithmId.getEncodedParams());

	    digestAlgs.add(digAlgId);

	    // 3. CONTENTINFO
	    // si se introduce el contenido o no

	    ContentInfo encInfo = createContentInto(includeContent, dataType, parameters);

	    // 4. CERTIFICADOS
	    // obtenemos la lista de certificados e incluimos el certificado
	    // firmante

	    X509Certificate signerCertificate = (X509Certificate) parameters.getPrivateKey().getCertificate();
	    ASN1Set certificates = createBerSetFromList(X509CertificateStructure.getInstance(ASN1Object.fromByteArray(signerCertificate.getEncoded())));

	    ASN1Set certrevlist = null;

	    // 5. SIGNERINFO
	    // raiz de la secuencia de SignerInfo
	    ASN1EncodableVector signerInfos = new ASN1EncodableVector();

	    TBSCertificateStructure tbs = TBSCertificateStructure.getInstance(ASN1Object.fromByteArray(signerCertificate.getTBSCertificate()));
	    IssuerAndSerialNumber encSid = new IssuerAndSerialNumber(X500Name.getInstance(tbs.getIssuer()), tbs.getSerialNumber().getValue());

	    SignerIdentifier identifier = new SignerIdentifier(encSid);

	    // AlgorithmIdentifier
	    digAlgId = new AlgorithmIdentifier(new DERObjectIdentifier(digestAlgorithmId.getOID().toString()), new DERNull());

	    // Atributos firmados
	    ASN1Set signedAttr = generateSignedAttr(parameters, digestAlgorithmId, digAlgId, digestAlgorithm, dataType, optionalParams, signatureForm, signaturePolicyID, includeContent, idClient);

	    // Generamos la firma
	    ASN1OctetString sign2 = sign(parameters.getSignatureAlgorithm(), parameters.getPrivateKey(), signedAttr);

	    // Atributos no firmados
	    ASN1Set unsignedAttr = null;

	    // Comprobamos si se ha indicado añadir sello de tiempo
	    if (includeTimestamp) {
		// Obtenemos el sello de tiempo de TS@
		TimeStampToken tst = generateTimestamp(sign2.getOctets(), idClient);

		// Llevamos a cabo la validación del sello de tiempo
		UtilsTimestampPdfBc.validateASN1Timestamp(tst);

		// Validamos el certificado firmante respecto a la fecha
		// indicada en el sello de tiempo
		UtilsSignatureOp.validateCertificate(signerCertificate, tst.getTimeStampInfo().getGenTime(), false, idClient, false);

		// Incluímos el sello de tiempo en el conjunto de atributos no
		// firmados
		InputStream is = null;
		try {
		    is = new ASN1InputStream(tst.getEncoded());
		    DERObject derObject = ((ASN1InputStream) is).readObject();
		    DERSet derSet = new DERSet(derObject);
		    Attribute unsignAtt = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, derSet);
		    Map<ASN1ObjectIdentifier, Attribute> hashtable = new Hashtable<ASN1ObjectIdentifier, Attribute>();
		    hashtable.put(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, unsignAtt);

		    AttributeTable unsignedAtts = new AttributeTable((Hashtable<ASN1ObjectIdentifier, Attribute>) hashtable);
		    unsignedAttr = getAttributeSet(unsignedAtts);
		} finally {
		    UtilsResourcesCommons.safeCloseInputStream(is);
		}
	    } else {
		// Validamos el certificado firmante respecto a la fecha actual
		UtilsSignatureOp.validateCertificate(signerCertificate, Calendar.getInstance().getTime(), false, idClient, false);
	    }

	    // digEncryptionAlgorithm
	    AlgorithmIdentifier encAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(parameters.getSignatureAlgorithm());

	    SignerInfo signerInfo = new SignerInfo(identifier, digAlgId, signedAttr, encAlgId, sign2, unsignedAttr);

	    // Comprobamos que la firma generada cumple con las características
	    // de
	    // la política de sello de tiempo, en el caso de ser EPES
	    if (isEPES) {
		try {
		    SignaturePolicyManager.validateGeneratedCAdESEPESSignature(signerInfo, policyID, null, false, idClient);
		} catch (SignaturePolicyException e) {
		    throw new SigningException(Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG034, new Object[ ] { e.getMessage() }), e);
		}
	    }
	    signerInfos.add(signerInfo);

	    // construimos el Signed Data y lo devolvemos
	    return new ContentInfo(PKCSObjectIdentifiers.signedData, new SignedData(new DERSet(digestAlgs), encInfo, certificates, certrevlist, new DERSet(signerInfos))).getDEREncoded();
	} catch (CertificateException e) {
	    throw new SigningException(Language.getResIntegra(ILogConstantKeys.CMSB_LOG006), e);
	} catch (NoSuchAlgorithmException e) {
	    throw new SigningException(Language.getResIntegra(ILogConstantKeys.CMSB_LOG007), e);
	} catch (IOException e) {
	    throw new SigningException(Language.getResIntegra(ILogConstantKeys.CMSB_LOG008), e);
	}

    }

    /**
     *<p> Builds a signedData object used in CAdES signatures. SignedData is defined in the
     * <a href="http://tools.ietf.org/html/rfc3852">rfc3852</a>:<br>
     * <code><pre>
     * id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
         us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }
    
      SignedData ::= SEQUENCE {
        version CMSVersion,
        digestAlgorithms DigestAlgorithmIdentifiers,
        encapContentInfo EncapsulatedContentInfo,
        certificates [0] IMPLICIT CertificateSet OPTIONAL,
        crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
        signerInfos SignerInfos }
    
    </pre></code></p>
     * @param parameters parameters used in the signature.
     * @param includeContent indicates whether the document content is included in the signature or is only referenced.
     * @param dataType type of content to sign.
     * @param extraParams optional parameters.
     * @param includeTimestamp Parameter that indicates if the signature will have a timestamp (true) or not (false).
     * @return a sinedData object.
     * @param signatureForm Parameter that represents the signature form.
     * The allowed values for CAdES signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_CADES_BES}</li>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_CADES_EPES}</li>
     * </ul>
     * The allowed values for PAdES signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_PADES_BES}</li>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_PADES_EPES}</li>
     * </ul>
     * @param signaturePolicyID Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @throws SigningException in error case.
     */
    public byte[ ] generateSignedData(final P7ContentSignerParameters parameters, final boolean includeContent, final Oid dataType, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID) throws SigningException {
	return generateSignedData(parameters, includeContent, dataType, extraParams, includeTimestamp, signatureForm, signaturePolicyID, null);

    }

    /**
     * Method that generates a timestamp.
     * @param dataToStamp Parameter that represents the data to stamp.
     * @return an object that represents the timestamp.
     * @throws SigningException If the method fails.
     */
    public TimeStampToken generateTimestamp(byte[ ] dataToStamp) throws SigningException {
	// Devolvemos el sello de tiempo
	return generateTimestamp(dataToStamp, null);
    }

    /**
     * Method that generates a timestamp.
     * @param dataToStamp Parameter that represents the data to stamp.
     * @param idClient Parameter that represents client id.
     * @return an object that represents the timestamp.
     * @throws SigningException If the method fails.
     */
    public TimeStampToken generateTimestamp(byte[ ] dataToStamp, String idClient) throws SigningException {
	TimeStampToken tst = null;

	String tsaCommunicationMode = null;
	String applicationID = null;

	Properties integraProperties = new IntegraProperties().getIntegraProperties(idClient);
	// Rescatamos del archivo de propiedades el modo en que
	// vamos a solicitar el sello de tiempo
	tsaCommunicationMode = (String) integraProperties.get(IntegraFacadeConstants.KEY_TSA_COMMUNICATION_TYPE);

	// Rescatamos del archivo de propiedades el identificador
	// de la aplicación cliente para conectarnos contra la TS@
	applicationID = (String) integraProperties.get(IntegraFacadeConstants.KEY_TSA_APP_ID);

	// Comprobamos que se ha indicado el identificador de la aplicación
	// cliente para la comunicación con TS@
	if (tsaCommunicationMode == null || tsaCommunicationMode.trim().isEmpty()) {
	    String propertiesName = IIntegraConstants.PROPERTIES_FILE;
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG041, new Object[ ] { propertiesName });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}

	// Comprobamos que se ha indicado el tipo de comunicación a usar para
	// obtener el sello de tiempo de TS@
	if (applicationID == null || applicationID.trim().isEmpty()) {
	    String propertiesName = IIntegraConstants.PROPERTIES_FILE;
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG040, new Object[ ] { propertiesName });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}

	// Si el modo de comunicación es Servicio Web (DSS)
	if (tsaCommunicationMode.equals(IUtilsTimestamp.TSA_DSS_COMMUNICATION)) {
	    // Obtenemos el sello de tiempo
	    tst = (TimeStampToken) UtilsTimestampWS.getTimestampFromDssService(dataToStamp, applicationID, DSSConstants.TimestampForm.RFC_3161, idClient);
	}
	// Si el modo de comunicación es RFC 3161
	else {
	    // Obtenemos el sello de tiempo
	    tst = UtilsTimestampOcspRfc3161.getTimestampFromRFC3161Service(dataToStamp, applicationID, tsaCommunicationMode, idClient);
	}
	// Validamos el sello de tiempo
	UtilsTimestampPdfBc.validateASN1Timestamp(tst);

	// Devolvemos el sello de tiempo
	return tst;
    }

    /**
     * Generates a set of signed attributes used in CMS messages defined in <a href="http://tools.ietf.org/html/rfc3852">rfc3852</a>.
     * Definition:
     * <pre>
     SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
    
      Attribute ::= SEQUENCE {
        attrType OBJECT IDENTIFIER,
        attrValues SET OF AttributeValue }
    
      AttributeValue ::= ANY
      </pre>
     * @param parameters parameters for signature process.
     * @param digestAlgorithmId digest algorithm identificator.
     * @param algId algorithm identificator.
     * @param digestAlgorithm digest algorithm name.
     * @param dataType data type oid identificator(Universal Object Identifiers) to sign.
     * @param extraParams optional parameters
     * @param signatureForm Parameter that represents the signature form.
     * The allowed values for CAdES signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_CADES_BES}</li>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_CADES_EPES}</li>
     * </ul>
     * The allowed values for PAdES signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_PADES_BES}</li>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_PADES_EPES}</li>
     * </ul>
     * @param signaturePolicyID Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @param includeContent Parameter that indicates whether the document content is included in the signature (true) or is only referenced (false).
     * @param idClient Parameter that represents the client application identifier.
     * @return a SignerInfo object.
     * @throws SigningException throws in error case.
     */
    @SuppressWarnings("restriction")
    private ASN1Set generateSignedAttr(P7ContentSignerParameters parameters, sun.security.x509.AlgorithmId digestAlgorithmId, AlgorithmIdentifier algId, String digestAlgorithm, Oid dataType, Properties extraParams, String signatureForm, String signaturePolicyID, boolean includeContent, String idClient) throws SigningException {

	try {
	    boolean isPadesSigner = extraParams.get(SignatureConstants.SIGN_FORMAT_PADES) == null ? false : true;
	    X509Certificate cert = (X509Certificate) parameters.getPrivateKey().getCertificate();

	    // // ATRIBUTOS

	    // authenticatedAttributes
	    ASN1EncodableVector contexExpecific = new ASN1EncodableVector();

	    // tipo de contenido
	    contexExpecific.add(new Attribute(CMSAttributes.contentType, new DERSet(new DERObjectIdentifier(dataType.toString()))));

	    // fecha de firma
	    if (!isPadesSigner) {
		contexExpecific.add(new Attribute(CMSAttributes.signingTime, new DERSet(new DERUTCTime(Calendar.getInstance().getTime()))));
	    }

	    AlgorithmIdentifier signAlgorithmId = new DefaultSignatureAlgorithmIdentifierFinder().find(parameters.getSignatureAlgorithm());

	    // Política de la firma --> elemento SignaturePolicyId
	    addPolicy(contexExpecific, extraParams, isPadesSigner, signatureForm, signaturePolicyID, signAlgorithmId, algId, includeContent, idClient);

	    // Digest del documento
	    byte[ ] messageDigest = null;
	    // Si el valor del digest viene externo lo incluimos directamente en
	    // los atributos.
	    if (parameters.getDigestValue() != null) {
		messageDigest = parameters.getDigestValue();
	    } else { // si no lo calculamos a partir de los datos del documento
		     // original.
		messageDigest = CryptoUtilPdfBc.digest(digestAlgorithm, parameters.getContent());
	    }
	    contexExpecific.add(new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(messageDigest))));

	    if (!signatureForm.equals(SignatureFormatDetector.FORMAT_PADES_BASIC)) {
		if (!digestAlgorithm.equals(ICryptoUtil.HASH_ALGORITHM_SHA1)) {

		    // INICIO SIGNING CERTIFICATE-V2

		    /**
		     * IssuerSerial ::= SEQUENCE {
		     *   issuer                   GeneralNames,
		     *   serialNumber             CertificateSerialNumber
		     *
		     */

		    TBSCertificateStructure tbs = TBSCertificateStructure.getInstance(ASN1Object.fromByteArray(cert.getTBSCertificate()));
		    GeneralName gn = new GeneralName(tbs.getIssuer());
		    GeneralNames gns = new GeneralNames(gn);

		    IssuerSerial isuerSerial = new IssuerSerial(gns, tbs.getSerialNumber());

		    /**
		     * ESSCertIDv2 ::=  SEQUENCE {
		     *       hashAlgorithm           AlgorithmIdentifier  DEFAULT {algorithm id-sha256},
		     *       certHash                 Hash,
		     *       issuerSerial             IssuerSerial OPTIONAL
		     *   }
		     *
		     *   Hash ::= OCTET STRING
		     */

		    MessageDigest md = MessageDigest.getInstance(CryptoUtilPdfBc.getDigestAlgorithmName(digestAlgorithmId.getName()));
		    byte[ ] certHash = md.digest(cert.getEncoded());
		    ESSCertIDv2[ ] essCertIDv2 = { new ESSCertIDv2(algId, certHash, isuerSerial) };

		    /**
		     * PolicyInformation ::= SEQUENCE {
		     *           policyIdentifier   CertPolicyId,
		     *           policyQualifiers   SEQUENCE SIZE (1..MAX) OF
		     *                                  PolicyQualifierInfo OPTIONAL }
		     *
		     *      CertPolicyId ::= OBJECT IDENTIFIER
		     *
		     *      PolicyQualifierInfo ::= SEQUENCE {
		     *           policyQualifierId  PolicyQualifierId,
		     *           qualifier          ANY DEFINED BY policyQualifierId }
		     *
		     */

		    SigningCertificateV2 scv2 = new SigningCertificateV2(essCertIDv2); // Sin

		    // Secuencia con singningCertificate
		    contexExpecific.add(new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new DERSet(scv2)));

		    // FIN SINGING CERTIFICATE-V2

		} else {

		    // INICIO SINGNING CERTIFICATE

		    /**
		     *	IssuerSerial ::= SEQUENCE {
		     *	     issuer                   GeneralNames,
		     *	     serialNumber             CertificateSerialNumber
		     *	}
		     */

		    TBSCertificateStructure tbs = TBSCertificateStructure.getInstance(ASN1Object.fromByteArray(cert.getTBSCertificate()));
		    GeneralName gn = new GeneralName(tbs.getIssuer());
		    GeneralNames gns = new GeneralNames(gn);

		    IssuerSerial isuerSerial = new IssuerSerial(gns, tbs.getSerialNumber());

		    /**
		     *	ESSCertID ::=  SEQUENCE {
		     *   certHash                 Hash,
		     *   issuerSerial             IssuerSerial OPTIONAL
		     *	}
		     * 
		     *	Hash ::= OCTET STRING -- SHA1 hash of entire certificate
		     */
		    // MessageDigest
		    String digestAlgorithmName = CryptoUtilPdfBc.getDigestAlgorithmName(digestAlgorithmId.getName());
		    MessageDigest md = MessageDigest.getInstance(digestAlgorithmName);
		    byte[ ] certHash = md.digest(cert.getEncoded());
		    ESSCertID essCertID = new ESSCertID(certHash, isuerSerial);

		    /**
		     * PolicyInformation ::= SEQUENCE {
		     *           policyIdentifier   CertPolicyId,
		     *           policyQualifiers   SEQUENCE SIZE (1..MAX) OF
		     *                                  PolicyQualifierInfo OPTIONAL }
		     *
		     *      CertPolicyId ::= OBJECT IDENTIFIER
		     *
		     *      PolicyQualifierInfo ::= SEQUENCE {
		     *           policyQualifierId  PolicyQualifierId,
		     *           qualifier          ANY DEFINED BY policyQualifierId }
		     *
		     */

		    SigningCertificate scv = new SigningCertificate(essCertID); // Sin
		    // politica

		    /**
		     * id-aa-signingCertificate OBJECT IDENTIFIER ::= { iso(1)
		     *   member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
		     *   smime(16) id-aa(2) 12 }
		     */
		    // Secuencia con singningCertificate
		    contexExpecific.add(new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificate, new DERSet(scv)));
		}
	    }
	    return getAttributeSet(new AttributeTable(contexExpecific));
	} catch (CertificateException e) {
	    throw new SigningException(Language.getResIntegra(ILogConstantKeys.CMSB_LOG006), e);
	} catch (NoSuchAlgorithmException e) {
	    throw new SigningException(Language.getResIntegra(ILogConstantKeys.CMSB_LOG007), e);
	} catch (IOException e) {
	    throw new SigningException(Language.getResIntegra(ILogConstantKeys.CMSB_LOG008), e);
	}
    }

    /**
     * Method that adds the <code>SignaturePolicyId</code> element to a CAdES signature.
     * @param contexExpecific Parameter that represents the set of values of the signer info.
     * @param extraParams Set of extra configuration parameters.
     * @param signaturePolicyID Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param signAlgorithmId Parameter that represents the OID of the signature algorithm.
     * @param digestAlgorithmId Parameter that represents the OID of the digest algorithm.
     * @param includeContent Parameter that indicates whether the document content is included in the signature (true) or is only referenced (false).
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the method fails.
     */
    private void addPolicyToCAdESSignature(ASN1EncodableVector contexExpecific, Properties extraParams, String signaturePolicyID, Properties policyProperties, AlgorithmIdentifier signAlgorithmId, AlgorithmIdentifier digestAlgorithmId, boolean includeContent, String idClient) throws SigningException {
	isEPES = true;

	// Comprobamos si se ha indicado un identificador de política de
	// firma
	if (signaturePolicyID == null) {
	    // Rescatamos del archivo con las propiedades asociadas a las
	    // políticas de firma el identificador de la política de firma
	    // asociada a las firmas ASN.1
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_ASN1_POLICY_ID);
	    // Comprobamos que el identificador de la política de firma no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG023, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		isEPES = false;
	    } else {
		LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG025, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	    }
	} else {
	    // Buscamos en el archivo con las propiedades asociadas a las
	    // políticas de firma si existe la política de firma para el
	    // identificador indicado
	    if (policyProperties.get(signaturePolicyID + ISignPolicyConstants.KEY_IDENTIFIER_ASN1) != null) {
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG026, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE, signaturePolicyID }));
		policyID = signaturePolicyID;
	    } else {
		// Rescatamos del archivo con las propiedades asociadas a
		// las políticas de firma el identificador de la política de
		// firma
		// asociada a las firmas ASN.1
		policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_ASN1_POLICY_ID);
		// Comprobamos que el identificador de la política de firma
		// no sea nulo ni vacío
		if (!GenericUtilsCommons.assertStringValue(policyID)) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG027, new Object[ ] { signaturePolicyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		    LOGGER.warn(errorMsg);
		    isEPES = false;
		} else {
		    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG029, new Object[ ] { signaturePolicyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE, policyID }));
		}
	    }
	}
	if (isEPES) {
	    checkEPESParams(policyProperties, signAlgorithmId, digestAlgorithmId, includeContent, idClient);

	    // Accedemos a la propiedad con el valor del
	    // elemento SigPolicyQualifier
	    String qualifier = extraParams.getProperty(SignatureProperties.CADES_POLICY_QUALIFIER_PROP);

	    // Procesamos los parámetros asociados a la política de firma
	    // que utilizar
	    try {
		SignaturePolicyManager.addASN1SignPolicy(contexExpecific, qualifier, policyID, policyProperties, false, idClient);
		// Incluimos el atributo content-hints
		contexExpecific.add(new Attribute(CMSAttributes.contentHint, new DERSet(new ContentHints(PKCSObjectIdentifiers.data))));
	    } catch (SignaturePolicyException e) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.CMSB_LOG033);
		LOGGER.error(errorMsg, e);
		throw new SigningException(errorMsg, e);
	    }
	}
    }

    /**
     * Method that checks:
     * <ul>
     * <li>If the OID of the signature algorithm is valid for the signature policy.</li>
     * <li>If the OID of the hash algorithm is valid for the signature policy.</li>
     * <li>If the signingMode is valid for the signature policy.</li>
     * </ul>
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param signAlgorithmId Parameter that represents the OID of the signature algorithm.
     * @param digestAlgorithmId Parameter that represents the OID of the digest algorithm.
     * @param includeContent Parameter that indicates whether the document content is included in the signature (true) or is only referenced (false).
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the validation fails.
     */
    private void checkEPESParams(Properties policyProperties, AlgorithmIdentifier signAlgorithmId, AlgorithmIdentifier digestAlgorithmId, boolean includeContent, String idClient) throws SigningException {
	// Comprobamos si el algoritmo de firma está soportado por la
	// política de firma
	if (!SignaturePolicyManager.isValidASN1SignAlgorithmByPolicy(signAlgorithmId, policyID, policyProperties, idClient)) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG031, new Object[ ] { signAlgorithmId, policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
	// Comprobamos si el algoritmo de hash está soportado por la
	// política de firma
	if (!SignaturePolicyManager.isValidASN1HashAlgorithmByPolicy(digestAlgorithmId, policyID, policyProperties, idClient)) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG032, new Object[ ] { digestAlgorithmId, policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
	// Comprobamos si el modo de firma está soportado por la política de
	// firma
	if (!SignaturePolicyManager.isValidASN1SigningModeByPolicy(includeContent, policyID, policyProperties, idClient)) {
	    String signingMode = IUtilsSignature.IMPLICIT_SIGNATURE_MODE;
	    if (!includeContent) {
		signingMode = IUtilsSignature.EXPLICIT_SIGNATURE_MODE;
	    }
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG035, new Object[ ] { signingMode, policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that adds the <code>SignaturePolicyId</code> element to a PAdES signature.
     * @param contexExpecific Parameter that represents the set of values of the signer info.
     * @param extraParams Set of extra configuration parameters.
     * @param signaturePolicyID Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param signAlgorithmId Parameter that represents the OID of the signature algorithm.
     * @param digestAlgorithmId Parameter that represents the OID of the digest algorithm.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the method fails.
     */
    private void addPolicyToPAdESSignature(ASN1EncodableVector contexExpecific, Properties extraParams, String signaturePolicyID, Properties policyProperties, AlgorithmIdentifier signAlgorithmId, AlgorithmIdentifier digestAlgorithmId, String idClient) throws SigningException {
	isEPES = true;

	// Comprobamos si se ha indicado un identificador de política de
	// firma
	if (signaturePolicyID == null) {
	    // Rescatamos del archivo con las propiedades asociadas a las
	    // políticas de firma el identificador de la política de firma
	    // asociada a las firmas PDF
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_PDF_POLICY_ID);
	    // Comprobamos que el identificador de la política de firma no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG024, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		isEPES = false;
	    } else {
		LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG025, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	    }
	} else {
	    // Buscamos en el archivo con las propiedades asociadas a las
	    // políticas de firma si existe la política de firma para el
	    // identificador indicado
	    if (policyProperties.get(signaturePolicyID + ISignPolicyConstants.KEY_IDENTIFIER_PDF) != null) {
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG026, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE, signaturePolicyID }));
		policyID = signaturePolicyID;
	    } else {
		// Rescatamos del archivo con las propiedades asociadas a
		// las políticas de firma el identificador de la política de
		// firma
		// asociada a las firmas PDF
		policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_PDF_POLICY_ID);
		// Comprobamos que el identificador de la política de firma
		// no sea nulo ni vacío
		if (!GenericUtilsCommons.assertStringValue(policyID)) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG028, new Object[ ] { signaturePolicyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		    LOGGER.warn(errorMsg);
		    isEPES = false;
		} else {
		    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG030, new Object[ ] { signaturePolicyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE, policyID }));
		}
	    }
	}
	if (isEPES) {
	    // Comprobamos si el algoritmo de firma está soportado por la
	    // política de firma
	    if (!SignaturePolicyManager.isValidASN1SignAlgorithmByPolicy(signAlgorithmId, policyID, policyProperties, idClient)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG031, new Object[ ] { signAlgorithmId, policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    // Comprobamos si el algoritmo de hash está soportado por la
	    // política de firma
	    if (!SignaturePolicyManager.isValidASN1HashAlgorithmByPolicy(digestAlgorithmId, policyID, policyProperties, idClient)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG032, new Object[ ] { digestAlgorithmId, policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    // Accedemos a la propiedad con el valor del
	    // elemento SigPolicyQualifier
	    String qualifier = extraParams.getProperty(SignatureProperties.CADES_POLICY_QUALIFIER_PROP);

	    // Procesamos los parámetros asociados a la política de firma
	    // que utilizar
	    try {
		SignaturePolicyManager.addASN1SignPolicy(contexExpecific, qualifier, policyID, policyProperties, true, idClient);
	    } catch (SignaturePolicyException e) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.CMSB_LOG033);
		LOGGER.error(errorMsg, e);
		throw new SigningException(errorMsg, e);
	    }
	}
    }

    /**
     * Method that adds the <code>SignaturePolicyId</code> element to a signature if it's required.
     * @param contexExpecific Parameter that represents the set of values of the signer info.
     * @param extraParams Set of extra configuration parameters.
     * @param isPadesSigner Parameter that indicates if the signature is PAdES (true) or CAdES (false).
     * @param signatureForm Parameter that represents the signature form.
     * The allowed values for CAdES signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_CADES_BES}</li>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_CADES_EPES}</li>
     * </ul>
     * The allowed values for PAdES signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_PADES_BES}</li>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_PADES_EPES}</li>
     * </ul>
     * @param signaturePolicyID Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @param signAlgorithmId Parameter that represents the OID of the signature algorithm.
     * @param digestAlgorithmId Parameter that represents the OID of the digest algorithm.
     * @param includeContent Parameter that indicates whether the document content is included in the signature (true) or is only referenced (false).
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the method fails.
     */
    private void addPolicy(ASN1EncodableVector contexExpecific, Properties extraParams, boolean isPadesSigner, String signatureForm, String signaturePolicyID, AlgorithmIdentifier signAlgorithmId, AlgorithmIdentifier digestAlgorithmId, boolean includeContent, String idClient) throws SigningException {

	// Comprobamos si la firma a realizar debe ser BES o EPES
	isEPES = signatureForm.equals(ISignatureFormatDetector.FORMAT_CADES_EPES) || signatureForm.equals(ISignatureFormatDetector.FORMAT_PADES_EPES) || (signatureForm.equals(ISignatureFormatDetector.FORMAT_CADES_B_LEVEL) || signatureForm.equals(ISignatureFormatDetector.FORMAT_PADES_B_LEVEL)) && signaturePolicyID != null;

	// Si la firma a realizar es EPES
	if (isEPES) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);
	    if (!isPadesSigner) {
		addPolicyToCAdESSignature(contexExpecific, extraParams, signaturePolicyID, policyProperties, signAlgorithmId, digestAlgorithmId, includeContent, idClient);
	    }
	    // Si la firma es PAdES
	    else {
		addPolicyToPAdESSignature(contexExpecific, extraParams, signaturePolicyID, policyProperties, signAlgorithmId, digestAlgorithmId, idClient);
	    }
	}
    }

    /**
     * Performs sign of signed attributes.
     * @param signatureAlgorithm signature algorithm
     * @param keyEntry private key.
     * @param signedAttributes signed attributes of SignedInfo.
     * @return signature in ASN1OctetString format.
     * @throws SigningException in error case.
     */
    private ASN1OctetString sign(String signatureAlgorithm, PrivateKeyEntry keyEntry, ASN1Set signedAttributes) throws SigningException {

	Signature sig = null;
	try {
	    sig = Signature.getInstance(signatureAlgorithm);
	} catch (Exception e) {
	    throw new SigningException(Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG011, new Object[ ] { signatureAlgorithm }), e);
	}

	byte[ ] tmp = null;

	try {
	    tmp = signedAttributes.getEncoded(ASN1Encodable.DER);
	} catch (IOException ex) {
	    LOGGER.error(ex);
	    throw new SigningException(Language.getResIntegra(ILogConstantKeys.CMSB_LOG012), ex);
	}

	// Indicar clave privada para la firma
	try {
	    sig.initSign(keyEntry.getPrivateKey());
	} catch (InvalidKeyException e) {
	    throw new SigningException(Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG013, new Object[ ] { signatureAlgorithm }), e);
	}

	// Actualizamos la configuracion de firma
	try {
	    sig.update(tmp);
	} catch (SignatureException e) {
	    throw new SigningException(Language.getResIntegra(ILogConstantKeys.CMSB_LOG014), e);
	}

	// firmamos.
	byte[ ] realSig = null;
	try {
	    realSig = sig.sign();
	} catch (SignatureException e) {
	    throw new SigningException(Language.getResIntegra(ILogConstantKeys.CMSB_LOG015), e);
	}

	ASN1OctetString encDigest = new DEROctetString(realSig);

	return encDigest;

    }

    /**
     * Builds a SignerInfo object used in CAdES. SignerInfo is defined in the
     * <a href="http://tools.ietf.org/html/rfc3852">RFC 3852</a>:<br>
     *<pre>
     *SignerInfo ::= SEQUENCE {
        version CMSVersion,
        sid SignerIdentifier,
        digestAlgorithm DigestAlgorithmIdentifier,
        signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
        signatureAlgorithm SignatureAlgorithmIdentifier,
        signature SignatureValue,
        unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
    
      SignerIdentifier ::= CHOICE {
        issuerAndSerialNumber IssuerAndSerialNumber,
        subjectKeyIdentifier [0] SubjectKeyIdentifier }
    
      SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
    
      UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
    
      Attribute ::= SEQUENCE {
        attrType OBJECT IDENTIFIER,
        attrValues SET OF AttributeValue }
    
      AttributeValue ::= ANY
    
      SignatureValue ::= OCTET STRING
      </pre>
     * @param parameters object that includes all data to generate SignerInfo object.
     * @param signType SignerInfo type to generate.
     * @param includeTimestamp Parameter that indicates if the signature will have a timestamp (true) or not (false).
     * @param signatureForm Parameter that represents the signature form.
     * The allowed values for CAdES signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_CADES_BES}</li>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_CADES_EPES}</li>
     * </ul>
     * The allowed values for PAdES signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_PADES_BES}</li>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_PADES_EPES}</li>
     * </ul>
     * @param signaturePolicyID Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @param includeContent Parameter that indicates whether the document content is included in the signature (true) or is only referenced (false).
     * @param idClient Parameter that represents the client application identifier.
     * @return a new {@link SignerInfo} instance.
     * @throws SigningException in error case.
     */
    public SignerInfo generateSignerInfo(P7ContentSignerParameters parameters, SignerInfoTypes signType, boolean includeTimestamp, String signatureForm, String signaturePolicyID, boolean includeContent, String idClient) throws SigningException {
	try {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.CMSB_LOG016));
	    // obtención del certificado firmante
	    PrivateKeyEntry privateKey = parameters.getPrivateKey();
	    X509Certificate signerCertificate = (X509Certificate) privateKey.getCertificate();
	    X509CertificateHolder cert = new X509CertificateHolder(signerCertificate.getEncoded());
	    IssuerAndSerialNumber issuerAndSerial = cert.getIssuerAndSerialNumber();

	    // SignerIdentifier
	    SignerIdentifier signerIdentifier = new SignerIdentifier(issuerAndSerial);

	    // DigestAlgorithmIdentifier
	    String digestAlgorithm = SignatureConstants.SIGN_ALGORITHMS_SUPPORT_CADES.get(parameters.getSignatureAlgorithm());
	    AlgorithmIdentifier digestAlgorithmId = makeDigestAlgorithmId(digestAlgorithm);

	    // ATRIBUTOS FIRMADOS
	    // =====================================================================================
	    ASN1EncodableVector signedAttributes = new ASN1EncodableVector();

	    // ContentType (no se incluye en counterSignature CMS por
	    // especificación de RFC 3852)
	    if (!signType.equals(SignerInfoTypes.COUNTERSIGNATURE)) {
		signedAttributes.add(new Attribute(CMSAttributes.contentType, new DERSet(PKCSObjectIdentifiers.data)));
	    }
	    // SigningTime (fecha de firma)
	    signedAttributes.add(new Attribute(CMSAttributes.signingTime, new DERSet(new DERUTCTime(Calendar.getInstance().getTime()))));

	    // SignatureAlgorithmIdentifier
	    AlgorithmIdentifier signAlgorithmId = new DefaultSignatureAlgorithmIdentifierFinder().find(parameters.getSignatureAlgorithm());

	    // Política de la firma --> elemento SignaturePolicyId
	    addPolicy(signedAttributes, parameters.getOptionalParams(), false, signatureForm, signaturePolicyID, signAlgorithmId, digestAlgorithmId, includeContent, idClient);

	    // MessageDigest
	    // si es countersignature el digest se crea a partir del campo
	    // signatureValue del SignerInfo padre.
	    // si es cosign el digest se crea a partir del contenido pasado como
	    // argumento.
	    byte[ ] messageDigest = CryptoUtilPdfBc.digest(digestAlgorithm, parameters.getContent());
	    signedAttributes.add(new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(messageDigest))));

	    // Signing Certificate Attributes
	    signedAttributes.add(generateSigningCertAttr(cert, digestAlgorithm, digestAlgorithmId));

	    ASN1Set signedAttrSet = getAttributeSet(new AttributeTable(signedAttributes));
	    // ========================================================================================================

	    // SignatureValue (cálculo de la firma de los atributos firmados)
	    ASN1OctetString signatureValue = sign(parameters.getSignatureAlgorithm(), privateKey, signedAttrSet);

	    // Atributos no firmados
	    ASN1Set unsignedAttr = null;

	    // Comprobamos si se ha indicado añadir sello de tiempo
	    if (includeTimestamp) {
		// Obtenemos el sello de tiempo de TS@
		TimeStampToken tst = generateTimestamp(signatureValue.getOctets(), idClient);

		// Validamos el sello de tiempo
		UtilsTimestampPdfBc.validateASN1Timestamp(tst);

		// Validamos el certificado firmante respecto a la fecha
		// indicada en el sello de tiempo
		UtilsSignatureOp.validateCertificate(signerCertificate, tst.getTimeStampInfo().getGenTime(), false, idClient, false);

		// Incluímos el sello de tiempo en el conjunto de atributos no
		// firmados
		InputStream is = null;
		try {
		    is = new ASN1InputStream(tst.getEncoded());
		    DERObject derObject = ((ASN1InputStream) is).readObject();
		    DERSet derSet = new DERSet(derObject);
		    Attribute unsignAtt = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, derSet);
		    Map<ASN1ObjectIdentifier, Attribute> hashtable = new Hashtable<ASN1ObjectIdentifier, Attribute>();
		    hashtable.put(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, unsignAtt);

		    AttributeTable unsignedAtts = new AttributeTable((Hashtable<ASN1ObjectIdentifier, Attribute>) hashtable);
		    unsignedAttr = getAttributeSet(unsignedAtts);
		} finally {
		    UtilsResourcesCommons.safeCloseInputStream(is);
		}
	    } else {
		// Validamos el certificado firmante respecto a la fecha actual
		UtilsSignatureOp.validateCertificate(signerCertificate, Calendar.getInstance().getTime(), false, idClient, false);
	    }

	    // Generamos el objeto SignerInfo
	    SignerInfo signerInfo = new SignerInfo(signerIdentifier, digestAlgorithmId, signedAttrSet, signAlgorithmId, signatureValue, unsignedAttr);

	    // Comprobamos que la firma generada cumple con las características
	    // de
	    // la política de sello de tiempo, en el caso de ser EPES
	    if (isEPES) {
		try {
		    SignaturePolicyManager.validateGeneratedCAdESEPESSignature(signerInfo, policyID, null, signType.equals(SignerInfoTypes.COUNTERSIGNATURE), idClient);
		} catch (SignaturePolicyException e) {
		    throw new SigningException(Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG034, new Object[ ] { e.getMessage() }), e);
		}
	    }
	    return signerInfo;
	} catch (CertificateException e) {
	    throw new SigningException(Language.getResIntegra(ILogConstantKeys.CMSB_LOG006), e);
	} catch (IOException e) {
	    throw new SigningException(Language.getResIntegra(ILogConstantKeys.CMSB_LOG008), e);
	}
    }

    /**
     * Builds a SignerInfo object used in CAdES. SignerInfo is defined in the
     * <a href="http://tools.ietf.org/html/rfc3852">RFC 3852</a>:<br>
     *<pre>
     *SignerInfo ::= SEQUENCE {
        version CMSVersion,
        sid SignerIdentifier,
        digestAlgorithm DigestAlgorithmIdentifier,
        signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
        signatureAlgorithm SignatureAlgorithmIdentifier,
        signature SignatureValue,
        unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
    
      SignerIdentifier ::= CHOICE {
        issuerAndSerialNumber IssuerAndSerialNumber,
        subjectKeyIdentifier [0] SubjectKeyIdentifier }
    
      SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
    
      UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
    
      Attribute ::= SEQUENCE {
        attrType OBJECT IDENTIFIER,
        attrValues SET OF AttributeValue }
    
      AttributeValue ::= ANY
    
      SignatureValue ::= OCTET STRING
      </pre>
     * @param parameters object that includes all data to generate SignerInfo object.
     * @param signType SignerInfo type to generate.
     * @param includeTimestamp Parameter that indicates if the signature will have a timestamp (true) or not (false).
     * @param signatureForm Parameter that represents the signature form.
     * The allowed values for CAdES signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_CADES_BES}</li>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_CADES_EPES}</li>
     * </ul>
     * The allowed values for PAdES signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_PADES_BES}</li>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCommons#FORMAT_PADES_EPES}</li>
     * </ul>
     * @param signaturePolicyID Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @param includeContent Parameter that indicates whether the document content is included in the signature (true) or is only referenced (false).
     * @return a new {@link SignerInfo} instance.
     * @throws SigningException in error case.
     */
    public SignerInfo generateSignerInfo(P7ContentSignerParameters parameters, SignerInfoTypes signType, boolean includeTimestamp, String signatureForm, String signaturePolicyID, boolean includeContent) throws SigningException {
	return generateSignerInfo(parameters, signType, includeTimestamp, signatureForm, signaturePolicyID, includeContent, null);
    }

    /**
     * Method that checks whether a timestamp can be added to the unsigned attributes of a signer.
     * @param unsignedAttributes Parameter that represents the unsigned attributes of a signer.
     * @return a boolean that indicates whether a timestamp can be added to the unsigned attributes of a signer (true), or not (false).
     */
    private static boolean checkAddTimestamp(AttributeTable unsignedAttributes) {
	if (unsignedAttributes == null || unsignedAttributes.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) == null && unsignedAttributes.get(ESFAttributes.archiveTimestamp) == null && unsignedAttributes.get(ESFAttributes.archiveTimestampV2) == null) {
	    return true;
	}
	return false;
    }

    /**
     * Method that checks whether to add a timestamp to a signer of a signature (true) or not (false).
     * @param signerInformation Parameter that represents the information of the signature signer.
     * @param listCertificates Parameter that represents the list with the certificates of the signers to upgrade.
     * @return a boolean that indicates whether to add a timestamp to a signer of a signature (true) or not (false).
     */
    private static boolean checkUpgradeSignature(SignerInformation signerInformation, List<X509Certificate> listCertificates) {
	boolean upgrade = false;
	/*
	 * Comprobamos si hay que actualizar el firmante, esto se hará si se cumple alguna de las siguientes condiciones:
	 * 
	 * 1- La lista con los certificados de los firmantes a actualizar es vacía o nula, por lo que se deben actualizar todos los que no posean
	 * un sello de tiempo previo ni los que posean el atributo no firmado id-aa-ets-archiveTimeStamp o id-aa-ets-archiveTimestampV2.
	 * 2- El certificado del firmante coincide con alguno de los indicados como parámetro no posee un sello de tiempo previo ni posee
	 * como atributo no firmado id-aa-ets-archiveTimeStamp o id-aa-ets-archiveTimestampV2.
	 */
	if (listCertificates == null || listCertificates.size() == 0) {
	    // Comprobamos que la firma no contenga un sello de tiempo previo
	    upgrade = checkAddTimestamp(signerInformation.getUnsignedAttributes());
	} else {
	    // Obtenemos la información del firmante
	    SignerId signerID = signerInformation.getSID();
	    int i = 0;
	    boolean enc = false;
	    // Recorremos la lista de certificados indicados para
	    // actualizar
	    while (!enc && i < listCertificates.size()) {
		X509Certificate certificateToUpgrade = listCertificates.get(i);
		// Comprobamos si el certificado del firmante contenido
		// en la firma coincide con el certificado indicado para
		// actualizar
		if (signerID.match(certificateToUpgrade)) {
		    enc = true;
		    // Comprobamos que la firma no contenga un sello de tiempo
		    // previo
		    upgrade = checkAddTimestamp(signerInformation.getUnsignedAttributes());
		}
		i++;
	    }
	}
	return upgrade;
    }

    /**
     * Method that upgrades a list of signers by adding a timestamp to each one. The timestamp will be added only to those signers that don't have
     * a previous timestamp.
     * @param signedData Parameter that represents the signature which contain the signers.
     * @param listCertificates Parameter that represents the list of signers of the signature to upgrade with a timestamp. If the list is null or empty,
     * all of the signers will be updated.
     * @param listSignersSignature Parameter that represents the list of signers to upgrade.
     * @param idClient Parameter that represents the client application identifier.
     * @return the list with all the signers, upgraded or not.
     * @throws SigningException If the method fails.
     */
    @SuppressWarnings("unchecked")
    public List<SignerInformation> upgradeSignersWithTimestamp(CMSSignedData signedData, List<X509Certificate> listCertificates, List<SignerInformation> listSignersSignature, String idClient) throws SigningException {
	try {

	    // Definimos una lista con todos los firmantes que tendrá la firma
	    // actualizada
	    List<SignerInformation> listNewSigners = new ArrayList<SignerInformation>();

	    // Recorremos la lista de firmantes contenidos en la firma
	    for (SignerInformation signerInformation: listSignersSignature) {
		/*
		 * Comprobamos si hay que actualizar el firmante, esto se hará si se cumple alguna de las siguientes condiciones:
		 * 
		 * 1- La lista con los certificados de los firmantes a actualizar es vacía o nula, por lo que se deben actualizar todos los que no posean
		 * un sello de tiempo previo ni los que posean el atributo no firmado id-aa-ets-archiveTimeStamp o id-aa-ets-archiveTimestampV2.
		 * 2- El certificado del firmante coincide con alguno de los indicados como parámetro no posee un sello de tiempo previo ni posee
		 * como atributo no firmado id-aa-ets-archiveTimeStamp o id-aa-ets-archiveTimestampV2.
		 */
		boolean upgrade = checkUpgradeSignature(signerInformation, listCertificates);

		// Si se debe actualizar el firmante comprobamos si ya tiene un
		// sello de tiempo
		// asociado. En dicho caso, no se le añade otro.
		String issuer = signerInformation.getSID().getIssuerAsString();
		BigInteger serialNumber = signerInformation.getSID().getSerialNumber();

		if (upgrade) {
		    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG022, new Object[ ] { issuer, serialNumber }));
		    AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();

		    // Generamos el sello de tiempo
		    TimeStampToken tst = generateTimestamp(signerInformation.getSignature(), idClient);

		    // Llevamos a cabo la validación del sello de tiempo
		    UtilsTimestampPdfBc.validateASN1Timestamp(tst);

		    // Obtenemos el certificado firmante
		    X509Certificate signingCertificate = UtilsSignatureOp.getSigningCertificate(signedData, signerInformation);

		    // Validamos el certificado firmante respecto a la fecha del
		    // sello de tiempo
		    UtilsSignatureOp.validateCertificate(signingCertificate, tst.getTimeStampInfo().getGenTime(), true, idClient, false);

		    // Si el firmante carece de atributos no firmados, los
		    // creamos
		    if (unsignedAttributes == null) {
			unsignedAttributes = new AttributeTable(new Hashtable<ASN1ObjectIdentifier, DERSequence>());
		    }
		    // Añadimos el sello de tiempo al conjunto de atributos
		    // no
		    // firmados
		    InputStream is = null;
		    try {
			unsignedAttributes = unsignedAttributes.add(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, ASN1Sequence.getInstance(tst.getEncoded()));

			// Accedemos al conjunto de contrafirmas del firmante,
			// en caso de tener
			SignerInformationStore signerInformationStore = signerInformation.getCounterSignatures();
			List<SignerInformation> listCounterSignatures = (List<SignerInformation>) signerInformationStore.getSigners();
			if (!listCounterSignatures.isEmpty()) {
			    // Actualizamos los firmantes de las contrafirmas
			    List<SignerInformation> listUpdatedCounterSignatures = upgradeSignersWithTimestamp(signedData, listCertificates, listCounterSignatures, idClient);

			    // Eliminamos las contrafirmas del firmante
			    unsignedAttributes = unsignedAttributes.remove(PKCSObjectIdentifiers.pkcs_9_at_counterSignature);
			    signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);

			    // Añadimos al firmante las contrafirmas
			    // actualizadas
			    signerInformation = SignerInformation.addCounterSigners(signerInformation, new SignerInformationStore(listUpdatedCounterSignatures));
			} else {
			    // Actualizamos el firmante en lo que se refiere a
			    // atributos no firmados
			    signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
			}
		    } finally {
			UtilsResourcesCommons.safeCloseInputStream(is);
		    }
		} else {
		    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG021, new Object[ ] { issuer, serialNumber }));
		}
		// Añadimos el firmante a la lista con los firmantes
		// que tendrá la firma actualizada
		listNewSigners.add(signerInformation);
	    }
	    return listNewSigners;
	} catch (IOException e) {
	    String msg = Language.getResIntegra(ILogConstantKeys.CMSB_LOG020);
	    LOGGER.error(msg, e);
	    throw new SigningException(msg, e);
	}
    }

    /**
     * Generates a SigningCertificate attribute (version 1 or 2 depending of type digest algorithm). Definition:
     *<pre>
    SigningCertificate ::=  SEQUENCE {
           certs        SEQUENCE OF ESSCertID,
           policies     SEQUENCE OF PolicyInformation OPTIONAL
       }
     	ESSCertID ::=  SEQUENCE {
        	certHash                 Hash,
        	issuerSerial             IssuerSerial OPTIONAL
     	}
    
     	Hash ::= OCTET STRING -- SHA1 hash of entire certificate
     	 -------------------------
     SigningCertificateV2 ::=  SEQUENCE {
            certs        SEQUENCE OF ESSCertIDv2,
            policies     SEQUENCE OF PolicyInformation OPTIONAL
        }
    	ESSCertIDv2 ::=  SEQUENCE {
            hashAlgorithm   	AlgorithmIdentifier DEFAULT {algorithm id-sha256},
            certHash            Hash,
            issuerSerial        IssuerSerial OPTIONAL
        }
    
    	Hash ::= OCTET STRING
     	</pre>
     * 
     * @param cert certificate object.
     * @param digestAlgorithm digest algorithm.
     * @param digestAlgorithmId digest algorithm identification.
     * @return a SigningCertificate attribute.
     * @throws SigningException in error case.
     * @throws IOException if cetificate is wrong.
     */
    private Attribute generateSigningCertAttr(X509CertificateHolder cert, String digestAlgorithm, AlgorithmIdentifier digestAlgorithmId) throws SigningException, IOException {
	X500Name x500Name = cert.getIssuerAndSerialNumber().getName();
	DERInteger serialNumber = cert.getIssuerAndSerialNumber().getSerialNumber();

	/**
	 IssuerSerial ::= SEQUENCE {
	        issuer                   GeneralNames,
	        serialNumber             CertificateSerialNumber
	   }
	 */
	IssuerSerial issuerSerial = new IssuerSerial(new GeneralNames(new GeneralName(x500Name)), serialNumber);

	byte[ ] certHash = CryptoUtilPdfBc.digest(digestAlgorithm, cert.getEncoded());

	// Comprobación si se emplea SigningCertificate ó
	// SigningCertificate-V2 (sha1 o demás sha2 respectivamente)
	if (ICryptoUtil.HASH_ALGORITHM_SHA1.equals(digestAlgorithm)) {
	    // INICIO SigningCertificate
	    /**
	    	SigningCertificate ::=  SEQUENCE {
	           certs        SEQUENCE OF ESSCertID,
	           policies     SEQUENCE OF PolicyInformation OPTIONAL
	       }
	     	ESSCertID ::=  SEQUENCE {
	        	certHash                 Hash,
	        	issuerSerial             IssuerSerial OPTIONAL
	     	}
	    
	     	Hash ::= OCTET STRING -- SHA1 hash of entire certificate
	     */

	    // creación objeto ESSCertID
	    ESSCertID essCertID = new ESSCertID(certHash, issuerSerial);
	    // creación objeto SigningCertificate
	    SigningCertificate scv = new SigningCertificate(essCertID); // SigningCertificate
	    // sin
	    // politica.

	    // Secuencia con singningCertificate
	    return new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificate, new DERSet(scv));

	} else {
	    // INICIO SigningCertificateV2
	    /**
	     SigningCertificateV2 ::=  SEQUENCE {
	            certs        SEQUENCE OF ESSCertIDv2,
	            policies     SEQUENCE OF PolicyInformation OPTIONAL
	        }
	    	ESSCertIDv2 ::=  SEQUENCE {
	            hashAlgorithm   	AlgorithmIdentifier DEFAULT {algorithm id-sha256},
	            certHash            Hash,
	            issuerSerial        IssuerSerial OPTIONAL
	        }
	    
	    	Hash ::= OCTET STRING
	    
	     */
	    ESSCertIDv2[ ] essCertIDv2 = { new ESSCertIDv2(digestAlgorithmId, certHash, issuerSerial) };

	    SigningCertificateV2 scv2 = new SigningCertificateV2(essCertIDv2); // SigningCertificateV2
	    // sin
	    // política

	    return new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new DERSet(scv2));
	}
    }

    /**
     * Generates a new CMSData instance.
     * @param oldSignedData original signedData object.
     * @param certificates store with all signer certificates (list of  X509CertificateHolder objects).
     * @param signerInfos collection of new SignerInformation objects.
     * @return a new CMSData instance.
     * @throws SigningException in error case.
     */
    CMSSignedData generateCMSData(CMSSignedData oldSignedData, Store certificates, SignerInformationStore signerInfos) throws SigningException {
	try {
	    CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
	    cmsGenerator.addCertificates(certificates);
	    cmsGenerator.addSigners(signerInfos);
	    return cmsGenerator.generate(oldSignedData.getSignedContent(), new BouncyCastleProvider());
	} catch (CMSException e) {
	    LOGGER.error(e);
	    throw new SigningException(e);
	} catch (NoSuchAlgorithmException e) {
	    LOGGER.error(e);
	    throw new SigningException(e);
	}
    }

    /**
     * Generates a signature object.
     * @param cmsSignedData object that contains all data of original signature.
     * @param digestAlgId digest algorithm OID.
     * @param certificates list of certificates to include in the signature.
     * @param signerInfos list of signers to include in the signature.
     * @return a DER byte array of signature object (SignedData object).
     * @throws SigningException if happens a error in the
     */
    byte[ ] generateSignedData(CMSSignedData cmsSignedData, AlgorithmIdentifier digestAlgId, Store certificates, ASN1Set signerInfos) throws SigningException {
	// Obtención del contentInfo de la firma original.
	SignedData originalSignedData = SignedData.getInstance(cmsSignedData.getContentInfo().getContent());
	ASN1Set digestAlgorithms = originalSignedData.getDigestAlgorithms();
	digestAlgorithms = addElementToASN1Set(digestAlgorithms, digestAlgId.getDERObject());
	SignedData newSignedData = new SignedData(digestAlgorithms, originalSignedData.getEncapContentInfo(), convertCertStoreToASN1Set(certificates), null, signerInfos);
	return new ContentInfo(PKCSObjectIdentifiers.signedData, newSignedData).getDEREncoded();
    }

    /**
     * Converts a {@link SignerInformation} store to a set of {@link SignerInfo}.
     * @param signerInfos store with a collection of SignatureInformation objects.
     * @return a set of {@link SignerInfo} objects.
     */
    ASN1Set convertToASN1Set(SignerInformationStore signerInfos) {
	ASN1EncodableVector result = new ASN1EncodableVector();
	for (Object signerInformation: signerInfos.getSigners()) {
	    result.add(((SignerInformation) signerInformation).toASN1Structure());
	}
	return new DERSet(result);
    }

    /**
     * Converts a certificate store to a set of {@link org.bouncycastle.asn1.x509.X509CertificateStructure X509CertificateStructure}.
     * @param store store with a collection of {@link X509CertificateHolder}
     * @return a ASN1Set with a collection of certificates(X509CertificateStructure objects).
     */
    ASN1Set convertCertStoreToASN1Set(Store store) {
	ASN1EncodableVector asn1Vector = new ASN1EncodableVector();
	for (Object element: store.getMatches(null)) {
	    if (element instanceof X509CertificateHolder) {
		asn1Vector.add(((X509CertificateHolder) element).toASN1Structure());
	    }
	}
	return new DERSet(asn1Vector);
    }

    /**
     * Adds a new element to a ASN1Set list.
     * @param set list of ASN1Encodable elements.
     * @param element ASN1Encodable object to add.
     * @return a new ASN1Set with element included.
     */
    ASN1Set addElementToASN1Set(ASN1Set set, ASN1Encodable element) {
	ASN1Encodable[ ] arrayTmp = set.toArray();
	ASN1Encodable[ ] newArray = new ASN1Encodable[arrayTmp.length + 1];
	System.arraycopy(arrayTmp, 0, newArray, 0, arrayTmp.length);
	newArray[newArray.length - 1] = element;
	return new DERSet(newArray);
    }

    /**
     * Obtains the OID identifier associated to digest algorithm given.
     * @param digestAlg digest algorithm.
     * @return the OID identifier associated to digest algorithm.
     * @throws SigningException if algorithm given is wrong.
     */
    @SuppressWarnings("restriction")
    AlgorithmIdentifier makeDigestAlgorithmId(String digestAlg) throws SigningException {
	try {
	    sun.security.x509.AlgorithmId digestAlgorithmId = sun.security.x509.AlgorithmId.get(digestAlg);
	    return makeAlgId(digestAlgorithmId.getOID().toString(), digestAlgorithmId.getEncodedParams());
	} catch (NoSuchAlgorithmException e) {
	    throw new SigningException(Language.getResIntegra(ILogConstantKeys.CMSB_LOG007), e);
	} catch (IOException e) {
	    throw new SigningException(Language.getResIntegra(ILogConstantKeys.CMSB_LOG007), e);
	}
    }

    /**
     * Method that obtains the identifier from the OID of an algorithm.
     * @param oid Parameter that represents the OID of the algorithm.
     * @param params Set of elements to identify the algorithm.
     * @return the found identifier.
     * @throws IOException If the method fails.
     */
    private AlgorithmIdentifier makeAlgId(String oid, byte[ ] params) throws IOException {
	if (params != null) {
	    return new AlgorithmIdentifier(new DERObjectIdentifier(oid), makeObj(params));
	}
	return new AlgorithmIdentifier(new DERObjectIdentifier(oid), new DERNull());
    }

    /**
     * Method that generates an ASN.1 object from the bytes array.
     * @param encoding Parameter that represents the ASN.1 object.
     * @return an object that represents the ASN.1 element.
     * @throws IOException If the method fails.
     */
    @SuppressWarnings("resource")
    private DERObject makeObj(byte[ ] encoding) throws IOException {
	if (encoding == null) {
	    LOGGER.warn(Language.getResIntegra(ILogConstantKeys.CMSB_LOG017));
	    return null;
	}
	return new ASN1InputStream(new ByteArrayInputStream(encoding)).readObject();
    }

    /**
     * Method that obtains a {@link ASN1Set} from a table of attributes.
     * @param attr Parameter that represents the table of attributes.
     * @return the generated element.
     */
    private ASN1Set getAttributeSet(AttributeTable attr) {
	if (attr != null) {
	    return new DERSet(attr.toASN1EncodableVector());
	}
	LOGGER.warn(Language.getResIntegra(ILogConstantKeys.CMSB_LOG018));
	return null;
    }

    /**
     * Method that generates a {@link ASN1Set} from a DER element.
     * @param derObject Parameter that represents the DER element.
     * @return the generated element.
     */
    private ASN1Set createBerSetFromList(DEREncodable derObject) {
	ASN1EncodableVector v = new ASN1EncodableVector();
	v.add(derObject);
	return new BERSet(v);
    }

    /**
     * Gets the value of the attribute {@link #isEPES}.
     * @return the value of the attribute {@link #isEPES}.
     */
    public boolean isEPES() {
	return isEPES;
    }

    /**
     * Gets the value of the attribute {@link #policyID}.
     * @return the value of the attribute {@link #policyID}.
     */
    public String getPolicyID() {
	return policyID;
    }

    /**
     * Method that signs the leaft of each signer (end node of each signerInfo).
     * @param signerInfos store with all SignerInfomation to sign.
     * @param parameters countersigner parameters.
     * @param includeTimestamp Parameter that indicates if the signature will have a timestamp (true) or not (false).
     * @param signatureForm Parameter that represents the signature form.
     * The allowed values for CAdES signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCadesPades#FORMAT_CADES_BES}</li>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCadesPades#FORMAT_CADES_EPES}</li>
     * </ul>
     * @param signaturePolicyID Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @param includeContent Parameter that indicates whether the document content is included in the signature (true) or is only referenced (false).
     * @param idClient Parameter that represents the client application identifier.
     * @return a store with all instance of SignerInformation signed.
     * @throws SigningException If the method fails.
     */
    public SignerInformationStore counterSignLeaf(SignerInformationStore signerInfos, P7ContentSignerParameters parameters, boolean includeTimestamp, String signatureForm, String signaturePolicyID, boolean includeContent, String idClient) throws SigningException {
	List<SignerInformation> newSignerInfos = new ArrayList<SignerInformation>();
	LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG036, new Object[ ] { signerInfos.getSigners().size() }));
	// se busca el último firmante o contrafirmante para realizar la
	// contrafirma
	for (Iterator<?> iterator = signerInfos.getSigners().iterator(); iterator.hasNext();) {
	    SignerInformation signerInfoOld = (SignerInformation) iterator.next();
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG037, new Object[ ] { signerInfoOld.getSID().getIssuerAsString(), signerInfoOld.getSID().getSerialNumber() }));

	    // Accedemos al conjunto de atributos no firmados
	    AttributeTable unsignedAtts = signerInfoOld.getUnsignedAttributes();
	    ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();

	    // Si el firmante no posee atributos no firmados los inicializamos
	    if (unsignedAtts == null) {
		unsignedAtts = new AttributeTable(asn1EncodableVector);
	    } else {
		asn1EncodableVector = unsignedAtts.toASN1EncodableVector();
	    }
	    // Accedemos a los contra-firmantes que pudiera tener el firmante
	    SignerInformationStore counterSignsStore = signerInfoOld.getCounterSignatures();

	    // Si no posee contra-firmantes
	    if (counterSignsStore.getSigners().isEmpty()) {
		LOGGER.debug(Language.getResIntegra(ILogConstantKeys.CMSB_LOG038));

		// Incluimos el valor de la firma del signerInfo padre en los
		// parámetros de entrada.
		parameters.setContent(signerInfoOld.toASN1Structure().getEncryptedDigest().getOctets());

		// Creamos un objeto countersignature (de tipo signerInfo)
		SignerInfo counterSignature = generateSignerInfo(parameters, SignerInfoTypes.COUNTERSIGNATURE, includeTimestamp, signatureForm, signaturePolicyID, includeContent, idClient);

		// Añadimos el atributo no firmado counter-signature
		unsignedAtts = unsignedAtts.add(CMSAttributes.counterSignature, counterSignature);

		// creamos un nuevo signerInfo con los datos originales pero
		// incluyendo como atributo no firmado, el/los ojeto/s
		// countersignature/s.
		SignerInformation newSignerInfo = SignerInformation.replaceUnsignedAttributes(signerInfoOld, unsignedAtts);
		// newSignerInfo =
		// newSignerInfo(signerInfoOld.toASN1Structure(),
		// counterAttributes);
		newSignerInfos.add(newSignerInfo);
	    }
	    // Si posee contra-firmantes buscamos dentro la hoja a firmar
	    // (última firma/contrafirma)
	    else {
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.CMSB_LOG039, new Object[ ] { counterSignsStore.size() }));
		SignerInformationStore counterSignatures = counterSignLeaf(counterSignsStore, parameters, includeTimestamp, signatureForm, signaturePolicyID, includeContent, idClient);

		// creamos un nuevo signerInfo con los datos originales pero
		// incluyendo como atributo no firmado, el/los ojeto/s
		// countersignature/s.
		SignerInformation newSignerInfo = SignerInformation.addCounterSigners(signerInfoOld, counterSignatures);
		newSignerInfos.add(newSignerInfo);
	    }
	}
	return new SignerInformationStore(newSignerInfos);
    }

    /**
     * Method that signs the leaft of each signer (end node of each signerInfo).
     * @param signerInfos store with all SignerInfomation to sign.
     * @param parameters countersigner parameters.
     * @param includeTimestamp Parameter that indicates if the signature will have a timestamp (true) or not (false).
     * @param signatureForm Parameter that represents the signature form.
     * The allowed values for CAdES signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCadesPades#FORMAT_CADES_BES}</li>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetectorCadesPades#FORMAT_CADES_EPES}</li>
     * </ul>
     * @param signaturePolicyID Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @param includeContent Parameter that indicates whether the document content is included in the signature (true) or is only referenced (false).
     * @return a store with all instance of SignerInformation signed.
     * @throws SigningException If the method fails.
     */
    public SignerInformationStore counterSignLeaf(SignerInformationStore signerInfos, P7ContentSignerParameters parameters, boolean includeTimestamp, String signatureForm, String signaturePolicyID, boolean includeContent) throws SigningException {

	return counterSignLeaf(signerInfos, parameters, includeTimestamp, signatureForm, signaturePolicyID, includeContent, null);
    }
}
