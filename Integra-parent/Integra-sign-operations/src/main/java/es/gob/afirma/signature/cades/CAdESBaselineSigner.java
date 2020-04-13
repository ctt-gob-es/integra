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
 * <b>File:</b><p>es.gob.afirma.signature.cades.CAdESBaselineSigner.java.</p>
 * <b>Description:</b><p>Class that manages the generation, validation and upgrade of CAdES Baseline signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>18/01/2016.</p>
 * @author Gobierno de España.
 * @version 1.7, 13/04/2020.
 */
package es.gob.afirma.signature.cades;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.signature.ISignatureFormatDetector;
import es.gob.afirma.signature.OriginalSignedData;
import es.gob.afirma.signature.SignatureConstants;
import es.gob.afirma.signature.SignatureFormatDetectorCadesPades;
import es.gob.afirma.signature.Signer;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.signature.cades.CMSBuilder.SignerInfoTypes;
import es.gob.afirma.signature.policy.SignaturePolicyException;
import es.gob.afirma.signature.policy.SignaturePolicyManager;
import es.gob.afirma.signature.validation.ISignatureValidationTaskID;
import es.gob.afirma.signature.validation.ITimestampValidationTaskID;
import es.gob.afirma.signature.validation.SignerValidationResult;
import es.gob.afirma.signature.validation.TimeStampValidationInfo;
import es.gob.afirma.signature.validation.TimestampValidationResult;
import es.gob.afirma.signature.validation.ValidationInfo;
import es.gob.afirma.signature.validation.ValidationResult;
import es.gob.afirma.utils.CryptoUtilPdfBc;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.utils.UtilsResourcesSignOperations;
import es.gob.afirma.utils.UtilsSignatureOp;
import es.gob.afirma.utils.UtilsTimestampPdfBc;

/**
 * <p>Class that manages the generation, validation and upgrade of CAdES Baseline signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.7, 13/04/2020.
 */
public final class CAdESBaselineSigner implements Signer {

    /**
     *  Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(CAdESBaselineSigner.class);

    /**
     * Attribute that allows to create elements used in PKCS7/CMS.
     */
    private CMSBuilder cmsBuilder = new CMSBuilder();

    /**
     * Constructor method for the class CAdESBaselineSigner.java.
     */
    public CAdESBaselineSigner() {
	// Añadimos el proveedor criptográfico Bouncycastle en caso de que no
	// esté incluído
	if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
	    Security.addProvider(new BouncyCastleProvider());
	}
    }

    /**
     * Method that checks if the input algorithm is valid or not.
     * @param algorithm Algorithm parameter to verify.
     * @param isExplicitHash if the algorithm is not valid.
     */
    private void checkSignAlg(String algorithm, boolean isExplicitHash) {

	if (isExplicitHash) {
	    checkInputSignatureAlgorithmHash(algorithm);
	} else {
	    checkInputSignatureAlgorithm(algorithm);
	}
    }

    /**
     * Method that checks if the input signature algorithm is <code>null</code> and is allowed to use.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     */
    private void checkInputSignatureAlgorithm(String signatureAlgorithm) {
	// Comprobamos que el algoritmo de firma no es nulo
	GenericUtilsCommons.checkInputParameterIsNotNull(signatureAlgorithm, Language.getResIntegra(ILogConstantKeys.CBS_LOG003));

	// Comprobamos que el algoritmo de firma está soportado
	if (!SignatureConstants.SIGN_ALGORITHMS_SUPPORT_CADES.containsKey(signatureAlgorithm)) {
	    String msg = Language.getFormatResIntegra(ILogConstantKeys.CBS_LOG004, new Object[ ] { signatureAlgorithm });
	    LOGGER.error(msg);
	    throw new IllegalArgumentException(msg);
	}
    }

    /**
     * Method that checks if the input hash algorithm is valid or not.
     * @param algorithm Parameter that represents the signature algorithm.
     */
    private void checkInputSignatureAlgorithmHash(String algorithm) {
	// Comprobamos que el algoritmo de firma no es nulo
	GenericUtilsCommons.checkInputParameterIsNotNull(algorithm, Language.getResIntegra(ILogConstantKeys.CBS_LOG003));

	// Comprobamos que el algoritmo de firma está soportado
	if (!SignatureConstants.DIGEST_ALGORITHMS_SUPPORT_CADES.containsKey(algorithm)) {
	    String msg = Language.getFormatResIntegra(ILogConstantKeys.CBS_LOG004, new Object[ ] { algorithm });
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
	GenericUtilsCommons.checkInputParameterIsNotNull(signatureForm, Language.getResIntegra(ILogConstantKeys.CBS_LOG007));

	// Comprobamos que el formato de la firma a generar está
	// soportado.
	if (!signatureForm.equals(ISignatureFormatDetector.FORMAT_CADES_B_LEVEL)) {
	    String msg = Language.getFormatResIntegra(ILogConstantKeys.CBS_LOG008, new Object[ ] { signatureForm });
	    LOGGER.error(msg);
	    throw new IllegalArgumentException(msg);
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#sign(byte[], java.lang.String, java.lang.String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public byte[ ] sign(byte[ ] data, String algorithm, String signatureFormat, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID, String idClient) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.CBS_LOG001));
	boolean isExplicitHash = signatureFormat.equals(SignatureConstants.SIGN_MODE_EXPLICIT_HASH);
	try {
	    // Comprobamos que se ha indicado el algoritmo de firma y tiene un
	    // valor admitido
	    checkSignAlg(algorithm, isExplicitHash);

	    // Comprobamos que se han indicado los datos a firmar
	    GenericUtilsCommons.checkInputParameterIsNotNull(data, Language.getResIntegra(ILogConstantKeys.CBS_LOG005));

	    // Comprobamos que se ha indicado la clave privada
	    GenericUtilsCommons.checkInputParameterIsNotNull(privateKey, Language.getResIntegra(ILogConstantKeys.CBS_LOG006));

	    // Comprobamos que se ha indicado el formato de la firma a generar y
	    // es un formato admitido
	    checkInputSignatureForm(signatureForm);

	    // Si no se han indicado parámetros adicionales los inicializamos
	    Properties externalParams = extraParams;
	    if (externalParams == null) {
		externalParams = new Properties();
	    }

	    // Instanciamos los parámetros que recibirá el método encargado de
	    // generar la firma CAdES Baseline
	    P7ContentSignerParameters csp = null;
	    if (isExplicitHash) {
		csp = new P7ContentSignerParameters(null, SignatureConstants.DIGEST_ALGORITHMS_SUPPORT_CADES.get(algorithm), privateKey);
		csp.setDigestValue(data);
	    } else {
		csp = new P7ContentSignerParameters(data, algorithm, privateKey);
	    }

	    // Instanciamos el OID para el atributo content-type, que deberá
	    // tener el valor id-data
	    Oid dataType = new Oid(PKCSObjectIdentifiers.data.getId());

	    // Definimos el modo de firma en función del valor indicado como
	    // parámetro de entrada. Si no se ha indicado modo, se realizará una
	    // firma explícita
	    String mode = signatureFormat == null ? SignatureConstants.DEFAULT_SIGN_MODE : signatureFormat;
	    boolean includeContent = false;
	    if (mode.equals(SignatureConstants.SIGN_MODE_IMPLICIT)) {
		includeContent = true;
	    }

	    // Generamos la firma CAdES Baseline
	    byte[ ] result = cmsBuilder.generateSignedData(csp, includeContent, dataType, externalParams, includeTimestamp, signatureForm, signaturePolicyID, idClient);

	    // Informamos de que hemos generado la firma CAdES Baseline
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.CBS_LOG010));

	    // Escribimos la firma en el Log
	    GenericUtilsCommons.printResult(result, LOGGER);

	    // Devolvemos la firma generada
	    return result;
	} catch (GSSException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.CBS_LOG009);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.CBS_LOG002));
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
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#coSign(byte[], byte[], java.lang.String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public byte[ ] coSign(byte[ ] signature, byte[ ] document, String algorithm, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID, String idClient) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.CBS_LOG011));
	try {
	    // Comprobamos que se ha indicado el algoritmo de firma y tiene un
	    // valor admitido
	    checkInputSignatureAlgorithm(algorithm);

	    // Comprobamos que se ha indicado los datos originales a co-firmar
	    GenericUtilsCommons.checkInputParameterIsNotNull(document, Language.getResIntegra(ILogConstantKeys.CBS_LOG005));

	    // Comprobamos que se han indicado la firma a actualizar
	    GenericUtilsCommons.checkInputParameterIsNotNull(signature, Language.getResIntegra(ILogConstantKeys.CBS_LOG013));

	    // Comprobamos que se ha indicado la clave privada
	    GenericUtilsCommons.checkInputParameterIsNotNull(privateKey, Language.getResIntegra(ILogConstantKeys.CBS_LOG006));

	    // Comprobamos que se ha indicado el formato de la firma a generar y
	    // es un formato admitido
	    checkInputSignatureForm(signatureForm);

	    // Si no se han indicado parámetros adicionales los inicializamos
	    Properties externalParams = extraParams;
	    if (externalParams == null) {
		externalParams = new Properties();
	    }

	    // Obtenemos la firma original como objeto CMS
	    CMSSignedData signedData = UtilsSignatureOp.getCMSSignedData(signature);

	    // Determinamos si la firma es implícita o explícita
	    boolean includeContent = UtilsSignatureOp.isImplicit(signedData);

	    // Obtenemos un almacén con los certificados de la firma original
	    // junto con el nuevo certificado firmante
	    Store allCerts = UtilsSignatureOp.addCertificateToStore(signedData.getCertificates(), (X509Certificate) privateKey.getCertificate());

	    // Obtenemos los firmantes contenidos en la firma original
	    SignerInformationStore signerInformations = signedData.getSignerInfos();

	    // Obtenemos el resumen de la firma
	    SignerInformation signerInformation = (SignerInformation) signerInformations.getSigners().iterator().next();
	    ASN1Set attValues = signerInformation.getSignedAttributes().get(CMSAttributes.messageDigest).getAttrValues();
	    byte[ ] digestSignature = attValues.getObjects().hasMoreElements() ? ((DEROctetString) attValues.getObjects().nextElement()).getOctets() : new byte[0];

	    // Obtenemos el algoritmo de hash utilizado para calcular el resumen
	    // de la firma
	    String digestAlgName = CryptoUtilPdfBc.translateAlgorithmIdentifier(signerInformation.getDigestAlgorithmID());
	    if (digestAlgName == null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.CBS_LOG015, new Object[ ] { signerInformation.getDigestAlgorithmID().toString() });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Calculamos el resumen de los datos originales usando el mismo
	    // algoritmo de hash que la firma
	    // calculo del hash del documento original y comparación con el hash
	    // del
	    // firmante original.
	    byte[ ] digestDoc = CryptoUtilPdfBc.digest(digestAlgName, document);

	    // Comprobamos si el resumen contenido en la firma coincide con el
	    // resumen de los datos indicados como originales
	    if (!MessageDigest.isEqual(digestSignature, digestDoc)) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.CBS_LOG016);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Instanciamos los parámetros que recibirá el método encargado de
	    // generar la co-firma CAdES Baseline
	    P7ContentSignerParameters pkcs7Params = new P7ContentSignerParameters(document, algorithm, privateKey, externalParams);

	    // Creamos el nuevo firmante
	    SignerInfo newSignerInfo = cmsBuilder.generateSignerInfo(pkcs7Params, SignerInfoTypes.COSIGNATURE, includeTimestamp, signatureForm, signaturePolicyID, includeContent, idClient);

	    // Creación de un set que incluya todos los firmantes, incluyendo el
	    // nuevo
	    ASN1Set newSigners = cmsBuilder.convertToASN1Set(signerInformations);
	    newSigners = cmsBuilder.addElementToASN1Set(newSigners, newSignerInfo);

	    // Generamos la co-firma
	    byte[ ] result = cmsBuilder.generateSignedData(signedData, newSignerInfo.getDigestAlgorithm(), allCerts, newSigners);

	    // Informamos de que hemos generado la co-firma CAdES Baseline
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.CBS_LOG017));

	    // Escribimos la firma en el Log
	    GenericUtilsCommons.printResult(result, LOGGER);

	    // Devolvemos la firma generada
	    return result;

	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.CBS_LOG012));
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
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.CBS_LOG018));
	try {
	    // Comprobamos que se ha indicado el algoritmo de firma y tiene un
	    // valor admitido
	    checkInputSignatureAlgorithm(algorithm);

	    // Comprobamos que se han indicado la firma a actualizar
	    GenericUtilsCommons.checkInputParameterIsNotNull(signature, Language.getResIntegra(ILogConstantKeys.CBS_LOG013));

	    // Comprobamos que se ha indicado la clave privada
	    GenericUtilsCommons.checkInputParameterIsNotNull(privateKey, Language.getResIntegra(ILogConstantKeys.CBS_LOG006));

	    // Comprobamos que se ha indicado el formato de la firma a generar y
	    // es un formato admitido
	    checkInputSignatureForm(signatureForm);

	    // Si no se han indicado parámetros adicionales los inicializamos
	    Properties externalParams = extraParams;
	    if (externalParams == null) {
		externalParams = new Properties();
	    }

	    // Obtenemos la firma original como objeto CMS
	    CMSSignedData signedData = UtilsSignatureOp.getCMSSignedData(signature);

	    // Determinamos si la firma es implícita o explícita
	    boolean includeContent = UtilsSignatureOp.isImplicit(signedData);

	    // Obtenemos todos los firmantes de la firma CAdES
	    SignerInformationStore oldSignerInfos = signedData.getSignerInfos();

	    // Obtenemos un almacén con los certificados de la firma original
	    // junto con el nuevo certificado firmante
	    Store allCerts = UtilsSignatureOp.addCertificateToStore(signedData.getCertificates(), (X509Certificate) privateKey.getCertificate());

	    // Buscamos los últimos firmantes (incluyendo co-firmas y
	    // contra-firmas) para realizar la contra-firma
	    P7ContentSignerParameters params = new P7ContentSignerParameters(algorithm, privateKey, externalParams);
	    SignerInformationStore newSignerInfomations = cmsBuilder.counterSignLeaf(oldSignerInfos, params, includeTimestamp, signatureForm, signaturePolicyID, includeContent, idClient);

	    // Creamos un conjunto que incluya todos los firmantes
	    ASN1Set newSigners = cmsBuilder.convertToASN1Set(newSignerInfomations);

	    // Construimos la firma
	    String digestAlgorithm = SignatureConstants.SIGN_ALGORITHMS_SUPPORT_CADES.get(algorithm);
	    AlgorithmIdentifier digestAlgorithmId = cmsBuilder.makeDigestAlgorithmId(digestAlgorithm);
	    byte[ ] result = cmsBuilder.generateSignedData(signedData, digestAlgorithmId, allCerts, newSigners);

	    // Informamos de que hemos generado la contra-firma CAdES Baseline
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.CBS_LOG020));

	    // Escribimos la firma en el Log
	    GenericUtilsCommons.printResult(result, LOGGER);

	    // Devolvemos la firma generada
	    return result;

	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.CBS_LOG019));
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
    @SuppressWarnings("unchecked")
    @Override
    public byte[ ] upgrade(byte[ ] signature, List<X509Certificate> listCertificates, String idClient) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.CBS_LOG021));
	try {
	    // Comprobamos que se han indicado la firma a actualizar
	    GenericUtilsCommons.checkInputParameterIsNotNull(signature, Language.getResIntegra(ILogConstantKeys.CBS_LOG013));

	    // En caso de que la lista de firmantes sea vacía o nula se añadirá
	    // el sello de tiempo a todos los firmantes ya existentes en la
	    // firma
	    if (listCertificates == null || listCertificates.size() == 0) {
		LOGGER.debug(Language.getResIntegra(ILogConstantKeys.CBS_LOG014));
	    }

	    // Obtenemos la firma original como objeto CMS
	    CMSSignedData signedData = UtilsSignatureOp.getCMSSignedData(signature);

	    // Obtenemos la lista con todos los firmantes contenidos en la firma
	    SignerInformationStore signerInformationStore = signedData.getSignerInfos();
	    List<SignerInformation> listSignersSignature = (List<SignerInformation>) signerInformationStore.getSigners();

	    // Llevamos a cabo la actualización de los firmantes
	    List<SignerInformation> listNewSigners = cmsBuilder.upgradeSignersWithTimestamp(signedData, listCertificates, listSignersSignature, idClient);

	    // Actualizamos la firma con la nueva lista de firmantes, en caso de
	    // que los firmantes se hayan actualizado
	    byte[ ] upgradedSignature = signature;
	    if (!listSignersSignature.equals(listNewSigners)) {
		SignerInformationStore sis = new SignerInformationStore(listNewSigners);
		CMSSignedData newSignedData = CMSSignedData.replaceSigners(signedData, sis);
		// Obtenemos la firma actualizada
		upgradedSignature = newSignedData.getContentInfo().getDEREncoded();
	    }

	    // Escribimos la firma actualizada en el Log
	    GenericUtilsCommons.printResult(upgradedSignature, LOGGER);

	    // Devolvemos la firma actualizada
	    return upgradedSignature;
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.CBS_LOG022));
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#upgrade(byte[], java.util.List)
     */
    @Override
    public byte[ ] upgrade(byte[ ] signature, List<X509Certificate> listCertificates) throws SigningException {
	return upgrade(signature, listCertificates, null);
    }

    /**
     * Method that validates the signers of a CAdES signature.
     * @param eSignature Parameter that represents the signature to validate.
     * @param document Parameter that represents the original document signed by the signature.
     * @return an object that contains the information about the validation result.
     */
    public ValidationResult verifySignature(byte[ ] eSignature, byte[ ] document) {
	return verifySignature(eSignature, document, null);
    }

    /**
     * 
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#getSignedData(byte[])
     */
    @SuppressWarnings("unchecked")
    @Override
    public OriginalSignedData getSignedData(byte[ ] signature) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.CBS_LOG028));
	OriginalSignedData result = new OriginalSignedData();

	CMSSignedData cmsSignedData = null;
	byte[ ] signedData = null;

	// obtenemos la firma
	cmsSignedData = UtilsSignatureOp.getCMSSignedData(signature);

	// comprobamos si es implícita
	if (UtilsSignatureOp.isImplicit(cmsSignedData)) {
	    // si es implícita se obtiene el hash, que coincide con el contenido
	    // de los datos firmados
	    signedData = (byte[ ]) cmsSignedData.getSignedContent().getContent();

	    // se obtiene el mimetype del documento
	    result.setSignedData(signedData);
	    result.setMimetype(UtilsResourcesSignOperations.getMimeType(signedData));

	}
	// Explícita
	else {
	    // accedemos al signedContent para obtener los datos firmados
	    if (cmsSignedData.getSignedContent() != null) {
		signedData = (byte[ ]) cmsSignedData.getSignedContent().getContent();
	    } else {
		signedData = (byte[ ]) cmsSignedData.getContentInfo().getContent().getDERObject().getDEREncoded();
	    }
	    // Accedemos al primer firmante
	    SignerInformation signerInformation = ((List<SignerInformation>) cmsSignedData.getSignerInfos().getSigners()).iterator().next();
	    // del primer firmante obtenemos el algoritmo utilizado
	    // se obtiene el algoritmo resumen utilizado
	    AlgorithmIdentifier hashAlgorithmSignature = signerInformation.getDigestAlgorithmID();

	    result.setHashSignedData(signedData);
	    result.setMimetype(UtilsResourcesSignOperations.getMimeType(signedData));
	    result.setHashAlgorithm(CryptoUtilPdfBc.translateAlgorithmIdentifier(hashAlgorithmSignature));
	}
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.CBS_LOG029));
	return result;
    }

    /**
     * Method that validates a CAdES Baseline signature.
     * @param eSignature Parameter that represents the signature to validate.
     * @param document Parameter that represents the original data. This parameter is required if the signature is explicit.
     * @param idClient Parameter that represents the client application identifier.
     * @return an object that contains information about the validation of the signature, including all the signers and counter-signers contained inside it.
     */
    public ValidationResult verifySignature(byte[ ] eSignature, byte[ ] document, String idClient) {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.CBS_LOG023));

	// Instanciamos el objeto a devolver
	ValidationResult validationResult = new ValidationResult();

	// Por defecto indicamos que la validación de la firma ha sido correcta
	validationResult.setCorrect(true);

	try {
	    // Comprobamos que se ha indicado la firma a validar
	    GenericUtilsCommons.checkInputParameterIsNotNull(eSignature, Language.getResIntegra(ILogConstantKeys.CBS_LOG013));

	    // Definimos un objeto donde ubicar la lista de firmantes y
	    // contra-firmantes contenidos en la firma
	    List<CAdESSignerInfo> listSigners = new ArrayList<CAdESSignerInfo>();

	    /*
	     * Validación de la Integridad: Se comprobará que la firma posee al menos un firmante y que, si la firma es explicita, se hayan indicado los datos originales.
	     */
	    CMSSignedData signedData = checkSignatureIntegrity(eSignature, document, validationResult, listSigners);

	    // Instanciamos una lista donde ubicar la información de validación
	    // de cada firmante y la asociamos al resultado final
	    List<SignerValidationResult> listSignersValidationResults = new ArrayList<SignerValidationResult>();
	    validationResult.setListSignersValidationResults(listSignersValidationResults);

	    // inicializamos la fecha que determinará la caducidad de la firma.
	    Date currentDate = null;

	    // Recorremos la lista de firmantes
	    for (CAdESSignerInfo signerInfo: listSigners) {
		// Primero, determinamos el formato del firmante
		String signerFormat = SignatureFormatDetectorCadesPades.resolveSignerCAdESFormat(signedData, signerInfo.getSignerInformation());

		// Si el firmante tiene formato Baseline, nos mantenemos en este
		// clase. En otro caso, derivamos la validación del firmante a
		// la clase asociada a firmas no Baseline
		SignerValidationResult signerValidationResult = null;
		if (!signerIsBaseline(signerFormat)) {
		    CadesSigner cadesSigner = new CadesSigner();

		    // Obtenemos la información de validación asociada al
		    // firmante de tipo No Baseline
		    signerValidationResult = cadesSigner.validateSigner(signedData, signerInfo, validationResult, idClient, false, signerFormat);
		} else {
		    // Obtenemos la información de validación asociada al
		    // firmante de tipo Baseline
		    signerValidationResult = validateSigner(signedData, signerInfo, validationResult, idClient, false, signerFormat);
		}

		// Añadimos los datos de validación del firmante a la lista
		// asociada.
		listSignersValidationResults.add(signerValidationResult);

		// Validamos los contra-firmantes asociados al firmante
		validateCounterSigners(signerInfo, signerValidationResult, signedData, validationResult, idClient);

		// Recuperamos la fecha de expiración de los archiveTimestamp.
		X509Certificate archiveTstClosestCert = UtilsSignatureOp.obtainCertificateArchiveTimestamps(signerInfo.getSignerInformation().getUnsignedAttributes());
		signerValidationResult.setLastArchiveTst(archiveTstClosestCert);

		// Obtenemos la fecha de caducidad de la firma.
		currentDate = UtilsSignatureOp.calculateExpirationDateForValidations(signerValidationResult, currentDate);
	    }
	    
	    validationResult.setExpirationDate(currentDate);
	                                       
	    // Indicamos en el log que la firma es correcta
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.CBS_LOG031));
	} catch (SigningException e) {
	    // Establecemos en la información asociada a la validación de la
	    // firma que ésta no es correcta
	    validationResult.setCorrect(false);

	    // Indicamos en el log que la firma no es correcta
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.CBS_LOG030));
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.CBS_LOG024));
	}
	// Devolvemos el objeto con la información de validación
	return validationResult;
    }

    /**
     * Method that checks:
     * <ul>
     * <li>If the signature is explicit, the original data was passed as parameter.</li>
     * <li>The signature contains at least one signer.</li>
     * </ul>
     * @param eSignature Parameter that reprsents the signature.
     * @param originalData Parameter that represents the original data.
     * @param validationResult Parameter that contains the information related to the validation of the signature.
     * @param listSigners Parameter that represents the list to update with the signers and counter-signers contained inside of the signature.
     * @return an object that represents the signature message.
     * @throws SigningException If the validation fails.
     */
    private CMSSignedData checkSignatureIntegrity(byte[ ] eSignature, byte[ ] originalData, ValidationResult validationResult, List<CAdESSignerInfo> listSigners) throws SigningException {
	// Establecemos, por defecto, que la firma es estructuralmente correcta
	validationResult.setIntegrallyCorrect(true);

	try {
	    // Inicializamos el elemento SignedData
	    CMSSignedData signedData = null;

	    // Si se han indicado los datos originales
	    if (originalData != null) {
		signedData = new CMSSignedData(new CMSProcessableByteArray(originalData), eSignature);
	    }
	    // Si no se han indicado los datos originales
	    else {
		signedData = new CMSSignedData(eSignature);
		// Si la firma es explícita y no se han indicado los datos
		// originales no podemos continuar
		if (!UtilsSignatureOp.isImplicit(signedData)) {
		    String errorMsg = Language.getResIntegra(ILogConstantKeys.CBS_LOG025);
		    LOGGER.error(errorMsg);
		    validationResult.setIntegrallyCorrect(false);
		    validationResult.setErrorMsg(errorMsg);
		    throw new SigningException(errorMsg);
		}
	    }

	    // Obtenemos la lista de firmantes y contra-firmantes contenidos en
	    // la firma
	    List<CAdESSignerInfo> listSignersFound = UtilsSignatureOp.getCAdESListSigners(signedData);

	    // Comprobamos que exista al menos un firmante
	    if (listSignersFound.isEmpty()) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.CBS_LOG026);
		LOGGER.error(errorMsg);
		validationResult.setIntegrallyCorrect(false);
		validationResult.setErrorMsg(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    listSigners.addAll(listSignersFound);

	    return signedData;
	} catch (CMSException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.CBS_LOG027);
	    LOGGER.error(errorMsg, e);
	    validationResult.setIntegrallyCorrect(false);
	    validationResult.setErrorMsg(errorMsg);
	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates a signer/counter-signer of a signature.
     * @param signedData Parameter that represents the signature message.
     * @param signerInfo Parameter that represents the information about the signer.
     * @param validationResult Parameter that represents the information about the validation of the signature.
     * @param idClient Parameter that represents the client application identifier.
     * @param isCounterSignature Parameter that indicates if the element to validate is a signer (false) or a counter-signer (true).
     * @param signerFormat Parameter that represents the format associated to the signer/counter-signer.
     * @return an object that represents the validation information about the signer/counter-signer.
     */
    public SignerValidationResult validateSigner(CMSSignedData signedData, CAdESSignerInfo signerInfo, ValidationResult validationResult, String idClient, boolean isCounterSignature, String signerFormat) {
	// Instanciamos el objeto que representa la información de
	// validación del firmante y lo añadimos a la lista asociada
	SignerValidationResult signerValidationResult = new SignerValidationResult();

	// Por defecto indicamos que la validación del firmante ha sido correcta
	signerValidationResult.setCorrect(true);

	// Instanciamos una lista donde ubicar la información asociada
	// de las validaciones aplicadas sobre el firmante
	signerValidationResult.setListValidations(new ArrayList<ValidationInfo>());

	// Añadimos en la información de validación del firmante su formato
	signerValidationResult.setFormat(signerFormat);

	try {
	    // Añadimos a la información de validación del firmante los
	    // datos de su
	    // certificado
	    addSigningCertificateInfo(signerValidationResult, signerInfo, validationResult);

	    // Obtenemos la fecha de validación que será la fecha de
	    // generación del primer sello de tiempo contenido en un
	    // atributo signature-time-stamp. En caso de no
	    // haber ninguno se tomará la fecha actual
	    Date validationDate = getValidationDate(signerInfo);

	    /*
	     * Validación del Núcleo de Firma: Se comprobará que el firmante verifica la firma.
	     */
	    validateSignatureCore(signerValidationResult, signerInfo, validationResult);

	    /*
	     * Validación de la Información de Clave Pública: Se comprobará que el firmante incluye el atributo firmado signing-certificate o el atributo
	     * firmado signing-certificate-v2, y que dicho atributo identifica al certificado del firmante. Además, en el caso de que el atributo que incluya
	     * de los dos sea signing-certificate se comprobará que el algoritmo de firma utilizado ha sido SHA-1.
	     */
	    validateKeyInfo(signerValidationResult, signerInfo, validationResult, signedData);

	    /*
	     * Validación del Instante de Firma: Si el firmante incluye el atributo firmado signing-time se comprobará que dicho atributo está bien
	     * formado y que la fecha contenida en el mismo es anterior a la fecha de validación.
	     */
	    validateSigningTime(signerValidationResult, signerInfo, validationResult, signedData, validationDate);

	    /*
	     * Validación de la Política de Firma: Si el firmante incluye el atributo firmado signature-policy-identifier se comprobará si el OID
	     * de la política de firma definida en dicho atributo coincide con el OID de la política de firma definida para firmas ASN.1 en el
	     * fichero policy.properties, en cuyo caso, se comprobará que los datos de la firma y del firmante concreto son válidos respecto a las propiedades
	     * definidas en dicho fichero.
	     */
	    validateSignaturePolicy(signerValidationResult, signerInfo, validationResult, signedData, isCounterSignature, idClient);

	    /*
	     * Validación del Certificado Firmante: Se comprobará el estado del certificado firmante en base a la fecha de validación respecto del método de
	     * validación definido para el mismo, ya sea en el fichero integraFacade.properties (si la validación se realiza desde la fachada de firma), o
	     * bien en el fichero signer.properties (si la validación se realiza desde la interfaz Signer).
	     */
	    validateSigningCertificate(signerValidationResult, signerInfo, validationResult, idClient, validationDate);

	    /*
	     * Validación de los Atributos signature-time-stamp: Si el firmante posee atributos signature-time-stamp se comprobará que todos ellos poseen una
	     * estructura correcta y que los sellos de tiempo que contienen están bien formados. Respecto a cada sello de tiempo se definen las siguientes tareas de validación:
	     * 		> Validación de la Firma del Sello de Tiempo: Se comprobará que la firma del sello de tiempo es correcta.
	     * 		> Validación de la Integridad del Sello de Tiempo: Se comprobará que los datos sellados son correctos.
	     * 		> Validación del Certificado Firmante del Sello de Tiempo: Se comprobará el estado del certificado firmante del sello de tiempo respecto a la fecha de
	     * 		generación del siguiente sello de tiempo, utilizando el método de validación definido para los certificados firmantes, ya sea en el fichero
	     * 		integraFacade.properties (si la validación se realiza desde la fachada de firma), o bien en el fichero signer.properties (si la validación
	     * 		se realiza desde la interfaz Signer). Cuando se esté procesando el certificado firmante del sello de tiempo más reciente (y por lo tanto el último)
	     * 		se utilizará como fecha de validación la fecha actual. Además, se verificará que el certificado posee la extensión id-kp-timestamp.
	     */
	    validateSignatureTimeStampAttributes(signerValidationResult, signerInfo, validationResult, idClient);
	} catch (Exception e) {
	    // Establecemos en la información asociada a la validación
	    // del firmante que éste no es correcto
	    signerValidationResult.setCorrect(false);

	    // Establecemos en la información asociada a la validación
	    // de la firma que ésta no es correcta
	    validationResult.setCorrect(false);
	}
	return signerValidationResult;
    }

    /**
     * Method that includes into the object with the information about the validation of a signer/counter-signer the information about the signing certificate.
     * @param signerValidationResult Parameter that represents the information about the validation of the signer/counter-signer to update.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @param validationResult Parameter that represents the information about the validation of the signature.
     * @throws SigningException If the signing certificate cannot be retrieved.
     */
    private void addSigningCertificateInfo(SignerValidationResult signerValidationResult, CAdESSignerInfo signerInfo, ValidationResult validationResult) throws SigningException {
	// Añadimos a la información de validación del firmante su certificado
	signerValidationResult.setSigningCertificate(signerInfo.getSigningCertificate());

	// Verificamos que no se haya producido ningún error durante el proceso
	// de obtener el certificado del firmante
	if (signerInfo.getErrorMsg() != null) {
	    // Establecemos, a nivel general, el error asociado a la validación
	    // de la
	    // firma CAdES como el error producido, si es que no se indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(signerInfo.getErrorMsg());
	    }

	    // Establecemos, a nivel de firmante, el error asociado a la
	    // validación como el error producido
	    signerValidationResult.setErrorMsg(signerInfo.getErrorMsg());

	    throw new SigningException(signerInfo.getErrorMsg());
	}
    }

    /**
     * Method that obtains the date to use for validating the information about a signer/counter-signer. This date will be the generation time of the first time-stamp contained inside
     * of a <code>signature-time-stamp</code> attribute. If the signer/counter-signer doesn't contain any <code>signature-time-stamp</code> attribute, the date will be the current date.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @return the validation date.
     */
    private Date getValidationDate(CAdESSignerInfo signerInfo) {
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
	return validationDate;
    }

    /**
     * Method that checks if a signer/counter-signer verifies the signature.
     * @param signerValidationResult Parameter that represents the information about the validation of the signer/counter-signer to update with the result of the validation.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @param validationResult Parameter that represents the information about the validation of the signature.
     * @throws SigningException If the validation fails.
     */
    private void validateSignatureCore(SignerValidationResult signerValidationResult, CAdESSignerInfo signerInfo, ValidationResult validationResult) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	ValidationInfo validationInfo = new ValidationInfo();
	validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_SIGNATURE_CORE_VALIDATION);

	// Añadimos a la lista de validaciones del firmante/contra-firmante la
	// información asociada a esta validación
	signerValidationResult.getListValidations().add(validationInfo);
	try {
	    // Comprobamos que el firmante verifica la firma
	    UtilsSignatureOp.validateCAdESSignatureCore(signerInfo.getSignerInformation(), signerInfo.getSigningCertificate(), false);

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

	    // Establecemos, a nivel de firmante, el error asociado a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (signerValidationResult.getErrorMsg() == null) {
		signerValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that checks if the signer includes a SigningCertificate signed attribute, or a SigningCertificateV2 signed attribute, and this matches to the signing certificate.
     * @param signerValidationResult Parameter that represents the information about the validation of the signer/counter-signer to update with the result of the validation.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @param validationResult Parameter that represents the information about the validation of the signature.
     * @param signedData Parameter that represents the signature message.
     * @throws SigningException If the validation fails.
     */
    private void validateKeyInfo(SignerValidationResult signerValidationResult, CAdESSignerInfo signerInfo, ValidationResult validationResult, CMSSignedData signedData) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	ValidationInfo validationInfo = new ValidationInfo();
	validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_PUBLIC_KEY_INFO_VALIDATION);

	// Añadimos a la lista de validaciones del firmante/contra-firmante la
	// información asociada a esta validación
	signerValidationResult.getListValidations().add(validationInfo);
	try {
	    // Comprobamos que la información de clave pública del firmante es
	    // correcta
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

	    // Establecemos, a nivel de firmante, el error asociado a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (signerValidationResult.getErrorMsg() == null) {
		signerValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates if the signing time of a signature is previous than certain date.
     * @param signerValidationResult Parameter that represents the information about the validation of the signer/counter-signer to update with the result of the validation.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @param validationResult Parameter that represents the information about the validation of the signature.
     * @param signedData Parameter that represents the signature message.
     * @param validationDate Parameter that represents the validation date.
     * @throws SigningException If the validation fails.
     */
    private void validateSigningTime(SignerValidationResult signerValidationResult, CAdESSignerInfo signerInfo, ValidationResult validationResult, CMSSignedData signedData, Date validationDate) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	ValidationInfo validationInfo = new ValidationInfo();
	validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_SIGNING_TIME_VALIDATION);

	// Añadimos a la lista de validaciones del firmante/contra-firmante la
	// información asociada a esta validación
	signerValidationResult.getListValidations().add(validationInfo);

	// Por defecto suponemos que el atributo signing-time no es obligatorio
	// en la firma, salvo que ésta tenga formato Baseline
	boolean signingTimeIsRequired = false;
	String signatureFormat = signerValidationResult.getFormat();
	if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_B_LEVEL) || signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_T_LEVEL) || signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_LT_LEVEL) || signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_LTA_LEVEL)) {
	    signingTimeIsRequired = true;
	}
	try {
	    // Comprobamos que el atributo signing-time es correcto
	    UtilsSignatureOp.validateCAdESSigningTime(signedData, signerInfo.getSignerInformation(), signingTimeIsRequired, validationDate, signerInfo.getSigningCertificate());

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

	    // Establecemos, a nivel de firmante, el error asociado a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (signerValidationResult.getErrorMsg() == null) {
		signerValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates a CAdES signature by the signature policy defined on the properties file where to configure the validation and generation of signatures
     * with signature policies.
     * @param signerValidationResult Parameter that represents the information about the validation of the signer/counter-signer to update with the result of the validation.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @param validationResult Parameter that represents the information about the validation of the signature.
     * @param signedData Parameter that represents the signature message.
     * @param isCounterSigner Parameter that indicates if the element to ptocess is a counter-signer (true) or a signer (false).
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the validation fails.
     */
    private void validateSignaturePolicy(SignerValidationResult signerValidationResult, CAdESSignerInfo signerInfo, ValidationResult validationResult, CMSSignedData signedData, boolean isCounterSigner, String idClient) throws SigningException {
	// Comprobamos si el firmante incluye política de firma
	if (SignatureFormatDetectorCadesPades.hasSignaturePolicyIdentifier(signerInfo.getSignerInformation())) {
	    // Instanciamos el objeto que ofrece información sobre la validación
	    // llevada a cabo
	    ValidationInfo validationInfo = new ValidationInfo();
	    validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_SIGNATURE_POLICY_VALIDATION);

	    // Añadimos a la lista de validaciones del firmante/contra-firmante
	    // la
	    // información asociada a esta validación
	    signerValidationResult.getListValidations().add(validationInfo);

	    try {
		// Validamos la política de firma asociada al firmante
		SignaturePolicyManager.validateCAdESEPESSignature(signerInfo.getSignerInformation(), null, isCounterSigner, UtilsSignatureOp.isImplicit(signedData), idClient);
		// Indicamos que la validación ha sido correcta
		validationInfo.setSucess(true);
	    } catch (SignaturePolicyException e) {
		// Establecemos, a nivel general, el error asociado a la
		// validación
		// de la
		// firma CAdES como el error producido, si es que no se indicó
		// previamente
		if (validationResult.getErrorMsg() == null) {
		    validationResult.setErrorMsg(e.getMessage());
		}

		// Establecemos, a nivel de firmante, el error asociado a la
		// validación como el error producido, si es que no se indicó
		// previamente
		if (signerValidationResult.getErrorMsg() == null) {
		    signerValidationResult.setErrorMsg(e.getMessage());
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
     * Method that validates the signing certificate of a signer/counter-signer.
     * @param signerValidationResult Parameter that represents the information about the validation of the signer/counter-signer to update with the result of the validation.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @param validationResult Parameter that represents the information about the validation of the signature.
     * @param idClient Parameter that represents the client application identifier.
     * @param validationDate Parameter that represents the validation date.
     * @throws SigningException If the validation fails.
     */
    private void validateSigningCertificate(SignerValidationResult signerValidationResult, CAdESSignerInfo signerInfo, ValidationResult validationResult, String idClient, Date validationDate) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	ValidationInfo validationInfo = new ValidationInfo();
	validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_SIGNING_CERTIFICATE_VALIDATION);

	// Añadimos a la lista de validaciones del firmante/contra-firmante la
	// información asociada a esta validación
	signerValidationResult.getListValidations().add(validationInfo);
	try {
	    // Validamos el certificado del firmante
	    UtilsSignatureOp.validateCertificate(signerInfo.getSigningCertificate(), validationDate, false, idClient, false);

	    // Indicamos que la validación ha sido correcta
	    validationInfo.setSucess(true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la
	    // validación
	    // de la
	    // firma CAdES como el error producido, si es que no se indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel de firmante, el error asociado a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (signerValidationResult.getErrorMsg() == null) {
		signerValidationResult.setErrorMsg(e.getMessage());
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
     * Method that validates the <code>signature-time-stamp</code> attributes associated to certain signer/counter-signer.
     * @param signerValidationResult Parameter that represents the information about the validation of the signer/counter-signer to update with the result of the validation.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @param validationResult Parameter that represents the information about the validation of the signature.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the validation fails.
     */
    private void validateSignatureTimeStampAttributes(SignerValidationResult signerValidationResult, CAdESSignerInfo signerInfo, ValidationResult validationResult, String idClient) throws SigningException {
	// Si el firmante posee algún atributo signature-time-stamp
	if (signerInfo.getListTimeStamps() != null && !signerInfo.getListTimeStamps().isEmpty()) {
	    // Instanciamos el objeto que ofrece información sobre la
	    // validación
	    // llevada a cabo
	    ValidationInfo validationInfo = new ValidationInfo();
	    validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_SIGNATURE_TIME_STAMP_ATTRIBUTES_VALIDATION);

	    // Por defecto establecemos que la validación ha sido correcta
	    validationInfo.setSucess(true);

	    // Añadimos a la lista de validaciones del
	    // firmante/contra-firmante la
	    // información asociada a esta validación
	    signerValidationResult.getListValidations().add(validationInfo);

	    // Añadmos a la información de validación del
	    // firmante/contra-firmante una lista donde ubicar la
	    // información de validación de cada sello de tiempo asociado
	    signerValidationResult.setListTimestampsValidations(new ArrayList<TimestampValidationResult>());

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
		    // de validación del firmante
		    TimestampValidationResult timestampValidationResult = new TimestampValidationResult();
		    signerValidationResult.getListTimestampsValidations().add(timestampValidationResult);

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
		    validateTimeStamp(currentTimestamp, timestampValidationResult, signerValidationResult, signerInfo, validationResult, idClient, validationDate, validationInfo);
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

		// Establecemos, a nivel de firmante, el error asociado a la
		// validación como el error producido, si es que no se
		// indicó
		// previamente
		if (signerValidationResult.getErrorMsg() == null) {
		    signerValidationResult.setErrorMsg(e.getMessage());
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
     * Method that validates a time-stamp and updates the information about the result of the validation.
     * @param tst Parameter that represents the time-stamp to validate.
     * @param timestampValidationResult Parameter that represents the information to update with the result of the validation of the time-stamp.
     * @param signerValidationResult Parameter that represents the information about the validation of the signer/counter-signer to update with the result of the validation.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @param validationResult Parameter that represents the information about the validation of the signature.
     * @param idClient Parameter that represents the client application identifier.
     * @param validationDate Parameter that represents the validation date.
     * @param validationInfo Parameter that represents the information about the result of the valdation of the <code>signature-time-stamp</code> attributes associated
     * to the current signer/counter-signer.
     * @throws SigningException If the validation fails.
     */
    private void validateTimeStamp(TimeStampToken tst, TimestampValidationResult timestampValidationResult, SignerValidationResult signerValidationResult, CAdESSignerInfo signerInfo, ValidationResult validationResult, String idClient, Date validationDate, ValidationInfo validationInfo) throws SigningException {
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
	    // validación
	    // de la
	    // firma CAdES como el error producido, si es que no
	    // se indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel de firmante, el error
	    // asociado a la
	    // validación como el error producido, si es que no
	    // se indicó
	    // previamente
	    if (signerValidationResult.getErrorMsg() == null) {
		signerValidationResult.setErrorMsg(e.getMessage());
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
     * Method that validates the signature of a time-stamp contained inside of a <code>signature-time-stamp</code> attribute associated to a signer/counter-signer.
     * @param timestampValidationResult Parameter that represents the information about the validation of the time-stamp to update with the result of the validation.
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
     * @param timestampValidationResult Parameter that represents the information about the validation of the time-stamp to update with the result of the validation.
     * @param tst Parameter that represents the time-stamp to validate.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
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
     * Method that validates the signing certificate of a time-stamp contained inside a <code>signature-time-stamp</code> attribute associated to a signer/counter-signer.
     * @param timestampValidationResult Parameter that represents the information about the validation of the time-stamp to update with the result of the validation.
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
     * Method that validates all the counter-signers associated to a signer.
     * @param signerInfo Parameter that represents the information about the parent signer.
     * @param signerValidationResult Parameter that represents the information about the validation of the parent signer.
     * @param signedData Parameter that represents the signature message.
     * @param validationResult Parameter that represents the information about the validation of the signature.
     * @param idClient Parameter that represents the client application identifier.
     */
    public void validateCounterSigners(CAdESSignerInfo signerInfo, SignerValidationResult signerValidationResult, CMSSignedData signedData, ValidationResult validationResult, String idClient) {
	// Accedemos a la lista de contra-firmantes, en caso de haber
	List<CAdESSignerInfo> listCounterSignerInfo = signerInfo.getListCounterSigners();
	if (listCounterSignerInfo != null && !listCounterSignerInfo.isEmpty()) {
	    // Si el firmante posee contra-firmantes instanciamos una lista
	    // donde ubicar la información de validación
	    // de cada contra-firmante y la asociamos al resultado final de
	    // validar el firmante padre
	    List<SignerValidationResult> listCounterSignersValidationResults = new ArrayList<SignerValidationResult>();
	    signerValidationResult.setListCounterSignersValidationsResults(listCounterSignersValidationResults);

	    // Recorremos la lista de contra-firmantes
	    for (CAdESSignerInfo counterSignerInfo: listCounterSignerInfo) {
		// Primero, determinamos el formato del firmante
		String signerFormat = SignatureFormatDetectorCadesPades.resolveSignerCAdESFormat(signedData, counterSignerInfo.getSignerInformation());

		// Si el firmante tiene formato Baseline, nos mantenemos en este
		// clase. En otro caso, derivamos la validación del firmante a
		// la clase asociada a firmas no Baseline
		SignerValidationResult counterSignerValidationResult = null;
		if (!signerIsBaseline(signerFormat)) {
		    CadesSigner cadesSigner = new CadesSigner();

		    // Obtenemos la información de validación asociada al
		    // contra-firmante
		    counterSignerValidationResult = cadesSigner.validateSigner(signedData, counterSignerInfo, validationResult, idClient, true, signerFormat);
		} else {
		    // Obtenemos la información de validación asociada al
		    // contra-firmante
		    counterSignerValidationResult = validateSigner(signedData, counterSignerInfo, validationResult, idClient, true, signerFormat);
		}

		// Añadimos a la lista donde ubicar la información de validación
		// de cada contra-firmante la información asociada a la
		// validación del contra-firmante actual
		listCounterSignersValidationResults.add(counterSignerValidationResult);

		// Validamos los contra-firmantes asociados al contra-firmante
		validateCounterSigners(counterSignerInfo, counterSignerValidationResult, signedData, validationResult, idClient);
	    }

	}
    }

    /**
     * Method that indicates if a signer has Baseline form.
     * @param signerFormat Parameter that represents the format associated to the signer.
     * @return a boolean that indicates if a signer has Baseline form.
     */
    private boolean signerIsBaseline(String signerFormat) {
	return signerFormat.equals(ISignatureFormatDetector.FORMAT_CADES_B_LEVEL) || signerFormat.equals(ISignatureFormatDetector.FORMAT_CADES_T_LEVEL) || signerFormat.equals(ISignatureFormatDetector.FORMAT_CADES_LT_LEVEL) || signerFormat.equals(ISignatureFormatDetector.FORMAT_CADES_LTA_LEVEL);
    }
}
