// Copyright (C) 2012-13 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.utils.UtilsTimestampPdfBc.java.</p>
 * <b>Description:</b><p>Class that contains methods related to the manage of timestamps.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>05/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 05/11/2014.
 */
package es.gob.afirma.utils;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampToken;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.signature.SigningException;

/**
 * <p>Class that contains methods related to the manage of timestamps.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 05/11/2014.
 */
public final class UtilsTimestampPdfBc {

	/**
	 * Attribute that represents the object that manages the log of the class.
	 */
	public static final Logger LOGGER = IntegraLogger.getInstance().getLogger(UtilsTimestampPdfBc.class);

	/**
	 * Constructor method for the class TimestampUtils.java.
	 */
	private UtilsTimestampPdfBc() {
	}

	/**
	 * Method that obtain the the signing certificate of a timestamp.
	 * @param tst Parameter that represents the timestamp.
	 * @return an object that represents the certificate.
	 * @throws SigningException If the method fails.
	 */
	@SuppressWarnings("unchecked")
	public static X509Certificate getSigningCertificate(TimeStampToken tst) throws SigningException {
		LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG020));
		try {
			// Comprobamos que el sello de tiempo no sea nulo
			GenericUtilsCommons.checkInputParameterIsNotNull(tst, Language.getResIntegra(ILogConstantKeys.TSU_LOG014));
			// Obtenemos al colección de certificados definidos en el almacén de
			// certificados dentro del sello de tiempo
			CertStore certStore = null;

			try {
				certStore = tst.getCertificatesAndCRLs("Collection", BouncyCastleProvider.PROVIDER_NAME);
				Collection<X509Certificate> collectionSigningCertificate = (Collection<X509Certificate>) certStore.getCertificates(tst.getSID());

				if (collectionSigningCertificate.size() != 1) {
					String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG015);
					LOGGER.error(errorMsg);
					throw new SigningException(errorMsg);
				}
				return collectionSigningCertificate.iterator().next();
			} catch (NoSuchAlgorithmException e) {
				String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG016);
				LOGGER.error(errorMsg);
				throw new SigningException(errorMsg, e);

			} catch (NoSuchProviderException e) {
				String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG017);
				LOGGER.error(errorMsg);
				throw new SigningException(errorMsg, e);
			} catch (CMSException e) {
				String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG018);
				LOGGER.error(errorMsg);
				throw new SigningException(errorMsg, e);
			} catch (CertStoreException e) {
				String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG019);
				LOGGER.error(errorMsg);
				throw new SigningException(errorMsg, e);
			}
		} finally {
			LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG039));
		}
	}

	/**
	 * Method that validates an ASN.1 timestamp.
	 * @param tst Parameter that represents the ASN.1 timestamp to validate.
	 * @throws SigningException If the method fails or the timestamp isn't valid.
	 */
	public static void validateASN1Timestamp(TimeStampToken tst) throws SigningException {
		LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG042));
		try {
			// Comprobamos que el sello de tiempo no es nulo
			GenericUtilsCommons.checkInputParameterIsNotNull(tst, Language.getResIntegra(ILogConstantKeys.TSU_LOG014));

			// Obtenemos el certificado firmante del sello de tiempo
			X509Certificate signingCertificate = getSigningCertificate(tst);

			// Validamos la firma del sello de tiempo
			LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG021));
			try {
				JcaContentVerifierProviderBuilder jcaContentVerifierProviderBuilder = new JcaContentVerifierProviderBuilder();
				jcaContentVerifierProviderBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);

				ContentVerifierProvider contentVerifierProvider = jcaContentVerifierProviderBuilder.build(signingCertificate);

				JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
				digestCalculatorProviderBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
				DigestCalculatorProvider digestCalculatorProvider = digestCalculatorProviderBuilder.build();

				SignerInformationVerifier signerInformationVerifier = new SignerInformationVerifier(contentVerifierProvider, digestCalculatorProvider);

				tst.validate(signerInformationVerifier);

			} catch (TSPValidationException e) {
				String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG022);
				LOGGER.error(errorMsg);
				throw new SigningException(errorMsg, e);
			} catch (Exception e) {
				String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG023);
				LOGGER.error(errorMsg, e);
				throw new SigningException(errorMsg, e);
			}
		} finally {
			LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG043));
		}
	}

	/**
	 * Method that obtains the timestamp from the information about a signer of a signature, if it contains a timestamp.
	 * @param signerInformation Parameter that represents the information of the signer.
	 * @return an object that represents the timestamp, or <code>null</code>.
	 * @throws SigningException If the timestamp is malformed.
	 */
	public static TimeStampToken getTimeStampToken(SignerInformation signerInformation) throws SigningException {
		LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG044));
		try {
			// Comprobamos que la información del firmante no es nula
			GenericUtilsCommons.checkInputParameterIsNotNull(signerInformation, Language.getResIntegra(ILogConstantKeys.TSU_LOG025));

			// Obtenemos el conjunto de atributos no firmados
			AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();

			// Comprobamos si está contenido el sello de tiempo
			if (unsignedAttributes != null && unsignedAttributes.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) != null) {
				Attribute attributeTimeStampToken = unsignedAttributes.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
				try {
					return new TimeStampToken(new CMSSignedData(attributeTimeStampToken.getAttrValues().getObjectAt(0).getDERObject().getDEREncoded()));
				} catch (Exception e) {
					String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG026);
					LOGGER.error(errorMsg);
					throw new SigningException(errorMsg, e);
				}
			}
			return null;
		} finally {
			LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG045));
		}
	}

	/**
	 * Method that obtains the first time-stamp contained inside of a list of unsigned attributes.
	 * @param unsignedAttributes Parameter that represents the list of unsigned attribute of an ASN.1 signature.
	 * @return an object that represents the time-stamp.
	 * @throws SigningException If one of the attributes contains a badly formed time-stamp.
	 */
	public static TimeStampToken getFirstTimeStampToken(ASN1EncodableVector unsignedAttributes) throws SigningException {
		LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG084));
		Date timestampGenTime = null;
		TimeStampToken timestamp = null;
		try {
			// Comprobamos que se ha indicado la lista de atributos no firmados
			if (unsignedAttributes == null || unsignedAttributes.size() == 0) {
				throw new IllegalArgumentException(Language.getResIntegra(ILogConstantKeys.TSU_LOG086));
			}

			Date currentTSTGenTime = null;
			// Recorremos la lista de atributos no firmados
			for (int i = 0; i < unsignedAttributes.size(); i++) {
				// Obtenemos el sello de tiempo
				Attribute attribute = (Attribute) unsignedAttributes.get(i);
				TimeStampToken currentTimestamp = null;
				try {
					currentTimestamp = new TimeStampToken(new CMSSignedData(attribute.getAttrValues().getObjectAt(0).getDERObject().getEncoded()));
					// Obtenemos la fecha de generación del sello de tiempo
					currentTSTGenTime = currentTimestamp.getTimeStampInfo().getGenTime();
				} catch (Exception e) {
					// Sello de tiempo ASN.1 incorrecto
					String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG087);
					LOGGER.error(errorMsg, e);
					throw new SigningException(errorMsg, e);
				}
				// Si la fecha de generación del sello de tiempo es menos
				// reciente, actualizamos el valor de la variable con dicha
				// fecha
				// de generación y el elemento SignatureTimeStamp
				if (timestampGenTime == null || currentTSTGenTime.before(timestampGenTime)) {
					timestampGenTime = currentTSTGenTime;
					timestamp = currentTimestamp;
				}
			}
			if (timestamp != null) {
				LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG088));
			} else {
				LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG089));
			}
			return timestamp;
		} finally {
			LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG085));
		}
	}

	/**
	 * Method that obtains the time-stamp contained inside of a <code>signature-time-stamp</code> attribute.
	 * @param signatureTimeStampAttribute Parameter that represents the <code>signature-time-stamp</code> attribute.
	 * @param signingCertificate Parameter that represents the signing certificate.
	 * @return an object that represents the time-stamp.
	 * @throws SigningException If the time-stamp is badly encoded.
	 */
	public static TimeStampToken getTimeStampToken(Attribute signatureTimeStampAttribute, X509Certificate signingCertificate) throws SigningException {
		LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG090));
		try {
			// Comprobamos que se ha indicado el atributo signature-time-stamp
			GenericUtilsCommons.checkInputParameterIsNotNull(signatureTimeStampAttribute, Language.getResIntegra(ILogConstantKeys.TSU_LOG092));

			// Comprobamos que se ha indicado el certificado firmante
			GenericUtilsCommons.checkInputParameterIsNotNull(signingCertificate, Language.getResIntegra(ILogConstantKeys.TSU_LOG093));

			// Accedemos al sello de tiempo contenido en el atributo
			// signature-time-stamp
			TimeStampToken result = new TimeStampToken(new CMSSignedData(signatureTimeStampAttribute.getAttrValues().getObjectAt(0).getDERObject().getEncoded()));
			LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG095));
			return result;
		} catch (Exception e) {
			String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG094, new Object[ ] { signingCertificate.getSubjectDN().getName() });
			LOGGER.error(errorMsg, e);
			throw new SigningException(errorMsg, e);
		} finally {
			LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG091));
		}
	}

	/**
	 * Method that checks if the value of the messageImprint field within time-stamp token is a hash of the value indicated.
	 * @param tst Parameter that represents the timestamp.
	 * @param stampedData Parameter that represents the data stamped to compare with it.
	 * @throws SigningException If the validation fails.
	 */
	public static void validateTimestampMessageImprint(TimeStampToken tst, byte[ ] stampedData) throws SigningException {
		LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG096));
		try {
			//Comprobamos que se ha indicado el sello de tiempo
			GenericUtilsCommons.checkInputParameterIsNotNull(tst, Language.getResIntegra(ILogConstantKeys.TSU_LOG014));
			
			//Comprobamos que se han indicado los datos sellados
			GenericUtilsCommons.checkInputParameterIsNotNull(stampedData, Language.getResIntegra(ILogConstantKeys.TSU_LOG109));
			
			// Tomamos el valor de los datos sobre los que se ha calculado el
			// sello
			// de tiempo
			MessageImprint mif = tst.getTimeStampInfo().toTSTInfo().getMessageImprint();

			// Obtenemos el algoritmo de hash usado para calcular el resumen
			// de los datos
			String hashAlgorithm = CryptoUtilPdfBc.translateAlgorithmIdentifier(tst.getTimeStampInfo().getHashAlgorithm());

			// Calculamos el valor de los datos sobre los que se ha calculado el
			// sello de tiempo
			MessageDigest md = MessageDigest.getInstance(hashAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
			md.update(stampedData);
			MessageImprint calculatedMif = new MessageImprint(tst.getTimeStampInfo().getHashAlgorithm(), md.digest());

			// Comprobamos que el valor sobre el que se ha calculado el sello de
			// tiempo se corresponde con la firma de firmante
			if (!mif.equals(calculatedMif)) {
				String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG098, new Object[ ] { tst.getSID().toString() });
				LOGGER.error(errorMsg);
				throw new SigningException(errorMsg);
			}
			LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG099, new Object[ ] { tst.getSID().toString() }));
		} catch (NoSuchAlgorithmException e) {
			String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG100, new Object[ ] { tst.getSID().toString() });
			LOGGER.error(errorMsg);
			throw new SigningException(errorMsg, e);
		} catch (NoSuchProviderException e) {
			String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG100, new Object[ ] { tst.getSID().toString() });
			LOGGER.error(errorMsg);
			throw new SigningException(errorMsg, e);
		} finally {
			LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG097));
		}
	}

	/**
	 * Method that obtains a list with the timestamps contained inside of a set of unsigned attributes.
	 * @param unsignedAttributes Parameter that represents the set of unsigned attributes.
	 * @return the list sorted in ascending order.
	 * @throws SigningException If the method fails.
	 */
	public static List<TimeStampToken> getOrderedTimeStampTokens(ASN1EncodableVector unsignedAttributes) throws SigningException {
		LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG101));
		try {
			// Comprobamos que se ha indicado la lista de atributos no firmados
			if (unsignedAttributes == null || unsignedAttributes.size() == 0) {
				throw new IllegalArgumentException(Language.getResIntegra(ILogConstantKeys.TSU_LOG086));
			}

			// Definimos un conjunto con los sellos de tiempo contenidos en los
			// atributos signature-time-stamp ordenados ascendentemente por
			// fecha
			// de generación, esto es, el primero es el más antiguo
			Set<TimeStampToken> setTimestamps = new TreeSet<TimeStampToken>(new TimestampGenDateComparator());

			// Recorremos la lista de atributos no firmados
			for (int i = 0; i < unsignedAttributes.size(); i++) {
				// Obtenemos el sello de tiempo asociado al atributo
				// no firmado y lo añadimos al conjunto
				Attribute attribute = (Attribute) unsignedAttributes.get(i);
				setTimestamps.add(new TimeStampToken(new CMSSignedData(attribute.getAttrValues().getObjectAt(0).getDERObject().getEncoded())));
			}
			Language.getResIntegra(ILogConstantKeys.TSU_LOG103);

			// Devolvemos los sellos de tiempo ordenados ascendentemente por
			// fecha de generación
			return new ArrayList<TimeStampToken>(setTimestamps);
		} catch (TSPException e) {
			// Sello de tiempo ASN.1 incorrecto
			String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG087);
			LOGGER.error(errorMsg, e);
			throw new SigningException(errorMsg, e);
		} catch (IOException e) {
			// Sello de tiempo ASN.1 incorrecto
			String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG087);
			LOGGER.error(errorMsg, e);
			throw new SigningException(errorMsg, e);
		} catch (CMSException e) {
			// Sello de tiempo ASN.1 incorrecto
			String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG087);
			LOGGER.error(errorMsg, e);
			throw new SigningException(errorMsg, e);
		} finally {
			LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG102));
		}
	}
}
