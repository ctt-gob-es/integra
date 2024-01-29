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
 * <b>File:</b><p>es.gob.afirma.tsl.utils.UtilsCrypto.java.</p>
 * <b>Description:</b><p>Utilities class for cryptographics operations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 15/06/2021.
 */
package es.gob.afirma.tsl.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import org.apache.commons.codec.binary.Base64;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.exceptions.CommonUtilsException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;

/** 
 * <p>Utilities class for cryptographics operations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 15/06/2021.
 */
public final class UtilsCrypto {


	/**
	 * Constructor method for the class UtilsCrypto.java.
	 */
	private UtilsCrypto() {
		super();
	}

	/**
	 * Method that obtains the name of certain algorithm from the URI of the algorithm (only for XML format).
	 * For example: "http://www.w3.org/2000/09/xmldsig#sha1" --&lt; "SHA1".
	 * @param algorithmURI Parameter that represents the URI of the algorithm.
	 * @return the name of the algorithm.
	 * @throws CommonUtilsException If the algorithm isn't supported.
	 */
	public static synchronized String translateHashAlgorithmXML(String algorithmURI) throws CommonUtilsException {
		// Obtenemos el nombre del algoritmo correspondiente
		if (algorithmURI.equalsIgnoreCase(CryptographicConstants.HASH_ALGORITHM_XML_SHA1)) {
			return CryptographicConstants.HASH_ALGORITHM_SHA1;
		} else if (algorithmURI.equalsIgnoreCase(CryptographicConstants.HASH_ALGORITHM_XML_SHA256)) {
			return CryptographicConstants.HASH_ALGORITHM_SHA256;
		} else if (algorithmURI.equalsIgnoreCase(CryptographicConstants.HASH_ALGORITHM_XML_SHA512)) {
			return CryptographicConstants.HASH_ALGORITHM_SHA512;
		} else if (algorithmURI.equalsIgnoreCase(CryptographicConstants.HASH_ALGORITHM_XML_SHA384)) {
			return CryptographicConstants.HASH_ALGORITHM_SHA384;
		} else if (algorithmURI.equalsIgnoreCase(CryptographicConstants.HASH_ALGORITHM_XML_MD5)) {
			return CryptographicConstants.HASH_ALGORITHM_MD5;
		} else {
			throw new CommonUtilsException(Language.getFormatResIntegraTsl(ILogTslConstant.UTILS_CRYPTO_000, new Object[ ] { algorithmURI }));
		}
	}

	/**
	 * Calculate the digest of the input data with the algorithm specified.
	 * @param algorithm Hash algorithm to apply. It can not be null or empty.
	 * @param data Array of bytes that represents the data to calculate the hash. It can not be null or empty.
	 * @param provider Provider to use for calculate the hash algorithm. If it is <code>null</code>, then
	 * tries to use the provider setted in java security providers configuration.
	 * @return Array of bytes that represents the hash calculated.
	 * @throws CommonUtilsException In case of the input hash or data are note properly defined, or that
	 * the input hash is not recognized.
	 */
	public static byte[ ] calculateDigest(String algorithm, byte[ ] data, Provider provider) throws CommonUtilsException {

		byte[ ] result = null;

		// Si el algoritmo no está definido, lanzamos excepción...
		if (UtilsStringChar.isNullOrEmptyTrim(algorithm)) {
			throw new CommonUtilsException(Language.getResIntegraTsl(ILogTslConstant.UTILS_CRYPTO_001));
		}
		// Si no hay datos, lanzamos excepción...
		else if (data == null || data.length == 0) {
			throw new CommonUtilsException(Language.getResIntegraTsl(ILogTslConstant.UTILS_CRYPTO_002));
		} else {

			// Intentamos calcular el hash sobre los datos...
			try {
				// Instanciamos el gestor que calcula el digest en función
				// de si se ha especificado un provider o no.
				if (provider == null) {
					result = MessageDigest.getInstance(algorithm).digest(data);
				} else {
					result = MessageDigest.getInstance(algorithm, provider).digest(data);
				}
			} catch (NoSuchAlgorithmException e) {
				throw new CommonUtilsException(Language.getFormatResIntegraTsl(ILogTslConstant.UTILS_CRYPTO_000, new Object[ ] { algorithm }));
			}

		}

		return result;

	}

	/**
	 * Calculate the digest in base 64 of the input data with the algorithm specified.
	 * @param algorithm Hash algorithm to apply. It can not be null or empty.
	 * @param data Array of bytes that represents the data to calculate the hash. It can not be null or empty.
	 * @param provider Provider to use for calculate the hash algorithm. If it is <code>null</code>, then
	 * tries to use the provider setted in java security providers configuration.
	 * @return Array of bytes that represents the hash calculated in base 64 (not chunked).
	 * @throws CommonUtilsException In case of the input hash or data are note properly defined, or that
	 * the input hash is not recognized.
	 */
	public static byte[ ] calculateDigestReturnB64ByteArray(String algorithm, byte[ ] data, Provider provider) throws CommonUtilsException {

		return Base64.encodeBase64(calculateDigest(algorithm, data, provider));

	}

	/**
	 * Calculate the digest in base 64 of the input data with the algorithm specified.
	 * @param algorithm Hash algorithm to apply. It can not be null or empty.
	 * @param data Array of bytes that represents the data to calculate the hash. It can not be null or empty.
	 * @param provider Provider to use for calculate the hash algorithm. If it is <code>null</code>, then
	 * tries to use the provider setted in java security providers configuration.
	 * @return {@link String} that represents the hash calculated in base 64 (not chunked).
	 * @throws CommonUtilsException In case of the input hash or data are note properly defined, or that
	 * the input hash is not recognized.
	 */
	public static String calculateDigestReturnB64String(String algorithm, byte[ ] data, Provider provider) throws CommonUtilsException {

		return Base64.encodeBase64String(calculateDigest(algorithm, data, provider));

	}
}
