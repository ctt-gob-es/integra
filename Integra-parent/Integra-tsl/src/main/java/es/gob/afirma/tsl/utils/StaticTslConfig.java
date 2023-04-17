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
 * <b>File:</b><p>es.gob.afirma.tsl.utils.TSLProperties.java.</p>
 * <b>Description:</b><p><p>Class contains static properties of Integra-tsl module.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 12/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.2, 17/04/2023.
 */
package es.gob.afirma.tsl.utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import es.gob.afirma.tsl.logger.Logger;



/** 
 * <p>Class contains static properties of Integra-tsl module.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 17/04/2023.
 */
public final class StaticTslConfig {

	/**
	 * Attribute that represents set of properties of @Firma.
	 */
	private static Properties staticProperties;
	/**
	 * Constant attribute that represents the log manager of the class.
	 */
	private static final Logger LOGGER = Logger.getLogger(StaticTslConfig.class);
	
	/**
	 * Constant attribute that represents the name of properties file.
	 */
	public static final String STATIC_TSL_FILENAME = "staticTsl.properties";


	/**
	 * Constant attribute that represents the prefix <code>tsl.eu.lotl.</code>.
	 */
	public static final String TSL_EU_LOTL_PREFIX = "tsl.eu.lotl.";

	/**
	 * Attribute that represents the key for the property that indicates the flag to indicate if it is
	 * necessary to check the structure of the TSL signature.
	 */
	public static final String TSL_SIGNATURE_VERIFY_STRUCTURE = "tsl.signature.verify.structure";
	/**
	 * Constant attribute that represents the key for the property that indicates the timgap allowed for the input
	 * parameter in the service 'detectCertInTslInfoAndValidation' that represents the validation date.
	 */
	public static final String TSL_SERVICE_DETECTCERTINTSLINFOANDVALIDATION_VALIDATIONDATE_TIMEGAPALLOWED = "tsl.service.detectCertInTslInfoAndValidation.validationDate.timeGapAllowed";

	/**
	 * Attribute that represents the key for the property that indicates the flag to indicate if it is
	 * necessary to check the specification requirements for the TSL signature.
	 */
	public static final String TSL_SIGNATURE_VERIFY_SPECIFICATION = "tsl.signature.verify.specification";

	/**
	 * Constant attribute that represents the key for the property that indicates read timeout for ocsp requests (milliseconds).
	 */
	public static final String TSL_VALIDATION_OCSP_TIMEOUT_READ = "tsl.validation.ocsp.timeout.read";

	/**
	 * Attribute that represents the key for the property that indicates connection timeout for ocsp requests (milliseconds).
	 */
	public static final String TSL_VALIDATION_OCSP_TIMEOUT_CONNECTION = "tsl.validation.ocsp.timeout.connection";

	/**
	 * Constant attribute that represents the key for the property that indicates read timeout to get a CRL (milliseconds).
	 */
	public static final String TSL_VALIDATION_CRL_TIMEOUT_READ = "tsl.validation.crl.timeout.read";

	/**
	 * Constant attribute that represents the key for the property that indicates connection timeout to get a CRL (milliseconds).
	 */
	public static final String TSL_VALIDATION_CRL_TIMEOUT_CONNECTION = "tsl.validation.crl.timeout.connection";
	
	/**
	 * Attribute that represents the key for the property that indicates the initial date from which is
	 * allowed to use TSL to validate certificates.
	 */
	public static final String TSL_VALIDATION_INITIAL_DATE = "tsl.validation.initial.date";

	/**
	 * Constant attribute that represents the key for the property that indicates the set of values recognized
	 * for a certificate classification to 'Natural Person'.
	 */
	public static final String TSL_MAPPING_CERTCLASSIFICATION_NATURALPERSON = "tsl.mapping.certClassification.NATURAL_PERSON";
	
	/**
	 * Constant attribute that represents the key for the property that indicates the set of values recognized
	 * for a certificate classification to 'Legal Person'.
	 */
	public static final String TSL_MAPPING_CERTCLASSIFICATION_LEGALPERSON = "tsl.mapping.certClassification.LEGAL_PERSON";

	/**
	 * Constant attribute that represents the key for the property that indicates the set of values recognized
	 * for a certificate classification to 'Electronic Signature'.
	 */
	public static final String TSL_MAPPING_CERTCLASSIFICATION_ESIG = "tsl.mapping.certClassification.ESIG";

	/**
	 * Constant attribute that represents the key for the property that indicates the set of values recognized
	 * for a certificate classification to 'Electronic Seal'.
	 */
	public static final String TSL_MAPPING_CERTCLASSIFICATION_ESEAL = "tsl.mapping.certClassification.ESEAL";

	/**
	 * Constant attribute that represents the key for the property that indicates the set of values recognized
	 * for a certificate classification to 'Web Service Authentication'.
	 */
	public static final String TSL_MAPPING_CERTCLASSIFICATION_WSA = "tsl.mapping.certClassification.WSA";

	/**
	 * Constant attribute that represents the key for the property that indicates the set of values recognized
	 * for a certificate classification to 'TimeStamping Authority'.
	 */
	public static final String TSL_MAPPING_CERTCLASSIFICATION_TSA = "tsl.mapping.certClassification.TSA";

	/**
	 * Constant attribute that represents the key for the property that indicates the set of values recognized
	 * for a certificate qualified to 'YES'.
	 */
	public static final String TSL_MAPPING_CERTQUALIFIED_YES = "tsl.mapping.certQualified.YES";

	/**
	 * Constant attribute that represents the key for the property that indicates the set of values recognized
	 * for a certificate qualified to 'NO'.
	 */
	public static final String TSL_MAPPING_CERTQUALIFIED_NO = "tsl.mapping.certQualified.NO";

	/**
	 * Constant attribute that represents the key for the property that indicates the interval allowed to accept a OCSP response
	 * by a specified validation date (seconds).
	 */
	public static final String TSL_VALIDATION_OCSP_INTERVAL_ALLOWED = "tsl.validation.ocsp.interval.allowed";

	/**
	 * Constant attribute that represents date time of TSL
	 */
	public static final String TSL_DATE_TIME = "tsl.date.time";
	
	/**
	 * Constant attribute that represents name for property <i>"connection.MaxSize"</i>.
	 */
	public static final String CONECTION_MAXSIZE = "connection.MaxSize";

	/**
	 * Attribute that represents the key for the property that indicates the AES algorithm name.
	 */
	public static final String AES_ALGORITHM = "aes.algorithm";

	/**
	 * Attribute that represents the key for the property that indicates the password for the AES algorithm.
	 */
	public static final String AES_PASSWORD = "aes.password";

	/**
	 * Attribute that represents the key for the property that indicates the Padding algorithm for the AES cipher.
	 */
	public static final String AES_NO_PADDING_ALG = "aes.nopadding.alg";
	/**
	 * Constant attribute that represents name for property <i>"ssl.restricted.cipher.suites"</i>.
	 */
	public static final String SSL_RESTRICTED_CIPHER_SUITES = "ssl.restricted.cipher.suites";

	/**
	 * Constant attribute that represents name for property <i>"ssl.restricted.protocols"</i>.
	 */
	public static final String SSL_RESTRICTED_PROTOCOLS = "ssl.restricted.protocols";
	
	/**
	 * Constructor method for the class StaticTslConfig.java.
	 */
	private StaticTslConfig() {
		super();
	}

	/**
	 * Gets all properties from original file.
	 * @return all properties
	 */
	public static Properties getProperties() {
		if (staticProperties == null) {
			reloadStaticTslConfig();
		}
		return staticProperties;
	}
	
	/**
	 * Method that load/reload the static integra-tsl properties
	 * @return <code>true</code> if the properties file has been loaded,
	 * otherwise <code>false</code>.
	 */
	public static boolean reloadStaticTslConfig() {

		boolean result = false;

		synchronized (StaticTslConfig.class) {
			if (staticProperties == null) {
				staticProperties = new Properties();
				FileInputStream configStream = null;
				try {
				    InputStream in = StaticTslConfig.class.getClassLoader().getResourceAsStream(STATIC_TSL_FILENAME);
//				    URL res = StaticTslConfig.class.getClassLoader().getResource(STATIC_TSL_FILENAME);
//				    File file = Paths.get(res.toURI()).toFile();
//				    String absolutePath = file.getAbsolutePath();
					
				 //  configStream = new FileInputStream(absolutePath);
					staticProperties.load(in);
					result = true;
				} catch (IOException e) {
					e.printStackTrace();
				} finally {
					UtilsResourcesCommons.safeCloseInputStream(configStream);
				}
			}
		}

		return result;

	}

	/**
	 * Returns the value of property given.
	 * @param propertyName name of  property.
	 * @return the value of property given.
	 */
	public static String getProperty(final String propertyName) {
		String result = (String) getProperties().get(propertyName);
		if (result != null) {
			return result.trim();
		} else {
			return result;
		}
	}

	/**
	 * Obtains a collection of static properties which key name start with the prefix given.
	 * @param prefix word placed in the beginning of the key name of property.
	 * @return a collection of static properties.
	 */
	public static Properties getProperties(final String prefix) {
		Properties result = new Properties();
		if (prefix != null) {
			for (Object key: getProperties().keySet()) {
				if (key != null && key.toString().startsWith(prefix)) {
					result.put(key, getProperties().get(key));
				}
			}
		}
		return result;
	}
}
