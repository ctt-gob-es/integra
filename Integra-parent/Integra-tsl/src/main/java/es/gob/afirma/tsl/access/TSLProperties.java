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
 * <b>File:</b><p>es.gob.afirma.tsl.access.TSLProperties.java.</p>
 * <b>Description:</b><p>Class that provides access to the differents properties associated to the TSL operations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 13/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 18/04/2022.
 */
package es.gob.afirma.tsl.access;

import es.gob.afirma.tsl.logger.Logger;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.utils.NumberConstants;
import es.gob.afirma.tsl.utils.StaticTslConfig;
import es.gob.afirma.tsl.utils.UtilsDate;
import es.gob.afirma.tsl.utils.UtilsStringChar;

import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.Set;
import java.util.TreeSet;

/** 
 * <p>Class that provides access to the differents properties associated to the TSL operations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 18/04/2022.
 */
public final class TSLProperties {

	/**
	 * Constant attribute that represents the log manager of the class.
	 */
	private static final Logger LOGGER = Logger.getLogger(TSLProperties.class);

	/**
	 * Constant attribute that represents the initial date 01/07/2016 from which allow the use of TSL.
	 */
	private static Date initialDate = null;

	static {
		Calendar cal = Calendar.getInstance();
		cal.set(NumberConstants.INT_2016, NumberConstants.INT_6, 1, 0, 0, 0);
		cal.set(Calendar.MILLISECOND, 0);
		initialDate = cal.getTime();
	}

	/**
	 * Constructor method for the class TSLProperties.java.
	 */
	private TSLProperties() {
		super();
	}

	/**
	 * Checks if it is necessary to check the structure of the TSL signature.
	 * @return <code>true</code> if it is necessary to check the structure of the TSL signature,
	 * otherwise <code>false</code>.
	 */
	public static boolean isRequiredToCheckTslSignatureStructure() {
		return Boolean.parseBoolean(StaticTslConfig.getProperty(StaticTslConfig.TSL_SIGNATURE_VERIFY_STRUCTURE));
	}

	/**
	 * Checks if it is necessary to check the TSL signature by its specification.
	 * @return <code>true</code> if it is necessary to check the TSL signature by its specification,
	 * otherwise <code>false</code>.
	 */
	public static boolean isRequiredToCheckTslSignatureByItsSpecification() {
		return Boolean.parseBoolean(StaticTslConfig.getProperty(StaticTslConfig.TSL_SIGNATURE_VERIFY_SPECIFICATION));
	}

	/**
	 * Gets the OCSP Read Timeout for TSL operations.
	 * @return The OCSP Read Timeout for TSL operations in milliseconds.
	 */
	public static int getOcspReadTimeout() {

		int result = NumberConstants.INT_10000;

		try {
			String ocspTimeoutRead = StaticTslConfig.getProperty(StaticTslConfig.TSL_VALIDATION_OCSP_TIMEOUT_READ);
			result = Integer.valueOf(ocspTimeoutRead);
		} catch (NumberFormatException e) {
			LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.TP_LOG001, new Object[ ] { StaticTslConfig.TSL_VALIDATION_OCSP_TIMEOUT_READ, result }), e);
		}

		return result;

	}

	/**
	 * Gets the OCSP Connection Timeout for TSL operations.
	 * @return The OCSP Connection Timeout for TSL operations in milliseconds.
	 */
	public static int getOcspConnectionTimeout() {

		int result = NumberConstants.INT_10000;

		try {
			String ocspTimeoutConnection = StaticTslConfig.getProperty(StaticTslConfig.TSL_VALIDATION_OCSP_TIMEOUT_CONNECTION);
			result = Integer.valueOf(ocspTimeoutConnection);
		} catch (NumberFormatException e) {
			LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.TP_LOG001, new Object[ ] { StaticTslConfig.TSL_VALIDATION_OCSP_TIMEOUT_CONNECTION, result }), e);
		}

		return result;

	}

	/**
	 * Gets the OCSP Time Interval Allowed for TSL operations.
	 * @return The OCSP Time Interval Allowed for TSL operations in milliseconds.
	 */
	public static int getOcspTimeIntervalAllowed() {

		int result = NumberConstants.INT_3600;

		try {
			String ocspTimeoutConnection = StaticTslConfig.getProperty(StaticTslConfig.TSL_VALIDATION_OCSP_INTERVAL_ALLOWED);
			result = Integer.valueOf(ocspTimeoutConnection);
		} catch (NumberFormatException e) {
			LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.TP_LOG001, new Object[ ] { StaticTslConfig.TSL_VALIDATION_OCSP_INTERVAL_ALLOWED, result }), e);
		}

		return result;

	}

	/**
	 * Gets the CRL Timeout Read for TSL operations.
	 * @return The CRL Timeout Read for TSL operations in milliseconds.
	 */
	public static int getCrlTimeoutRead() {

		int result = NumberConstants.INT_10000;

		try {
			String crlTimeoutRead = StaticTslConfig.getProperty(StaticTslConfig.TSL_VALIDATION_CRL_TIMEOUT_READ);
			result = Integer.valueOf(crlTimeoutRead);
		} catch (NumberFormatException e) {
			LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.TP_LOG001, new Object[ ] { StaticTslConfig.TSL_VALIDATION_CRL_TIMEOUT_READ, result }), e);
		}

		return result;

	}

	/**
	 * Gets the CRL Timeout Connection for TSL operations.
	 * @return The CRL Timeout Connection for TSL operations in milliseconds.
	 */
	public static int getCrlTimeoutConnection() {

		int result = NumberConstants.INT_10000;

		try {
			String crlTimeoutConnection = StaticTslConfig.getProperty(StaticTslConfig.TSL_VALIDATION_CRL_TIMEOUT_CONNECTION);
			result = Integer.valueOf(crlTimeoutConnection);
		} catch (NumberFormatException e) {
			LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.TP_LOG001, new Object[ ] { StaticTslConfig.TSL_VALIDATION_CRL_TIMEOUT_CONNECTION, result }), e);
		}

		return result;

	}

	/**
	 * Gets the initial date from which is allowed use TSL to detect and validate certificate.
	 * @return the initial date from which is allowed use TSL to detect and validate certificate.
	 */
	public static Date getInitialDate() {

		Date result = initialDate;

		try {
			String initialDateString = StaticTslConfig.getProperty(StaticTslConfig.TSL_VALIDATION_INITIAL_DATE);
			result = UtilsDate.transformDate(initialDateString, UtilsDate.FORMAT_DATE_SMALL);
			Calendar cal = Calendar.getInstance();
			cal.setTime(result);
			cal.set(Calendar.HOUR_OF_DAY, 0);
			cal.set(Calendar.MINUTE, 0);
			cal.set(Calendar.SECOND, 0);
			cal.set(Calendar.MILLISECOND, 0);
			result = cal.getTime();
		} catch (ParseException e) {
			LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.TP_LOG001, new Object[ ] { StaticTslConfig.TSL_VALIDATION_INITIAL_DATE, result }), e);
		}

		return result;

	}

	/**
	 * Gets the set of values from the logical field 'clasificacion' associated to
	 * the logical field 'certClassification' for the mapping NATURAL_PERSON.
	 * @return Set of values from the logical field 'clasificacion' associated to
	 * the logical field 'certClassification' for the mapping NATURAL_PERSON.
	 */
	public static Set<Integer> getClassificationSetForCertClassificationNaturalPerson() {

		return getClassificationSet(StaticTslConfig.TSL_MAPPING_CERTCLASSIFICATION_NATURALPERSON);

	}

	/**
	 * Gets the set of values from the logical field 'clasificacion' associated to
	 * the logical field 'certClassification' for the mapping LEGAL_PERSON.
	 * @return Set of values from the logical field 'clasificacion' associated to
	 * the logical field 'certClassification' for the mapping LEGAL_PERSON.
	 */
	public static Set<Integer> getClassificationSetForCertClassificationLegalPerson() {

		return getClassificationSet(StaticTslConfig.TSL_MAPPING_CERTCLASSIFICATION_LEGALPERSON);

	}

	/**
	 * Gets the set of values from the logical field 'clasificacion' associated to
	 * the logical field 'certClassification' for the mapping ESIG.
	 * @return Set of values from the logical field 'clasificacion' associated to
	 * the logical field 'certClassification' for the mapping ESIG.
	 */
	public static Set<Integer> getClassificationSetForCertClassificationESIG() {

		return getClassificationSet(StaticTslConfig.TSL_MAPPING_CERTCLASSIFICATION_ESIG);

	}

	/**
	 * Gets the set of values from the logical field 'clasificacion' associated to
	 * the logical field 'certClassification' for the mapping ESEAL.
	 * @return Set of values from the logical field 'clasificacion' associated to
	 * the logical field 'certClassification' for the mapping ESEAL.
	 */
	public static Set<Integer> getClassificationSetForCertClassificationESEAL() {

		return getClassificationSet(StaticTslConfig.TSL_MAPPING_CERTCLASSIFICATION_ESEAL);

	}

	/**
	 * Gets the set of values from the logical field 'clasificacion' associated to
	 * the logical field 'certClassification' for the mapping WSA.
	 * @return Set of values from the logical field 'clasificacion' associated to
	 * the logical field 'certClassification' for the mapping WSA.
	 */
	public static Set<Integer> getClassificationSetForCertClassificationWSA() {

		return getClassificationSet(StaticTslConfig.TSL_MAPPING_CERTCLASSIFICATION_WSA);

	}

	/**
	 * Gets the set of values from the logical field 'clasificacion' associated to
	 * the logical field 'certClassification' for the mapping TSA.
	 * @return Set of values from the logical field 'clasificacion' associated to
	 * the logical field 'certClassification' for the mapping TSA.
	 */
	public static Set<Integer> getClassificationSetForCertClassificationTSA() {

		return getClassificationSet(StaticTslConfig.TSL_MAPPING_CERTCLASSIFICATION_TSA);

	}

	/**
	 * Gets the set of values from the logical field 'clasificacion' associated to
	 * the logical field 'certQualified' for the mapping YES.
	 * @return Set of values from the logical field 'clasificacion' associated to
	 * the logical field 'certQualified' for the mapping YES.
	 */
	public static Set<Integer> getClassificationSetForCertQualifiedYES() {

		return getClassificationSet(StaticTslConfig.TSL_MAPPING_CERTQUALIFIED_YES);

	}

	/**
	 * Gets the set of values from the logical field 'clasificacion' associated to
	 * the logical field 'certQualified' for the mapping NO.
	 * @return Set of values from the logical field 'clasificacion' associated to
	 * the logical field 'certQualified' for the mapping NO.
	 */
	public static Set<Integer> getClassificationSetForCertQualifiedNO() {

		return getClassificationSet(StaticTslConfig.TSL_MAPPING_CERTQUALIFIED_NO);

	}

	/**
	 * Gets the set of values from the logical field 'clasificacion' associated to
	 * the logical field 'certClassification' and 'certQualified' for the mapping of the input property.
	 * @param propertyKey Property Key to get from the configuration data base.
	 * @return Set of values from the logical field 'clasificacion' associated to
	 * the logical field 'certClassification' and 'certQualified' for the mapping of the input property.
	 */
	private static Set<Integer> getClassificationSet(String propertyKey) {

		Set<Integer> result = new TreeSet<Integer>();

		String setOfValuesString = StaticTslConfig.getProperty(propertyKey);
		if (!UtilsStringChar.isNullOrEmptyTrim(setOfValuesString)) {

			String[ ] setOfValuesArray = setOfValuesString.split(UtilsStringChar.SYMBOL_COMMA_STRING);
			if (setOfValuesArray != null && setOfValuesArray.length > 0) {

				for (String value: setOfValuesArray) {

					try {
						result.add(Integer.valueOf(value.trim()));
					} catch (NumberFormatException e) {
						LOGGER.error(Language.getFormatResIntegraTsl(ILogTslConstant.TP_LOG002, new Object[ ] { value.trim(), propertyKey }));
					}

				}

			}

		}

		return result;

	}

	/**
	 * Gets the value for the timegap for the validation date in the service 'DetectCertInTslInfoAndValidation'.
	 * @return the value for the timegap for the validation date in the service 'DetectCertInTslInfoAndValidation'.
	 * If there is some proble recovering it, then is returned the default value 30000.
	 */
	public static int getServiceDetectCertInTslInfoAndValidationParamValDateTimeGap() {

		int result = NumberConstants.INT_30000;

		String timeGap = StaticTslConfig.getProperty(StaticTslConfig.TSL_SERVICE_DETECTCERTINTSLINFOANDVALIDATION_VALIDATIONDATE_TIMEGAPALLOWED);
		if (!UtilsStringChar.isNullOrEmptyTrim(timeGap)) {

			try {
				result = Integer.parseInt(timeGap);
			} catch (NumberFormatException e) {
				LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.TP_LOG001, new Object[ ] { StaticTslConfig.TSL_SERVICE_DETECTCERTINTSLINFOANDVALIDATION_VALIDATIONDATE_TIMEGAPALLOWED, NumberConstants.INT_30000 }), e);
			}

		}

		return result;

	}
}
