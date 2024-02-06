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
// https://eupl.eu/1.1/es/

/** 
 * <b>File:</b><p>es.gob.afirma.tsl.certValidation.impl.TSLValidatorMappingCalculator.java.</p>
 * <b>Description:</b><p>This class offers static methods to extract mappings of a certificate
 * validated through a TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 17/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.4, 19/09/2022.
 */
package es.gob.afirma.tsl.certValidation.impl;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;

import es.gob.afirma.tsl.logger.Logger;


import es.gob.afirma.tsl.access.TSLProperties;
import es.gob.afirma.tsl.certValidation.ifaces.ITSLValidatorOtherConstants;
import es.gob.afirma.tsl.certValidation.ifaces.ITSLValidatorResult;
import es.gob.afirma.tsl.constants.ITslMappingConstants;
import es.gob.afirma.tsl.exceptions.TSLValidationException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.parsing.ifaces.ITSLOIDs;
import es.gob.afirma.tsl.parsing.impl.common.TSLCertificateExtensionAnalyzer;
import es.gob.afirma.tsl.utils.UtilsStringChar;

/** 
 * <p>This class offers static methods to extract mappings of a certificate
 * validated through a TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.4, 19/09/2022.
 */
public final class TSLValidatorMappingCalculator {
    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = Logger.getLogger(TSLValidatorMappingCalculator.class);
	/**
	 * Constant attribute that represents the set of mapping names that are static.
	 */
	public static final Set<String> STATIC_MAPPING_NAMES_SET = new HashSet<String>(Arrays.asList(ITslMappingConstants.MAPPING_KEY_CERT_QUALIFIED, ITslMappingConstants.MAPPING_KEY_CERT_CLASSIFICATION, ITslMappingConstants.MAPPING_KEY_QSCD));

	/**
	 * Constructor method for the class TSLValidatorMappingCalculator.java.
	 */
	private TSLValidatorMappingCalculator() {
		super();
	}
	/**
	 * Checks if the input mapping name matches with some of the static mapping names.
	 * @param mappingName Mapping name to check.
	 * @return <code>true</code> if the input mapping name matches with some of the static mapping names,
	 * otherwise <code>false</code>.
	 */
	public static boolean checksIfMappingNameMatchesWithSomeStaticMappingName(String mappingName) {
		return STATIC_MAPPING_NAMES_SET.contains(mappingName);
	}

	/**
	 * Extracts the static mappings from the validation result, and add these on the input mapping set.
	 * @param tslCertExtAnalyzer TSL Certificate Extension Analyzer needed to resolve the mappings of the certificate.
	 * @param mappings Map in which adds the pairs &lt;MappingName, MappingValue&gt; calculated for the validated certificate.
	 * @param tslValidationResult TSL validation result from which get the static mapping information.
	 */
	public static void extractStaticMappingsFromResult(TSLCertificateExtensionAnalyzer tslCertExtAnalyzer, Map<String, String> mappings, ITSLValidatorResult tslValidationResult) {
	    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG001));
		// Si ninguno de los parámetros de entrada es nulo...
		if (mappings != null && tslValidationResult != null) {
			// Establecemos primero si el certificado es qualified o no.
			switch (tslValidationResult.getMappingType()) {

				case ITSLValidatorResult.MAPPING_TYPE_UNKNOWN:
					try {
					    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG010));
						mappings.put(ITslMappingConstants.MAPPING_KEY_CERT_QUALIFIED, getMappingTypeQualifiedFromCertificate(tslCertExtAnalyzer));
					} catch (TSLValidationException e) {
					    LOGGER.error(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG006));
						mappings.put(ITslMappingConstants.MAPPING_KEY_CERT_QUALIFIED, ITslMappingConstants.MAPPING_VALUE_UNKNOWN);
					}
					break;

				case ITSLValidatorResult.MAPPING_TYPE_NONQUALIFIED:
				    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG011));
					mappings.put(ITslMappingConstants.MAPPING_KEY_CERT_QUALIFIED, ITslMappingConstants.MAPPING_VALUE_NO);
					break;

				case ITSLValidatorResult.MAPPING_TYPE_QUALIFIED:
				    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG012));
					mappings.put(ITslMappingConstants.MAPPING_KEY_CERT_QUALIFIED, ITslMappingConstants.MAPPING_VALUE_YES);
					break;

				default:
					break;
			}

			// Establecemos la clasificación del certificado.
			switch (tslValidationResult.getMappingClassification()) {
				case ITSLValidatorResult.MAPPING_CLASSIFICATION_OTHER_UNKNOWN:
					try {
					    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG009));
						mappings.put(ITslMappingConstants.MAPPING_KEY_CERT_CLASSIFICATION, getMappingClassificationFromCertificate(tslCertExtAnalyzer, true));
					} catch (TSLValidationException e) {
						mappings.put(ITslMappingConstants.MAPPING_KEY_CERT_CLASSIFICATION, ITslMappingConstants.MAPPING_VALUE_UNKNOWN);
					}
					break;

				case ITSLValidatorResult.MAPPING_CLASSIFICATION_NATURAL_PERSON:
				    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG013));
					mappings.put(ITslMappingConstants.MAPPING_KEY_CERT_CLASSIFICATION, ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_NATURAL_PERSON);
					break;

				case ITSLValidatorResult.MAPPING_CLASSIFICATION_LEGALPERSON:
				    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG014));
					mappings.put(ITslMappingConstants.MAPPING_KEY_CERT_CLASSIFICATION, ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_LEGALPERSON);
					break;

				case ITSLValidatorResult.MAPPING_CLASSIFICATION_ESEAL:
				    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG015));
					mappings.put(ITslMappingConstants.MAPPING_KEY_CERT_CLASSIFICATION, ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_ESEAL);
					break;

				case ITSLValidatorResult.MAPPING_CLASSIFICATION_ESIG:
				    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG016));
					mappings.put(ITslMappingConstants.MAPPING_KEY_CERT_CLASSIFICATION, ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_ESIG);
					break;

				case ITSLValidatorResult.MAPPING_CLASSIFICATION_WSA:
				    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG017));
					mappings.put(ITslMappingConstants.MAPPING_KEY_CERT_CLASSIFICATION, ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_WSA);
					break;

				case ITSLValidatorResult.MAPPING_CLASSIFICATION_TSA:
				    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG018));
					mappings.put(ITslMappingConstants.MAPPING_KEY_CERT_CLASSIFICATION, ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_TSA);
					break;

				default:
					break;
			}

			// Establecemos si el certificado es de un QSCD.
			switch (tslValidationResult.getMappingQSCD()) {

				case ITSLValidatorResult.MAPPING_QSCD_UNKNOWN:
					try {
					    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG007));
						mappings.put(ITslMappingConstants.MAPPING_KEY_QSCD, getMappingQSCDFromCertificate(tslCertExtAnalyzer));
					} catch (TSLValidationException e) {
					    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG021));
						mappings.put(ITslMappingConstants.MAPPING_KEY_QSCD, ITslMappingConstants.MAPPING_VALUE_UNKNOWN);
					}
					break;

				case ITSLValidatorResult.MAPPING_QSCD_NO:
				    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG019));
					mappings.put(ITslMappingConstants.MAPPING_KEY_QSCD, ITslMappingConstants.MAPPING_VALUE_NO);
					break;

				case ITSLValidatorResult.MAPPING_QSCD_YES:
				    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG020));
					mappings.put(ITslMappingConstants.MAPPING_KEY_QSCD, ITslMappingConstants.MAPPING_VALUE_YES);
					break;

				case ITSLValidatorResult.MAPPING_QSCD_ASINCERT:
					try {
					    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG008));
						mappings.put(ITslMappingConstants.MAPPING_KEY_QSCD, getMappingQSCDFromCertificate(tslCertExtAnalyzer));
					} catch (TSLValidationException e) {
					    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG021));
						mappings.put(ITslMappingConstants.MAPPING_KEY_QSCD, ITslMappingConstants.MAPPING_VALUE_UNKNOWN);
					}
					break;

				case ITSLValidatorResult.MAPPING_QSCD_YES_MANAGEDONBEHALF:
				    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG022));
					mappings.put(ITslMappingConstants.MAPPING_KEY_QSCD, ITslMappingConstants.MAPPING_VALUE_QSCD_YES_MANAGEDONBEHALF);
					break;

				default:
					break;
			}

		}

	}

	/**
	 * Tries to extract from the certificate if it is qualified or not.
	 * @param tslCertExtAnalyzer TSL Certificate Extension Analyzer needed to resolve the mappings of the certificate.
	 * @return String that represents the mapping type of the input certificate. It only can be one of the following:<br>
	 * <ul>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_YES}</li>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_NO}</li>
	 * </ul>
	 * @throws TSLValidationException In case of some error parsing the input certificate with BC provider.
	 */
	public static String getMappingTypeQualifiedFromCertificate(TSLCertificateExtensionAnalyzer tslCertExtAnalyzer) throws TSLValidationException {
	   
		// Por defecto el valor es desconocido.
		String result = ITslMappingConstants.MAPPING_VALUE_UNKNOWN;
		 LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG003));
		// Si dispone de la extensión QcStatement y al menos uno es de los
		// cualificados, o en su defecto hay una extensión Certificate Policies
		// Policy Information que determina que es cualificado...
		if (tslCertExtAnalyzer.hasSomeQcStatementExtensionOid(ITSLValidatorOtherConstants.QCSTATEMENTS_OIDS_FOR_QUALIFIED_CERTS_LIST) || tslCertExtAnalyzer.hasSomeCertPolPolInfExtensionOid(ITSLValidatorOtherConstants.POLICYIDENTIFIERS_OIDS_FOR_QUALIFIED_CERTS_LIST)) {

			result = ITslMappingConstants.MAPPING_VALUE_YES;
			LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG004));
		} else {

			result = ITslMappingConstants.MAPPING_VALUE_NO;
			LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TVMC_LOG005));
		}

		return result;

	}

	/**
	 * Tries to extract from the certificate its classification type.
	 * @param tslCertExtAnalyzer TSL Certificate Extension Analyzer needed to resolve the mappings of the certificate.
	 * @param translateMapping Flag that if it is <code>true</code>, then the returned mapping values
	 * {@link ITslMappingConstants#MAPPING_VALUE_CLASSIFICATION_NATURAL_PERSON} and {@link ITslMappingConstants#MAPPING_VALUE_CLASSIFICATION_LEGALPERSON}
	 * are translated to {@link ITslMappingConstants#MAPPING_VALUE_CLASSIFICATION_ESEAL} and
	 * {@link ITslMappingConstants#MAPPING_VALUE_CLASSIFICATION_ESIG} respectively.
	 * @return String that represents the mapping classification of the input certificate. It only can be one of the following:<br>
	 * <ul>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_UNKNOWN}</li>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_CLASSIFICATION_NATURAL_PERSON}</li>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_CLASSIFICATION_LEGALPERSON}</li>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_CLASSIFICATION_ESEAL}</li>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_CLASSIFICATION_ESIG}</li>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_CLASSIFICATION_WSA}</li>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_CLASSIFICATION_TSA}</li>
	 * </ul>
	 * @throws TSLValidationException In case of some error parsing the input certificate with BC provider.
	 */
	public static String getMappingClassificationFromCertificate(TSLCertificateExtensionAnalyzer tslCertExtAnalyzer, boolean translateMapping) throws TSLValidationException {

		// Por defecto el valor es desconocido.
		String result = ITslMappingConstants.MAPPING_VALUE_UNKNOWN;

		// Comprobamos si se dispone del QCStatements Extension - EuType
		// 1.3.6.1.5.5.7.1.3, la cual es opcional.
		if (tslCertExtAnalyzer.isThereSomeQcStatementEuTypeExtension()) {

			// Comprobamos los OID de ESIG, ESEAL y WSA.
			if (tslCertExtAnalyzer.hasQcStatementEuTypeExtensionOid(ITSLOIDs.OID_QCSTATEMENT_EXT_EUTYPE_ESIGN.getId())) {

				result = ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_ESIG;

			} else if (tslCertExtAnalyzer.hasQcStatementEuTypeExtensionOid(ITSLOIDs.OID_QCSTATEMENT_EXT_EUTYPE_ESEAL.getId())) {

				result = ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_ESEAL;

			} else if (tslCertExtAnalyzer.hasQcStatementEuTypeExtensionOid(ITSLOIDs.OID_QCSTATEMENT_EXT_EUTYPE_WEB.getId())) {

				result = ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_WSA;

			}

		}

		// IMPORTANTE, si al menos tiene el QcCompliance, ya se considera de
		// firma,
		// por lo que si aún no lo hemos determinado, lo comprobamos.
		if (result.equals(ITslMappingConstants.MAPPING_VALUE_UNKNOWN) && tslCertExtAnalyzer.isThereSomeQcStatementExtension()) {
			result = ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_ESIG;
		}

		// Si aún no hemos podido verificar que el certificado sea detectado,
		// comprobamos los CertificatePolicies.
		if (result.equals(ITslMappingConstants.MAPPING_VALUE_UNKNOWN) && tslCertExtAnalyzer.isThereSomeCertPolPolInfExtension()) {

			if (tslCertExtAnalyzer.hasSomeCertPolPolInfExtensionOid(ITSLValidatorOtherConstants.POLICYIDENTIFIERS_OIDS_FOR_ESIG_CERTS_LIST)) {
				result = translateMapping ? ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_ESIG : ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_NATURAL_PERSON;
			} else if (tslCertExtAnalyzer.hasSomeCertPolPolInfExtensionOid(ITSLValidatorOtherConstants.POLICYIDENTIFIERS_OIDS_FOR_ESEAL_CERTS_LIST)) {
				result = translateMapping ? ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_ESEAL : ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_LEGALPERSON;
			} else if (tslCertExtAnalyzer.hasSomeCertPolPolInfExtensionOid(ITSLValidatorOtherConstants.POLICYIDENTIFIERS_OIDS_FOR_WSA_CERTS_LIST)) {
				result = ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_WSA;
			}

		}

		return result;

	}

	/**
	 * Tries to extract from the certificate if it has its private key in a QSCD.
	 * @param tslCertExtAnalyzer TSL Certificate Extension Analyzer needed to resolve the mappings of the certificate.
	 * @return String that represents the mapping for the input certificate. It only can be one of the following:<br>
	 * <ul>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_UNKNOWN}</li>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_YES}</li>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_NO}</li>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_ASINCERT}</li>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_QSCD_YES_MANAGEDONBEHALF}</li>
	 * </ul>
	 * @throws TSLValidationException In case of some error parsing the input certificate with BC provider.
	 */
	public static String getMappingQSCDFromCertificate(TSLCertificateExtensionAnalyzer tslCertExtAnalyzer) throws TSLValidationException {

		// Inicializamos el resultado a desconocido.
		String result = ITslMappingConstants.MAPPING_VALUE_UNKNOWN;

		// Comprobamos si tiene la extensión QcStatement - QcEuSSCD
		if (tslCertExtAnalyzer.hasQcStatementExtensionOid(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD.getId())) {

			result = ITslMappingConstants.MAPPING_VALUE_YES;

		}

		// Comprobamos los CertificatePolicies - Policy Information.
		if (result.equals(ITslMappingConstants.MAPPING_VALUE_UNKNOWN) && tslCertExtAnalyzer.isThereSomeCertPolPolInfExtension()) {

			if (tslCertExtAnalyzer.hasSomeCertPolPolInfExtensionOid(ITSLValidatorOtherConstants.POLICYIDENTIFIERS_OIDS_FOR_CERTS_IN_QSCD_LIST)) {
				result = ITslMappingConstants.MAPPING_VALUE_YES;
			} else if (tslCertExtAnalyzer.hasSomeCertPolPolInfExtensionOid(ITSLValidatorOtherConstants.POLICYIDENTIFIERS_OIDS_FOR_CERTS_IN_NO_QSCD_LIST)) {
				result = ITslMappingConstants.MAPPING_VALUE_NO;
			}

		}

		// Se devuelve el resultado.
		return result;

	}



	/**
	 * Calculates the mapping for the logic field 'certClassification' from the input mapping value
	 * of the logic field 'clasificacion'.
	 * @param classificationValue String representation of the mapping value of the logical field 'clasificacion'.
	 * @return String that represents the mapping classification for the input value. It only can be one of the following:<br>
	 * <ul>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_UNKNOWN}</li>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_CLASSIFICATION_NATURAL_PERSON}</li>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_CLASSIFICATION_LEGALPERSON}</li>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_CLASSIFICATION_ESEAL}</li>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_CLASSIFICATION_ESIG}</li>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_CLASSIFICATION_WSA}</li>
	 *   <li>{@link ITslMappingConstants#MAPPING_VALUE_CLASSIFICATION_TSA}</li>
	 * </ul>
	 */
	public static String calculateMappingCertClassificationFromMappingClassification(String classificationValue) {
	
		String result = ITslMappingConstants.MAPPING_VALUE_UNKNOWN;
	
		// Si la entrada no es nula...
		if (!UtilsStringChar.isNullOrEmptyTrim(classificationValue)) {
	
			try {
	
				// Se intenta parsear.
				Integer classificationValueInteger = Integer.valueOf(classificationValue);
	
				// Miramos primero si es de tipo NATURAL_PERSON.
				Set<Integer> setOfValues = TSLProperties.getClassificationSetForCertClassificationNaturalPerson();
				if (setOfValues.contains(classificationValueInteger)) {
	
					result = ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_NATURAL_PERSON;
	
				} else {
	
					// Ahora si es de tipo LEGAL_PERSON.
					setOfValues = TSLProperties.getClassificationSetForCertClassificationLegalPerson();
					if (setOfValues.contains(classificationValueInteger)) {
	
						result = ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_LEGALPERSON;
	
					} else {
	
						// Ahora si es de tipo ESIG.
						setOfValues = TSLProperties.getClassificationSetForCertClassificationESIG();
						if (setOfValues.contains(classificationValueInteger)) {
	
							result = ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_ESIG;
	
						} else {
	
							// Ahora si es de tipo ESEAL.
							setOfValues = TSLProperties.getClassificationSetForCertClassificationESEAL();
							if (setOfValues.contains(classificationValueInteger)) {
	
								result = ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_ESEAL;
	
							} else {
	
								// Ahora si es de tipo WSA.
								setOfValues = TSLProperties.getClassificationSetForCertClassificationWSA();
								if (setOfValues.contains(classificationValueInteger)) {
	
									result = ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_WSA;
	
								} else {
	
									// Ahora si es de tipo TSA.
									setOfValues = TSLProperties.getClassificationSetForCertClassificationTSA();
									if (setOfValues.contains(classificationValueInteger)) {
	
										result = ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_TSA;
	
									}
	
								}
	
							}
	
						}
	
					}
	
				}
	
			} catch (NumberFormatException e) {
				result = ITslMappingConstants.MAPPING_VALUE_UNKNOWN;
			}
	
		}
	
		return result;
	
	}
	

	/**
	 * Adds the mappings extracted from the TSL information (and certificate) over the mappings configured in the certificate policies.
	 * If the {@link ITslMappingConstants#MAPPING_KEY_CERT_CLASSIFICATION} is with {@link ITslMappingConstants#MAPPING_VALUE_UNKNOWN} in TSL mappings, then is calculated
	 * from the {@link ITslMappingConstants#MAPPING_KEY_CERT_CLASIFICACION} field from the original mappings.
	 * @param certInfoMap Mappings calculated from the certificate policy configuration.
	 * @param certInfoMapFromTSL Mappings calculated from the information in the TSL and the certificate.
	 * @return Map with all the mixed mappings.
	 */
	public static Map<String, String> addMappingsAndCheckCertClassification(Map<String, String> certInfoMap, Map<String, String> certInfoMapFromTSL) {

		// Inicializamos el resultado.
		Map<String, String> result = certInfoMap;

		// Si los mapeos obtenidos de la TSL no son nulos...
		if (certInfoMapFromTSL != null) {

			// Si fuera nulo el resultado, creamos el map.
			if (result == null) {
				result = new HashMap<String, String>();
			}

			// Comprobamos el valor del campo 'certClassification' en los mapeos
			// de la TSL.
			String certClassificationValue = certInfoMapFromTSL.get(ITslMappingConstants.MAPPING_KEY_CERT_CLASSIFICATION);

			// Si es nulo, vació o con valor desconocido, lo modificamos.
			if (UtilsStringChar.isNullOrEmptyTrim(certClassificationValue) || certClassificationValue.equals(ITslMappingConstants.MAPPING_VALUE_UNKNOWN)) {

				certInfoMapFromTSL.put(ITslMappingConstants.MAPPING_KEY_CERT_CLASSIFICATION, calculateMappingCertClassificationFromMappingClassification(result.get(ITslMappingConstants.MAPPING_KEY_CERT_CLASIFICACION)));

			}

			// Añadimos todos los mapeos obtenidos de la TSL, sobrescribiendo
			// los que hubiera en la política de certificación.
			result.putAll(certInfoMapFromTSL);

		}

		// Devolvemos el resultado.
		return result;

	}
	
	
	
	

}
