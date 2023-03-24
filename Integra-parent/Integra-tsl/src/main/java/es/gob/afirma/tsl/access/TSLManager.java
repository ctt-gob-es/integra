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
 * <b>File:</b><p>es.gob.afirma.tsl.access.TSLManager.java.</p>
 * <b>Description:</b><p>Class that reprensents the TSL Manager for all the differents operations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.2, 22/03/2023.
 */
package es.gob.afirma.tsl.access;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

import org.apache.log4j.Logger; 
import es.gob.afirma.tsl.logger.IntegraLogger;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.certValidation.ifaces.ITSLValidator;
import es.gob.afirma.tsl.certValidation.ifaces.ITSLValidatorResult;
import es.gob.afirma.tsl.certValidation.impl.TSLValidatorFactory;
import es.gob.afirma.tsl.certValidation.impl.TSLValidatorMappingCalculator;
import es.gob.afirma.tsl.exceptions.CommonUtilsException;
import es.gob.afirma.tsl.exceptions.TSLArgumentException;
import es.gob.afirma.tsl.exceptions.TSLMalformedException;
import es.gob.afirma.tsl.exceptions.TSLManagingException;
import es.gob.afirma.tsl.exceptions.TSLParsingException;
import es.gob.afirma.tsl.exceptions.TSLValidationException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.parsing.ifaces.ITSLCommonURIs;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.impl.common.TSLObject;
import es.gob.afirma.tsl.utils.StaticTslConfig;
import es.gob.afirma.tsl.utils.UtilsCertificateTsl;
import es.gob.afirma.tsl.utils.UtilsStringChar;

/** 
 * <p>Class that reprensents the TSL Manager for all the differents operations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 22/03/2023.
 */
public final class TSLManager {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(TSLManager.class);

    /**
     * Attribute that represents the unique instance of this class (singleton).
     */
    private static TSLManager instance = null;
    /**
     * Attribute that represents a set of URL (String format) that represents the official
     * european list of trusted lists. 
     */
    private Set<String> setOfURLStringThatRepresentsEuLOTL = new TreeSet<String>();

    /**
     * Attribute that represents a set of URL (String format) that represents the official
     * european list of trusted lists splitted by commas.
     */
    private String setOfURLStringThatRepresentsEuLOTLinString = null;


    /**
     * Constructor method for the class TSLManager.java.
     */
    private TSLManager() {
	super();
    }

    /**
     * Gets the unique instance of this class.
     * @return The unique instance of the {@link TSLManager} class.
     */
    public static TSLManager getInstance() {

	if (instance == null) {
	    instance = new TSLManager();
	}
	return instance;

    }


    /**
     * Method to obtain the TSL mapped from a file.
     * 
     * @param bais InputStream Input Stream of the XML (TSL representation).
     * @return a TSL Data Object representation.
     * @throws TSLManagingException In case of some error getting the information from the file.
     */
    public ITSLObject buildTsl(ByteArrayInputStream bais) throws TSLManagingException {
	ITSLObject tslObject = null;

	tslObject = new TSLObject();
	try {
	    tslObject.buildTSLFromXMLcheckValues(bais);

	} catch (TSLArgumentException e) {
	    LOGGER.error(e.getMessage());
	    throw new TSLManagingException(Language.getResIntegraTsl(ILogTslConstant.TM_LOG001), e);
	} catch (TSLParsingException e) {
	    LOGGER.error(e.getMessage());
	    throw new TSLManagingException(Language.getResIntegraTsl(ILogTslConstant.TM_LOG001), e);
	} catch (TSLMalformedException e) {
	    LOGGER.error(e.getMessage());
	    throw new TSLManagingException(Language.getResIntegraTsl(ILogTslConstant.TM_LOG001), e);
	}

	return tslObject;
    }

    /**
     * Gets the set of URL (String format) that represents the official
     * european list of trusted lists.
     * @return set of URL (String format) that represents the official
     * european list of trusted lists.
     */
    public Set<String> getSetOfURLStringThatRepresentsEuLOTL() {

	// Si aún no se ha inicializado...
	if (setOfURLStringThatRepresentsEuLOTL.isEmpty()) {

	    // Como mínimo añadimos las dos URL conocidas a fecha de 20/08/2019:
	    // -
	    // https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml
	    setOfURLStringThatRepresentsEuLOTL.add(ITSLCommonURIs.TSL_EU_LIST_OF_THE_LISTS_1);
	    setOfURLStringThatRepresentsEuLOTLinString = ITSLCommonURIs.TSL_EU_LIST_OF_THE_LISTS_1;
	    // - https://ec.europa.eu/tools/lotl/eu-lotl.xml
	    setOfURLStringThatRepresentsEuLOTL.add(ITSLCommonURIs.TSL_EU_LIST_OF_THE_LISTS_2);
	    setOfURLStringThatRepresentsEuLOTLinString += UtilsStringChar.SYMBOL_COMMA_STRING;
	    setOfURLStringThatRepresentsEuLOTLinString += UtilsStringChar.SPECIAL_BLANK_SPACE_STRING;
	    setOfURLStringThatRepresentsEuLOTLinString += ITSLCommonURIs.TSL_EU_LIST_OF_THE_LISTS_2;

	    // Ahora recolectamos las establecidas en la configuración estática,
	    // y añadimos aquellas que
	    // no estén ya.
	    Properties props = StaticTslConfig.getProperties(StaticTslConfig.TSL_EU_LOTL_PREFIX);
	    if (props != null && !props.isEmpty()) {
		Collection<Object> urlStringColl = props.values();
		for (Object urlStringObject: urlStringColl) {
		    if (urlStringObject != null) {
			String urlString = ((String) urlStringObject).trim();
			if (!UtilsStringChar.isNullOrEmpty(urlString) && !setOfURLStringThatRepresentsEuLOTL.contains(urlString)) {
			    setOfURLStringThatRepresentsEuLOTL.add(urlString);
			    setOfURLStringThatRepresentsEuLOTLinString += UtilsStringChar.SYMBOL_COMMA_STRING;
			    setOfURLStringThatRepresentsEuLOTLinString += UtilsStringChar.SPECIAL_BLANK_SPACE_STRING;
			    setOfURLStringThatRepresentsEuLOTLinString += urlString;
			}
		    }
		}
	    }

	}

	// Devolvemos el conjunto de URL que reconocen la lista de las TSL
	// europeas...
	return setOfURLStringThatRepresentsEuLOTL;

    }

    /**
    Gets the set of URL (String format) that represents the official
     * european list of trusted lists splitted by commas.
     * @return set of URL (String format) that represents the official
     * european list of trusted lists splitted by commas.
     */
    public String getSetOfURLStringThatRepresentsEuLOTLinString() {

	return setOfURLStringThatRepresentsEuLOTLinString;

    }

    /**
     * Tries to validate the input X509v3 certificate with.
     * @param auditTransNumber Audit transaction number.
     * @param cert X509v3 certificate to validate.
     * @param validationDate Validation date to check.
     * @param checkStatusRevocation Flag that indicates if only try to detect the input certificate (<code>false</code>)
     * or also checks the revocation status of this (<code>true</code>).
     * @param calculateMappings Flag that indicates if it is necessary to calculate the mappings associated if the certificate
     * has been detected (<code>true</code>) or not (<code>false</code>).
     * @param tslObject TSL object representation to use.
     * @return TSL validation result, with all the collected information.
     * @throws TSLManagingException If there is some error with the cache or validating the certificate with the TSL.
     */
    public ITSLValidatorResult validateX509withTSL(X509Certificate cert, Date validationDate, boolean checkStatusRevocation, boolean calculateMappings, TSLObject tslObject) throws TSLManagingException {

	LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.TM_LOG003, new Object[ ] { tslObject.getSchemeInformation().getTslVersionIdentifier(), tslObject.getSchemeInformation().getSchemeTerritory(), tslObject.getSchemeInformation().getTslSequenceNumber() }));

	ITSLValidatorResult result = null;

	// Tratamos de construir el validador de certificados mediante TSL.
	ITSLValidator tslValidator = TSLValidatorFactory.createTSLValidator(tslObject);

	// Si la fecha de validación es nula, utilizamos la fecha actual.
	Date validationDateToUse = validationDate;
	if (validationDateToUse == null) {
	    validationDateToUse = Calendar.getInstance().getTime();
	}

	// Almacenamos en una variable si el certificado está orientado a
	// sellado de tiempo.
	boolean isTsaCertificate = checkIfCertificateIsForTSA(cert);

	// Guardamos en una variable si el certificado se corresponde
	// con el certificado de una CA.
	boolean isCACert = isTsaCertificate ? false : UtilsCertificateTsl.isCA(cert);

	// Ejecutamos la validación del certificado con el validador construido
	// para la fecha indicada.
	try {
	    result = tslValidator.validateCertificateWithTSL(cert, isCACert, isTsaCertificate, validationDateToUse, checkStatusRevocation);
	} catch (TSLArgumentException e) {
	    throw new TSLManagingException(Language.getFormatResIntegraTsl(ILogTslConstant.TM_LOG007, new Object[ ] { tslObject.getSchemeInformation().getSchemeTerritory(), tslObject.getSchemeInformation().getTslSequenceNumber() }), e);
	} catch (TSLValidationException e) {
	    throw new TSLManagingException(Language.getFormatResIntegraTsl(ILogTslConstant.TM_LOG007, new Object[ ] { tslObject.getSchemeInformation().getSchemeTerritory(), tslObject.getSchemeInformation().getTslSequenceNumber() }), e);
	} catch (Exception e){
	    throw new TSLManagingException(Language.getFormatResIntegraTsl(ILogTslConstant.TM_LOG007, new Object[ ] { tslObject.getSchemeInformation().getSchemeTerritory(), tslObject.getSchemeInformation().getTslSequenceNumber() }), e);
	}
	
	//si no se ha producido excepción, el resutlado no es nulo, y el certificado ha sido detectado, calculamos los mapeos asociados.
	if(calculateMappings){
	    calculateMappingsForCertificateAndSetInResult(cert, tslObject, result);
	}

	return result;

    }

    /**
     * Checks if the input certificate has the key purpose for id-kp-timestamping.
     * @param auditTransNumber Audit transaction number.
     * @param cert X509v3 Certificate to check.
     * @return <code>true</code> if the input certificate has the key purpose for id-kp-timestamping,
     * otherwise <code>false</code>.
     * @throws TSLManagingException In case of some error getting the keyPurpose list from the input certificate.
     */
    private boolean checkIfCertificateIsForTSA(X509Certificate cert) throws TSLManagingException {

	try {
	    boolean result = UtilsCertificateTsl.hasCertKeyPurposeTimeStamping(cert);
	    if (result) {
		LOGGER.debug(Language.getResIntegraTsl(ILogTslConstant.TM_LOG004));
	    } 
	    // Añadimos la traza de auditoría...
	    // CommonsCertificatesAuditTraces.addCertIsTsaCert(auditTransNumber,
	    // result);
	    return result;
	} catch (CommonUtilsException e) {
	    throw new TSLManagingException(Language.getResIntegraTsl(ILogTslConstant.TM_LOG006), e);
	}

    }

    /**
	 * Calculates the mapping for the input certificate and set these in the result. If there is some
	 * error parsing any mapping, then this is not returned.
	 * @param cert X509v3 certificate from which extracts the mapping information values.
	 * @param tslObject TSL object representation to use.
	 * @param tslValidationResult TSL validation result in which store the result mappings.
	 */
	private void calculateMappingsForCertificateAndSetInResult(X509Certificate cert, TSLObject tslObject, ITSLValidatorResult tslValidationResult) {
		// Si el resultado no es nulo,
		// y el certificado ha sido detectado,
		// calculamos los mapeos asociados.
		if (tslValidationResult != null && tslValidationResult.hasBeenDetectedTheCertificate()) {

			// Los calculamos y establecemos en el resultado.
			calculateMappingsForCertificateAndSetInResult( cert, tslValidationResult);

		}

	}
	
	/**
	 * Calculates the mapping for the input certificate and set these in the result. If there is some
	 * error parsing any mapping, then this is not returned.
	 * @param cert X509v3 certificate from which extracts the mapping information values.
	 * @param tslValidationResult TSL validation result where store the result mappings.
	 */
	private void calculateMappingsForCertificateAndSetInResult(X509Certificate cert,  ITSLValidatorResult tslValidationResult) {

		// Iniciamos un map donde se almacenarán los pares <NombreMapeo,
		// ValorMapeo>.
		Map<String, String> mappings = new HashMap<String, String>();
		// Extraemos los valores de los mapeos fijos para todas las validaciones
		// mediante TSL.
		TSLValidatorMappingCalculator.extractStaticMappingsFromResult(mappings, tslValidationResult);
		
		// Guardamos los mapeos calculados en el resultado de la validación.
		tslValidationResult.setMappings(mappings);

	}

}
