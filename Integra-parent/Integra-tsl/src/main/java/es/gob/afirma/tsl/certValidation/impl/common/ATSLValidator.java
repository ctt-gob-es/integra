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
 * <b>File:</b><p>es.gob.afirma.tsl.certValidation.impl.common.ATSLValidator.java.</p>
 * <b>Description:</b><p>Abstract class that represents a TSL validator with the principal functions
 * regardless it implementation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 16/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.2, 15/06/2021.
 */
package es.gob.afirma.tsl.certValidation.impl.common;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.apache.log4j.Logger;

import es.gob.afirma.tsl.certValidation.ifaces.ITSLValidator;
import es.gob.afirma.tsl.certValidation.ifaces.ITSLValidatorResult;
import es.gob.afirma.tsl.exceptions.CommonUtilsException;
import es.gob.afirma.tsl.exceptions.TSLArgumentException;
import es.gob.afirma.tsl.exceptions.TSLQualificationEvalProcessException;
import es.gob.afirma.tsl.exceptions.TSLValidationException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.parsing.ifaces.IAnyTypeExtension;
import es.gob.afirma.tsl.parsing.ifaces.ITSLCommonURIs;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.impl.common.DigitalID;
import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;
import es.gob.afirma.tsl.parsing.impl.common.TSLCertificateExtensionAnalyzer;
import es.gob.afirma.tsl.parsing.impl.common.TSPService;
import es.gob.afirma.tsl.parsing.impl.common.TrustServiceProvider;
import es.gob.afirma.tsl.parsing.impl.common.extensions.CriteriaList;
import es.gob.afirma.tsl.parsing.impl.common.extensions.QualificationElement;
import es.gob.afirma.tsl.parsing.impl.common.extensions.Qualifications;
import es.gob.afirma.tsl.utils.UtilsCertificateTsl;
import es.gob.afirma.tsl.utils.UtilsStringChar;

/** 
 * <p>Abstract class that represents a TSL validator with the principal functions
 * regardless it implementation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 15/06/2021.
 */
public abstract class ATSLValidator implements ITSLValidator {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = Logger.getLogger(ATSLValidator.class);

    /**
     * Constant attribute that represents a token for a TSP Service Name when the validation has been executed
     * using the Distribution Point of the certificate to validate.
     */
    public static final String TSP_SERVICE_NAME_FOR_DIST_POINT = "TSPService-Certificate-DistributionPoint";

    /**
     * Attribute that represents the TSL object to use for validate certificates.
     */
    private ITSLObject tsl = null;

    /**
     * Constructor method for the class ATSLValidator.java.
     */
    public ATSLValidator() {
	super();
    }

    /**
     * Constructor method for the class ATSLValidator.java.
     * @param tslObject TSL to use for validate certificates.
     */
    protected ATSLValidator(ITSLObject tslObject) {
	this();
	tsl = tslObject;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.certValidation.ifaces.ITSLValidator#validateCertificateWithTSL(java.lang.String, java.security.cert.X509Certificate, boolean, boolean, java.util.Date, boolean)
     */
    @Override
    public ITSLValidatorResult validateCertificateWithTSL(X509Certificate cert, boolean isCACert, boolean isTsaCertificate, Date validationDate, boolean checkStatusRevocation) throws TSLArgumentException, TSLValidationException {

	// Comprobamos que el certificado de entrada no sea nulo.
	if (cert == null) {
	    throw new TSLArgumentException(Language.getResIntegraTsl(ILogTslConstant.ATV_LOG001));
	}

	// Comprobamos que la fecha de entrada no sea nula.
	if (validationDate == null) {
	    throw new TSLArgumentException(Language.getResIntegraTsl(ILogTslConstant.ATV_LOG002));
	}

	// Calculamos ahora la representación del certificado como objeto IAIK.
	iaik.x509.X509Certificate certIaik = null;
	try {
		certIaik = UtilsCertificateTsl.getIaikCertificate(cert);
	} catch (CommonUtilsException e) {
		throw new TSLValidationException(Language.getResIntegraTsl(ILogTslConstant.TV_LOG022), e);
	}
	// Inicializamos el resultado a devolver.
	TSLValidatorResult result = new TSLValidatorResult(certIaik, getTSLObject());

	// Establecemos si se trata de una norma Europea o externa.
	result.setEuropean(checkIfTSLisFromEuropeanMember());

	// Comprobamos si el tipo de la TSL determina si se trata de una lista
	// de listas...
	if (checkIfTSLisListOfLists(tsl.getSchemeInformation().getTslType().toString())) {

	    // Si se trata de una lista de listas...
	    validateCertificateWithListOfLists(cert, isCACert, isTsaCertificate, validationDate, checkStatusRevocation, result);

	} else {

	    // Si no es una lista de listas, continuamos con la validación.
	    validateCertificate(cert, isCACert, isTsaCertificate, validationDate, checkStatusRevocation, result);

	}

	return result;

    }

    /**
     * Gets the TSL object used to validate certificates.
     * @return the TSL object used to validate certificates.
     */
    protected final ITSLObject getTSLObject() {
	return tsl;
    }

    /**
     * Cehcks if the TSL is from an European Member.
     * @return <code>true</code> if the TSL is from European Member, otherwise <code>false</code>.
     */
    protected abstract boolean checkIfTSLisFromEuropeanMember();

    /**
     * Checks if the TSL is a List of Lists.
     * @param tslType String that represents the TSL type to analyze.
     * @return <code>true</code> if the TSL is a list of lists, otherwise <code>false</code>.
     */
    protected abstract boolean checkIfTSLisListOfLists(String tslType);

    /**
     * Checks if the input TSP Service Type is for a qualified TSA.
     * @param tspServiceType TSP Service type URI to check.
     * @return <code>true</code> if it represents a Qualified TSA TSP Service, otherwise <code>false</code>.
     */
    protected abstract boolean checkIfTSPServiceTypeIsTSAQualified(String tspServiceType);

    /**
     * Checks if the input TSP Service Type is for a non qualified TSA.
     * @param tspServiceType TSP Service type URI to check.
     * @return <code>true</code> if it represents a Non Qualified TSA TSP Service, otherwise <code>false</code>.
     */
    protected abstract boolean checkIfTSPServiceTypeIsTSANonQualified(String tspServiceType);

    /**
     * Checks if the input service status URI defines an OK status.
     * @param serviceStatus Service Status URI string to check.
     * @return <code>true</code> if represents an OK status, otherwise <code>false</code>.
     */
    public abstract boolean checkIfTSPServiceStatusIsOK(String serviceStatus);

    /**
     * Checks if the input TSP Service Type is CA QC.
     * @param tspServiceType TSP Service type URI to check.
     * @return <code>true</code> if it represents a CA QC TSP Service, otherwise <code>false</code>.
     */
    public abstract boolean checkIfTSPServiceTypeIsCAQC(String tspServiceType);

    /**
     * Checks if the input TSP Service Type is CA PKC.
     * @param tspServiceType TSP Service type URI to check.
     * @return <code>true</code> if it represents a CA PKC TSP Service, otherwise <code>false</code>.
     */
    public abstract boolean checkIfTSPServiceTypeIsCAPKC(String tspServiceType);

    /**
     * Checks if the input TSP Service Type is National Root CA for Qualified Certificates.
     * @param tspServiceType TSP Service type URI to check.
     * @return <code>true</code> if it represents a National Root CA QC TSP Service, otherwise <code>false</code>.
     */
    protected abstract boolean checkIfTSPServiceTypeIsNationalRootCAQC(String tspServiceType);

    /**
     * Checks if the certificate is detected by the differents Additional Service Extension of the input TSP Service.
     * @param validationResult Object where stores the validation result data.
     * @param shi Trust Service Provider Service History-Information to use for detect the status of the input certificate.
     * @return <code>null</code> if there is not any AdditionalServiceInformation Extension defined, {@link Boolean#TRUE}
     * if the certificate has the extensions that matches with the defined AdditionalService Extension values,
     * otherwise {@link Boolean#FALSE}.
     */
    protected abstract Boolean checkIfTSPServiceAdditionalServiceInformationExtensionsDetectCert(TSLValidatorResult validationResult, ServiceHistoryInstance shi);

    /**
     * Checks (in function of the TSL Specification) if the input certificate obey the conditions
     * to be detected without need the Qualifications Extension.
     * @param tslCertExtAnalyzer TSL Certificate Extension Analyzer with the certificate to check.
     * @return <code>true</code> if the input certificate obey the conditions
     * to be detected without need the Qualifications Extension, otherwise <code>false</code>.
     */
    protected abstract boolean checkIfCertificateObeyWithConditionsToBeDetected(TSLCertificateExtensionAnalyzer tslCertExtAnalyzer);

    /**
     * Sets the status result according to the service status.
     * @param isCACert Flag that indicates if the input certificate has the Basic Constraints with the CA flag activated
     * (<code>true</code>) or not (<code>false</code>).
     * @param serviceStatus TSP Service Status URI string to analyze.
     * @param serviceStatusStartingTime TSP Service Status starting time.
     * @param validationDate Validation date to check the certificate status revocation.
     * @param validationResult Object where is stored the validation result data.
     */
    protected abstract void setStatusResultInAccordanceWithTSPServiceCurrentStatus(boolean isCACert, String serviceStatus, Date serviceStatusStartingTime, Date validationDate, TSLValidatorResult validationResult);

    /**
    * Validates the input certificate knowing this TSL is a List of Lists.
    * @param cert Certificate X509 v3 to validate.
    * @param isCACert Flag that indicates if the input certificate has the Basic Constraints with the CA flag activated
    * (<code>true</code>) or not (<code>false</code>).
    * @param isTsaCertificate Flag that indicates if the input certificate has the id-kp-timestamping key purpose
    * (<code>true</code>) or not (<code>false</code>).
    * @param validationDate Validation date to check the certificate status revocation.
    * @param checkStatusRevocation Flag that indicates if only try to detect the input certificate (<code>false</code>)
    * or also checks the revocation status of this (<code>true</code>).
    * @param validationResult Object where stores the validation result data.
    */
    private void validateCertificateWithListOfLists(X509Certificate cert, boolean isCACert, boolean isTsaCertificate, Date validationDate, boolean checkStatusRevocation, TSLValidatorResult validationResult) {

	// TODO De momento no se consideran las listas de listas.
	// Si se trata de una lista de listas, la ignoramos y concluímos que no
	// se puede validar el certificado
	// indicando como no detectado (valor por defecto en la respuesta).
	LOGGER.warn(Language.getResIntegraTsl(ILogTslConstant.ATV_LOG003));

    }

    /**
     * Validates the input certificate knowing this TSL is not list of lists.
     * @param cert Certificate X509 v3 to validate.
     * @param isCACert Flag that indicates if the input certificate has the Basic Constraints with the CA flag activated
     * (<code>true</code>) or not (<code>false</code>).
     * @param isTsaCertificate Flag that indicates if the input certificate has the id-kp-timestamping key purpose
     * (<code>true</code>) or not (<code>false</code>).
     * @param validationDate Validation date to check the certificate status revocation.
     * @param checkStatusRevocation Flag that indicates if only try to detect the input certificate (<code>false</code>)
     * or also checks the revocation status of this (<code>true</code>).
     * @param validationResult Object where stores the validation result data.
     * @throws TSLValidationException If there is some error or inconsistency in the certificate validation.
     */
    private void validateCertificate(X509Certificate cert, boolean isCACert, boolean isTsaCertificate, Date validationDate, boolean checkStatusRevocation, TSLValidatorResult validationResult) throws TSLValidationException {

	// Comprobamos que el "Status Determination Approach" no sea
	// "delinquent" o equivalente.
	if (checkIfStatusDeterminationApproachIsDelinquentOrEquivalent(tsl.getSchemeInformation().getStatusDeterminationApproach().toString())) {

	    throw new TSLValidationException(Language.getResIntegraTsl(ILogTslConstant.ATV_LOG004));

	} else {

	    // TODO: Aún no se hace nada con las extensiones del esquema. No se
	    // identifica ninguna.
	    // doSomethingWithSchemeExtensions();

	    // Recuperamos la lista de TSP y vamos analizando uno a uno.
	    List<TrustServiceProvider> tspList = tsl.getTrustServiceProviderList();
	    // Si la lista no es nula ni vacía...
	    if (tspList != null && !tspList.isEmpty()) {

		// La vamos recorriendo mientras no se termine y no se haya
		// modificado el resultado de la validación del certificado.
		for (int index = 0; index < tspList.size() && !validationResult.hasBeenDetectedTheCertificate(); index++) {

		    // Almacenamos en una variable el TSP a tratar.
		    TrustServiceProvider tsp = tspList.get(index);

		    // Validamos el certificado respecto al TSP.
		    try {
			validateCertificateWithTSP(cert, isCACert, isTsaCertificate, validationDate, validationResult, tsp, checkStatusRevocation);
		    } catch (TSLQualificationEvalProcessException e) {

			// Si se produce esta excepción, significa que se
			// produjo un error
			// evaluando el certificado frente a un CriteriaList de
			// un QualificationExtension,
			// siendo esta una extensión crítica. En consecuencia se
			// debe considerar
			// como certificado no detectado, e impedir que se
			// continúen evaluando
			// otros servicios.
			// Mostramos en el log el motivo y la excepción.
			LOGGER.error(Language.getResIntegraTsl(ILogTslConstant.ATV_LOG019));
			LOGGER.error(e.getMessage(), e);
			// Limpiamos toda la información acumulada hasta el
			// momento.
			validationResult.resetAllData();
			// Cancelamos que el proceso continúe.
			break;

		    }

		    // Si el certificado se ha detectado, almacenamos el TSP
		    // usado
		    // y su nombre.
		    if (validationResult.hasBeenDetectedTheCertificate()) {
			assignTSPandNameToResult(validationResult, tsp);
		    }

		}

	    }

	    // Si no ha sido detectado el certificado, lo indicamos en
	    // auditoría.
	    if (!validationResult.hasBeenDetectedTheCertificate()) {
		LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.ATV_LOG020));

	    }

	}

	// Mostramos en el log si el certificado ha sido detectado/validado y
	// por cual TSP y servicio.
	showInLogResultOfValidation(validationResult, checkStatusRevocation);

    }

    /**
    * Tries to validate the input certificate with the input Trust Service Provider information.
    * @param cert Certificate X509 v3 to validate.
    * @param isCACert Flag that indicates if the input certificate has the Basic Constraints with the CA flag activated
    * (<code>true</code>) or not (<code>false</code>).
    * @param isTsaCertificate Flag that indicates if the input certificate has the id-kp-timestamping key purpose
    * (<code>true</code>) or not (<code>false</code>).
    * @param validationDate Validation date to check the certificate status revocation.
    * @param validationResult Object where stores the validation result data.
    * @param tsp Trust Service Provider to use for validate the status of the input certificate.
    * @param checkStatusRevocation Flag that indicates if only try to detect the input certificate (<code>false</code>)
    * or also checks the revocation status of this (<code>true</code>).
    * @throws TSLQualificationEvalProcessException In case of some error evaluating the Criteria List of a Qualification
    * Extension over the input certificate, and being critical that Qualification Extension.
    */
    private void validateCertificateWithTSP(X509Certificate cert, boolean isCACert, boolean isTsaCertificate, Date validationDate, TSLValidatorResult validationResult, TrustServiceProvider tsp, boolean checkStatusRevocation) throws TSLQualificationEvalProcessException {

	// TODO: Aún no se hace nada con las extensiones del TSP. No se
	// identifica ninguna.
	// doSomethingWithTSPExtensions();

	// Obtenemos la lista de servicios.
	List<TSPService> tspServiceList = tsp.getAllTSPServices();

	// Si la lista no es nula ni vacía...
	if (tspServiceList != null && !tspServiceList.isEmpty()) {

	    // La vamos recorriendo mientras no se termine y no se haya
	    // detectado el certificado.
	    for (int index = 0; index < tspServiceList.size() && !validationResult.hasBeenDetectedTheCertificate(); index++) {

		// Almacenamos en una variable el servicio a analizar en esta
		// vuelta.
		TSPService tspService = tspServiceList.get(index);

		// Tratamos de detectar el certificado respecto al servicio...
		detectCertificateWithTSPService(cert, isCACert, isTsaCertificate, validationDate, validationResult, tspService);

		// Si el certificado se ha detectado...
		if (validationResult.hasBeenDetectedTheCertificate()) {

		    // Almacenamos el nombre del TSP Service usado.
		    assignTSPServiceNameForDetectToResult(validationResult, tspService);
		    // Y el servicio.
		    validationResult.setTSPServiceForDetect(tspService);

		    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.ATV_LOG015));
		    // Si el estado no es desconocido, significa que ya se ha
		    // determinado la validez del certificado,
		    // por lo que asignamos el mismo nombre de servicio al
		    // resultado de la validación (y el servicio).
		    if (!validationResult.hasBeenDetectedTheCertificateWithUnknownState()) {
			LOGGER.debug(Language.getResIntegraTsl(ILogTslConstant.ATV_LOG014));
			validationResult.setResultFromServiceStatus(Boolean.TRUE);
			validationResult.setResultFromDPorAIA(Boolean.FALSE);
			validationResult.setTSPServiceNameForValidate(validationResult.getTSPServiceNameForDetect());
			validationResult.setTSPServiceForValidate(validationResult.getTSPServiceForDetect());
			validationResult.setTspServiceHistoryInformationInstanceNameForValidate(validationResult.getTSPServiceHistoryInformationInstanceNameForDetect());
			validationResult.setTspServiceHistoryInformationInstanceForValidate(validationResult.getTSPServiceHistoryInformationInstanceForDetect());
			// Indicamos que se considera validado por el servicio
			// en auditoría.
			LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.ATV_LOG016));

		    }

		}

	    }

	}

    }

    /**
     * Check if the Status Determination Approach of the TSL is set to Delinquent or equivalent.
     * @param statusDeterminationApproach String that represents the Status Determination Approach to check.
     * @return <code>true</code> if the Status Determination Approach of the TSL is set to Delinquent or equivalent,
     * otherwise <code>false</code>.
     */
    protected abstract boolean checkIfStatusDeterminationApproachIsDelinquentOrEquivalent(String statusDeterminationApproach);

    /**
     * Tries to detect the input certificate with the input Trust Service Provider Service information.
     * @param cert Certificate X509 v3 to detect.
     * @param isCACert Flag that indicates if the input certificate has the Basic Constraints with the CA flag activated
     * (<code>true</code>) or not (<code>false</code>).
     * @param isTsaCertificate Flag that indicates if the input certificate has the id-kp-timestamping key purpose
     * (<code>true</code>) or not (<code>false</code>).
     * @param validationDate Validation date to check the certificate status revocation.
     * @param validationResult Object where is stored the validation result data.
     * @param tspService Trust Service Provider Service to use for detect the input certificate.
     * @throws TSLQualificationEvalProcessException In case of some error evaluating the Criteria List of a Qualification
     * Extension over the input certificate, and being critical that Qualification Extension.
     */
    private void detectCertificateWithTSPService(X509Certificate cert, boolean isCACert, boolean isTsaCertificate, Date validationDate, TSLValidatorResult validationResult, TSPService tspService) throws TSLQualificationEvalProcessException {

	// Primero, en función de la fecha indicada, comprobamos
	// si tenemos que hacer uso de este servicio o de alguno
	// de sus históricos.
	ServiceHistoryInstance shi = null;
	boolean isHistoricServiceInf = false;
	if (tspService.getServiceInformation().getServiceStatusStartingTime().before(validationDate)) {

	    if (tspService.getServiceInformation().isServiceValidAndUsable()) {
		shi = tspService.getServiceInformation();
	    }

	} else {

	    if (tspService.isThereSomeServiceHistory()) {

		List<ServiceHistoryInstance> shiList = tspService.getAllServiceHistory();
		for (ServiceHistoryInstance shiFromList: shiList) {
		    if (shiFromList.getServiceStatusStartingTime().before(validationDate)) {
			if (shiFromList.isServiceValidAndUsable()) {
			    shi = shiFromList;
			    isHistoricServiceInf = true;
			}
			break;
		    }
		}

	    }

	}

	// Si hemos encontrado al menos uno, intentamos detectar el certificado
	// con esa información de servicio.
	if (shi != null) {
	    detectCertificateWithTSPServiceHistoryInstance(cert, isCACert, isTsaCertificate, validationDate, validationResult, tspService, shi, isHistoricServiceInf);
	}

    }

    /**
     * Tries to detect the input certificate with the input Trust Service Provider Service History Information.
     * @param cert Certificate X509 v3 to detect.
     * @param isCACert Flag that indicates if the input certificate has the Basic Constraints with the CA flag activated
     * (<code>true</code>) or not (<code>false</code>).
     * @param isTsaCertificate Flag that indicates if the input certificate has the id-kp-timestamping key purpose
     * (<code>true</code>) or not (<code>false</code>).
     * @param validationDate Validation date to check the certificate status revocation.
     * @param validationResult Object where is stored the validation result data.
     * @param tspService Trust Service Provider Service to use for detect the input certificate.
     * @param shi Trust Service Provider Service History-Information to use for detect the input certificate.
     * @param isHistoricServiceInf Flag that indicates if the input Service Information is from an Historic Service (<code>true</code>)
     * or not (<code>false</code>).
     * @throws TSLQualificationEvalProcessException In case of some error evaluating the Criteria List of a Qualification
     * Extension over the input certificate, and being critical that Qualification Extension.
     */
    private void detectCertificateWithTSPServiceHistoryInstance(X509Certificate cert, boolean isCACert, boolean isTsaCertificate, Date validationDate, TSLValidatorResult validationResult, TSPService tspService, ServiceHistoryInstance shi, boolean isHistoricServiceInf) throws TSLQualificationEvalProcessException {

	// Obtenemos el tipo del servicio.
	String tspServiceType = shi.getServiceTypeIdentifier().toString();

	// Si el certificado corresponde con uno de sello de tiempo, tendremos
	// en cuenta
	// tan solo los servicios de tipo TSA.
	if (isTsaCertificate) {

	    // Comprobamos si el servicio es de tipo TSA (cualificado o no).
	    if (checkIfTSPServiceTypeIsTSAQualified(tspServiceType) || checkIfTSPServiceTypeIsTSANonQualified(tspServiceType)) {

		// Comprobamos si dicho servicio identifica al certificado...
		if (checkIfDigitalIdentitiesMatchesCertificate(shi.getAllDigitalIdentities(), cert, isTsaCertificate)) {

		    // Establecemos la clasificación a sello de tiempo.
		    validationResult.setMappingClassification(ITSLValidatorResult.MAPPING_CLASSIFICATION_TSA);

		    // Establecemos su tipo.
		    // Si es una TSA "qualified"...
		    if (checkIfTSPServiceTypeIsTSAQualified(tspServiceType)) {

			validationResult.setMappingType(ITSLValidatorResult.MAPPING_TYPE_QUALIFIED);

		    }
		    // Si no...
		    else if (checkIfTSPServiceTypeIsTSANonQualified(tspServiceType)) {

			validationResult.setMappingType(ITSLValidatorResult.MAPPING_TYPE_NONQUALIFIED);

		    }

		    // Indicamos que es detectado.
		    validationResult.setResult(ITSLValidatorResult.RESULT_DETECTED_STATE_UNKNOWN);

		    // Se establece el resultado según el estado del servicio.
		    setStatusResultInAccordanceWithTSPServiceCurrentStatus(isCACert, shi.getServiceStatus().toString(), shi.getServiceStatusStartingTime(), validationDate, validationResult);

		    // Si se trata de un servicio histórico, guardamos la
		    // información
		    // de este.
		    if (isHistoricServiceInf) {
			assignTSPServiceHistoryInformationNameForDetectToResult(validationResult, shi);
			validationResult.setTSPServiceHistoryInformationInstanceForDetect(shi);
		    }

		}

	    }

	}
	// Si no, los servicios de tipo CA.
	else {

	    // Comprobamos si el servicio es de tipo CA (certificados
	    // cualificados o no).
	    if (checkIfTSPServiceTypeIsCAQC(tspServiceType) || checkIfTSPServiceTypeIsCAPKC(tspServiceType) || checkIfTSPServiceTypeIsNationalRootCAQC(tspServiceType)) {

		// Comprobamos si dicho servicio identifica al certificado...
		// Si es una CA, comprobamos en sus identidades digitales que
		// coincida con alguna de las declaradas, si no,
		// que alguna de estas sea la emisora del certificado.
		if (checkIfCADigitalIdentitiesVerifyCertificateAndSetItInResult(shi.getAllDigitalIdentities(), cert, isCACert, validationResult)) {

		    // Creamos una bandera que indica si de momento hemos
		    // detectado el certificado.
		    Boolean detectedCert = null;

		    // Si se trata de una TSL de un miembro europeo y de una CA
		    // para certificados "qualified"...
		    if (checkIfTSLisFromEuropeanMember() && (checkIfTSPServiceTypeIsCAQC(tspServiceType) || checkIfTSPServiceTypeIsNationalRootCAQC(tspServiceType))) {

			// Si es el certificado de una CA...
			if (isCACert) {

			    // La consideramos detectada y cualificada.
			    detectedCert = Boolean.TRUE;
			    validationResult.setMappingType(ITSLValidatorResult.MAPPING_TYPE_QUALIFIED);

			}
			// Si es un tipo final...
			else {

			    // Comprobamos que los valores de las extensiones
			    // AdditionalServiceInformation concuerdan con
			    // los del certificado. Esto depende de la
			    // especificación.
			    detectedCert = checkIfTSPServiceAdditionalServiceInformationExtensionsDetectCert(validationResult, shi);

			    // Si se ha obtenido null, es porque no está
			    // definida la
			    // extensión
			    // AdditionalServiceInformation, en cuyo caso
			    // consideramos que el
			    // certificado NO es cualificado (al menos de
			    // momento).
			    if (detectedCert == null) {

				// TODO Según se indica en la especificación y
				// así
				// confirma MINETUR,
				// la extensión AdditionalServiceInformation
				// debe
				// ser obligatoria (cumplirla) en este caso.
				// Por consenso con Dirección de Proyecto se
				// permite
				// su relajación.
				// Lo informamos en un mensaje de log.
				LOGGER.warn(Language.getResIntegraTsl(ILogTslConstant.ATV_LOG011));
				validationResult.setMappingType(ITSLValidatorResult.MAPPING_TYPE_NONQUALIFIED);

			    }
			    // Si se ha encontrado la extensión, y el
			    // certificado
			    // encaja con su
			    // definición, entonces lo consideramos cualificado.
			    else if (detectedCert.booleanValue()) {

				validationResult.setMappingType(ITSLValidatorResult.MAPPING_TYPE_QUALIFIED);

			    }

			    // Por último, si está definida la extensión pero el
			    // certificado no encaja
			    // con su definición, consideramos que desconocemos
			    // si
			    // es cualificado o no.

			    // Comprobamos en la extensión qualifications si se
			    // // detecta el tipo de certificado.
			    boolean detectedInQualificationsExtension = checkIfTSPServiceQualificationsExtensionsDetectCert(cert, validationResult, shi);

			    // Concluimos si consideramos detectado el
			    // certificado
			    // en función del valor que ya tuviera y el obtenido
			    // analizando la extensión Qualifications.
			    detectedCert = detectedCert == null ? detectedInQualificationsExtension : detectedCert || detectedInQualificationsExtension;

			}

		    }

		    // Si se trata de una CA/PKC, sabemos que es un certificado
		    // "non qualified".
		    if (checkIfTSPServiceTypeIsCAPKC(tspServiceType) || isWithdrawnBeforeDateOfIssue(cert, tspService)) {

			validationResult.setMappingType(ITSLValidatorResult.MAPPING_TYPE_NONQUALIFIED);

		    }

		    // Si finalmente hemos detectado el certificado, o es una
		    // CA PKC:
		    // 1 - establecemos el resultado como detectado.
		    // 2 - lo modificamos según el estado del servicio.
		    // define la clasificación del certificado
		    // (si no se ha determinado ya).
		    if (detectedCert != null || checkIfTSPServiceTypeIsCAPKC(tspServiceType)) {
			// Indicamos que es detectado.
			validationResult.setResult(ITSLValidatorResult.RESULT_DETECTED_STATE_UNKNOWN);
			// Se establece el resultado según el estado.
			setStatusResultInAccordanceWithTSPServiceCurrentStatus(isCACert, shi.getServiceStatus().toString(), shi.getServiceStatusStartingTime(), validationDate, validationResult);
			// Guardamos la información del servicio histórico
			// usado.
			if (isHistoricServiceInf) {
			    assignTSPServiceHistoryInformationNameForDetectToResult(validationResult, shi);
			    validationResult.setTSPServiceHistoryInformationInstanceForDetect(shi);
			}

		    }

		}

	    }

	}

    }

    /**
     * Checks if some of the input identities matches with the input X509v3 certificate.
     * @param digitalIdentitiesList List of digital identities.
     * @param cert X509v3 certificate to check.
     * @param isTsaService Flag to indicate if the digital identities are from a TSA Service or a
     * CA Service.
     * @return <code>true</code> if the certificate matches with some of the input identities, otherwise <code>false</code>.
     */
    private boolean checkIfDigitalIdentitiesMatchesCertificate(List<DigitalID> digitalIdentitiesList, X509Certificate cert, boolean isTsaService) {

	// Por defecto consideramos que no coincide con ninguna identidad,
	// y a la primera identidad que coincida, se le cambia el resultado.
	boolean result = false;

	// Si la lista de identidades no es nula ni vacía...
	if (digitalIdentitiesList != null && !digitalIdentitiesList.isEmpty()) {

	    // Creamos el procesador de identidades digitales.
	    DigitalIdentitiesProcessor dip = new DigitalIdentitiesProcessor(digitalIdentitiesList);
	    // Procesamos el certificado a validar.
	    result = dip.checkIfDigitalIdentitiesMatchesCertificate(cert);

	    // Si se ha encontrado, lo indicamos en el log.
	    if (result) {
		if (isTsaService) {
		    LOGGER.debug(Language.getResIntegraTsl(ILogTslConstant.ATV_LOG005));
		} else {
		    LOGGER.debug(Language.getResIntegraTsl(ILogTslConstant.ATV_LOG006));
		}
	    }

	} else {

	    // Si no hay identidades digitales, se considera que no se ha
	    // encontrado.
	    result = false;

	}

	return result;

    }

    /**
     * Method that assign the TSP Service name used to detect the certificate to the validation result.
     * @param validationResult Object where is stored the validation result data.
     * @param shi TSP Service History Information used for detect the input certificate.
     */
    private void assignTSPServiceHistoryInformationNameForDetectToResult(TSLValidatorResult validationResult, ServiceHistoryInstance shi) {

	// Verificamos que haya algún nombre asignado al servicio.
	if (shi.isThereSomeServiceName()) {

	    // Recuperamos el correspondiente al idioma inglés por defecto.
	    String shiName = shi.getServiceNameInLanguage(Locale.UK.getLanguage());

	    // Si no lo hemos obtenido, tomamos el primer nombre que
	    // aparezca.
	    if (UtilsStringChar.isNullOrEmptyTrim(shiName)) {
		Map<String, String> shiMap = shi.getServiceNames();
		shiName = shiMap.values().iterator().next();
	    }

	    // Si lo hemos obtenido, asignamos el nombre al resultado.
	    if (!UtilsStringChar.isNullOrEmptyTrim(shiName)) {
		validationResult.setTSPServiceHistoryInformationInstanceNameForDetect(shiName);
	    }

	}

    }

    /**
     * Method that assign the TSP Service name used to detect the certificate to the validation result.
     * @param validationResult Object where is stored the validation result data.
     * @param tspService TSP Service used for detect the input certificate.
     */
    private void assignTSPServiceNameForDetectToResult(TSLValidatorResult validationResult, TSPService tspService) {

	// Verificamos que haya algún nombre asignado al servicio.
	if (tspService.getServiceInformation().isThereSomeServiceName()) {

	    // Recuperamos el correspondiente al idioma inglés por defecto.
	    String serviceName = tspService.getServiceInformation().getServiceNameInLanguage(Locale.UK.getLanguage());

	    // Si no lo hemos obtenido, tomamos el primer nombre que
	    // aparezca.
	    if (UtilsStringChar.isNullOrEmptyTrim(serviceName)) {
		Map<String, String> tspServiceNamesMap = tspService.getServiceInformation().getServiceNames();
		serviceName = tspServiceNamesMap.values().iterator().next();
	    }

	    // Si lo hemos obtenido, asignamos el nombre al resultado.
	    if (!UtilsStringChar.isNullOrEmptyTrim(serviceName)) {
		validationResult.setTSPServiceNameForDetect(serviceName);
	    }

	}

    }

    /**
     * Checks if some of the input CA identities detect the input X509v3 certificate and then set its information
     * on the result.
     * @param digitalIdentitiesList List of CA digital identities.
     * @param cert X509v3 certificate to check.
     * @param isCACert Flag that indicates if the input certificate has the Basic Constraints with the CA flag activated
     * (<code>true</code>) or not (<code>false</code>).
     * @param validationResult Object where is stored the validation result data.
     * @return <code>true</code> if the certificate is issued by some of the input identities, otherwise <code>false</code>.
     */
    private boolean checkIfCADigitalIdentitiesVerifyCertificateAndSetItInResult(List<DigitalID> digitalIdentitiesList, X509Certificate cert, boolean isCACert, TSLValidatorResult validationResult) {

	// Por defecto consideramos que no lo detecta,
	// y a la primera identidad
	// que coincida, se le cambia el resultado.
	boolean result = false;

	// Si la lista de identidades no es nula ni vacía...
	if (digitalIdentitiesList != null && !digitalIdentitiesList.isEmpty()) {

	    // Creamos el procesador de identidades digitales.
	    DigitalIdentitiesProcessor dip = new DigitalIdentitiesProcessor(digitalIdentitiesList);
	    // Procesamos el certificado a validar y modificamos el resultado si
	    // fuera necesario.
	    if (isCACert) {
		result = dip.checkIfDigitalIdentitiesMatchesCertificate(cert);
	    } else {
		result = dip.checkIfCertificateIsIssuedBySomeIdentity(cert, validationResult);
	    }

	    // Si se ha encontrado el certificado, lo indicamos en el
	    // log.
	    if (result) {

		LOGGER.debug(Language.getResIntegraTsl(ILogTslConstant.ATV_LOG009));

		// Además, si el certificado es de CA y autoemitido, podemos
		// definir
		// las propiedades de su emisor (él mismo).
		if (isCACert && UtilsCertificateTsl.isSelfSigned(cert)) {
//TODO como obtener issuerCert iaik
		    //validationResult.setIssuerCert(cert);
		    validationResult.setIssuerPublicKey(cert.getPublicKey());
		    try {
			validationResult.setIssuerSubjectName(UtilsCertificateTsl.getCertificateId(cert));
		    } catch (CommonUtilsException e) {
			LOGGER.warn(Language.getResIntegraTsl(ILogTslConstant.ATV_LOG010));
		    }

		}

	    }

	} else {

	    // Si no hay identidades digitales, se considera que no se ha
	    // encontrado.
	    result = false;

	}

	return result;

    }

    /**
     * Checks if the input certificate is detected by the criterias on the Qualifications Extension of the input TSP Service.
     * @param cert Certificate X509 v3 to detect.
     * @param validationResult Object where stores the validation result data.
     * @param shi Trust Service Provider Service History-Information to use for detect the status of the input certificate.
     * @return <code>true</code> if the certificate is detected by the criterias on the Qualifications Extension of the input
     * TSP Service, otherwise <code>false</code>.
     * @throws TSLQualificationEvalProcessException In case of some error evaluating the criteria list of the Qualifications
     * extension over the input certificate and the extension is critical.
     */
    private boolean checkIfTSPServiceQualificationsExtensionsDetectCert(X509Certificate cert, TSLValidatorResult validationResult, ServiceHistoryInstance shi) throws TSLQualificationEvalProcessException {

	boolean result = false;

	// Creamos una bandera para indicar si ya se ha analizado
	// una extension Qualifications.
	boolean qualificationExtAlreadyChecked = false;

	// Recuperamos la lista de extensiones del servicio, y si no es nula ni
	// vacía, continuamos.
	List<IAnyTypeExtension> extensionsList = shi.getServiceInformationExtensions();
	if (extensionsList != null && !extensionsList.isEmpty()) {

	    // Recorremos la lista buscando el elemento Qualifications.
	    for (IAnyTypeExtension extension: extensionsList) {

		// Si es del tipo Qualifications...
		if (extension.getImplementationExtension() == IAnyTypeExtension.IMPL_QUALIFICATIONS) {

		    // Indicamos que ya se analiza una extension Qualifications.
		    qualificationExtAlreadyChecked = true;
		    // Obtenemos el objeto Qualifications Extension.
		    Qualifications qualificationsExtension = (Qualifications) extension;
		    try {
			// Iniciamos la comprobación según los criteria.
			result = checkIfTSPServiceQualificationsExtensionsDetectCert(cert, validationResult, shi, qualificationsExtension);
		    } catch (TSLQualificationEvalProcessException e) {
			// Si la extensión es crítica, propagamos la excepción.
			if (qualificationsExtension.isCritical()) {
			    throw e;
			} else {
			    // Al no ser crítica, simplemente lo notificamos con
			    // un warn y continuamos.
			    LOGGER.warn(Language.getResIntegraTsl(ILogTslConstant.ATV_LOG012));
			}
		    }

		    // Dejamos de recorrer las extensiones.
		    break;

		}

	    }

	}

	// Si no se encontró ningún Qualifications Extensions...
	if (!qualificationExtAlreadyChecked) {

	    // Según la especificación de TSL, puede considerarse detectado si
	    // se cumplen una serie de condiciones en el certificado, como que
	    // se pueda saber por sus atributos/extensiones si es QC, si está
	    // almacenado en un SSCD/QSCD... etc.
	    result = checkIfCertificateObeyWithConditionsToBeDetected(validationResult.getTslCertificateExtensionAnalyzer());

	    // Si se comprueba, el certificado pasa a considerarse cualificado.
	    if (result) {
		validationResult.setMappingType(ITSLValidatorResult.MAPPING_TYPE_QUALIFIED);
	    } else {
		// TODO IMPORTANTE: Se ha decidido en coordinación con Dirección
		// de Proyecto suavizar esta condición, de modo que si no se ha
		// encontrado la extensión Qualifications, y aún así, el
		// certificado no cumple las condiciones necesarias, se
		// considere detectado.
		LOGGER.warn(Language.getResIntegraTsl(ILogTslConstant.ATV_LOG013));
	    }

	}

	return result;

    }

    /**
     * Checks if the input certificate is detected by the criterias on the Qualifications Extension of the input TSP Service.
     * @param cert Certificate X509 v3 to detect.
     * @param validationResult Object where is stored the validation result data.
     * @param shi Trust Service Provider Service History-Information to use for detect the status of the input certificate.
     * @param qualificationsExtension Qualifications Extension to use.
     * @return <code>true</code> if the certificate has been detected, otherwise <code>false</code>.
     * @throws TSLQualificationEvalProcessException In case of some error evaluating the criteria list over
     * the input certificate.
     */
    private boolean checkIfTSPServiceQualificationsExtensionsDetectCert(X509Certificate cert, TSLValidatorResult validationResult, ServiceHistoryInstance shi, Qualifications qualificationsExtension) throws TSLQualificationEvalProcessException {

	boolean result = false;

	// Recorremos la lista de Qualifications mientras no encontremos uno que
	// encaje con el certificado.
	for (QualificationElement qe: qualificationsExtension.getQualificationsList()) {

	    // Primero analizamos si se cumplen los criteria para detectar el
	    // certificado.
	    // Obtenemos la lista de criterios.
	    CriteriaList cl = qe.getCriteriaList();
	    // Analizamos el certificado.
	    if (cl.checkCertificate(cert)) {

		// Ya seguro que al menos un criteria ha identificado el
		// certificado.
		result = true;
		// Si se cumplen, analizamos los Qualifiers para determinar
		// mapeos
		// del certificado.
		analyzeQualifiersToSetMappings(validationResult, qe);

		// No paramos el bucle porque es posible que cumpla otros
		// criterias que determinen
		// más qualifiers para los mapeos.

	    }

	}

	return result;

    }

    /**
     * Analyze the qualifiers and set the mapping in the validation result object.
     * @param validationResult Object where is stored the validation result data.
     * @param qe Qualification element to analyze.
     */
    private void analyzeQualifiersToSetMappings(TSLValidatorResult validationResult, QualificationElement qe) {

	// Si hay algún qualifier...
	if (qe.isThereSomeQualifierUri()) {

	    for (URI qualifierUri: qe.getQualifiersList()) {

		analyzeQualifierToSetMapping(validationResult, qualifierUri.toString());

	    }

	}

    }

    /**
     * Analyze the qualifier URI and set the mapping in the validation result object.
     * @param validationResult Object where is stored the validation result data.
     * @param qualifierUriString Qualifier URI String to analyze.
     */
    protected abstract void analyzeQualifierToSetMapping(TSLValidatorResult validationResult, String qualifierUriString);

    /**
     * Checks if the service type is a CRL compatible type. It will be compatible when the certificate was qualified,
     * and this service was for qualified certificates, or the certificate is not qualified, and the service is for not qualified.
     * @param shi TSP Service History Information to analyze.
     * @param isCertQualified Flag that indicates if the certificate is qualified (<code>true</code>) or not (<code>false</code>).
     * @return <code>true</code> if the Service type is CRL compatible with the certificate to validate. otherwise <code>false</code>.
     */
    public abstract boolean checkIfTSPServiceTypeIsCRLCompatible(ServiceHistoryInstance shi, boolean isCertQualified);

    /**
     * Checks if the service type is a OCSP compatible type. It will be compatible when the certificate was qualified,
     * and this service was for qualified certificates, or the certificate is not qualified, and the service is for not qualified.
     * @param shi TSP Service History Information to analyze.
     * @param isCertQualified Flag that indicates if the certificate is qualified (<code>true</code>) or not (<code>false</code>).
     * @return <code>true</code> if the Service type is OCSP compatible with the certificate to validate. otherwise <code>false</code>.
     */
    public abstract boolean checkIfTSPServiceTypeIsOCSPCompatible(ServiceHistoryInstance shi, boolean isCertQualified);


    /**
     * Method that assign the TSP and its name to the validation result.
     * @param validationResult Object where stores the validation result data.
     * @param tsp Trust Service Provider to use for validate the status of the input certificate.
     */
    private void assignTSPandNameToResult(TSLValidatorResult validationResult, TrustServiceProvider tsp) {

	validationResult.setTSP(tsp);

	String tspName = getTSPName(tsp);

	if (tspName != null) {
	    validationResult.setTSPName(tspName);
	}

    }

    /**
     * Auxiliar method to extract a TSP name from the TSP provider.
     * @param tsp TSP provider from which extracts the name.
     * @return TSP name from the TSP provider.
     */
    private String getTSPName(TrustServiceProvider tsp) {

	String result = null;

	// Verificamos que haya algún nombre asignado al TSP.
	if (tsp.getTspInformation().isThereSomeName()) {

	    // Recuperamos el correspondiente al idioma inglés por defecto.
	    List<String> tspNamesEnglish = tsp.getTspInformation().getTSPNamesForLanguage(Locale.UK.getLanguage());

	    // Si lo hemos obtenido, asignamos el nombre al resultado.
	    if (tspNamesEnglish != null && !tspNamesEnglish.isEmpty()) {

		result = tspNamesEnglish.get(0);

	    } else {

		// Si no lo hemos obtenido, tomamos el primer nombre que
		// aparezca.
		Map<String, List<String>> tspNames = tsp.getTspInformation().getAllTSPNames();
		tspNamesEnglish = tspNames.values().iterator().next();
		// Si lo hemos obtenido, asignamos el nombre al resultado.
		if (tspNamesEnglish != null && !tspNamesEnglish.isEmpty()) {

		    result = tspNamesEnglish.get(0);

		}

	    }

	}

	return result;

    }

    /**
     * Shows in log the result of the validation.
     * @param validationResult Object where is stored the validation result data.
     * @param checkStatusRevocation Flag that indicates if only try to detect the input certificate (<code>false</code>)
     * or also checks the revocation status of this (<code>true</code>).
     */
    private void showInLogResultOfValidation(TSLValidatorResult validationResult, boolean checkStatusRevocation) {

	// Si el certificado ha sido detectado...
	if (validationResult.hasBeenDetectedTheCertificate()) {

	    String detectedWithShiMsg = UtilsStringChar.EMPTY_STRING;
	    if (validationResult.getTSPServiceForDetect().getServiceInformation() == validationResult.getTSPServiceHistoryInformationInstanceForDetect()) {
		detectedWithShiMsg = Language.getFormatResIntegraTsl(ILogTslConstant.ATV_LOG021, new Object[ ] { validationResult.getTSPServiceHistoryInformationInstanceNameForDetect(), validationResult.getTSPServiceHistoryInformationInstanceForDetect().getServiceStatusStartingTime() });
	    }

	    // Lo analizamos en función de si se ha comprobado su estado de
	    // revocación.
	    // Si se desconoce el estado del certificado...
	    if (validationResult.hasBeenDetectedTheCertificateWithUnknownState()) {
		 LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.ATV_LOG031, new Object[ ] { validationResult.getTSPName(), validationResult.getTSPServiceNameForDetect() }));

	    }
	    // Si el certificado ha sido detectado y validado...
	    else {

		if (UtilsStringChar.isNullOrEmptyTrim(validationResult.getTSPServiceNameForValidate())) {

		    // En función del resultado exacto...
		    switch (validationResult.getResult()) {

			case ITSLValidatorResult.RESULT_DETECTED_STATE_VALID:
			    LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.ATV_LOG028, new Object[ ] { validationResult.getTSPName(), validationResult.getTSPServiceNameForDetect(), detectedWithShiMsg, Language.getResIntegraTsl(ILogTslConstant.ATV_LOG023) }));
			    break;

			case ITSLValidatorResult.RESULT_DETECTED_STATE_REVOKED:
			    LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.ATV_LOG028, new Object[ ] { validationResult.getTSPName(), validationResult.getTSPServiceNameForDetect(), detectedWithShiMsg, Language.getResIntegraTsl(ILogTslConstant.ATV_LOG024) }));
			    break;

			case ITSLValidatorResult.RESULT_DETECTED_STATE_CERTCHAIN_NOTVALID:
			    LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.ATV_LOG028, new Object[ ] { validationResult.getTSPName(), validationResult.getTSPServiceNameForDetect(), detectedWithShiMsg, Language.getResIntegraTsl(ILogTslConstant.ATV_LOG025) }));
			    break;

			case ITSLValidatorResult.RESULT_DETECTED_STATE_REVOKED_SERVICESTATUS:
			    LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.ATV_LOG028, new Object[ ] { validationResult.getTSPName(), validationResult.getTSPServiceNameForDetect(), detectedWithShiMsg, Language.getResIntegraTsl(ILogTslConstant.ATV_LOG026) }));
			    break;

			case ITSLValidatorResult.RESULT_DETECTED_STATE_CERTCHAIN_NOTVALID_SERVICESTATUS:
			    LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.ATV_LOG028, new Object[ ] { validationResult.getTSPName(), validationResult.getTSPServiceNameForDetect(), detectedWithShiMsg, Language.getResIntegraTsl(ILogTslConstant.ATV_LOG027) }));
			    break;

			default:
			    break;

		    }

		} else {

		    String validatedWithShiMsg = UtilsStringChar.EMPTY_STRING;
		    if (validationResult.getTSPServiceForValidate().getServiceInformation() == validationResult.getTSPServiceHistoryInformationInstanceForValidate()) {
			validatedWithShiMsg = Language.getFormatResIntegraTsl(ILogTslConstant.ATV_LOG021, new Object[ ] { validationResult.getTSPServiceHistoryInformationInstanceNameForValidate(), validationResult.getTSPServiceHistoryInformationInstanceForValidate().getServiceStatusStartingTime() });
		    }

		    // En función del resultado exacto...
		    switch (validationResult.getResult()) {

			case ITSLValidatorResult.RESULT_DETECTED_STATE_VALID:
			    LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.ATV_LOG022, new Object[ ] { validationResult.getTSPName(), validationResult.getTSPServiceNameForDetect(), detectedWithShiMsg, validationResult.getTSPServiceNameForValidate(), validatedWithShiMsg, Language.getResIntegraTsl(ILogTslConstant.ATV_LOG023) }));
			    break;

			case ITSLValidatorResult.RESULT_DETECTED_STATE_REVOKED:
			    LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.ATV_LOG022, new Object[ ] { validationResult.getTSPName(), validationResult.getTSPServiceNameForDetect(), detectedWithShiMsg, validationResult.getTSPServiceNameForValidate(), validatedWithShiMsg, Language.getResIntegraTsl(ILogTslConstant.ATV_LOG024) }));
			    break;

			case ITSLValidatorResult.RESULT_DETECTED_STATE_CERTCHAIN_NOTVALID:
			    LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.ATV_LOG022, new Object[ ] { validationResult.getTSPName(), validationResult.getTSPServiceNameForDetect(), detectedWithShiMsg, validationResult.getTSPServiceNameForValidate(), validatedWithShiMsg, Language.getResIntegraTsl(ILogTslConstant.ATV_LOG025) }));
			    break;

			case ITSLValidatorResult.RESULT_DETECTED_STATE_REVOKED_SERVICESTATUS:
			    LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.ATV_LOG022, new Object[ ] { validationResult.getTSPName(), validationResult.getTSPServiceNameForDetect(), detectedWithShiMsg, validationResult.getTSPServiceNameForValidate(), validatedWithShiMsg, Language.getResIntegraTsl(ILogTslConstant.ATV_LOG026) }));
			    break;

			case ITSLValidatorResult.RESULT_DETECTED_STATE_CERTCHAIN_NOTVALID_SERVICESTATUS:
			    LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.ATV_LOG022, new Object[ ] { validationResult.getTSPName(), validationResult.getTSPServiceNameForDetect(), detectedWithShiMsg, validationResult.getTSPServiceNameForValidate(), validatedWithShiMsg, Language.getResIntegraTsl(ILogTslConstant.ATV_LOG027) }));
			    break;

			default:
			    break;

		    }

		}

	    }

	} else {

	    // El certificado no ha sido detectado por la TSL.
	    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.ATV_LOG029));

	}

    }

    /**
     * Method that checks if the TSP service have "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn" status
     * in date of issue of the certificate.
     * @param cert certificate to check date of issue.
     * @param tspService service to be checked.
     * @return
     */
    private boolean isWithdrawnBeforeDateOfIssue(X509Certificate cert, TSPService tspService) {
	return !cert.getNotBefore().before(tspService.getServiceInformation().getServiceStatusStartingTime()) && tspService.getServiceInformation().getServiceStatus().toString().equals(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_WITHDRAWN);

    }
}
