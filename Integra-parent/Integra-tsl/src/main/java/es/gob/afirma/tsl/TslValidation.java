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
 * <b>File:</b><p>es.gob.afirma.tsl.TslValidation.java.</p>
 * <b>Description:</b><p> Class that implements the necessary methods to perform certificate validation using a TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.4, 26/09/2022.
 */
package es.gob.afirma.tsl;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

import es.gob.afirma.tsl.logger.Logger;

import es.gob.afirma.tsl.access.TSLManager;
import es.gob.afirma.tsl.access.TSLProperties;
import es.gob.afirma.tsl.certValidation.ifaces.ITSLValidatorResult;
import es.gob.afirma.tsl.certValidation.ifaces.ITslRevocationEvidenceType;
import es.gob.afirma.tsl.certValidation.ifaces.ITslRevocationStatus;
import es.gob.afirma.tsl.certValidation.ifaces.ITslValidationStatusResult;
import es.gob.afirma.tsl.elements.CertDetectedInTSL;
import es.gob.afirma.tsl.elements.DetectCertInTslInfoAndValidationResponse;
import es.gob.afirma.tsl.elements.ResultTslInfVal;
import es.gob.afirma.tsl.elements.TslInformation;
import es.gob.afirma.tsl.elements.TslRevocationStatus;
import es.gob.afirma.tsl.elements.TspServiceHistoryInf;
import es.gob.afirma.tsl.elements.TspServiceInformation;
import es.gob.afirma.tsl.elements.json.ByteArrayB64;
import es.gob.afirma.tsl.elements.json.DateString;
import es.gob.afirma.tsl.exceptions.CommonUtilsException;
import es.gob.afirma.tsl.exceptions.TSLManagingException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.impl.common.TSLObject;
import es.gob.afirma.tsl.utils.UtilsCertificateTsl;
import es.gob.afirma.tsl.utils.UtilsFileSystemCommons;
import es.gob.afirma.tsl.utils.UtilsHTTP;
import es.gob.afirma.tsl.utils.UtilsStringChar;

/** 
 * <p>Class that implements the necessary methods to perform certificate validation using a TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version  1.4, 26/09/2022.
 */
public class TslValidation implements ITslValidation {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = Logger.getLogger(TslValidation.class);

    /**
     * Constructor method for the class TslValidation.java. 
     */
    public TslValidation() {
	super();
    }

    
    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.ITslValidation#validateCertificateTsl(byte[], es.gob.afirma.tsl.parsing.impl.common.TSLObject, java.util.Date)
     */
    public DetectCertInTslInfoAndValidationResponse validateCertificateTsl(byte[ ] certByteArrayB64, TSLObject tslObject, Date detectionDate, boolean getInfo, boolean checkRevStatus) throws TSLManagingException {

	DetectCertInTslInfoAndValidationResponse result = new DetectCertInTslInfoAndValidationResponse();
	ITSLValidatorResult tslValidatorResult = null;
	// Inicialmente consideramos que todo es OK para proceder.
	boolean allIsOk = true;
	// se comprueban los parámetros de entrada
	String resultCheckParams = checkParameterValidateCertificateTsl(certByteArrayB64, tslObject);

	if (resultCheckParams != null) {
	    allIsOk = false;
	    LOGGER.error(resultCheckParams);
	    result = new DetectCertInTslInfoAndValidationResponse();
	    result.setStatus(ITslValidationStatusResult.STATUS_ERROR_INPUT_PARAMETERS);
	    result.setDescription(resultCheckParams);
	}

	// Comprobamos que se parsea correctamente el certificado a detectar.
	X509Certificate x509cert = null;
	if (allIsOk) {
	    try {
		x509cert = UtilsCertificateTsl.getX509Certificate(certByteArrayB64);
	    } catch (CommonUtilsException e) {
		allIsOk = false;
		LOGGER.error(Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG012));
		result = new DetectCertInTslInfoAndValidationResponse();
		result.setStatus(ITslValidationStatusResult.STATUS_ERROR_INPUT_PARAMETERS);
		result.setDescription(Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG012));
	    }
	}
	// Comprobamos que el formato de la fecha sea adecuado si es que se
	// proporciona

	Date detectionDateAux = null;
	if (allIsOk) {
	    // Si no es nula, hay que parsearla y comprobar que no sobrepasa
	    // hacia el futuro respecto al intervalo permitido.
	    if (detectionDate != null) {

		detectionDateAux = detectionDate;

		// Calculamos la fecha límite.
		int timeGapInMilliseconds = TSLProperties.getServiceDetectCertInTslInfoAndValidationParamValDateTimeGap();
		Calendar limitDateCal = Calendar.getInstance();
		limitDateCal.add(Calendar.MILLISECOND, timeGapInMilliseconds);
		Date limitDate = limitDateCal.getTime();

		// Comparamos la fecha respecto a la límite.
		// Si la fecha límite es anterior a la fecha de validación,
		// devolvemos
		// error en los parámetros de entrada.
		if (limitDate.before(detectionDateAux)) {

		    allIsOk = false;
		    String errorMsg = Language.getFormatResIntegraTsl(ILogTslConstant.TSLVAL_LOG006, new Object[ ] { detectionDate.toString() });
		    LOGGER.error(errorMsg);
		    result = new DetectCertInTslInfoAndValidationResponse();
		    result.setStatus(ITslValidationStatusResult.STATUS_ERROR_INPUT_PARAMETERS);
		    result.setDescription(errorMsg);

		}

	    }
	    // Se establece la fecha actual como fecha de validación.
	    else {
		detectionDateAux = Calendar.getInstance().getTime();
	    }

	}

	
	// si todo ha ido bien, continuamos con el proceso de validar
	if (allIsOk) {
	    tslValidatorResult = TSLManager.getInstance().validateX509withTSL(x509cert, detectionDateAux, checkRevStatus, getInfo, tslObject);

	    String tslLocation = UtilsCertificateTsl.getCountryOfTheCertificateString(x509cert);

	    if (tslValidatorResult == null) {
		String msg = Language.getFormatResIntegraTsl(ILogTslConstant.TSLVAL_LOG013, new Object[ ] { tslLocation });
		LOGGER.info(msg);
		result.setStatus(ITslValidationStatusResult.STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_NOT_FINDED);
		result.setDescription(msg);
	    } else {
		// si el resultado no es nulo, se empieza a construir la
		// respuesta
		String msg = Language.getFormatResIntegraTsl(ILogTslConstant.TSLVAL_LOG015, new Object[ ] { tslLocation, detectionDateAux.toString() });
		LOGGER.info(msg);
		result.setStatus(ITslValidationStatusResult.STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED);
		result.setDescription(msg);

		ResultTslInfVal resultTslInfVal = new ResultTslInfVal();
		TslInformation tslInformation = new TslInformation();
		tslInformation.setEtsiSpecificationAndVersion(tslValidatorResult.getTslEtsiSpecificationAndVersion());
		tslInformation.setCountryRegion(tslValidatorResult.getTslCountryRegionCode());
		tslInformation.setSequenceNumber(tslValidatorResult.getTslSequenceNumber());
		String uriTslLocation = new String();
		if (tslObject.getSchemeInformation() != null && tslObject.getSchemeInformation().getDistributionPoints() != null && tslObject.getSchemeInformation().getDistributionPoints().get(0) != null) {
		    uriTslLocation = tslObject.getSchemeInformation().getDistributionPoints().get(0).toString();
		}
		tslInformation.setTslLocation(uriTslLocation);
		tslInformation.setIssued(new DateString(tslValidatorResult.getTslIssueDate()));
		tslInformation.setNextUpdate(new DateString(tslValidatorResult.getTslNextUpdate()));
		tslInformation.setTslXmlData(null);
		resultTslInfVal.setTslInformation(tslInformation);
		result.setResultTslInfVal(resultTslInfVal);

		// si se ha solicitado información del certificado o comprobar
		// el estado de revocación

		boolean returnRevocationEvidence = false;
		if (getInfo || checkRevStatus) {
		    // Si no se ha detectado el certificado en la TSL...
		    if (tslValidatorResult.getResult() == ITSLValidatorResult.RESULT_NOT_DETECTED) {

			// Lo marcamos en la respuesta.
			msg = Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG017);
			LOGGER.info(msg);
			result.setStatus(ITslValidationStatusResult.STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_NOT_DETECTED);
			result.setDescription(msg);

		    } else {
			// si se ha detectado el certificado en la TSL
			// Lo marcamos en la respuesta.
			msg = Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG018);
			LOGGER.info(msg);
			result.setStatus(ITslValidationStatusResult.STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_DETECTED);
			result.setDescription(msg);

			// Creamos el objeto que representa la información común
			// para ambos casos.
			CertDetectedInTSL certDetectedInTsl = new CertDetectedInTSL();
			certDetectedInTsl.setTspName(tslValidatorResult.getTSPName());
			// Creamos el objeto que define la información del
			// TSP-Service.
			TspServiceInformation tspServiceInformation = new TspServiceInformation();
			tspServiceInformation.setTspServiceName(tslValidatorResult.getTSPServiceNameForDetect());
			tspServiceInformation.setTspServiceType(tslValidatorResult.getTSPServiceForDetect().getServiceInformation().getServiceTypeIdentifier().toString());
			tspServiceInformation.setTspServiceStatus(tslValidatorResult.getTSPServiceForDetect().getServiceInformation().getServiceStatus().toString());
			tspServiceInformation.setTspServiceStatusStartingDate(new DateString(tslValidatorResult.getTSPServiceForDetect().getServiceInformation().getServiceStatusStartingTime()));

			// Si se ha hecho uso de la información del histórico
			// del
			// servicio...
			if (tslValidatorResult.getTSPServiceHistoryInformationInstanceNameForDetect() != null) {

			    // Creamos el objeto que representa la información
			    // del
			    // histórico del servicio.
			    TspServiceHistoryInf tspServiceHistoryInf = new TspServiceHistoryInf();
			    tspServiceHistoryInf.setTspServiceName(tslValidatorResult.getTSPServiceHistoryInformationInstanceNameForDetect());
			    tspServiceHistoryInf.setTspServiceType(tslValidatorResult.getTSPServiceHistoryInformationInstanceForDetect().getServiceTypeIdentifier().toString());
			    tspServiceHistoryInf.setTspServiceStatus(tslValidatorResult.getTSPServiceHistoryInformationInstanceForDetect().getServiceStatus().toString());
			    tspServiceHistoryInf.setTspServiceStatusStartingDate(new DateString(tslValidatorResult.getTSPServiceHistoryInformationInstanceForDetect().getServiceStatusStartingTime()));
			    // Lo asignamos a la información del servicio.
			    tspServiceInformation.setTspServiceHistoryInf(tspServiceHistoryInf);

			}

			// Lo establecemos en la información de detección del
			// certificado
			certDetectedInTsl.setTspServiceInformation(tspServiceInformation);
			// Si se ha solicitado obtener información del
			// certificado...
			if (getInfo) {
			    Map<String, String> mappings = tslValidatorResult.getMappings();
			    certDetectedInTsl.setCertInfo(mappings);
			}
			// Si se ha solicitado comprobar el estado de revocación
			// del
			// certificado...
			if (checkRevStatus) {
			    // Construimos el objeto que contendrá la
			    // información de
			    // revocación.
			    TslRevocationStatus tslRevocationStatus = new TslRevocationStatus();
			    try {

				// Asignamos el resultado de comprobación de
				// estado de
				// revocación.
				tslRevocationStatus.setRevocationStatus(tslValidatorResult.getResult());
				tslRevocationStatus.setIsFromServStat(tslValidatorResult.isResultFromServiceStatus());

				// En función del resultado (sabemos que ha sido
				// detectado)...
				switch (tslRevocationStatus.getRevocationStatus()) {
				    case ITslRevocationStatus.RESULT_DETECTED_REVSTATUS_UNKNOWN:
					msg = Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG021);
					LOGGER.info(msg);
					tslRevocationStatus.setRevocationDesc(msg);
					break;

				    case ITslRevocationStatus.RESULT_DETECTED_REVSTATUS_VALID:
					msg = Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG022);
					LOGGER.info(msg);
					tslRevocationStatus.setRevocationDesc(msg);
					addRevocationInfoInResult(tslRevocationStatus, tslValidatorResult, returnRevocationEvidence);
					break;

				    case ITslRevocationStatus.RESULT_DETECTED_REVSTATUS_REVOKED:
					msg = Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG023);
					LOGGER.info(msg);
					tslRevocationStatus.setRevocationDesc(msg);
					if (!tslRevocationStatus.getIsFromServStat()) {
					    addRevocationInfoInResult(tslRevocationStatus, tslValidatorResult, returnRevocationEvidence);
					}
					break;

				    case ITslRevocationStatus.RESULT_DETECTED_REVSTATUS_CERTCHAIN_NOTVALID:
					msg = Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG024);
					LOGGER.info(msg);
					tslRevocationStatus.setRevocationDesc(msg);
					break;

				    case ITslRevocationStatus.RESULT_DETECTED_REVSTATUS_REVOKED_SERVICESTATUS:
					msg = Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG025);
					LOGGER.info(msg);
					tslRevocationStatus.setRevocationDesc(msg);
					break;

				    case ITslRevocationStatus.RESULT_DETECTED_REVSTATUS_CERTCHAIN_NOTVALID_SERVICESTATUS:
					msg = Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG026);
					LOGGER.info(msg);
					tslRevocationStatus.setRevocationDesc(msg);
					break;
				    default:
					break;
				}
				
				

			    } catch (CRLException e) {
				throw new TSLManagingException(e);
			    } catch (IOException e) {
				throw new TSLManagingException(e);
			    }
			    // Añadimos toda la información de revocación en la
			    // respuesta.
			    certDetectedInTsl.setTslRevocStatus(tslRevocationStatus);

			}

			// Asignamos la información de detección del certificado
			// a
			// la respuesta final.
			resultTslInfVal.setCertDetectedInTSL(certDetectedInTsl);

			// Establecemos el resultado general en función de si se
			// ha
			// solicitado
			// información del certificado y/o su estado de
			// revocación,
			// y lo que finalmente
			// se pudo obtener.
			setGeneralStatusResponseGetInfoRevocationStatus(result, getInfo, checkRevStatus);
		    }

		}

	    }
	}
	return result;
    }
    
    
    /**
    * Method to establish the general result depending on whether or not its revocation status has been requested.
    * @param result
    * @param getInfo
    * @param checkRevStatus
    */
   private void setGeneralStatusResponseGetInfoRevocationStatus(DetectCertInTslInfoAndValidationResponse result, boolean getInfo, boolean checkRevStatus) {

	// Obtenemos el objeto que contiene la información de haber detectado
	// el certificado en la TSL.
	CertDetectedInTSL certDetectedInTsl = result.getResultTslInfVal().getCertDetectedInTSL();

	// Cadena donde se almacenará el mensaje descriptivo a asignar
	// finalmente.
	String msg = null;

	// Si se ha solicitado información del certificado...
	if (getInfo) {

	    // Comprobamos si se ha obtenido la información solicitada.
	    boolean infoCertObtained = certDetectedInTsl.getCertInfo() != null && !certDetectedInTsl.getCertInfo().isEmpty();

	    // Si también se ha solicitado la información de revocación...
	    if (checkRevStatus) {

		// Comprobamos si se ha obtenido la información de revocación.
		boolean revStatusInfoObtained = certDetectedInTsl.getTslRevocStatus().getRevocationStatus() != ITslRevocationStatus.RESULT_DETECTED_REVSTATUS_UNKNOWN;

		if (infoCertObtained) {

		    if (revStatusInfoObtained) {
			msg = Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG032);
			result.setStatus(ITslValidationStatusResult.STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_DETECTED_INFO_COLLECTED_REVSTATUS_COLLECTED);
		    } else {
			msg = Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG031);
			result.setStatus(ITslValidationStatusResult.STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_DETECTED_INFO_COLLECTED_REVSTATUS_NOT_COLLECTED);
		    }

		} else {

		    if (revStatusInfoObtained) {
			msg = Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG030);
			result.setStatus(ITslValidationStatusResult.STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_DETECTED_INFO_NOT_COLLECTED_REVSTATUS_COLLECTED);
		    } else {
			msg = Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG029);
			result.setStatus(ITslValidationStatusResult.STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_DETECTED_INFO_NOT_COLLECTED_REVSTATUS_NOT_COLLECTED);
		    }

		}

	    }
	    // Si entramos aquí significa que solo se solicitó la información
	    // del certificado.
	    else {

		if (infoCertObtained) {

		    msg = Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG020);
		    result.setStatus(ITslValidationStatusResult.STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_DETECTED_INFO_COLLECTED);

		} else {

		    msg = Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG019);
		    result.setStatus(ITslValidationStatusResult.STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_DETECTED_INFO_NOT_COLLECTED);

		}

	    }

	}
	// Si no se ha solicitado información del certificado significa que al
	// menos
	// se ha solicitado la información de revocación.
	else {

	    // Comprobamos si se ha obtenido la información de revocación.
	    boolean revStatusInfoObtained = certDetectedInTsl.getTslRevocStatus().getRevocationStatus() != ITslRevocationStatus.RESULT_DETECTED_REVSTATUS_UNKNOWN;

	    if (revStatusInfoObtained) {

		msg = Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG027);
		result.setStatus(ITslValidationStatusResult.STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_DETECTED_REVSTATUS_COLLECTED);

	    } else {

		msg = Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG028);
		result.setStatus(ITslValidationStatusResult.STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_DETECTED_REVSTATUS_NOT_COLLECTED);

	    }

	}

	// Lo asignamos al resultado y pintamos en el log.
	result.setDescription(msg);
	LOGGER.info(msg);

   }
   
   /**
    * Add the revocation information in the result.
    * @param tslRevocationStatus TSL revocation status information to return.
    * @param tslValidatorResult TSL validation process result to analyze.
    * @param returnRevocationEvidence Flag that indicates if it is necessary to return the revocation evidence (only if {@code checkRevStatus} is <code>true</code>).
    * @throws IOException In case of some error decoding a Basic OCSP Response.
    * @throws CRLException Incase of some error decoding a CRL.
    */
   private void addRevocationInfoInResult(TslRevocationStatus tslRevocationStatus, ITSLValidatorResult tslValidatorResult, boolean returnRevocationEvidence) throws IOException, CRLException {

	// Establecemos la URL de donde se haya obtenido la evidencia de
	// revocación.
	tslRevocationStatus.setUrl(tslValidatorResult.getRevocationValueURL());
	// Consultamos si se ha obtenido mediante el DistributionPoint / AIA del
	// certificado.
	tslRevocationStatus.setDpAia(tslValidatorResult.isResultFromDPorAIA());
	// Si no ha sido por el DP / AIA, es por un servicio...
	if (!tslRevocationStatus.getDpAia()) {

	    // Creamos el objeto que define la información del TSP-Service.
	    TspServiceInformation tspServiceInformation = new TspServiceInformation();
	    tspServiceInformation.setTspServiceName(tslValidatorResult.getTSPServiceNameForValidate());
	    tspServiceInformation.setTspServiceType(tslValidatorResult.getTSPServiceForValidate().getServiceInformation().getServiceTypeIdentifier().toString());
	    tspServiceInformation.setTspServiceStatus(tslValidatorResult.getTSPServiceForValidate().getServiceInformation().getServiceStatus().toString());
	    tspServiceInformation.setTspServiceStatusStartingDate(new DateString(tslValidatorResult.getTSPServiceForValidate().getServiceInformation().getServiceStatusStartingTime()));

	    // Si se ha hecho uso de la información del histórico del
	    // servicio...
	    if (tslValidatorResult.getTSPServiceHistoryInformationInstanceNameForValidate() != null) {

		// Creamos el objeto que representa la información del
		// histórico del servicio.
		TspServiceHistoryInf tspServiceHistoryInf = new TspServiceHistoryInf();
		tspServiceHistoryInf.setTspServiceName(tslValidatorResult.getTSPServiceHistoryInformationInstanceNameForValidate());
		tspServiceHistoryInf.setTspServiceType(tslValidatorResult.getTSPServiceHistoryInformationInstanceForValidate().getServiceTypeIdentifier().toString());
		tspServiceHistoryInf.setTspServiceStatus(tslValidatorResult.getTSPServiceHistoryInformationInstanceForValidate().getServiceStatus().toString());
		tspServiceHistoryInf.setTspServiceStatusStartingDate(new DateString(tslValidatorResult.getTSPServiceHistoryInformationInstanceForValidate().getServiceStatusStartingTime()));
		// Lo asignamos a la información del servicio.
		tspServiceInformation.setTspServiceHistoryInf(tspServiceHistoryInf);

	    }

	    // Lo establecemos en la información de revocación del certificado.
	    tslRevocationStatus.setTspServiceInformation(tspServiceInformation);

	}

	// En función del tipo de evidencia...
	// Si es OCSP...
	if (tslValidatorResult.getRevocationValueBasicOCSPResp() != null) {
	    if (returnRevocationEvidence) {
		tslRevocationStatus.setEvidenceType(ITslRevocationEvidenceType.REVOCATION_EVIDENCE_TYPE_OCSP);
		tslRevocationStatus.setEvidence(new ByteArrayB64(tslValidatorResult.getRevocationValueBasicOCSPResp().getEncoded()));
	    }
	    // Si el estado es revocado, devolvemos la razón y fecha.
	    if (tslRevocationStatus.getRevocationStatus().intValue() == ITslRevocationStatus.RESULT_DETECTED_REVSTATUS_REVOKED) {
		tslRevocationStatus.setRevocationReason(tslValidatorResult.getRevocationReason());
		tslRevocationStatus.setRevocationDate(new DateString(tslValidatorResult.getRevocationDate()));
	    }
	}
	// Si es CRL...
	else if (tslValidatorResult.getRevocationValueCRL() != null) {
	    if (returnRevocationEvidence) {
		tslRevocationStatus.setEvidenceType(ITslRevocationEvidenceType.REVOCATION_EVIDENCE_TYPE_CRL);
		tslRevocationStatus.setEvidence(new ByteArrayB64(tslValidatorResult.getRevocationValueCRL().getEncoded()));
	    }
	    // Si el estado es revocado, devolvemos la razón y fecha.
	    if (tslRevocationStatus.getRevocationStatus().intValue() == ITslRevocationStatus.RESULT_DETECTED_REVSTATUS_REVOKED) {
		tslRevocationStatus.setRevocationReason(tslValidatorResult.getRevocationReason());
		tslRevocationStatus.setRevocationDate(new DateString(tslValidatorResult.getRevocationDate()));
	    }
	}

   }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.ITslValidation#getTSLObjectFromPath(java.lang.String)
     */
    @Override
    public ITSLObject getTSLObjectFromPath(String pathTsl) throws TSLManagingException {
	ITSLObject tslObject = null;

	File xmlFile = null;
	byte[ ] tslByteArray = null;
	if (!UtilsStringChar.isNullOrEmptyTrim(pathTsl)) {
	    xmlFile = new File(pathTsl);
	    if (xmlFile.exists()) {

		tslByteArray = UtilsFileSystemCommons.readFile(pathTsl, false);
		ByteArrayInputStream bais = null;
		bais = new ByteArrayInputStream(tslByteArray);
		// se construye la TSL
		tslObject = TSLManager.getInstance().buildTsl(bais);

	    } else {
		throw new TSLManagingException(Language.getResIntegraTsl(ILogTslConstant.TM_LOG002));
	    }
	}

	return tslObject;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.ITslValidation#downloadTLSbyHTTP(java.lang.String)
     */
    @Override
    public ITSLObject downloadTLSbyHTTP(String uriTSL, int connectionTimeout, int readTimeout) throws TSLManagingException {
	ITSLObject tslObject = null;
	ByteArrayInputStream inStream = null;

	// se descarga la TSL en un array de bytes
	byte[ ] buffer;

	try {
	    buffer = UtilsHTTP.getDataFromURI(uriTSL, connectionTimeout, readTimeout, null, null, null);
	    inStream = new ByteArrayInputStream(buffer);
	    tslObject = TSLManager.getInstance().buildTsl(inStream);
	} catch (CommonUtilsException e) {
	    throw new TSLManagingException(Language.getFormatResIntegraTsl(ILogTslConstant.TM_LOG008, new Object[ ] { uriTSL }), e);
	}

	return tslObject;
    }

    /**
     * Method that checks required parameters for {@link es.gob.afirma.tsl.TslValidation#validateCertificateTsl} method.
     * @param certByteArrayB64 Certificate to detect (byte[]).
     * @param tslObject TSL object representation to use.
     * @return {@link String} with the parameter that not are correctly defined, otherwise <code>null</code>.
     */
    private String checkParameterValidateCertificateTsl(final byte[ ] certByteArrayB64, final TSLObject tslObject) {
	StringBuffer result = new StringBuffer();
	boolean checkError = false;

	result.append(Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG003));
	if (certByteArrayB64 == null) {
	    checkError = true;
	    result.append(UtilsStringChar.EMPTY_STRING);
	    result.append(UtilsStringChar.SYMBOL_OPEN_BRACKET_STRING);
	    result.append(ITslValidation.PARAM_CERTIFICATE);
	    result.append(UtilsStringChar.SYMBOL_CLOSE_BRACKET_STRING);
	}

	if (tslObject == null) {
	    checkError = true;
	    result.append(UtilsStringChar.EMPTY_STRING);
	    result.append(UtilsStringChar.SYMBOL_OPEN_BRACKET_STRING);
	    result.append(ITslValidation.PARAM_CERTIFICATE);
	    result.append(UtilsStringChar.SYMBOL_CLOSE_BRACKET_STRING);
	}

	if (checkError) {
	    return result.toString();
	} else {
	    return null;
	}

    }

   
}
