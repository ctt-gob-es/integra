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
 * <b>File:</b><p>es.gob.afirma.tsl.certValidation.impl.ts119612.v020101.TSLValidator.java.</p>
 * <b>Description:</b><p>Class that represents a TSL Validator implementation for the
 * ETSI TS 119612 2.1.1 specification.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 17/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.5, 19/09/2022.
 */
package es.gob.afirma.tsl.certValidation.impl.ts119612.v020101;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;

import es.gob.afirma.tsl.logger.Logger;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.certValidation.CertificateExtension;
import es.gob.afirma.tsl.certValidation.SIResult;
import es.gob.afirma.tsl.certValidation.TspServiceQualifier;
import es.gob.afirma.tsl.certValidation.ifaces.ITSLValidatorOtherConstants;
import es.gob.afirma.tsl.certValidation.ifaces.ITSLValidatorResult;
import es.gob.afirma.tsl.certValidation.impl.TSLValidatorMappingCalculator;
import es.gob.afirma.tsl.certValidation.impl.common.ATSLValidator;
import es.gob.afirma.tsl.certValidation.impl.common.TSLValidatorResult;
import es.gob.afirma.tsl.constants.ITslMappingConstants;
import es.gob.afirma.tsl.exceptions.TSLValidationException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.parsing.ifaces.IAnyTypeExtension;
import es.gob.afirma.tsl.parsing.ifaces.ITSLCommonURIs;
import es.gob.afirma.tsl.parsing.ifaces.ITSLOIDs;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;
import es.gob.afirma.tsl.parsing.impl.common.TSLCertificateExtensionAnalyzer;
import es.gob.afirma.tsl.parsing.impl.tsl119612.v020101.AdditionalServiceInformation;
import es.gob.afirma.tsl.utils.UtilsStringChar;

/** 
 * <p>Class that represents a TSL Validator implementation for the
 * ETSI TS 119612 2.1.1 specification.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.5, 19/09/2022.
 */
public class TSLValidator extends ATSLValidator {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = Logger.getLogger(TSLValidator.class);

    /**
     * Constructor method for the class TSLValidator.java. 
     */
    public TSLValidator() {
    }

    /**
     * Constructor method for the class TSLValidator.java.
     * @param tslObject Tsl.
     */
    public TSLValidator(ITSLObject tslObject) {
	super(tslObject);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.certValidation.impl.common.ATSLValidator#checkIfTSLisFromEuropeanMember()
     */
    @Override
    protected boolean checkIfTSLisFromEuropeanMember() {
	String tslType = getTSLObject().getSchemeInformation().getTslType().toString();
	return tslType.equalsIgnoreCase(ITSLCommonURIs.TSL_TYPE_EUGENERIC) || tslType.equalsIgnoreCase(ITSLCommonURIs.TSL_TYPE_EULISTOFTHELIST);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.certValidation.impl.common.ATSLValidator#checkIfTSLisListOfLists(java.lang.String)
     */
    @Override
    protected boolean checkIfTSLisListOfLists(String tslType) {
	return tslType.equalsIgnoreCase(ITSLCommonURIs.TSL_TYPE_EULISTOFTHELIST) || tslType.startsWith(ITSLCommonURIs.TSL_TYPE_NONEULISTOFTHELISTS_PREFFIX) && tslType.endsWith(ITSLCommonURIs.TSL_TYPE_NONEULISTOFTHELISTS_PREFFIX);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.certValidation.impl.common.ATSLValidator#checkIfStatusDeterminationApproachIsDelinquentOrEquivalent(java.lang.String)
     */
    @Override
    protected boolean checkIfStatusDeterminationApproachIsDelinquentOrEquivalent(String statusDeterminationApproach) {
	return false;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.certValidation.impl.common.ATSLValidator#checkIfTSPServiceTypeIsTSAQualified(java.lang.String)
     */
    @Override
    protected boolean checkIfTSPServiceTypeIsTSAQualified(String tspServiceType) {
	return tspServiceType.equalsIgnoreCase(ITSLCommonURIs.TSL_SERVICETYPE_TSA_QTST);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.certValidation.impl.common.ATSLValidator#checkIfTSPServiceTypeIsTSANonQualified(java.lang.String)
     */
    @Override
    protected boolean checkIfTSPServiceTypeIsTSANonQualified(String tspServiceType) {
	return tspServiceType.equalsIgnoreCase(ITSLCommonURIs.TSL_SERVICETYPE_TSA) || tspServiceType.equalsIgnoreCase(ITSLCommonURIs.TSL_SERVICETYPE_TSA_TSSQC) || tspServiceType.equalsIgnoreCase(ITSLCommonURIs.TSL_SERVICETYPE_TSA_TSS_ADESQC_AND_QES);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.certValidation.impl.common.ATSLValidator#checkIfTSPServiceTypeIsCAQC(java.lang.String)
     */
    @Override
    public boolean checkIfTSPServiceTypeIsCAQC(String tspServiceType) {
	return tspServiceType.equalsIgnoreCase(ITSLCommonURIs.TSL_SERVICETYPE_CA_QC);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.certValidation.impl.common.ATSLValidator#checkIfTSPServiceStatusIsOK(java.lang.String)
     */
    @Override
    public boolean checkIfTSPServiceStatusIsOK(String serviceStatus) {

	boolean result = serviceStatus.equals(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_GRANTED) || serviceStatus.equals(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_RECOGNISEDATNATIONALLEVEL);
	result = result || serviceStatus.equals(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_UNDERSUPERVISION) || serviceStatus.equals(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_SUPERVISIONINCESSATION);
	result = result || serviceStatus.equals(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_ACCREDITED) || serviceStatus.equals(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_SETBYNATIONALLAW);
	result = result || serviceStatus.equals(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_WITHDRAWN);
	return result;

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.certValidation.impl.common.ATSLValidator#checkIfTSPServiceTypeIsCAPKC(java.lang.String)
     */
    @Override
    public boolean checkIfTSPServiceTypeIsCAPKC(String tspServiceType) {
	return tspServiceType.equalsIgnoreCase(ITSLCommonURIs.TSL_SERVICETYPE_CA_PKC);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.certValidation.impl.common.ATSLValidator#checkIfTSPServiceTypeIsNationalRootCAQC(java.lang.String)
     */
    @Override
    protected boolean checkIfTSPServiceTypeIsNationalRootCAQC(String tspServiceType) {
	return tspServiceType.equalsIgnoreCase(ITSLCommonURIs.TSL_SERVICETYPE_NATIONALROOTCA);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.certValidation.impl.common.ATSLValidator#setStatusResultInAccordanceWithTSPServiceCurrentStatus(boolean, java.lang.String, java.util.Date, java.util.Date, es.gob.afirma.tsl.certValidation.impl.common.TSLValidatorResult)
     */
    @Override
    protected void setStatusResultInAccordanceWithTSPServiceCurrentStatus(boolean isCACert, String serviceStatus, Date serviceStatusStartingTime, Date validationDate, TSLValidatorResult validationResult) {

	// Solo tenemos en cuenta el Servicio si su estado comenzó de forma
	// anterior
	// a la fecha de validación.
	if (serviceStatusStartingTime.before(validationDate)) {

	    boolean statusOK = checkIfTSPServiceStatusIsOK(serviceStatus);
	    LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.TV_LOG035, new Object[] {serviceStatus}));

	    boolean statusChainNotValid = serviceStatus.equals(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_SUPERVISIONCEASED) || serviceStatus.equals(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_ACCREDITATIONCEASED);

	    boolean statusRevoked = serviceStatus.equals(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_SUPERVISIONREVOKED) || serviceStatus.equals(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_ACCREDITATIONREVOKED);
	    statusRevoked = statusRevoked || serviceStatus.equals(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_DEPRECATEDBYNATIONALLAW) || serviceStatus.equals(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_DEPRECATEDATNATIONALLEVEL);
	    // Si el estado del servicio es OK, establecemos
	    // que se detecta el certificado.
	    if (statusOK) {

		// Si se trata de una CA, al haberse encontrado directamente en
		// la TSL,
		// se considera que su estado de revocación es OK.
		if (isCACert) {
		    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TV_LOG036));
		    validationResult.setResult(ITSLValidatorResult.RESULT_DETECTED_STATE_VALID);

		}
		// Al ser tipo final, se establece el estado a detectado
		// (desconocido), ya que
		// ahora habría que buscar la forma de comprobar el estado de
		// revocación.
		else {

		    validationResult.setResult(ITSLValidatorResult.RESULT_DETECTED_STATE_UNKNOWN);
		    //LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TV_LOG037));
		}

	    } else if (statusChainNotValid) {

		validationResult.setResult(ITSLValidatorResult.RESULT_DETECTED_STATE_CERTCHAIN_NOTVALID_SERVICESTATUS);
		LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TV_LOG038));
	    } else if (statusRevoked) {

		validationResult.setResult(ITSLValidatorResult.RESULT_DETECTED_STATE_REVOKED_SERVICESTATUS);
		LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TV_LOG039));

	    }

	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.certValidation.impl.common.ATSLValidator#checkIfTSPServiceAdditionalServiceInformationExtensionsDetectCert(es.gob.afirma.tsl.certValidation.impl.common.TSLValidatorResult, es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance)
     */
    @Override
    protected Boolean checkIfTSPServiceAdditionalServiceInformationExtensionsDetectCert(TSLValidatorResult validationResult, ServiceHistoryInstance shi) {

	// Inicialmente consideramos que no se han definido extensiones
	// AdditionalServiceInformation.
	Boolean result = null;

	// Primero recolectamos todas las extensiones del tipo
	// AdditionalServiceInformation.
	List<AdditionalServiceInformation> asiList = new ArrayList<AdditionalServiceInformation>();

	// Recuperamos la lista de extensiones del servicio, y si no es nula ni
	// vacía, continuamos.
	List<IAnyTypeExtension> extensionsList = shi.getServiceInformationExtensions();
	if (extensionsList != null && !extensionsList.isEmpty()) {

	    // Recorremos la lista buscando aquellas que sean de tipo
	    // AdditionalServiceInformation.
	    for (IAnyTypeExtension extension: extensionsList) {

		// Si es del tipo AdditionalServiceInformation...
		if (extension.getImplementationExtension() == IAnyTypeExtension.IMPL_ADDITIONAL_SERVICE_INFORMATION) {

		    // La añadimos a la lista final.
		    AdditionalServiceInformation ext = (AdditionalServiceInformation) extension;
		    asiList.add((AdditionalServiceInformation) extension);
		    LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.TV_LOG027, new Object[ ] { ext.getUri().toString() }));
		}

	    }

	}

	// Si la lista no es vacía...
	if (!asiList.isEmpty()) {

	    // Ahora indicamos que el resultado es false.
	    result = Boolean.FALSE;

	    // Inicializamos las banderas que nos marcarán los valores
	    // encontrados.
	    boolean asiForESIG = false;
	    boolean asiForESeal = false;
	    boolean asiForWSA = false;

	    // Recorremos la lista y vamos comprobando las URI.
	    for (AdditionalServiceInformation asi: asiList) {

		// En función de la URI, vamos marcando las banderas.
		switch (asi.getUri().toString()) {
		    case ITSLCommonURIs.TSL_SERVINFEXT_ADDSERVINFEXT_ROOTCAQC:
			break;

		    case ITSLCommonURIs.TSL_SERVINFEXT_ADDSERVINFEXT_FORESIGNATURES:
			asiForESIG = true;
			break;

		    case ITSLCommonURIs.TSL_SERVINFEXT_ADDSERVINFEXT_FORESEALS:
			asiForESeal = true;
			break;

		    case ITSLCommonURIs.TSL_SERVINFEXT_ADDSERVINFEXT_FORWEBSITEAUTHENTICATION:
			asiForWSA = true;
			break;

		    default:
			break;
		}

	    }

	    // Una vez tenemos los marcadores de los
	    // AdditionalServiceInformation,
	    // los vamos comprobando, y para ello recuperamos el analizador de
	    // extensiones.
	    TSLCertificateExtensionAnalyzer tslCertExtAnalyzer = validationResult.getTslCertificateExtensionAnalyzer();
	    
	  //se pinta en el log información obtenida del certificado.
	    extractInfoTslCertExtAnalycer(tslCertExtAnalyzer);

	    // Vamos comprobando de mayor requirimiento a menos...
	    // Primero autenticación servidor...
	    result = asiForWSA && (tslCertExtAnalyzer.hasQcStatementEuTypeExtensionOid(ITSLOIDs.OID_QCSTATEMENT_EXT_EUTYPE_WEB.getId()) || tslCertExtAnalyzer.hasSomeCertPolPolInfExtensionOid(ITSLValidatorOtherConstants.POLICYIDENTIFIERS_OIDS_FOR_WSA_CERTS_LIST));
	    if (result) {
		LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TV_LOG028));
		validationResult.setMappingClassification(ITSLValidatorResult.MAPPING_CLASSIFICATION_WSA);

	    } else {

		// Sello...
		result = asiForESeal && (tslCertExtAnalyzer.hasQcStatementEuTypeExtensionOid(ITSLOIDs.OID_QCSTATEMENT_EXT_EUTYPE_ESEAL.getId()) || tslCertExtAnalyzer.hasSomeCertPolPolInfExtensionOid(ITSLValidatorOtherConstants.POLICYIDENTIFIERS_OIDS_FOR_ESEAL_CERTS_LIST));
		if (result) {

		    validationResult.setMappingClassification(ITSLValidatorResult.MAPPING_CLASSIFICATION_ESEAL);
		    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TV_LOG033));
		} else {

		    result = asiForESIG && (tslCertExtAnalyzer.isThereSomeQcStatementExtension() || tslCertExtAnalyzer.hasSomeCertPolPolInfExtensionOid(ITSLValidatorOtherConstants.POLICYIDENTIFIERS_OIDS_FOR_ESIG_CERTS_LIST));
		    if (result) {

			validationResult.setMappingClassification(ITSLValidatorResult.MAPPING_CLASSIFICATION_ESIG);
			LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TV_LOG034));
		    }

		}

	    }

	}

	return result;

    }

    
	/**
	 * Method to extract information from the extension parser and display it in the log.
	 */
	private void extractInfoTslCertExtAnalycer(TSLCertificateExtensionAnalyzer tslCertExtAnalyzer) {
		// se obtienen la informacion para pintarla en el log
		if (tslCertExtAnalyzer != null) {
			LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TV_LOG029));
			if (tslCertExtAnalyzer.getPolicyInformationsOids() != null && !tslCertExtAnalyzer.getPolicyInformationsOids().isEmpty()) {
				String polInfOidsCert = String.join(",", tslCertExtAnalyzer.getPolicyInformationsOids());
				if (!UtilsStringChar.isNullOrEmpty(polInfOidsCert)) {
					LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.TV_LOG031, new Object[ ] { polInfOidsCert }));
				}
			}

			if (tslCertExtAnalyzer.getQcStatementsOids() != null && !tslCertExtAnalyzer.getQcStatementsOids().isEmpty()) {
				String qcStatementOids = String.join(",", tslCertExtAnalyzer.getQcStatementsOids());
				if (!UtilsStringChar.isNullOrEmpty(qcStatementOids)) {
					LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.TV_LOG030, new Object[ ] { qcStatementOids }));
				}
			}
			if (tslCertExtAnalyzer.getQcStatementExtEuTypeOids() != null && !tslCertExtAnalyzer.getQcStatementExtEuTypeOids().isEmpty()) {
				String qcStatementsExtEuTypeOids = String.join(",", tslCertExtAnalyzer.getQcStatementExtEuTypeOids());
				if (!UtilsStringChar.isNullOrEmpty(qcStatementsExtEuTypeOids)) {
					LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.TV_LOG032, new Object[ ] { qcStatementsExtEuTypeOids }));
				}
			}
		}
	}

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.certValidation.impl.common.ATSLValidator#analyzeQualifierToSetMapping(es.gob.afirma.tsl.certValidation.impl.common.TSLValidatorResult, java.lang.String)
     */
    @Override
    protected void analyzeQualifierToSetMapping(TSLValidatorResult validationResult, String qualifierUriString) {

	switch (qualifierUriString) {

	    case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCWITHSSCD:
		validationResult.setMappingQSCD(ITSLValidatorResult.MAPPING_QSCD_YES);
		break;

	    case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCNOSSCD:
		validationResult.setMappingQSCD(ITSLValidatorResult.MAPPING_QSCD_NO);
		break;

	    case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCSTATUSASINCERT:
		validationResult.setMappingQSCD(ITSLValidatorResult.MAPPING_QSCD_ASINCERT);
		break;

	    case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCWITHQSCD:
		validationResult.setMappingQSCD(ITSLValidatorResult.MAPPING_QSCD_YES);
		break;

	    case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCNOQSCD:
		validationResult.setMappingQSCD(ITSLValidatorResult.MAPPING_QSCD_NO);
		break;

	    case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCQSCDSTATUSASINCERT:
		validationResult.setMappingQSCD(ITSLValidatorResult.MAPPING_QSCD_ASINCERT);
		break;

	    case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCQSCDMANAGEDONBEHALF:
		validationResult.setMappingQSCD(ITSLValidatorResult.MAPPING_QSCD_YES_MANAGEDONBEHALF);
		break;

	    case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCFORLEGALPERSON:
		validationResult.setMappingClassification(ITSLValidatorResult.MAPPING_CLASSIFICATION_LEGALPERSON);
		break;

	    case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCFORESIG:
		validationResult.setMappingClassification(ITSLValidatorResult.MAPPING_CLASSIFICATION_ESIG);
		break;

	    case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCFORESEAL:
		validationResult.setMappingClassification(ITSLValidatorResult.MAPPING_CLASSIFICATION_ESEAL);
		break;

	    case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCFORWSA:
		validationResult.setMappingClassification(ITSLValidatorResult.MAPPING_CLASSIFICATION_WSA);
		break;

	    case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_NOTQUALIFIED:
		validationResult.setMappingType(ITSLValidatorResult.MAPPING_TYPE_NONQUALIFIED);
		break;

	    case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCSTATEMENT:
		validationResult.setMappingType(ITSLValidatorResult.MAPPING_TYPE_QUALIFIED);
		break;

	    default:
		break;

	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.certValidation.impl.common.ATSLValidator#checkIfCertificateObeyWithConditionsToBeDetected(es.gob.afirma.tsl.certValidation.impl.common.TSLCertificateExtensionAnalyzer)
     */
    @Override
    protected boolean checkIfCertificateObeyWithConditionsToBeDetected(TSLCertificateExtensionAnalyzer tslCertExtAnalyzer) {

	// Inicializamos el resultado a que el certificado no es detectado.
	boolean result = false;

	try {

	    // Obtenemos si es posible la información de si es Qualified.
	    String mappingQualifiedCert = TSLValidatorMappingCalculator.getMappingTypeQualifiedFromCertificate(tslCertExtAnalyzer);

	    // Obtenemos si es posible la información relativa a QSCD/SSCD.
	    String mappingQscd = TSLValidatorMappingCalculator.getMappingQSCDFromCertificate(tslCertExtAnalyzer);

	    // Obtenemos si es posible el tipo de certificado.
	    String mappingClassification = TSLValidatorMappingCalculator.getMappingClassificationFromCertificate(tslCertExtAnalyzer, false);

	    // Se debe cumplir:
	    // - Que se haya podido determinar que el certificado es
	    // cualificado.
	    // - Si el certificado se encuentra (o no) en un SSCD/QSCD.
	    // - Que el certificado haya sido emitido para una "legal person" o
	    // para ESIG, ESEAL o WSA.
	    result = ITslMappingConstants.MAPPING_VALUE_YES.equals(mappingQualifiedCert) && !ITslMappingConstants.MAPPING_VALUE_UNKNOWN.equals(mappingQscd);
	    if (result) {
		result = ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_LEGALPERSON.equals(mappingClassification) || ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_ESIG.equals(mappingClassification);
		result = result || ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_ESEAL.equals(mappingClassification) || ITslMappingConstants.MAPPING_VALUE_CLASSIFICATION_WSA.equals(mappingClassification);
	    }

	} catch (TSLValidationException e) {

	    // En caso de no parsear el certificado, se muestra error, y se
	    // considera
	    // no detectado.
	    LOGGER.error(Language.getResIntegraTsl(ILogTslConstant.TV_LOG019), e);

	}

	return result;

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.certValidation.impl.common.ATSLValidator#checkIfTSPServiceTypeIsCRLCompatible(es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance, boolean)
     */
    @Override
    public boolean checkIfTSPServiceTypeIsCRLCompatible(ServiceHistoryInstance shi, boolean isCertQualified) {

	boolean result = false;

	// Si el certificado es cualificado (qualified)...
	if (isCertQualified) {

	    result = shi.getServiceTypeIdentifier().toString().equals(ITSLCommonURIs.TSL_SERVICETYPE_CERTSTATUS_CRL_QC);

	}
	// Si no es cualificado...
	else {

	    result = shi.getServiceTypeIdentifier().toString().equals(ITSLCommonURIs.TSL_SERVICETYPE_CERTSTATUS_CRL);

	}

	return result;

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.certValidation.impl.common.ATSLValidator#checkIfTSPServiceTypeIsOCSPCompatible(es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance, boolean)
     */
    @Override
    public boolean checkIfTSPServiceTypeIsOCSPCompatible(ServiceHistoryInstance shi, boolean isCertQualified) {

	boolean result = false;

	// Si el certificado es cualificado (qualified)...
	if (isCertQualified) {

	    result = shi.getServiceTypeIdentifier().toString().equals(ITSLCommonURIs.TSL_SERVICETYPE_CERTSTATUS_OCSP_QC);

	}
	// Si no es cualificado...
	else {

	    result = shi.getServiceTypeIdentifier().toString().equals(ITSLCommonURIs.TSL_SERVICETYPE_CERTSTATUS_OCSP);

	}

	return result;

    }

    /**
	 * {@inheritDoc}
	 * @see es.gob.valet.tsl.certValidation.impl.common.ATSLValidator#checkAndAnalyzerExtensionCert(es.gob.valet.tsl.certValidation.impl.common.TSLCertificateExtensionAnalyzer)
	 */
	@Override
	protected CertificateExtension checkAndAnalyzerExtensionCert(TSLCertificateExtensionAnalyzer tslCertExtAnalyzer) {
		CertificateExtension  ce = null;
		if (tslCertExtAnalyzer != null) {
			ce = new CertificateExtension();
			if (tslCertExtAnalyzer.hasQcStatementExtensionOid(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance.getId())) {
				ce.setQcCompliance(Boolean.TRUE);
			}
			// QcType1
			if (tslCertExtAnalyzer.hasQcStatementEuTypeExtensionOid(ETSIQCObjectIdentifiers.id_etsi_qct_esign.getId())) {
				ce.setQcType1(Boolean.TRUE);
			}
			// QcType2
			if (tslCertExtAnalyzer.hasQcStatementEuTypeExtensionOid(ETSIQCObjectIdentifiers.id_etsi_qct_eseal.getId())) {
				ce.setQcType2(Boolean.TRUE);
			}
			// QcType3
			if (tslCertExtAnalyzer.hasQcStatementEuTypeExtensionOid(ETSIQCObjectIdentifiers.id_etsi_qct_web.getId())) {
				ce.setQcType3(Boolean.TRUE);
			}

			if (tslCertExtAnalyzer.hasCertPolPolInfExtensionOid(ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_PUBLIC_WITH_SSCD.getId())) {
				ce.setPolicyIdQCP_SSCD(Boolean.TRUE);
			}
			if (tslCertExtAnalyzer.hasCertPolPolInfExtensionOid(ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_PUBLIC.getId())) {
				ce.setPolicyIdQCP(Boolean.TRUE);
			}
			if (tslCertExtAnalyzer.hasQcStatementExtensionOid(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD.getId())) {
				ce.setQcSSCD(Boolean.TRUE);
			}
		}
		return ce;
	}
	/**
	 * {@inheritDoc}
	 * @see es.gob.valet.tsl.certValidation.impl.common.ATSLValidator#analyzeQuelifier(es.gob.valet.tsl.certValidation.TspServiceQualifier, java.lang.String)
	 */
	@Override
	protected void analyzeQuelifier(TspServiceQualifier tspServiceQualifier, String qualifierUriString) {
		switch (qualifierUriString) {

		case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCWITHSSCD:
			tspServiceQualifier.setQcWithSSCD(Boolean.TRUE);
			break;

		case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCNOSSCD:
			tspServiceQualifier.setQcNoSSCD(Boolean.TRUE);
			break;

		case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCSTATUSASINCERT:
			tspServiceQualifier.setQcSSCDStatusAsInCert(Boolean.TRUE);
			break;

		case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCWITHQSCD:
			tspServiceQualifier.setQcWithQSCD(Boolean.TRUE);
			break;

		case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCNOQSCD:
			tspServiceQualifier.setQcNoQSCD(Boolean.TRUE);
			break;

		case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCQSCDSTATUSASINCERT:
			tspServiceQualifier.setQcQSCDStatusAsInCert(Boolean.TRUE);
			break;

		case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCQSCDMANAGEDONBEHALF:
			tspServiceQualifier.setQcQSCDManagedOnBehalf(Boolean.TRUE);
			break;

		case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCFORLEGALPERSON:
			tspServiceQualifier.setQcForLegalPerson(Boolean.TRUE);
			break;

		case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCFORESIG:
			tspServiceQualifier.setQcForESig(Boolean.TRUE);
			break;

		case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCFORESEAL:
			tspServiceQualifier.setQcForESeal(Boolean.TRUE);
			break;

		case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCFORWSA:
			tspServiceQualifier.setQcForWSA(Boolean.TRUE);
			break;

		case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_NOTQUALIFIED:
			tspServiceQualifier.setNotQualified(Boolean.TRUE);
			break;

		case ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCSTATEMENT:
			tspServiceQualifier.setQcStatement(Boolean.TRUE);
			break;

		default:
			break;

	}
		
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.valet.tsl.certValidation.impl.common.ATSLValidator#getTSPServiceAdditionalServiceInformationExtensionsDetectCert(es.gob.valet.tsl.certValidation.SIResult)
	 */
	protected void getTSPServiceAdditionalServiceInformationExtensionsDetectCert(SIResult siResult) {

		// Inicialmente consideramos que no se han definido extensiones
		// AdditionalServiceInformation.
		LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.TV_LOG040, new Object[ ] { siResult.getTspName() }));
		
		// Primero recolectamos todas las extensiones del tipo
		// AdditionalServiceInformation.
		List<AdditionalServiceInformation> asiList = new ArrayList<AdditionalServiceInformation>();

		// Recuperamos la lista de extensiones del servicio, y si no es nula ni
		// vacía, continuamos.
		List<IAnyTypeExtension> extensionsList = siResult.getSiAtDateTime().getServiceInformationExtensions();
		if (extensionsList != null && !extensionsList.isEmpty()) {

			// Recorremos la lista buscando aquellas que sean de tipo
			// AdditionalServiceInformation.
			for (IAnyTypeExtension extension: extensionsList) {

				// Si es del tipo AdditionalServiceInformation...
				if (extension.getImplementationExtension() == IAnyTypeExtension.IMPL_ADDITIONAL_SERVICE_INFORMATION) {

					// La añadimos a la lista final.
					AdditionalServiceInformation ext = (AdditionalServiceInformation) extension;
					asiList.add((AdditionalServiceInformation) extension);
					LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.TV_LOG027, new Object[ ] { ext.getUri().toString() }));
					
				}

			}

		}

		// Si la lista no es vacía...
		if (!asiList.isEmpty()) {
			// Recorremos la lista y vamos comprobando las URI.
			for (AdditionalServiceInformation asi: asiList) {

				// En función de la URI, vamos marcando las banderas.
				switch (asi.getUri().toString()) {
					case ITSLCommonURIs.TSL_SERVINFEXT_ADDSERVINFEXT_ROOTCAQC:
						break;

					case ITSLCommonURIs.TSL_SERVINFEXT_ADDSERVINFEXT_FORESIGNATURES:
						LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TV_LOG041));
						siResult.setAsiForESIG(true);
						break;

					case ITSLCommonURIs.TSL_SERVINFEXT_ADDSERVINFEXT_FORESEALS:
						LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TV_LOG042));
						siResult.setAsiForESeal(true);
						break;

					case ITSLCommonURIs.TSL_SERVINFEXT_ADDSERVINFEXT_FORWEBSITEAUTHENTICATION:
						LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TV_LOG043));
						siResult.setAsiForWSA(true);
						break;

					default:
						break;
				}

			}

		}

	}

}
