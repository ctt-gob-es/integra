/*
/*******************************************************************************
 * Copyright (C) 2018 MINHAFP, Gobierno de España
 * This program is licensed and may be used, modified and redistributed under the  terms
 * of the European Public License (EUPL), either version 1.1 or (at your option)
 * any later version as soon as they are approved by the European Commission.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and
 * more details.
 * You should have received a copy of the EUPL1.1 license
 * along with this program; if not, you may find it at
 * http:joinup.ec.europa.eu/software/page/eupl/licence-eupl
 ******************************************************************************/

/**
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.ts119612.v020101.TSLChecker.java.</p>
 * <b>Description:</b><p>Class that represents a TSL Data Checker of TSL implementation as the
 * ETSI TS 119612 2.1.1 specification.</p>
 * <b>Project:</b><p>Platform for detection and validation of certificates recognized in European TSL.</p>
 * <b>Date:</b><p>06/11/2018.</p>
 * @author Gobierno de España.
 * @version 1.7, 17/04/2023.
 */
package es.gob.afirma.tsl.parsing.impl.tsl119612.v020101;

import java.net.URI;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.TreeSet;

import org.w3.x2000.x09.xmldsig.CanonicalizationMethodType;
import org.w3.x2000.x09.xmldsig.KeyValueType;
import org.w3.x2000.x09.xmldsig.ReferenceType;
import org.w3.x2000.x09.xmldsig.SignatureMethodType;
import org.w3.x2000.x09.xmldsig.SignatureType;
import org.w3.x2000.x09.xmldsig.SignatureValueType;
import org.w3.x2000.x09.xmldsig.SignedInfoType;
import org.w3.x2000.x09.xmldsig.TransformsType;

import es.gob.afirma.tsl.access.TSLManager;
import es.gob.afirma.tsl.exceptions.TSLMalformedException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.logger.Logger;
import es.gob.afirma.tsl.parsing.ifaces.IAnyTypeExtension;
import es.gob.afirma.tsl.parsing.ifaces.ITSLCommonURIs;
import es.gob.afirma.tsl.parsing.ifaces.ITSLElementsAndAttributes;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.ifaces.ITSLOtherConstants;
import es.gob.afirma.tsl.parsing.ifaces.ITSLSignatureConstants;
import es.gob.afirma.tsl.parsing.impl.common.ATSLChecker;
import es.gob.afirma.tsl.parsing.impl.common.Address;
import es.gob.afirma.tsl.parsing.impl.common.DigitalID;
import es.gob.afirma.tsl.parsing.impl.common.PostalAddress;
import es.gob.afirma.tsl.parsing.impl.common.ServiceDigitalIdentity;
import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;
import es.gob.afirma.tsl.parsing.impl.common.ServiceInformation;
import es.gob.afirma.tsl.parsing.impl.common.TSLPointer;
import es.gob.afirma.tsl.parsing.impl.common.TSPInformation;
import es.gob.afirma.tsl.utils.NumberConstants;
import es.gob.afirma.tsl.utils.UtilsCountryLanguage;
import es.gob.afirma.tsl.utils.UtilsStringChar;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.SubjectKeyIdentifier;

/**
 * <p>Class that represents a TSL Data Checker of TSL implementation as the
 * ETSI TS 119612 2.1.1 specification.</p>
 * <b>Project:</b><p>Platform for detection and validation of certificates recognized in European TSL.</p>
 * @version 1.7, 17/04/2023.
 */
public class TSLChecker extends ATSLChecker {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = Logger.getLogger(TSLChecker.class);

    /**
     * Constant attribute that represents the start date form which applies this specification.
     */
    private static Date startDate = null;

    /**
     * Gets the start date form which applies this specification.
     * @return the start date form which applies this specification.
     */
    private static Date getInitialDate() {

	if (startDate == null) {
	    Calendar cal = Calendar.getInstance();
	    cal.set(NumberConstants.INT_2016, NumberConstants.INT_6, 1, 0, 0, 0);
	    startDate = cal.getTime();
	}
	return startDate;

    }

    /**
     * Constructor method for the class TSLChecker.java.
     * @param tslObject TSL object representation that will be checked.
     */
    public TSLChecker(ITSLObject tslObject) {
	super(tslObject);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkTSLTagValue()
     */
    @Override
    protected void checkTSLTagValue() throws TSLMalformedException {

	URI tslTagUri = getTSLObject().getTSLTag();
	// A pesar de que la especificación (XSD) permite cualquier URI, vamos a
	// ser restrictivos
	// y solo vamos a permitir la correspondiente a la especificación
	// 119612.
	if (!ITSLCommonURIs.TSL_TAG_19612.equalsIgnoreCase(tslTagUri.toString())) {

	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG001, new Object[ ] { ITSLElementsAndAttributes.ATTRIBUTE_TSL_TAG }));

	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSchemeInformationTSLVersionIdentifierValue()
     */
    @Override
    protected void checkSchemeInformationTSLVersionIdentifierValue() throws TSLMalformedException {

	if (getTSLObject().getSchemeInformation().getTslVersionIdentifier() != NumberConstants.INT_5) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSL_VERSION_IDENTIFIER }));
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSchemeInformationTSLTypeValue()
     */
    @Override
    protected void checkSchemeInformationTSLTypeValue() throws TSLMalformedException {

	URI tslTypeUri = getTSLObject().getSchemeInformation().getTslType();
	if (tslTypeUri == null) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSL_TYPE }));
	}
	String tslTypeUriString = tslTypeUri.toString();
	boolean valueOK = isTSLTypeEUGeneric(tslTypeUriString) || isTSLTypeEUlistOfTheList(tslTypeUriString);
	valueOK = valueOK || isTSLTypeNonEUCountry(tslTypeUriString) || isTSLTypeNonEUCountryListOfTheList(tslTypeUriString);
	if (!valueOK) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSL_TYPE }));
	}

    }

    /**
     * Checks if the TSL type URI is valid and it is for an EU member.
     * @param tslType String that represents the TSL Type URI.
     * @return <code>true</code> if the TSL type URI is valid and it is for an EU member, otherwise <code>false</code>.
     */
    private boolean isTSLTypeEUGeneric(String tslType) {
	return tslType.equalsIgnoreCase(ITSLCommonURIs.TSL_TYPE_EUGENERIC);
    }

    /**
     * Checks if the TSL type URI is valid and it is EU list of the lists.
     * @param tslType String that represents the TSL Type URI.
     * @return <code>true</code> if the TSL type URI is valid and it is EU list of the lists, otherwise <code>false</code>.
     */
    private boolean isTSLTypeEUlistOfTheList(String tslType) {
	return tslType.equalsIgnoreCase(ITSLCommonURIs.TSL_TYPE_EULISTOFTHELIST);
    }

    /**
     * Checks if the TSL type URI is valid and it is for non EU country.
     * @param tslType String that represents the TSL Type URI.
     * @return <code>true</code> if the TSL type URI is valid and it is for non EU country, otherwise <code>false</code>.
     */
    private boolean isTSLTypeNonEUCountry(String tslType) {

	if (tslType.startsWith(ITSLCommonURIs.TSL_TYPE_NONEUGENERIC_PREFFIX) && tslType.endsWith(ITSLCommonURIs.TSL_TYPE_NONEUGENERIC_SUFFIX)) {
	    return UtilsCountryLanguage.checkCountryCode(tslType.substring(ITSLCommonURIs.TSL_TYPE_NONEUGENERIC_PREFFIX.length(), tslType.length() - ITSLCommonURIs.TSL_TYPE_NONEUGENERIC_SUFFIX.length()));
	}
	return false;

    }

    /**
     * Checks if the TSL type URI is valid and it is for non EU country.
     * @param tslType String that represents the TSL Type URI.
     * @return <code>true</code> if the TSL type URI is valid and it is for non EU country, otherwise <code>false</code>.
     */
    private boolean isTSLTypeNonEUCountryListOfTheList(String tslType) {

	if (tslType.startsWith(ITSLCommonURIs.TSL_TYPE_NONEULISTOFTHELISTS_PREFFIX) && tslType.endsWith(ITSLCommonURIs.TSL_TYPE_NONEULISTOFTHELISTS_PREFFIX)) {
	    return UtilsCountryLanguage.checkCountryCode(tslType.substring(ITSLCommonURIs.TSL_TYPE_NONEULISTOFTHELISTS_PREFFIX.length(), tslType.length() - ITSLCommonURIs.TSL_TYPE_NONEULISTOFTHELISTS_PREFFIX.length()));
	}
	return false;

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSchemeInformationOperatorNameValue()
     */
    @Override
    protected void checkSchemeInformationOperatorNameValue() throws TSLMalformedException {

	// Debe estar definido al menos en inglés.
	List<String> sionvList = getTSLObject().getSchemeInformation().getSchemeOperatorNameInLanguage(Locale.UK.getLanguage());
	if (sionvList == null || sionvList.isEmpty()) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_SCHEME_OPERATOR_NAME }));
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkAddressValue(es.gob.afirma.tsl.parsing.impl.common.Address)
     */
    @Override
    protected void checkAddressValue(Address address) throws TSLMalformedException {

	// Debe estar definido al menos en inglés.
	List<PostalAddress> paList = address.getPostalAddresses().get(Locale.UK.getLanguage());
	if (paList == null) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_SCHEME_OPERATOR_ADDRESS }));
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSchemeInformationNameValue()
     */
    @Override
    protected void checkSchemeInformationNameValue() throws TSLMalformedException {

	// Debe estar definido al menos en inglés.
	String nameEnglish = getTSLObject().getSchemeInformation().getSchemeName(Locale.UK.getLanguage());
	if (nameEnglish == null) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_SCHEME_NAME }));
	}

	// Cada uno de los nombres debe seguir el formato "CC:texto" donde CC
	// debe ser el valor asignado en "Scheme Territory Field".
	Map<String, String> names = getTSLObject().getSchemeInformation().getSchemeNames();
	if (names != null && !names.isEmpty()) {

	    Collection<String> namesCollection = names.values();
	    for (String name: namesCollection) {

		if (UtilsStringChar.isNullOrEmptyTrim(name) || name.length() < 2 || !name.startsWith(getTSLObject().getSchemeInformation().getSchemeTerritory())) {
		    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG006, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_SCHEME_NAME }));
		}

	    }

	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSchemeInformationURIValue()
     */
    @Override
    protected void checkSchemeInformationURIValue() throws TSLMalformedException {

	// Debe estar definido al menos en inglés.
	List<URI> uriList = getTSLObject().getSchemeInformation().getSchemeInformationURIinLanguage(Locale.UK.getLanguage());
	if (uriList == null || uriList.isEmpty()) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_SCHEME_INFORMATION_URI }));
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSchemeInformationStatusDeterminationApproachValue()
     */
    @Override
    protected void checkSchemeInformationStatusDeterminationApproachValue() throws TSLMalformedException {

	String sda = getTSLObject().getSchemeInformation().getStatusDeterminationApproach().toString();
	String tslType = getTSLObject().getSchemeInformation().getTslType().toString();

	boolean valueOK = false;
	if (isTSLTypeEUGeneric(tslType) || isTSLTypeEUlistOfTheList(tslType)) {

	    valueOK = sda.equalsIgnoreCase(ITSLCommonURIs.TSL_STATUSDETAPPROACH_EUAPPROPIATE);

	} else if (isTSLTypeNonEUCountry(tslType) || isTSLTypeNonEUCountryListOfTheList(tslType)) {

	    if (sda.startsWith(ITSLCommonURIs.TSL_STATUSDETAPPROACH_NONEU_PREFFIX) && sda.endsWith(ITSLCommonURIs.TSL_STATUSDETAPPROACH_NONEU_SUFFIX)) {

		String country = sda.substring(ITSLCommonURIs.TSL_STATUSDETAPPROACH_NONEU_PREFFIX.length(), sda.length() - ITSLCommonURIs.TSL_STATUSDETAPPROACH_NONEU_SUFFIX.length());
		valueOK = UtilsCountryLanguage.checkCountryCode(country);

	    }

	}

	if (!valueOK) {

	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_STATUS_DETERMINATION_APPROACH }));

	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSchemeInformationTypeCommunityRulesDefined()
     */
    @Override
    protected void checkSchemeInformationTypeCommunityRulesDefined() throws TSLMalformedException {

	// Para esta especificación, el elemento es obligatorio, por lo que en
	// caso de no estar
	// definido lanzamos excepción.
	if (!getTSLObject().getSchemeInformation().isThereSomeSchemeTypeCommunityRule()) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_SCHEME_TYPE_COMMUNITY_RULES }));
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSchemeTypeCommunityURIValue(java.net.URI)
     */
    @Override
    protected void checkSchemeTypeCommunityURIValue(URI uri) throws TSLMalformedException {

	boolean valueOK = false;

	String uriString = uri.toString();
	String tslType = getTSLObject().getSchemeInformation().getTslType().toString();

	if (isTSLTypeEUlistOfTheList(tslType)) {

	    valueOK = uriString.equalsIgnoreCase(ITSLCommonURIs.TSL_SCHEMECOMUNITYRULES_EULISTOFTHELISTS);

	} else if (isTSLTypeEUGeneric(tslType)) {

	    valueOK = uriString.equalsIgnoreCase(ITSLCommonURIs.TSL_SCHEMECOMUNITYRULES_EUCOMMON);
	    if (!valueOK) {
		if (uriString.startsWith(ITSLCommonURIs.TSL_SCHEMECOMUNITYRULES_CC_PREFFIX) && uriString.length() > ITSLCommonURIs.TSL_SCHEMECOMUNITYRULES_CC_PREFFIX.length()) {
		    valueOK = uriString.substring(ITSLCommonURIs.TSL_SCHEMECOMUNITYRULES_CC_PREFFIX.length()).equals(getTSLObject().getSchemeInformation().getSchemeTerritory());
		}
	    }

	} else if (isTSLTypeNonEUCountry(tslType) || isTSLTypeNonEUCountryListOfTheList(tslType)) {

	    valueOK = uriString.startsWith(ITSLCommonURIs.HTTP_PROTOCOL_PREFFIX);

	}

	if (!valueOK) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_SCHEME_TYPE_COMMUNITY_RULES }));
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSchemeInformationTerritoryValue()
     */
    @Override
    protected void checkSchemeInformationTerritoryValue() throws TSLMalformedException {

	if (!UtilsCountryLanguage.checkCountryCode(getTSLObject().getSchemeInformation().getSchemeTerritory())) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_SCHEME_TERRITORY }));
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSchemeInformationPolicyValues()
     */
    @Override
    protected void checkSchemeInformationPolicyValues() throws TSLMalformedException {

	// Al menos debe definirse en inglés.
	if (getTSLObject().getSchemeInformation().getPolicyInLanguage(Locale.UK.getLanguage()) == null) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_POLICY_OR_LEGAL_NOTICE }));
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSchemeInformationLegalNoticeValues()
     */
    @Override
    protected void checkSchemeInformationLegalNoticeValues() throws TSLMalformedException {

	// Al menos debe definirse en inglés.
	if (getTSLObject().getSchemeInformation().getLegalNoticeInLanguage(Locale.UK.getLanguage()) == null) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_POLICY_OR_LEGAL_NOTICE }));
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSchemeInformationHistoricalInformationPeriodValue()
     */
    @Override
    protected void checkSchemeInformationHistoricalInformationPeriodValue() throws TSLMalformedException {

	if (getTSLObject().getSchemeInformation().getHistoricalPeriod() != NumberConstants.INT_65535) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_HISTORICAL_INFORMATION_PERIOD }));
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSchemeInformationPointersToOtherTSLValue()
     */
    @Override
    protected void checkSchemeInformationPointersToOtherTSLValue() throws TSLMalformedException {

	// Según el tipo de TSL.
	String tslType = getTSLObject().getSchemeInformation().getTslType().toString();

	// Si se trata de un miembro europeo, o de la lista de listas, debe
	// estar definido
	// el campo con los TSLPointers.
	if ((isTSLTypeEUGeneric(tslType) || isTSLTypeEUlistOfTheList(tslType)) && !getTSLObject().getSchemeInformation().isThereSomePointerToOtherTSL()) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_POINTER_TO_OTHER_TSL_TSLLOCATION }));
	}

	// Si finalmente es de un estado miembro europeo, entonces debe contener
	// un TSL Pointer
	// que apunte a la lista de listas.
	if (isTSLTypeEUGeneric(tslType) || isTSLTypeEUlistOfTheList(tslType)) {

	    List<TSLPointer> tslPointers = getTSLObject().getSchemeInformation().getPointersToOtherTSL();
	    for (TSLPointer tslPointer: tslPointers) {

		if (TSLManager.getInstance().getSetOfURLStringThatRepresentsEuLOTL().contains(tslPointer.getTSLLocation().toString())) {

		    // Si lo hemos encontrado, hemos terminado.
		    return;

		}

	    }

	    // Si llegamos aquí, es que no hemos encontrado la URI.
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG007, new Object[ ] { TSLManager.getInstance().getSetOfURLStringThatRepresentsEuLOTLinString() }));

	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSchemeInformationPointerToOtherTSLValue(es.gob.afirma.tsl.parsing.impl.common.TSLPointer)
     */
    @Override
    protected void checkSchemeInformationPointerToOtherTSLValue(TSLPointer tslPointer) throws TSLMalformedException {

	// La URI no puede ser nula.
	if (tslPointer.getTSLLocation() == null) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_POINTER_TO_OTHER_TSL_TSLLOCATION }));
	}

	// Comprobamos las identidades de servicio digital.
	if (tslPointer.isThereSomeServiceDigitalIdentity()) {
	    List<ServiceDigitalIdentity> sdiList = tslPointer.getServiceDigitalIdentities();
	    for (ServiceDigitalIdentity sdi: sdiList) {
		if (sdi.isThereSomeIdentity()) {
		    try {
			checkDigitalIdsList(sdi.getAllDigitalIdentities());
		    } catch (TSLMalformedException e) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_POINTER_TO_OTHER_TSL }), e);
		    }
		}
	    }
	}

    }

    /**
     * Checks the Digital Ids List if it is not <code>null</code> or empty.
     * @param digitalIdsList Digital identities list to check.
     * @throws TSLMalformedException In case of some data has not a correct value.
     */
    private void checkDigitalIdsList(List<DigitalID> digitalIdsList) throws TSLMalformedException {

	if (digitalIdsList != null && !digitalIdsList.isEmpty()) {

	    for (DigitalID digitalId: digitalIdsList) {
		checkDigitalID(digitalId);
	    }

	}

    }

    /**
     * Checks the Digital Identity.
     * @param digitalId Digital identity to check.
     * @throws TSLMalformedException In case of some data has not a correct value.
     */
    private void checkDigitalID(DigitalID digitalId) throws TSLMalformedException {

	// Si es nulo lanzamos excepción.
	if (digitalId == null) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_DIGITAL_IDENTITY }));
	} else {

	    // Según el tipo lo analizamos.
	    int digitalIdType = digitalId.getType();
	    switch (digitalIdType) {
		case DigitalID.TYPE_X509CERTIFICATE:
		    checkDigitalIdTypeX509Certificate(digitalId.getX509cert());
		    break;

		case DigitalID.TYPE_X509SUBJECTNAME:
		    checkDigitalIdTypeSubjectName(digitalId.getX509SubjectName());
		    break;

		case DigitalID.TYPE_KEYVALUE:
		    checkDigitalIdTypeKeyValue(digitalId.getKeyValue());
		    break;

		case DigitalID.TYPE_X509SKI:
		    checkDigitalIdTypeX509SKI(digitalId.getSki());
		    break;

		case DigitalID.TYPE_OTHER:
		    checkDigitalIdTypeOther(digitalId.getOther());
		    break;

		default:
		    // Si no es ninguno de los tipos reconocidos, excepción.
		    throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.TC_LOG018));
	    }
	}

    }

    /**
     * Checks the Digital ID of type X509 Certificate.
     * @param cert X509 certificate to check.
     * @throws TSLMalformedException If the input certificate has not a valid value.
     */
    private void checkDigitalIdTypeX509Certificate(X509Certificate cert) throws TSLMalformedException {
	if (cert == null) {
	    throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.TC_LOG019));
	}
    }

    /**
     * Checks the Digital ID of type X509 Subject Name.
     * @param x509SubjectName X509 Subject Name to check.
     * @throws TSLMalformedException If the input X509 Subject Name has not a valid value.
     */
    private void checkDigitalIdTypeSubjectName(String x509SubjectName) throws TSLMalformedException {
	if (UtilsStringChar.isNullOrEmptyTrim(x509SubjectName)) {
	    throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.TC_LOG020));
	}
    }

    /**
     * Checks the Digital ID of type Key Value.
     * @param keyValue Key Value to check.
     * @throws TSLMalformedException If the input Key Value has not a valid value.
     */
    private void checkDigitalIdTypeKeyValue(KeyValueType keyValue) throws TSLMalformedException {
	if (keyValue == null) {
	    throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.TC_LOG021));
	}
    }

    /**
     * Checks the Digital ID of type X509 SKI.
     * @param ski X509 SKI to check.
     * @throws TSLMalformedException If the input X509 SKI has not a valid value.
     */
    private void checkDigitalIdTypeX509SKI(SubjectKeyIdentifier ski) throws TSLMalformedException {
	if (ski == null) {
	    throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.TC_LOG022));
	}
    }

    /**
     * Checks the Digital ID of type Other.
     * @param other String to check.
     * @throws TSLMalformedException If the input string is <code>null</code> or empty.
     */
    private void checkDigitalIdTypeOther(String other) throws TSLMalformedException {
	if (UtilsStringChar.isNullOrEmptyTrim(other)) {
	    throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.TC_LOG023));
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSchemeInformationListIssueDateTimeValue()
     */
    @Override
    protected void checkSchemeInformationListIssueDateTimeValue() throws TSLMalformedException {
	return;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSchemeInformationNextUpdateDefined()
     */
    @Override
    protected void checkSchemeInformationNextUpdateDefined() throws TSLMalformedException {
	// Para esta implementación, puede ser nulo (si la TSL a cesado de dar
	// servicios y todos están expirados).
	return;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSchemeInformationNextUpdateValue()
     */
    @Override
    protected void checkSchemeInformationNextUpdateValue() throws TSLMalformedException {

	// La diferencia entre la fecha de emisión y la de caducidad no puede
	// ser superior a 6 meses.
	// Recuperamos la fecha de emisión sumándole 6 meses.
	Date issueDate = getTSLObject().getSchemeInformation().getListIssueDateTime();
	Calendar issueDateCalendar = Calendar.getInstance();
	issueDateCalendar.setTime(issueDate);
	issueDateCalendar.add(Calendar.MONTH, NumberConstants.INT_6);
	Date issueDateMod = issueDateCalendar.getTime();
	// Calculamos el desplazamiento debido al cambio horario
	// invierno/verano.
	if (!TimeZone.getDefault().inDaylightTime(issueDate) && TimeZone.getDefault().inDaylightTime(issueDateMod)) {
	    issueDateMod = new Date(issueDateMod.getTime() + Integer.valueOf(TimeZone.getDefault().getDSTSavings()).longValue());
	} else if (TimeZone.getDefault().inDaylightTime(issueDate) && !TimeZone.getDefault().inDaylightTime(issueDateMod)) {
	    issueDateMod = new Date(issueDateMod.getTime() - Integer.valueOf(TimeZone.getDefault().getDSTSavings()).longValue());
	}
	Date nextUpdate = getTSLObject().getSchemeInformation().getNextUpdate();
	if (issueDateMod.before(nextUpdate)) {
	    // Por decisión de Dirección de Proyecto se suaviza esta
	    // comprobación.
	    LOGGER.warn(Language.getResIntegraTsl(ILogTslConstant.TC_LOG024));
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSchemeInformationDistributionPointsValues()
     */
    @Override
    protected void checkSchemeInformationDistributionPointsValues() throws TSLMalformedException {
	return;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSchemeInformationExtensionsDependingOnTSLType()
     */
    @Override
    protected void checkSchemeInformationExtensionsDependingOnTSLType() throws TSLMalformedException {

	// Obtenemos el tipo de TSL.
	String tslType = getTSLObject().getSchemeInformation().getTslType().toString();

	// Si la TSL es europea, entonces no deben definirse extensiones.
	if ((isTSLTypeEUGeneric(tslType) || isTSLTypeEUlistOfTheList(tslType)) && getTSLObject().getSchemeInformation().isThereSomeSchemeInformationExtension()) {
	    throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.TC_LOG025));
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#isListOfLists()
     */
    @Override
    protected boolean isListOfLists() {
	String tslTypeUriString = getTSLObject().getSchemeInformation().getTslType().toString();
	return isTSLTypeEUlistOfTheList(tslTypeUriString) || isTSLTypeNonEUCountryListOfTheList(tslTypeUriString);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkTSPInformationNamesValues(es.gob.afirma.tsl.parsing.impl.common.TSPInformation)
     */
    @Override
    protected void checkTSPInformationNamesValues(TSPInformation tspInformation) throws TSLMalformedException {

	// Debe estar definido al menos en inglés.
	List<String> namesList = tspInformation.getTSPNamesForLanguage(Locale.UK.getLanguage());
	if (namesList == null) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPINFORMATION_NAME }));
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkTSPInformationTradeNamesValues(es.gob.afirma.tsl.parsing.impl.common.TSPInformation)
     */
    @Override
    protected void checkTSPInformationTradeNamesValues(TSPInformation tspInformation) throws TSLMalformedException {

	// Primero comprobamos que no sea nulo.
	if (!tspInformation.isThereSomeTradeName()) {

	    // Por decisión de Dirección de Proyecto se decide suavizar esta
	    // comprobación.
	    LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPINFORMATION_TRADENAME }));
	} else {

	    // Debe estar definido al menos en inglés.
	    List<String> namesList = tspInformation.getTSPTradeNamesForLanguage(Locale.UK.getLanguage());
	    if (namesList == null || namesList.isEmpty()) {
		throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPINFORMATION_TRADENAME }));
	    }

	    // Ahora hay que comprobar que AL MENOS UNO de los TSPTradeNames
	    // definidos,
	    // mantiene la estructura "{COD}{CC}-Identifier" donde:
	    // - COD: [VAT | NTR | PAS | IDC | PNO | TIN].
	    // - CC: Country Code ISO 3166-1[15]
	    // - Carácter '-'.
	    // - Identificador.
	    // El resto basta comprobar que no sean cadenas vacías.

	    // Definimos la bandera que indica que hemos encontrado al menos
	    // uno.
	    boolean officialRegistrationIdentifierFinded = false;

	    // Los vamos recorriendo...
	    Map<String, List<String>> tradeNamesMap = tspInformation.getAllTSPTradeNames();
	    Set<String> languageKeys = tradeNamesMap.keySet();
	    for (String langKey: languageKeys) {

		List<String> tradeNamesList = tradeNamesMap.get(langKey);
		for (String tradeName: tradeNamesList) {

		    // Si no es una cadena vacía, es válido.
		    boolean validTradeName = !UtilsStringChar.isNullOrEmptyTrim(tradeName);

		    // Si es válido y no hemos encontrado aún uno con la
		    // estructura del identificador oficial,
		    // lo comprobamos.
		    if (validTradeName) {

			if (!officialRegistrationIdentifierFinded) {

			    officialRegistrationIdentifierFinded = checkIfTradeNameIsOfficialRegistrationIdentifier(tradeName);

			}

		    } else {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG006, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPINFORMATION_TRADENAME }));
		    }

		}

	    }

	    // Si no se ha encontrado un identificador de registro oficial...
	    if (!officialRegistrationIdentifierFinded) {
		// TODO: Se ha relajado la comprobación del identificador de
		// registro,
		// ya que se trata de un campo informativo y actualmente
		// (04/07/2016)
		// hay múltiples TSL que no lo definen adecuadamente.

		// En su lugar se muestra un warning.
		LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG008, new Object[ ] { tspInformation.getTSPNamesForLanguage(Locale.UK.getLanguage()), ITSLElementsAndAttributes.ELEMENT_TSPINFORMATION_TRADENAME }));
	    }

	}

    }

    /**
     * Cehcks if the input trade name is a official registration identifier.
     * @param tradeName Trade Name to check.
     * @return <code>true</code> if the input trade name is a official registration identifier,
     * otherwise <code>false</code>.
     */
    private boolean checkIfTradeNameIsOfficialRegistrationIdentifier(String tradeName) {

	boolean result = false;

	// La longitud debe ser mayor de 6.
	if (tradeName.length() > NumberConstants.INT_6) {

	    // Comprobamos COD.
	    result = tradeName.startsWith(ITSLOtherConstants.TOKEN_TSP_INF_TRADE_NAME_VAT) || tradeName.startsWith(ITSLOtherConstants.TOKEN_TSP_INF_TRADE_NAME_NTR);
	    result = result || tradeName.startsWith(ITSLOtherConstants.TOKEN_TSP_INF_TRADE_NAME_PAS) || tradeName.startsWith(ITSLOtherConstants.TOKEN_TSP_INF_TRADE_NAME_IDC);
	    result = result || tradeName.startsWith(ITSLOtherConstants.TOKEN_TSP_INF_TRADE_NAME_PNO) || tradeName.startsWith(ITSLOtherConstants.TOKEN_TSP_INF_TRADE_NAME_TIN);

	    if (result) {
		// Comprobamos CC.
		String cc = tradeName.substring(NumberConstants.INT_3, NumberConstants.INT_5);
		result = UtilsCountryLanguage.checkCountryCode(cc);
	    }

	    if (result) {
		// Comprobamos '-'.
		result = UtilsStringChar.SYMBOL_HYPHEN == tradeName.charAt(NumberConstants.INT_5);
	    }

	}

	return result;

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkTSPInformationURIvalues(es.gob.afirma.tsl.parsing.impl.common.TSPInformation)
     */
    @Override
    protected void checkTSPInformationURIvalues(TSPInformation tspInformation) throws TSLMalformedException {

	// Debe estar definido al menos en inglés.
	List<URI> uriList = tspInformation.getURIForLanguage(Locale.UK.getLanguage());
	if (uriList == null) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPINFORMATION_URI }));
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkTSPInformationExtensionsDependingOnTSLType(es.gob.afirma.tsl.parsing.impl.common.TSPInformation)
     */
    @Override
    protected void checkTSPInformationExtensionsDependingOnTSLType(TSPInformation tspInformation) throws TSLMalformedException {

	// Si la TSL pertenece a un miembro europeo, ninguna de las extensiones
	// puede ser crítica.
	String tslType = getTSLObject().getSchemeInformation().getTslType().toString();
	if (isTSLTypeEUGeneric(tslType) || isTSLTypeEUlistOfTheList(tslType)) {

	    List<IAnyTypeExtension> tspInformationExtensions = tspInformation.getTspInformationExtensions();
	    if (tspInformationExtensions != null && !tspInformationExtensions.isEmpty()) {
		for (IAnyTypeExtension extension: tspInformationExtensions) {
		    if (extension.isCritical()) {
			throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.TC_LOG009));
		    }
		}
	    }

	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkTSPServiceInformationType(es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance)
     */
    @Override
    protected void checkTSPServiceInformationType(ServiceHistoryInstance tspServiceInformation) throws TSLMalformedException {

	URI serviceTypeIdentifier = tspServiceInformation.getServiceTypeIdentifier();

	if (serviceTypeIdentifier == null) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_TYPE }));
	}

	String tslTypeUriString = getTSLObject().getSchemeInformation().getTslType().toString();
	String sti = serviceTypeIdentifier.toString();
	boolean valueOK = false;

	if (isTSLTypeEUGeneric(tslTypeUriString)) {

	    // Para certificados cualificados.
	    valueOK = isServiceTypeForQualifiedCerts(sti);

	    // Si se ha detectado que es de tipo CA/QC, hay que comprobar
	    // que al menos existe la extensión AdditionalServiceInformation
	    // en el servicio.
	    if (valueOK && sti.equals(ITSLCommonURIs.TSL_SERVICETYPE_CA_QC) && !checkIfIsDefinedSomeExtensionTypeInTSPService(tspServiceInformation, IAnyTypeExtension.IMPL_ADDITIONAL_SERVICE_INFORMATION)) {
		// TODO Se cambia la propagación de la excepción por el error
		// por un warning en el log,
		// ya que si no se relaja esta comprobación, muchas TSL serían
		// rechazadas.
		LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG010, new Object[ ] { tspServiceInformation.getServiceNameInLanguage(Locale.UK.getLanguage()) }));
	    }

	    // Para certificados no cualificados.
	    valueOK = valueOK || isServiceTypeForNonQualifiedCerts(sti);

	    // Para certificados no definidos a nivel europeo, pero sí nacional.
	    valueOK = valueOK || isServiceTypeForNationalCerts(sti);

	} else if (isTSLTypeNonEUCountry(tslTypeUriString)) {

	    valueOK = sti.startsWith(ITSLCommonURIs.HTTP_PROTOCOL_PREFFIX);

	}

	if (!valueOK) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_TYPE }));
	}

    }

    /**
     * Auxiliar method that checks if the input Service Type Identifier is for Qualified Certificates.
     * @param uriStringServiceType Service Type Identifier to analyze.
     * @return <code>true</code> if the input Service Type Identifier is for Qualified Certificates.
     */
    private boolean isServiceTypeForQualifiedCerts(String uriStringServiceType) {

	boolean result = false;

	if (!UtilsStringChar.isNullOrEmptyTrim(uriStringServiceType)) {

	    result = uriStringServiceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_CA_QC) || uriStringServiceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_CERTSTATUS_OCSP_QC) || uriStringServiceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_CERTSTATUS_CRL_QC);
	    result = result || uriStringServiceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_TSA_QTST) || uriStringServiceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_EDS_Q);
	    result = result || uriStringServiceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_EDS_REM_Q) || uriStringServiceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_PSES_Q);
	    result = result || uriStringServiceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_QESVALIDATION_Q);

	}

	return result;

    }

    /**
     * Attribute that represents a URI set that defines the service types for non qualified certificates.
     */
    private static Set<String> serviceTypesForNonQualifiedCertsSet = null;

    static {
	serviceTypesForNonQualifiedCertsSet = new TreeSet<String>();
	serviceTypesForNonQualifiedCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_CA_PKC);
	serviceTypesForNonQualifiedCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_CERTSTATUS_OCSP);
	serviceTypesForNonQualifiedCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_CERTSTATUS_CRL);
	serviceTypesForNonQualifiedCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_TSA);
	serviceTypesForNonQualifiedCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_TSA_TSSQC);
	serviceTypesForNonQualifiedCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_TSA_TSS_ADESQC_AND_QES);
	serviceTypesForNonQualifiedCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_EDS);
	serviceTypesForNonQualifiedCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_REM);
	serviceTypesForNonQualifiedCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_PSES);
	serviceTypesForNonQualifiedCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_ADESVALIDATION);
	serviceTypesForNonQualifiedCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_ADESGENERATION);
    }

    /**
     * Auxiliar method that checks if the input Service Type Identifier is for Non Qualified Certificates.
     * @param uriStringServiceType Service Type Identifier to analyze.
     * @return <code>true</code> if the input Service Type Identifier is for Non Qualified Certificates.
     */
    private boolean isServiceTypeForNonQualifiedCerts(String uriStringServiceType) {

	return !UtilsStringChar.isNullOrEmptyTrim(uriStringServiceType) && serviceTypesForNonQualifiedCertsSet.contains(uriStringServiceType);

    }

    /**
     * Attribute that represents a URI set that defines the service types for national certificates.
     */
    private static Set<String> serviceTypesForNationalCertsSet = null;

    static {
	serviceTypesForNationalCertsSet = new TreeSet<String>();
	serviceTypesForNationalCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_RA);
	serviceTypesForNationalCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_RA_NOTHAVINGPKIID);
	serviceTypesForNationalCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_ACA);
	serviceTypesForNationalCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_SIGNATURE_POLICY_AUTHORITY);
	serviceTypesForNationalCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_ARCHIV);
	serviceTypesForNationalCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_ARCHIV_NOTHAVINGPKIID);
	serviceTypesForNationalCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_IDV);
	serviceTypesForNationalCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_IDV_NOTHAVINGPKIID);
	serviceTypesForNationalCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_KESCROW);
	serviceTypesForNationalCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_KESCROW_NOTHAVINGPKIID);
	serviceTypesForNationalCertsSet.add(ITSLCommonURIs.TSL_SERVICETYPE_PPWD);
    }

    /**
     * Auxiliar method that checks if the input Service Type Identifier is for National Certificates.
     * @param uriStringServiceType Service Type Identifier to analyze.
     * @return <code>true</code> if the input Service Type Identifier is for National Certificates.
     */
    private boolean isServiceTypeForNationalCerts(String uriStringServiceType) {

	return !UtilsStringChar.isNullOrEmptyTrim(uriStringServiceType) && serviceTypesForNationalCertsSet.contains(uriStringServiceType);

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkTSPServiceInformationNamesValues(es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance)
     */
    @Override
    protected void checkTSPServiceInformationNamesValues(ServiceHistoryInstance tspServiceInformation) throws TSLMalformedException {

	// Debe estar definido al menos en inglés.
	String name = tspServiceInformation.getServiceNameInLanguage(Locale.UK.getLanguage());
	if (name == null) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_NAMES }));
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkTSPServiceInformationIdentitiesSize(es.gob.afirma.tsl.parsing.impl.common.ServiceInformation)
     */
    @Override
    protected void checkTSPServiceInformationIdentitiesSize(ServiceInformation tspServiceInformation) throws TSLMalformedException {

	// El número de identidades digitales debe ser uno según
	// la especificación, pero se contradice y permite que haya más de uno
	// (por ejemplo para publicar varios certificados con la misma clave
	// pública).
	// if (!tspServiceInformation.isThereSomeIdentity() ||
	// tspServiceInformation.getAllDigitalIdentities().size() != 1) {
	if (!tspServiceInformation.isThereSomeIdentity()) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_SERVICEDIGITALIDENTITY }));
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkTSPServiceInformationIdentitiesValues(es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance)
     */
    @Override
    protected void checkTSPServiceInformationIdentitiesValues(ServiceHistoryInstance tspServiceInformation) throws TSLMalformedException {

	// Obtenemos el tipo del servicio.
	String serviceType = tspServiceInformation.getServiceTypeIdentifier().toString();

	// Obtenemos la lista de identificaciones del servicio digital.
	List<DigitalID> diList = tspServiceInformation.getAllDigitalIdentities();

	// Si el servicio es de un tipo NO PKI, hay que comprobar que los
	// identificadores sean de tipo 'other' y que representan a una URI.
	if (checkIfServiceTypeIsNoPKIorUnspecified(serviceType)) {

	    checkTSPServiceInformationIdentitiesNonPKI(diList);

	} else {

	    // En caso contrario, analizamos cada identidad digital de forma
	    // independiente.
	    try {
		checkDigitalIdsList(diList);
	    } catch (TSLMalformedException e) {
		throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_SERVICEDIGITALIDENTITY }), e);
	    }

	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkIfServiceTypeIsNoPKIorUnspecified(java.lang.String)
     */
    @Override
    protected boolean checkIfServiceTypeIsNoPKIorUnspecified(String serviceType) {

	boolean result = false;

	result = serviceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_RA_NOTHAVINGPKIID) || serviceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_ARCHIV_NOTHAVINGPKIID) || serviceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_IDV_NOTHAVINGPKIID);
	result = result || serviceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_KESCROW_NOTHAVINGPKIID) || serviceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_PPWD_NOTHAVINGPKIID);

	return result;

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkTSPServiceInformationStatusValue(es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance)
     */
    @Override
    protected void checkTSPServiceInformationStatusValue(ServiceHistoryInstance tspServiceInformation) throws TSLMalformedException {

	// Obtenemos el tipo de TSL.
	String tslType = getTSLObject().getSchemeInformation().getTslType().toString();

	// Obtenemos el tipo del Servicio.
	String serviceType = tspServiceInformation.getServiceTypeIdentifier().toString();

	// Obtenemos el estado del servicio.
	String serviceStatus = tspServiceInformation.getServiceStatus().toString();

	// Inicialmente no es válido su valor.
	boolean isValid = false;

	// Si no es nulo o cadena vacía, comprobamos su valor...
	if (!UtilsStringChar.isNullOrEmptyTrim(serviceStatus)) {

	    // Si se trata de un miembro europeo.
	    if (isTSLTypeEUGeneric(tslType)) {

		// Comprobamos si el servicio cumple las condiciones de TSL EU
		// Generic.
		isValid = checkIfServiceTypeIsValidForTslTypeEuGeneric(serviceType, serviceStatus);

	    }
	    // Si se trata de un país/región no europeo.
	    else if (isTSLTypeNonEUCountry(tslType)) {

		// Comprobamos que la URI empieza por http://
		isValid = serviceStatus.startsWith(ITSLCommonURIs.HTTP_PROTOCOL_PREFFIX);

	    }

	}

	if (!isValid) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_STATUS }));
	}

    }

    /**
     * Checks if the input service type and status are valid for a TSL type EU-Generic.
     * @param serviceType Service type to check.
     * @param serviceStatus Service status to check.
     * @return <code>true</code> if the input service type and status are valid for a TSL type EU-Generic,
     * otherwise <code>false</code>.
     */
    private boolean checkIfServiceTypeIsValidForTslTypeEuGeneric(String serviceType, String serviceStatus) {

	boolean result = false;

	// Si el tipo de servicio es para certificados cualificados
	// (qualified)...
	if (isServiceTypeForQualifiedCerts(serviceType)) {

	    result = checkIfServiceStatusIsForServiceTypeForQualifiedCert(serviceStatus);

	}
	// Si es para no cualificados o nacionales...
	else if (isServiceTypeForNonQualifiedCerts(serviceType) || isServiceTypeForNationalCerts(serviceType)) {

	    result = serviceStatus.equals(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_RECOGNISEDATNATIONALLEVEL) || serviceStatus.equals(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_DEPRECATEDATNATIONALLEVEL);
	    // Si la fecha es anterior a la de entrada en vigor de la
	    // especificación,
	    // comprobamos también los valores antiguos.
	    if (Calendar.getInstance().getTime().before(getInitialDate())) {
		result = result || serviceStatus.equals(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_SETBYNATIONALLAW) || serviceStatus.equals(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_DEPRECATEDBYNATIONALLAW);
	    }

	}

	return result;

    }

    /**
     * Attribute that represents a set with the URI that represents the service status for a
     * TSL EU-Generic Serivice Type for qualified certificates.
     */
    private static Set<String> serviceStatusTSLEUGenericServiceTypeQualifiedCertSet = null;

    /**
     * Attribute that represents a set with the URI that represents the service status for a
     * TSL EU-Generic Serivice Type for qualified certificates before initial date.
     */
    private static Set<String> serviceStatusTSLEUGenericServiceTypeQualifiedCertBeforeInitialDateSet = null;

    static {
	serviceStatusTSLEUGenericServiceTypeQualifiedCertSet = new TreeSet<String>();
	serviceStatusTSLEUGenericServiceTypeQualifiedCertSet.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_GRANTED);
	serviceStatusTSLEUGenericServiceTypeQualifiedCertSet.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_WITHDRAWN);
	serviceStatusTSLEUGenericServiceTypeQualifiedCertBeforeInitialDateSet = new TreeSet<String>();
	serviceStatusTSLEUGenericServiceTypeQualifiedCertBeforeInitialDateSet.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_UNDERSUPERVISION);
	serviceStatusTSLEUGenericServiceTypeQualifiedCertBeforeInitialDateSet.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_SUPERVISIONINCESSATION);
	serviceStatusTSLEUGenericServiceTypeQualifiedCertBeforeInitialDateSet.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_SUPERVISIONCEASED);
	serviceStatusTSLEUGenericServiceTypeQualifiedCertBeforeInitialDateSet.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_SUPERVISIONREVOKED);
	serviceStatusTSLEUGenericServiceTypeQualifiedCertBeforeInitialDateSet.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_ACCREDITED);
	serviceStatusTSLEUGenericServiceTypeQualifiedCertBeforeInitialDateSet.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_ACCREDITATIONCEASED);
	serviceStatusTSLEUGenericServiceTypeQualifiedCertBeforeInitialDateSet.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_ACCREDITATIONREVOKED);
    }

    /**
     * Checks if the input service status is valid for a service type for qualified certificates.
     * @param serviceStatus Service status to check.
     * @return <code>true</code> if the input service status is valid for a service type for qualified certificates,
     * otherwise <code>false</code>.
     */
    private boolean checkIfServiceStatusIsForServiceTypeForQualifiedCert(String serviceStatus) {

	boolean result = false;

	result = serviceStatusTSLEUGenericServiceTypeQualifiedCertSet.contains(serviceStatus);
	// Si la fecha es anterior a la de entrada en vigor de la
	// especificación, comprobamos también los valores antiguos.
	if (Calendar.getInstance().getTime().before(getInitialDate())) {

	    result = result || serviceStatusTSLEUGenericServiceTypeQualifiedCertBeforeInitialDateSet.contains(serviceStatus);

	}

	return result;

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkTSPServiceHistoryInstanceType(es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance)
     */
    @Override
    protected void checkTSPServiceHistoryInstanceType(ServiceHistoryInstance serviceHistoryInstance) throws TSLMalformedException {

	URI serviceTypeIdentifier = serviceHistoryInstance.getServiceTypeIdentifier();

	if (serviceTypeIdentifier == null) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_TYPE }));
	}

	String tslTypeUriString = getTSLObject().getSchemeInformation().getTslType().toString();
	String sti = serviceTypeIdentifier.toString();
	boolean valueOK = false;

	if (isTSLTypeEUGeneric(tslTypeUriString)) {

	    // Para certificados cualificados.
	    valueOK = isServiceTypeForQualifiedCerts(sti);

	    // Si se ha detectado que es de tipo CA/QC, hay que comprobar
	    // que al menos existe la extensión AdditionalServiceInformation
	    // en el servicio.
	    if (valueOK && sti.equals(ITSLCommonURIs.TSL_SERVICETYPE_CA_QC) && !checkIfIsDefinedSomeExtensionTypeInTSPService(serviceHistoryInstance, IAnyTypeExtension.IMPL_ADDITIONAL_SERVICE_INFORMATION)) {

		// TODO Se cambia la propagación de la excepción por el error
		// por un warning en el log, ya que si no se relaja esta
		// comprobación, muchas TSL serían rechazadas.
		LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG010, new Object[ ] { serviceHistoryInstance.getServiceNameInLanguage(Locale.UK.getLanguage()) }));

	    }

	    // Para certificados no cualificados.
	    valueOK = valueOK || isServiceTypeForNonQualifiedCerts(sti);

	    // Para certificados no definidos a nivel europeo, pero sí nacional.
	    valueOK = valueOK || isServiceTypeForNationalCerts(sti);

	} else if (isTSLTypeNonEUCountry(tslTypeUriString)) {

	    valueOK = sti.startsWith(ITSLCommonURIs.HTTP_PROTOCOL_PREFFIX);

	}

	if (!valueOK) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_HISTORY_TYPE }));
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkTSPServiceHistoryInstanceNamesValues(es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance)
     */
    @Override
    protected void checkTSPServiceHistoryInstanceNamesValues(ServiceHistoryInstance serviceHistoryInstance) throws TSLMalformedException {

	try {
	    checkTSPServiceInformationNamesValues(serviceHistoryInstance);
	} catch (TSLMalformedException e) {
	    throw e;
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkTSPServiceHistoryInstanceIdentitiesValues(es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance)
     */
    @Override
    protected void checkTSPServiceHistoryInstanceIdentitiesValues(ServiceHistoryInstance serviceHistoryInstance) throws TSLMalformedException {

	try {

	    // Obtenemos el tipo del servicio.
	    String serviceType = serviceHistoryInstance.getServiceTypeIdentifier().toString();

	    // Obtenemos la lista de identificaciones del servicio digital.
	    List<DigitalID> diList = serviceHistoryInstance.getAllDigitalIdentities();

	    // Si el servicio es de un tipo NO PKI, hay que comprobar que los
	    // identificadores sean de tipo 'other' y que representan a una URI.
	    if (checkIfServiceTypeIsNoPKIorUnspecified(serviceType)) {

		checkTSPServiceInformationIdentitiesNonPKI(diList);

	    } else {

		// En caso contrario, hacemos las siguientes comprobaciones:
		// - Debe existir al menos una identidad digital de tipo
		// X509SKI.
		// - No debe existir ninguna identidad digital de tipo
		// X509Certificate.
		try {
		    checkDigitalIdsListInServiceHistoryInstance(diList);
		} catch (TSLMalformedException e) {

		    // TODO: Se suaviza esta comprobación para evitar que no se
		    // carguen algunas TSL, y se hará uso de toda la información
		    // de identidades digitales disponibles aunque esto no sea
		    // del todo correcto.
		    LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_SERVICEDIGITALIDENTITY }));

		}

	    }

	} catch (TSLMalformedException e) {
	    String msg = Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_HISTORY_SERVICEDIGITALIDENTITY });
	    e.setErrorDesc(msg);
	    throw e;
	}

    }

    /**
     * Checks the Digital Ids List if it is not <code>null</code> or empty. In this list must be
     * at least a X509SKI digital identity and not must be a X509Certificate digital identity.
     * @param digitalIdsList Digital identities list to check.
     * @throws TSLMalformedException In case of some data has not a correct value or there is a
     * X509Certificate digital identity or there is not a X509SKI digital identity
     */
    private void checkDigitalIdsListInServiceHistoryInstance(List<DigitalID> digitalIdsList) throws TSLMalformedException {

	// Banderas para comprobar si encontramos o no identidades digitales
	// de tipo X509SKI.
	boolean thereIsX509SKIDigIdent = false;

	if (digitalIdsList != null && !digitalIdsList.isEmpty()) {

	    for (DigitalID digitalId: digitalIdsList) {

		// Comprobamos que no sea nulo y su valor según su tipo.
		checkDigitalID(digitalId);

		// Si es de tipo X509Cert hay que lanzar excepción.
		if (digitalId.getType() == DigitalID.TYPE_X509CERTIFICATE) {
		    throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.TC_LOG026));
		}

		// Si es de tipo X509SKI marcamos que hemos encontrado uno.
		thereIsX509SKIDigIdent = thereIsX509SKIDigIdent || digitalId.getType() == DigitalID.TYPE_X509SKI;

	    }

	}

	// Si no hemos encontrado ninguna identidad digital de tipo X509SKI,
	// lanzamos excepción.
	if (!thereIsX509SKIDigIdent) {
	    throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.TC_LOG027));
	}

    }

    /**
     * Attribute that represents a set with the URI that defines the service status valid values for qualified certificates.
     */
    private static Set<String> serviceStatusForQualifiedCertificates = null;

    /**
     * Attribute that represents a set with the URI that defines the service status valid values for
     * non qualified certificates and national certificates.
     */
    private static Set<String> serviceStatusForNonQualifiedCertificatesOrNationalCertificates = null;

    static {
	serviceStatusForQualifiedCertificates = new TreeSet<String>();
	serviceStatusForQualifiedCertificates.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_GRANTED);
	serviceStatusForQualifiedCertificates.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_WITHDRAWN);
	serviceStatusForQualifiedCertificates.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_UNDERSUPERVISION);
	serviceStatusForQualifiedCertificates.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_SUPERVISIONINCESSATION);
	serviceStatusForQualifiedCertificates.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_SUPERVISIONCEASED);
	serviceStatusForQualifiedCertificates.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_SUPERVISIONREVOKED);
	serviceStatusForQualifiedCertificates.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_ACCREDITED);
	serviceStatusForQualifiedCertificates.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_ACCREDITATIONCEASED);
	serviceStatusForQualifiedCertificates.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_ACCREDITATIONREVOKED);
	serviceStatusForNonQualifiedCertificatesOrNationalCertificates = new TreeSet<String>();
	serviceStatusForNonQualifiedCertificatesOrNationalCertificates.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_RECOGNISEDATNATIONALLEVEL);
	serviceStatusForNonQualifiedCertificatesOrNationalCertificates.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_DEPRECATEDATNATIONALLEVEL);
	serviceStatusForNonQualifiedCertificatesOrNationalCertificates.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_SETBYNATIONALLAW);
	serviceStatusForNonQualifiedCertificatesOrNationalCertificates.add(ITSLCommonURIs.TSL_SERVICECURRENTSTATUS_DEPRECATEDBYNATIONALLAW);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkTSPServiceHistoryInstanceStatusValue(es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance)
     */
    @Override
    protected void checkTSPServiceHistoryInstanceStatusValue(ServiceHistoryInstance serviceHistoryInstance) throws TSLMalformedException {

	// Obtenemos el tipo de TSL.
	String tslType = getTSLObject().getSchemeInformation().getTslType().toString();

	// Obtenemos el tipo del Servicio.
	String serviceType = serviceHistoryInstance.getServiceTypeIdentifier().toString();

	// Obtenemos el estado del servicio.
	String serviceStatus = serviceHistoryInstance.getServiceStatus().toString();

	// Inicialmente no es válido su valor.
	boolean isValid = false;

	// Si no es nulo o cadena vacía, comprobamos su valor...
	if (!UtilsStringChar.isNullOrEmptyTrim(serviceStatus)) {

	    // Si se trata de un miembro europeo.
	    if (isTSLTypeEUGeneric(tslType)) {

		// Si el tipo de servicio es para certificados cualificados
		// (qualified)...
		if (isServiceTypeForQualifiedCerts(serviceType)) {

		    isValid = serviceStatusForQualifiedCertificates.contains(serviceStatus);

		}
		// Si es para no cualificados o nacionales...
		else if (isServiceTypeForNonQualifiedCerts(serviceType) || isServiceTypeForNationalCerts(serviceType)) {

		    isValid = serviceStatusForNonQualifiedCertificatesOrNationalCertificates.contains(serviceStatus);

		}

	    }
	    // Si se trata de un país/región no europeo.
	    else if (isTSLTypeNonEUCountry(tslType)) {

		// Comprobamos que la URI empieza por http://
		isValid = serviceStatus.startsWith(ITSLCommonURIs.HTTP_PROTOCOL_PREFFIX);

	    }

	}

	if (!isValid) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_HISTORY_STATUS }));
	    // TODO De momento no se relaja esta comprobación, ya que el
	    // estado del servicio es imprescindible para un tratamiento
	    // correcto.

	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#tslSignatureIsNotDefined()
     */
    @Override
    protected void tslSignatureIsNotDefined() throws TSLMalformedException {

	throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_SIGNATURE }));

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.impl.common.ATSLChecker#checkSignatureAccordingToSpecification(byte[])
     */
    @Override
    protected void checkSignatureAccordingToSpecification(byte[ ] fullTSLxml) throws TSLMalformedException {

	// Obtenemos la firma.
	SignatureType signature = getTSLObject().getSignature();

	// Comprobamos que SignatureValue se encuentra definido.
	SignatureValueType signatureValue = signature.getSignatureValue();
	if (signatureValue == null || signatureValue.getByteArrayValue() == null) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG011, new Object[ ] { ITSLSignatureConstants.ELEMENT_SIGNATUREMETHOD }));
	}

	// Recuperamos el SignedInfo.
	SignedInfoType signedInfo = signature.getSignedInfo();
	if (signedInfo == null) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG011, new Object[ ] { ITSLSignatureConstants.ELEMENT_SIGNEDINFO }));
	} else {

	    // Comprobamos que el algoritmo de firma se encuentra definido.
	    SignatureMethodType signatureMethod = signedInfo.getSignatureMethod();
	    if (signatureMethod == null || UtilsStringChar.isNullOrEmptyTrim(signatureMethod.getAlgorithm())) {
		throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG011, new Object[ ] { ITSLSignatureConstants.ELEMENT_SIGNATUREMETHOD }));
	    }

	    // Buscamos un Reference dentro de este que apunte al ID del
	    // TSLObject.
	    boolean referenceFinded = false;
	    String tslId = getTSLObject().getID();
	    for (int index = 0; !referenceFinded && index < signedInfo.sizeOfReferenceArray(); index++) {
		ReferenceType rt = signedInfo.getReferenceArray(index);
		// Si la URI del reference es nula o vacía, es como apuntar al
		// root,
		// o si es igual al ID del elemento TrustServiceStatusList,
		// significa que es la Reference que buscábamos.
		if (UtilsStringChar.isNullOrEmpty(rt.getURI()) || rt.getURI().equals(UtilsStringChar.SYMBOL_PAD_STRING + tslId)) {

		    // Marcamos que lo hemos encontrado.
		    referenceFinded = true;

		    // Una vez encontrado, comprobamos que contenga un único
		    // transforms.
		    if (rt.isSetTransforms()) {

			TransformsType tst = rt.getTransforms();
			// Este solo debe contener dos elementos transform
			// concretos en un orden específico.
			if (tst.sizeOfTransformArray() == 2) {

			    // El primero de los elementos debe ser
			    // "http://www.w3.org/2000/09/xmldsig#enveloped-signature".
			    if (!ITSLSignatureConstants.URI_XMLDSIG_ENVELOPED_SIGNATURE.equals(tst.getTransformArray(0).getAlgorithm())) {
				throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG012, new Object[ ] { tslId, 0, ITSLSignatureConstants.URI_XMLDSIG_ENVELOPED_SIGNATURE }));
			    }

			    // El segundo de los elementos debe ser
			    // "http://www.w3.org/2001/10/xmlexc-c14n#".
			    if (!ITSLSignatureConstants.URI_CANONICALIZATION_ALGORITHM_XMLEXC_C14N.equals(tst.getTransformArray(1).getAlgorithm())) {
				throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG012, new Object[ ] { tslId, 1, ITSLSignatureConstants.URI_CANONICALIZATION_ALGORITHM_XMLEXC_C14N }));
			    }

			} else {
			    // Debe haber dos elementos Transform.
			    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG013, new Object[ ] { tslId }));
			}

		    } else {
			// El elemento Transforms debe estar definido.
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG014, new Object[ ] { tslId }));
		    }

		}
	    }

	    // Si no se ha encontrado la referencia, excepción.
	    if (!referenceFinded) {
		throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG015, new Object[ ] { tslId }));
	    }

	    // El método de canonicalización debe ser
	    // "http://www.w3.org/2001/10/xmlexc-c14n#".
	    CanonicalizationMethodType cmt = signedInfo.getCanonicalizationMethod();
	    if (cmt == null) {
		throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.TC_LOG016));
	    } else {

		if (!ITSLSignatureConstants.URI_CANONICALIZATION_ALGORITHM_XMLEXC_C14N.equals(cmt.getAlgorithm())) {
		    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.TC_LOG017, new Object[ ] { ITSLSignatureConstants.URI_CANONICALIZATION_ALGORITHM_XMLEXC_C14N }));
		}

	    }

	}
    }
}
