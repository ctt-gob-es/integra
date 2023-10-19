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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.ATSLChecker.java.</p>
 * <b>Description:</b><p>Abstract class that represents a TSL data checker with the principal functions
 * regardless it implementation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.2, 18/04/2022.
 */
package es.gob.afirma.tsl.parsing.impl.common;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.xml.crypto.dsig.XMLSignature;

import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import es.gob.afirma.tsl.logger.Logger;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.access.TSLProperties;
import es.gob.afirma.tsl.exceptions.TSLMalformedException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.parsing.ifaces.IAnyTypeExtension;
import es.gob.afirma.tsl.parsing.ifaces.ITSLChecker;
import es.gob.afirma.tsl.parsing.ifaces.ITSLCommonURIs;
import es.gob.afirma.tsl.parsing.ifaces.ITSLElementsAndAttributes;
import es.gob.afirma.tsl.parsing.ifaces.ITSLOIDs;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.utils.UtilsStringChar;


/** 
 * <p>Abstract class that represents a TSL data checker with the principal functions
 * regardless it implementation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 18/04/2022.
 */
public abstract class ATSLChecker implements ITSLChecker {
    /**
	 * Attribute that represents the object that manages the log of the class.
	 */
	private static final Logger LOGGER = Logger.getLogger(ATSLChecker.class);
	

	/**
	 * Constant attribute that represents the token name for the Scheme Type Field.
	 */
	public static final String SCHEME_TYPE_FIELD_NAME = "type";
	

	/**
	 * Attribute that represents the TSL object to check.
	 */
	private ITSLObject tsl = null;

	/**
	 * Constructor method for the class ATSLChecker.java.
	 */
	private ATSLChecker() {
		super();
	}

	/**
	 * Constructor method for the class ATSLChecker.java.
	 * @param tslObject TSL object representation that will be checked.
	 */
	protected ATSLChecker(ITSLObject tslObject) {
		this();
		tsl = tslObject;
	}

	/**
	 * Gets the TSL object that must be checked.
	 * @return the TSL object that must be checked.
	 */
	protected final ITSLObject getTSLObject() {
		return tsl;
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.ifaces.ITSLChecker#checkTSLValues(boolean, byte[])
	 */
	@Override
	public final void checkTSLValues(boolean checkSignature, byte[ ] fullTSLxml) throws TSLMalformedException {

		// Comprobamos el atributo TSLTag
		checkTSLTag();
		// Comprobamos los valores contenidos en el Scheme Information.
		checkSchemeInformation();
		// Comprobamos la lista de los TSP declarados.
		checkTSPlist();
		// Comprobamos la firma si es necesario.
		if (checkSignature) {
			checkTSLSignature(fullTSLxml);
		}

	}

	/**
	 * Checks if the tslTag attribute has a value and it is correct for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data does not exist or has not a correct value.
	 */
	private void checkTSLTag() throws TSLMalformedException {

		if (tsl.getTSLTag() == null) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG001, new Object[ ] { ITSLElementsAndAttributes.ATTRIBUTE_TSL_TAG }));
		} else {
			checkTSLTagValue();
		}

	}

	/**
	 * Checks if the tslTag attribute has a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkTSLTagValue() throws TSLMalformedException;

	/**
	 * Checks if the Scheme Information has a correct values for the concrete
	 * specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkSchemeInformation() throws TSLMalformedException {

		// Comprobamos el identificador de versión.
		checkSchemeInformationTSLVersionIdentifierValue();
		// Comprobamos el número de secuencia.
		checkSchemeInformationTSLSequenceNumber();
		// Comprobamos el tipo de TSL.
		checkSchemeInformationTSLType();
		// Comprobamos los nombres del operador.
		checkSchemeInformationOperatorName();
		// Comprobamos las direcciones del operador.
		checkSchemeInformationAddress();
		// Comprobamos el nombre.
		checkSchemeInformationName();
		// Comprobamos las URI de información.
		checkSchemeInformationURI();
		// Comprobamos la URI que determina el estado.
		checkSchemeInformationStatusDeterminationApproach();
		// Comprobamos los type/community/rules
		checkSchemeInformationTypeCommunityRules();
		// Comprobamos el territorio de la TSL.
		checkSchemeInformationTerritory();
		// Comprobamos las políticas y notas legales.
		checkSchemeInformationPolicyOrLegalNotice();
		// Comprobamos el periodo de información histórica.
		checkSchemeInformationHistoricalInformationPeriod();
		// Comprobamos los "punteros" hacia otras TSL.
		checkSchemeInformationPointersToOtherTSL();
		// Comprobamos la fecha de emisión.
		checkSchemeInformationListIssueDateTime();
		// Comprobamos la fecha de caducidad (próxima emisión).
		checkSchemeInformationNextUpdate();
		// Comprobamos los puntos de distribución.
		checkSchemeInformationDistributionPoints();
		// Comprobamos las extensiones.
		checkSchemeInformationExtensions();

	}

	/**
	 * Checks if the Scheme Information TSL Version Identifier has a correct
	 * value for the concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkSchemeInformationTSLVersionIdentifierValue() throws TSLMalformedException;

	/**
	 * Checks if the Scheme Information Sequence Number has a correct value.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkSchemeInformationTSLSequenceNumber() throws TSLMalformedException {

		if (tsl.getSchemeInformation().getTslSequenceNumber() < 1) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSL_SEQUENCE_NUMBER }));
		}

	}

	/**
	 * Checks if the Scheme Information TSL Type has a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkSchemeInformationTSLType() throws TSLMalformedException {

		URI tslType = tsl.getSchemeInformation().getTslType();
		if (tslType == null) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSL_TYPE }));
		} else {
			checkSchemeInformationTSLTypeValue();
		}

	}

	/**
	 * Checks if the Scheme Information TSL Type has a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkSchemeInformationTSLTypeValue() throws TSLMalformedException;

	/**
	 * Checks if the Scheme Information Operator Name has a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkSchemeInformationOperatorName() throws TSLMalformedException {

		if (tsl.getSchemeInformation().getSchemeOperatorNames().isEmpty()) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_SCHEME_OPERATOR_NAME }));
		}
		checkSchemeInformationOperatorNameValue();

	}

	/**
	 * Checks if the Scheme Information TSL Operator Name has a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkSchemeInformationOperatorNameValue() throws TSLMalformedException;

	/**
	 * Checks if the Scheme Information Address has a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkSchemeInformationAddress() throws TSLMalformedException {

		Address address = tsl.getSchemeInformation().getSchemeOperatorAddress();
		try {
			checkAddress(address);
		} catch (TSLMalformedException e) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_SCHEME_OPERATOR_ADDRESS }), e);
		}

	}

	/**
	 * Checks if the Address has a correct value for the concrete specification and version.
	 * @param address Adress to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkAddress(Address address) throws TSLMalformedException {

		if (!address.isThereSomePostalAddress()) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_ADDRESS_POSTALADDRESSES }));
		}

		if (!address.isThereSomeElectronicAddress()) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_ADDRESS_ELECTRONICADDRESS }));
		}

		Map<String, List<PostalAddress>> postalAddresses = address.getPostalAddresses();
		Set<String> keys = postalAddresses.keySet();
		for (String key: keys) {
			List<PostalAddress> postalAddressList = postalAddresses.get(key);
			for (PostalAddress postalAddress: postalAddressList) {
				if (UtilsStringChar.isNullOrEmptyTrim(postalAddress.getStreet()) || UtilsStringChar.isNullOrEmptyTrim(postalAddress.getLocality()) || UtilsStringChar.isNullOrEmptyTrim(postalAddress.getCountryName())) {
					throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_ADDRESS_POSTALADDRESS }));
				}
			}
		}

		checkAddressValue(address);

	}

	/**
	 * Checks if the Scheme Information TSL Operator Address has a correct value for the
	 * concrete specification and version.
	 * @param address Adress to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkAddressValue(Address address) throws TSLMalformedException;

	/**
	 * Checks if the Scheme Information Name has a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkSchemeInformationName() throws TSLMalformedException {

		if (!tsl.getSchemeInformation().isThereSomeSchemeName()) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_SCHEME_NAME }));
		}
		checkSchemeInformationNameValue();

	}

	/**
	 * Checks if the Scheme Information Name has a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkSchemeInformationNameValue() throws TSLMalformedException;

	/**
	 * Checks if the Scheme Information URI has a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkSchemeInformationURI() throws TSLMalformedException {

		if (!tsl.getSchemeInformation().isThereSomeSchemeInformationURI()) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_SCHEME_INFORMATION_URI }));
		}
		checkSchemeInformationURIValue();

	}

	/**
	 * Checks if the Scheme Information URI has a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkSchemeInformationURIValue() throws TSLMalformedException;

	/**
	 * Checks if the Scheme Information Status Determination Approach URI has a correct
	 * value for the concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkSchemeInformationStatusDeterminationApproach() throws TSLMalformedException {

		URI sda = tsl.getSchemeInformation().getStatusDeterminationApproach();
		if (sda == null) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_STATUS_DETERMINATION_APPROACH }));
		}
		checkSchemeInformationStatusDeterminationApproachValue();

	}

	/**
	 * Checks if the Scheme Information Status Determination Approach URI has a correct
	 * value for the concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkSchemeInformationStatusDeterminationApproachValue() throws TSLMalformedException;

	/**
	 * Checks if the Scheme Information Type Community Rules URI have a correct
	 * value for the concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkSchemeInformationTypeCommunityRules() throws TSLMalformedException {

		// Se comprueba si este elemento es obligatorio, y en ese caso, si no
		// está definido,
		// se lanza excepción.
		checkSchemeInformationTypeCommunityRulesDefined();

		// Lo recorremos y analizamos.
		if (tsl.getSchemeInformation().isThereSomeSchemeTypeCommunityRule()) {
			Map<String, List<URI>> sitcrMap = tsl.getSchemeInformation().getSchemeTypeCommunityRules();
			Set<String> languageKeys = sitcrMap.keySet();
			for (String language: languageKeys) {
				List<URI> uriList = sitcrMap.get(language);
				for (URI uri: uriList) {
					checkSchemeTypeCommunityURIValue(uri);
				}
			}
		}
	}

	/**
	 * Checks if the Scheme Information Type Community Rules is defined
	 * and if it shall be present.
	 * @throws TSLMalformedException In case of the Scheme Information Type Community Rules
	 * shall be present and it is not defined.
	 */
	protected abstract void checkSchemeInformationTypeCommunityRulesDefined() throws TSLMalformedException;

	/**
	 * Checks if the Scheme Information Type Community Rules URI has a correct
	 * value for the concrete specification and version.
	 * @param uri URI to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkSchemeTypeCommunityURIValue(URI uri) throws TSLMalformedException;

	/**
	 * Checks if the Scheme Territory has a correct value for the concrete
	 * specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkSchemeInformationTerritory() throws TSLMalformedException {

		if (UtilsStringChar.isNullOrEmptyTrim(tsl.getSchemeInformation().getSchemeTerritory())) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_SCHEME_TERRITORY }));
		}
		checkSchemeInformationTerritoryValue();

	}

	/**
	 * Checks if the Scheme Territory has a correct value for the concrete
	 * specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkSchemeInformationTerritoryValue() throws TSLMalformedException;

	/**
	 * Checks if the Scheme Policies Or Legal Notces have a correct value.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkSchemeInformationPolicyOrLegalNotice() throws TSLMalformedException {

		if (tsl.getSchemeInformation().isThereSomePolicy() && tsl.getSchemeInformation().isThereSomeLegalNotice() || !tsl.getSchemeInformation().isThereSomePolicy() && !tsl.getSchemeInformation().isThereSomeLegalNotice()) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_POLICY_OR_LEGAL_NOTICE }));
		}

		if (tsl.getSchemeInformation().isThereSomePolicy()) {
			checkSchemeInformationPolicyValues();
		}

		if (tsl.getSchemeInformation().isThereSomeLegalNotice()) {
			checkSchemeInformationLegalNoticeValues();
		}

	}

	/**
	 * Checks if the Scheme Information Policy values has a correct value for the concrete
	 * specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkSchemeInformationPolicyValues() throws TSLMalformedException;

	/**
	 * Checks if the Scheme Information Legal Notice values has a correct value for the concrete
	 * specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkSchemeInformationLegalNoticeValues() throws TSLMalformedException;

	/**
	 * Checks if the Scheme Information Historical Information Period has a correct value for the concrete
	 * specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkSchemeInformationHistoricalInformationPeriod() throws TSLMalformedException {

		if (tsl.getSchemeInformation().getHistoricalPeriod() < 0) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_HISTORICAL_INFORMATION_PERIOD }));
		}
		checkSchemeInformationHistoricalInformationPeriodValue();

	}

	/**
	 * Checks if the Scheme Information Historical Information Period has a correct value for the concrete
	 * specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkSchemeInformationHistoricalInformationPeriodValue() throws TSLMalformedException;

	/**
	 * Checks if the Scheme Information Pointers to Other TSL have a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkSchemeInformationPointersToOtherTSL() throws TSLMalformedException {

		// Primero comprobamos los requerimientos generales de cada
		// especificación.
		checkSchemeInformationPointersToOtherTSLValue();

		// Si hay información sobre otras TSLs, las analizamos.
		if (getTSLObject().getSchemeInformation().isThereSomePointerToOtherTSL()) {

			// Obtenemos la lista y la recorremos.
			List<TSLPointer> tslPointersList = getTSLObject().getSchemeInformation().getPointersToOtherTSL();
			// Analizamos cada una.
			for (TSLPointer tslPointer: tslPointersList) {
				checkSchemeInformationPointerToOtherTSLValue(tslPointer);
			}

		}

	}

	/**
	 * Checks if the Scheme Information Pointers to Other TSL have a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value
	 */
	protected abstract void checkSchemeInformationPointersToOtherTSLValue() throws TSLMalformedException;

	/**
	 * Checks if a Scheme Information Pointer to Other TSL have a correct value for the
	 * concrete specification and version.
	 * @param tslPointer TSL Pointer to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkSchemeInformationPointerToOtherTSLValue(TSLPointer tslPointer) throws TSLMalformedException;

	/**
	 * Checks if the Scheme Information List Issue Date have a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkSchemeInformationListIssueDateTime() throws TSLMalformedException {

		if (tsl.getSchemeInformation().getListIssueDateTime() == null) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_LIST_ISSUE_DATE_TIME }));
		}
		checkSchemeInformationListIssueDateTimeValue();

	}

	/**
	 * Checks if the Scheme Information List Issue Date have a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkSchemeInformationListIssueDateTimeValue() throws TSLMalformedException;

	/**
	 * Checks if the Scheme Information Next Update Date have a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkSchemeInformationNextUpdate() throws TSLMalformedException {

		// Comprobamos (según la especificación), si la fecha de próxima
		// actualización
		// debe estar definida.
		checkSchemeInformationNextUpdateDefined();

		// Comprobamos que la fecha de emisión no sea posterior a la de
		// caducidad.
		if (tsl.getSchemeInformation().getNextUpdate() != null && tsl.getSchemeInformation().getListIssueDateTime().after(tsl.getSchemeInformation().getNextUpdate())) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_NEXT_UPDATE }));
		}

		// Comprobamos su valor.
		checkSchemeInformationNextUpdateValue();

	}

	/**
	 * Checks if the Scheme Information Next Update Date must be defined for the specification and version.
	 * @throws TSLMalformedException In case of the Scheme Information Next Update Date is not defined.
	 */
	protected abstract void checkSchemeInformationNextUpdateDefined() throws TSLMalformedException;

	/**
	 * Checks if the Scheme Information Next Update Date have a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkSchemeInformationNextUpdateValue() throws TSLMalformedException;

	/**
	 * Checks if the Scheme Information Distribution Points have a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkSchemeInformationDistributionPoints() throws TSLMalformedException {
		checkSchemeInformationDistributionPointsValues();
	}

	/**
	 * Checks if the Scheme Information Distribution Points have a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkSchemeInformationDistributionPointsValues() throws TSLMalformedException;

	/**
	 * Checks if the Scheme Information Extensions have a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkSchemeInformationExtensions() throws TSLMalformedException {

		// Comprobamos si según el tipo de TSL se permiten extensiones o no.
		checkSchemeInformationExtensionsDependingOnTSLType();

		// Comprobamos los valores para las extensiones.
		checkSchemeInformationExtensionsValues();

	}

	/**
	 * Checks if the Scheme Information Extensions have a correct value depending on the TSL type
	 * for the concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkSchemeInformationExtensionsDependingOnTSLType() throws TSLMalformedException;

	/**
	 * Checks if the Scheme Information Extensions have a correct value for the
	 * concrete specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkSchemeInformationExtensionsValues() throws TSLMalformedException {

		List<IAnyTypeExtension> schemeInformationExtensions = tsl.getSchemeInformation().getSchemeInformationExtensions();
		if (schemeInformationExtensions != null && !schemeInformationExtensions.isEmpty()) {
			for (IAnyTypeExtension extension: schemeInformationExtensions) {
				extension.checkExtensionValue(tsl, null);
			}
		}

	}

	/**
	 * Checks if the Trust Service Provider List has a correct value for the concrete
	 * specification and version.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPlist() throws TSLMalformedException {

		// Si se ha declarado como una lista de TSL, no debe contener TSP.
		if (isListOfLists() && tsl.isThereSomeTrustServiceProvider()) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TRUST_SERVICE_PROVIDER }));
		}

		// Recorremos cada TSP y lo analizamos.
		if (tsl.isThereSomeTrustServiceProvider()) {
			List<TrustServiceProvider> tspList = tsl.getTrustServiceProviderList();
			for (TrustServiceProvider tsp: tspList) {
				checkTSP(tsp);
			}
		}

	}

	/**
	 * Checks if the TSL is a list of lists.
	 * @return <code>true</code> if the TSL is a list of list, otherwise <code>false</code>.
	 */
	protected abstract boolean isListOfLists();

	/**
	 * Checks if the Trust Service Provider has a correct value for the concrete
	 * specification and version.
	 * @param tsp Trust Service Provider to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSP(TrustServiceProvider tsp) throws TSLMalformedException {

		// Comprobamos la información del TSP.
		checkTSPInformation(tsp.getTspInformation());
		// Comprobamos la lista de Servicios asociados.
		checkTSPServiceList(tsp);

	}

	/**
	 * Checks if the Trust Service Provider Information has a correct value for the concrete
	 * specification and version.
	 * @param tspInformation Trust Service Provider Information set to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPInformation(TSPInformation tspInformation) throws TSLMalformedException {

		// Comprobamos los nombres del TSP.
		checkTSPInformationNames(tspInformation);
		// Comprobamos los nombres de marca (trade).
		checkTSPInformationTradeNames(tspInformation);
		// Comprobamos la dirección.
		checkTSPInformationAddress(tspInformation);
		// Comprobamos las URI informativas.
		checkTSPInformationURI(tspInformation);
		// Comprobamos las extensiones.
		checkTSPInformationExtensions(tspInformation);

	}

	/**
	 * Checks if the Trust Service Provider Names has a correct value for the concrete
	 * specification and version.
	 * @param tspInformation Trust Service Provider Information set to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPInformationNames(TSPInformation tspInformation) throws TSLMalformedException {

		if (!tspInformation.isThereSomeName()) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPINFORMATION_NAME }));
		}
		checkTSPInformationNamesValues(tspInformation);

	}

	/**
	 * Checks if the Trust Service Provider Names has a correct value for the concrete
	 * specification and version.
	 * @param tspInformation Trust Service Provider Information set to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkTSPInformationNamesValues(TSPInformation tspInformation) throws TSLMalformedException;

	/**
	 * Checks if the Trust Service Provider Trade Names has a correct value for the concrete
	 * specification and version.
	 * @param tspInformation Trust Service Provider Information set to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPInformationTradeNames(TSPInformation tspInformation) throws TSLMalformedException {
		checkTSPInformationTradeNamesValues(tspInformation);
	}

	/**
	 * Checks if the Trust Service Provider Trade Names has a correct value for the concrete
	 * specification and version.
	 * @param tspInformation Trust Service Provider Information set to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkTSPInformationTradeNamesValues(TSPInformation tspInformation) throws TSLMalformedException;

	/**
	 * Checks if the Trust Service Provider Address has a correct value for the concrete
	 * specification and version.
	 * @param tspInformation Trust Service Provider Information set to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPInformationAddress(TSPInformation tspInformation) throws TSLMalformedException {

		Address address = tspInformation.getTspAddress();
		try {
			checkAddress(address);
		} catch (TSLMalformedException e) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPINFORMATION_ADDRESS }), e);
		}

	}

	/**
	 * Checks if the Trust Service Provider URI have a correct values for the concrete
	 * specification and version.
	 * @param tspInformation Trust Service Provider Information set to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPInformationURI(TSPInformation tspInformation) throws TSLMalformedException {

		if (!tspInformation.isThereSomeURI()) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPINFORMATION_URI }));
		}
		checkTSPInformationURIvalues(tspInformation);

	}

	/**
	 * Checks if the Trust Service Provider URI have a correct values for the concrete
	 * specification and version.
	 * @param tspInformation Trust Service Provider Information set to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkTSPInformationURIvalues(TSPInformation tspInformation) throws TSLMalformedException;

	/**
	 * Checks if the TSP Information Extensions have a correct value for the
	 * concrete specification and version.
	 * @param tspInformation Trust Service Provider Information set to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPInformationExtensions(TSPInformation tspInformation) throws TSLMalformedException {

		// Comprobamos si según el tipo de TSL existe alguna restricción para
		// las extensiones.
		checkTSPInformationExtensionsDependingOnTSLType(tspInformation);

		// Comprobamos que los valores de las extensiones sea el correcto.
		checkTSPInformationExtensionsValues(tspInformation);

	}

	/**
	 * Checks if the TSP Information Extensions have a correct value for the
	 * concrete specification and version looking its type.
	 * @param tspInformation Trust Service Provider Information set to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkTSPInformationExtensionsDependingOnTSLType(TSPInformation tspInformation) throws TSLMalformedException;

	/**
	 * Checks if the TSP Information Extensions have a correct value for the
	 * concrete specification and version.
	 * @param tspInformation Trust Service Provider Information set to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPInformationExtensionsValues(TSPInformation tspInformation) throws TSLMalformedException {

		List<IAnyTypeExtension> tspInformationExtensions = tspInformation.getTspInformationExtensions();
		if (tspInformationExtensions != null && !tspInformationExtensions.isEmpty()) {
			for (IAnyTypeExtension extension: tspInformationExtensions) {
				extension.checkExtensionValue(tsl, null);
			}
		}

	}

	/**
	 * Checks if the Trust Service Provider Services List has a correct value for the concrete
	 * specification and version.
	 * @param tsp Trust Service Provider which to check the service list.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPServiceList(TrustServiceProvider tsp) throws TSLMalformedException {

		if (!tsp.isThereSomeTSPService()) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_LIST }));
		}

		List<TSPService> serviceList = tsp.getAllTSPServices();
		for (TSPService tspService: serviceList) {
			checkTSPService(tspService);
		}

	}

	/**
	 * Checks if the TSP Service has a correct value for the concrete
	 * specification and version.
	 * @param tspService TSP Service to analyze.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPService(TSPService tspService) throws TSLMalformedException {

		// Nos quedamos con el nombre del servicio para temas de logging.
		String serviceName = getServiceName(tspService.getServiceInformation());

		try {

			// Comprobamos la información del servicio.
			checkTSPServiceInformation(tspService.getServiceInformation());

			// Comprobamos la información histórica.
			if (tspService.isThereSomeServiceHistory()) {
				List<ServiceHistoryInstance> servHistoryList = tspService.getAllServiceHistory();
				for (ServiceHistoryInstance serviceHistoryInstance: servHistoryList) {
					// Se decide que ante cualquier fallo evaluando un servicio
					// histórico
					// este se marque como NO usable.
					try {
						checkTSPServiceHistoryInstance(serviceHistoryInstance);
					} catch (TSLMalformedException e) {

						// Tratamos de obtener el nombre del servicio histórico.
						String serviceHistoryInstanceName = getServiceName(serviceHistoryInstance);

						// Marcamos el servicio histórico como NO usable.
						serviceHistoryInstance.setServiceValidAndUsable(false);

						// Lo indicamos en el log como warning.
						LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG015, new Object[ ] { serviceName, serviceHistoryInstanceName, e.getMessage() }));

					}
				}
			}

		} catch (TSLMalformedException e) {

			// Marcamos el servicio como NO usable.
			tspService.getServiceInformation().setServiceValidAndUsable(false);

			// Lo indicamos en el log como warning.
			LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG016, new Object[ ] { serviceName, e.getMessage() }));

		}

	}

	/**
	 * Auxiliar method that tries to get the name of the input service.
	 * @param shi Service History Instance with the information to check.
	 * @return the name of the input service or <code>null</code> if was not
	 * possible to obtain.
	 */
	private String getServiceName(ServiceHistoryInstance shi) {

		String result = null;

		if (shi != null && shi.isThereSomeServiceName()) {
			result = shi.getServiceNameInLanguage(Locale.UK.getLanguage());
			if (UtilsStringChar.isNullOrEmptyTrim(result)) {
				result = shi.getServiceNames().values().iterator().next();
			}
		}

		return result;

	}

	/**
	 * Checks if the TSP Service Information has a correct value for the concrete
	 * specification and version.
	 * @param tspServiceInformation TSP Service Information to analyze.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPServiceInformation(ServiceInformation tspServiceInformation) throws TSLMalformedException {

		// Comprobamos el tipo de servicio.
		checkTSPServiceInformationType(tspServiceInformation);
		// Comprobamos los nombres del servicio.
		checkTSPServiceInformationNames(tspServiceInformation);
		// Comprobamos las identidades del servicio.
		checkTSPServiceInformationIdentities(tspServiceInformation);
		// Comprobamos el estado del servicio.
		checkTSPServiceInformationStatus(tspServiceInformation);
		// Comprobamos la fecha de inicio del servicio.
		checkTSPServiceInformationStatusStartingDateAndTime(tspServiceInformation.getServiceStatusStartingTime());
		// Comprobamos las URIs de definición del servicio del esquema.
		checkTSPServiceInformationSchemeDefinitionURI(tspServiceInformation.getSchemeServiceDefinitionURIs());
		// Comprobamos los puntos de distribución del servicio.
		checkTSPServiceInformationServiceSupplyPoints(tspServiceInformation.getServiceSupplyPoints());
		// Comprobamos las URI de definición de servicios del TSP.
		checkTSPServiceInformationDefinitionURI(tspServiceInformation);
		// Comprobamos las extensiones.
		if (tspServiceInformation.isThereSomeServiceInformationExtension()) {
			for (IAnyTypeExtension serviceInformationExtension: tspServiceInformation.getServiceInformationExtensions()) {
				serviceInformationExtension.checkExtensionValue(tsl, tspServiceInformation);
			}
		}

	}

	/**
	 * Checks if at least exist one service information extension of the specified implementation type,
	 * in the input TSP Service.
	 * @param tspServiceInformation TSP Service Information to analyze.
	 * @param serviceExtensionImplType Implementation type of the TSP Service Information Extension to search.
	 * The differents implementation types are defined in {@link IAnyTypeExtension}.
	 * @return <code>true</code> if if at least exist one service information extension of the specified implementation type,
	 * in the input TSP Service, otherwise <code>false</code>.
	 */
	protected final boolean checkIfIsDefinedSomeExtensionTypeInTSPService(ServiceHistoryInstance tspServiceInformation, int serviceExtensionImplType) {

		boolean result = false;

		if (tspServiceInformation != null && tspServiceInformation.isThereSomeServiceInformationExtension()) {

			for (IAnyTypeExtension serviceInformationExtension: tspServiceInformation.getServiceInformationExtensions()) {

				if (serviceInformationExtension.getImplementationExtension() == serviceExtensionImplType) {
					result = true;
					break;
				}

			}

		}

		return result;

	}

	/**
	 * Checks if the TSP Service Information Type Identifier has a correct value.
	 * @param tspServiceInformation TSP Service Information to analyze.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkTSPServiceInformationType(ServiceHistoryInstance tspServiceInformation) throws TSLMalformedException;

	/**
	 * Checks if the TSP Service Information Name has a correct value.
	 * @param tspServiceInformation TSP Service Information to analyze.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPServiceInformationNames(ServiceInformation tspServiceInformation) throws TSLMalformedException {

		if (tspServiceInformation.isThereSomeServiceName()) {
			checkTSPServiceInformationNamesValues(tspServiceInformation);
		} else {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_NAMES }));
		}

	}

	/**
	 * Checks if the TSP Service Information Name has a correct value.
	 * @param tspServiceInformation TSP Service Information to analyze.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkTSPServiceInformationNamesValues(ServiceHistoryInstance tspServiceInformation) throws TSLMalformedException;

	/**
	 * Checks if the TSP Service Information Digital Identities have a correct value.
	 * @param tspServiceInformation TSP Service Information to analyze.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPServiceInformationIdentities(ServiceInformation tspServiceInformation) throws TSLMalformedException {

		// Comprobamos el número de identidades digitales según la
		// especificación.
		checkTSPServiceInformationIdentitiesSize(tspServiceInformation);

		// Si hay, las comprobamos.
		if (tspServiceInformation.isThereSomeIdentity()) {
			checkTSPServiceInformationIdentitiesValues(tspServiceInformation);
		}

	}

	/**
	 * Checks if the TSP Service Information Digital Identities have a correct size.
	 * @param tspServiceInformation TSP Service Information to analyze.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkTSPServiceInformationIdentitiesSize(ServiceInformation tspServiceInformation) throws TSLMalformedException;

	/**
	 * Checks if the TSP Service Information Digital Identities have a correct value.
	 * @param tspServiceInformation TSP Service Information to analyze.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkTSPServiceInformationIdentitiesValues(ServiceHistoryInstance tspServiceInformation) throws TSLMalformedException;

	/**
	 * Checks if the input service type identifier matches with some one that represents
	 * a service that not is using the PKI public key technology, or is unspecified.
	 * @param serviceType Service type identifier to check.
	 * @return <code>true</code> if the input service type identifier matches with some one that represents
	 * a service that not is using the PKI public key technology, otherwise <code>false</code>.
	 */
	protected abstract boolean checkIfServiceTypeIsNoPKIorUnspecified(String serviceType);

	/**
	 * Checks if all the Digital Identities are of "other type" clasification and these are
	 * of URI type.
	 * @param diList List of service identities to check.
	 * @throws TSLMalformedException In case of there is some identity that not is "other type" or not
	 * is in URI format.
	 */
	protected final void checkTSPServiceInformationIdentitiesNonPKI(List<DigitalID> diList) throws TSLMalformedException {

		if (diList != null && !diList.isEmpty()) {
			for (DigitalID digitalID: diList) {

				// Comprobamos que sea de tipo Other.
				if (DigitalID.TYPE_OTHER != digitalID.getType()) {
					throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.ATC_LOG013));
				}

				// Comprobamos que su valor sea una URI.
				try {
					new URI(digitalID.getOther());
				} catch (URISyntaxException e) {
					throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.ATC_LOG014), e);
				}

			}
		}

	}

	/**
	 * Checks if the TSP Service Information Status URI has a correct value.
	 * @param tspServiceInformation TSP Service Information to analyze.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPServiceInformationStatus(ServiceInformation tspServiceInformation) throws TSLMalformedException {

		// Comprobamos que no sea nula.
		if (tspServiceInformation.getServiceStatus() == null) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_STATUS }));
		} else {
			// Comprobamos los valores asignados según la especificación.
			checkTSPServiceInformationStatusValue(tspServiceInformation);
		}

	}

	/**
	 * Checks if the TSP Service Information Status URI has a correct value.
	 * @param tspServiceInformation TSP Service Information to analyze.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkTSPServiceInformationStatusValue(ServiceHistoryInstance tspServiceInformation) throws TSLMalformedException;

	/**
	 * Checks if the TSP Service Information Status Starting Date and Time has a correct value.
	 * @param serviceStatusStartingDateAndTime TSP Service Status Starting Date and Time to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPServiceInformationStatusStartingDateAndTime(Date serviceStatusStartingDateAndTime) throws TSLMalformedException {

		if (serviceStatusStartingDateAndTime == null) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_STATUS_STARTINGTIME }));
		}

	}

	/**
	 * Checks if the TSP Service Information Scheme Definition URI has a correct value.
	 * @param schemeServiceDefinitionURIs TSP Service Information Scheme Definition URI to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPServiceInformationSchemeDefinitionURI(Map<String, List<URI>> schemeServiceDefinitionURIs) throws TSLMalformedException {

		// Puede ser nulo, así que no es necesario comprobar nada.
		return;

	}

	/**
	 * Checks if the TSP Service Information Supply Points has a correct value.
	 * @param serviceSupplyPoints TSP Service Information Supply Points
	 */
	private void checkTSPServiceInformationServiceSupplyPoints(List<URI> serviceSupplyPoints) {

		// Puede ser nulo, así que no es necesario comprobar nada.
		return;

	}

	/**
	 * Checks if the TSP Service Information Definition URI has a correct value.
	 * @param tspServiceInformation TSP Service Information to analyze.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPServiceInformationDefinitionURI(ServiceInformation tspServiceInformation) throws TSLMalformedException {

		// En caso de que el tipo de servicio sea NationalRootCA, este atributo
		// es obligatorio.
		String serviceType = tspServiceInformation.getServiceTypeIdentifier().toString();
		if (serviceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_NATIONALROOTCA) && (tspServiceInformation.getServiceDefinitionURIs() == null || tspServiceInformation.getServiceDefinitionURIs().isEmpty())) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_TSPSERVICEDEFINITIONURI }));
		}

	}

	/**
	 * Checks if the TSP Service History Instance has a correct value.
	 * @param serviceHistoryInstance TSP Service History Instance to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPServiceHistoryInstance(ServiceHistoryInstance serviceHistoryInstance) throws TSLMalformedException {

		// Comprobamos el tipo de servicio histórico.
		checkTSPServiceHistoryInstanceType(serviceHistoryInstance);
		// Comprobamos los nombres del servicio histórico.
		checkTSPServiceHistoryInstanceNames(serviceHistoryInstance);
		// Comprobamos las identidades del servicio histórico.
		checkTSPServiceHistoryInstanceIdentities(serviceHistoryInstance);
		// Comprobamos el estado del servicio histórico.
		checkTSPServiceHistoryInstanceStatus(serviceHistoryInstance);
		// Comprobamos la fecha de inicio del servicio histórico.
		checkTSPServiceHistoryInstanceStatusStartingDateAndTime(serviceHistoryInstance.getServiceStatusStartingTime());
		// Comprobamos las extensiones.
		if (serviceHistoryInstance.isThereSomeServiceInformationExtension()) {
			for (IAnyTypeExtension serviceInformationExtension: serviceHistoryInstance.getServiceInformationExtensions()) {
				serviceInformationExtension.checkExtensionValue(tsl, serviceHistoryInstance);
			}
		}

	}

	/**
	 * Checks if the TSP Service History Instance Type Identifier has a correct value.
	 * @param serviceHistoryInstance TSP Service History Instance to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkTSPServiceHistoryInstanceType(ServiceHistoryInstance serviceHistoryInstance) throws TSLMalformedException;

	/**
	 * Checks if the TSP Service History Instance Name has a correct value.
	 * @param serviceHistoryInstance TSP Service History Instance to analyze.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPServiceHistoryInstanceNames(ServiceHistoryInstance serviceHistoryInstance) throws TSLMalformedException {

		if (serviceHistoryInstance.isThereSomeServiceName()) {
			checkTSPServiceHistoryInstanceNamesValues(serviceHistoryInstance);
		} else {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_HISTORY_NAMES }));
		}

	}

	/**
	 * Checks if the TSP Service Information Name has a correct value.
	 * @param serviceHistoryInstance TSP Service History Instance to analyze.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkTSPServiceHistoryInstanceNamesValues(ServiceHistoryInstance serviceHistoryInstance) throws TSLMalformedException;

	/**
	 * Checks if the TSP Service History Instance Digital Identities have a correct value.
	 * @param serviceHistoryInstance TSP Service History Instance to analyze.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPServiceHistoryInstanceIdentities(ServiceHistoryInstance serviceHistoryInstance) throws TSLMalformedException {

		if (serviceHistoryInstance.isThereSomeIdentity()) {
			checkTSPServiceHistoryInstanceIdentitiesValues(serviceHistoryInstance);
		} else {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_HISTORY_SERVICEDIGITALIDENTITY }));
		}

	}

	/**
	 * Checks if the TSP Service History Instance Digital Identities have a correct value.
	 * @param serviceHistoryInstance TSP Service History Instance to analyze.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkTSPServiceHistoryInstanceIdentitiesValues(ServiceHistoryInstance serviceHistoryInstance) throws TSLMalformedException;

	/**
	 * Checks if the TSP Service History Instance Status URI has a correct value.
	 * @param serviceHistoryInstance TSP Service History Instance to analyze.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPServiceHistoryInstanceStatus(ServiceHistoryInstance serviceHistoryInstance) throws TSLMalformedException {

		// Comprobamos que no sea nula.
		if (serviceHistoryInstance.getServiceStatus() == null) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_HISTORY_STATUS }));
		} else {
			// Comprobamos los valores asignados según la especificación.
			checkTSPServiceHistoryInstanceStatusValue(serviceHistoryInstance);
		}

	}

	/**
	 * Checks if the TSP Service History Instance Status URI has a correct value.
	 * @param serviceHistoryInstance TSP Service History Instance to analyze.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	protected abstract void checkTSPServiceHistoryInstanceStatusValue(ServiceHistoryInstance serviceHistoryInstance) throws TSLMalformedException;

	/**
	 * Checks if the TSP Service History Instance Status Starting Date and Time has a correct value.
	 * @param serviceStatusStartingDateAndTime TSP Service History Instance Status Starting Date and Time to check.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	private void checkTSPServiceHistoryInstanceStatusStartingDateAndTime(Date serviceStatusStartingDateAndTime) throws TSLMalformedException {

		if (serviceStatusStartingDateAndTime == null) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_HISTORY_STATUS_STARTINGTIME }));
		}

	}

	/**
	 * Checks if must be defined (according to its specification and version) or not the TSL signature.
	 * Also checks the integrity of the signature.
	 * @param fullTSLxml Byte array that represents the full TSL xml to check the signature.
	 * @throws TSLMalformedException In case of some data has not a correct value.
	 */
	public final void checkTSLSignature(byte[ ] fullTSLxml) throws TSLMalformedException {

		// Comprobamos por cada especificación, si obligatoriamente debe estar
		// la firma.
		if (tsl.getSignature() == null) {
			tslSignatureIsNotDefined();
		} else {
			// Comprobamos la firma.
			// Si así está configurado, comprobamos que la firma es correcta
			// estructuralmente.
		   
			if (TSLProperties.isRequiredToCheckTslSignatureStructure()) {
				veryfyTSLSignature(fullTSLxml);
			}
			// Si así está configurado, comprobamos que la firma cumple los
			// requisitos de la especificación.
			if (TSLProperties.isRequiredToCheckTslSignatureByItsSpecification()) {
			    checkSignatureAccordingToSpecification(fullTSLxml);
			}
			// Siempre se comprueba que se confía en los certificados firmantes.
			checkSignerCertificateIsInTrustedTSLKeystore(fullTSLxml);
		}

	}

	/**
	 * According to its specification and version, a exception must be thrown.
	 * @throws TSLMalformedException If the concrete specification and version requires that
	 * the TSL signature must be defined.
	 */
	protected abstract void tslSignatureIsNotDefined() throws TSLMalformedException;

	/**
	 * Checks the TSL signature structure according to the specification.
	 * @param fullTSLxml Byte array that represents the full TSL xml to check the signature.
	 * @throws TSLMalformedException In case of the signature is not valid according to the specification.
	 */
	protected abstract void checkSignatureAccordingToSpecification(byte[ ] fullTSLxml) throws TSLMalformedException;

	/**
	 * Verifies the TSL Signature.
	 * @param fullTSLxml Byte array that represents the full TSL xml to check the signature.
	 * @throws TSLMalformedException In case of the signature is not verified.
	 */
	protected final void veryfyTSLSignature(byte[ ] fullTSLxml) throws TSLMalformedException {

		SignValidity validity = new ValidateXMLSignature().validate(fullTSLxml);
		if (validity.getValidity() != SignValidity.SIGN_DETAIL_TYPE.OK) {
			throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.ATC_LOG004));
		}

	}

	/**
	 * Checks if the input X509v3 Certificate has the extended key usage extension for singning TSL.
	 * @param x509cert Input X509v3 certificate to check.
	 * @throws TSLMalformedException In case of the input parameter is <code>null</code>, the extended key usage extension
	 * list is <code>null</code> or empty, or does not exist the extension for signing TSL.
	 */
	protected final void checkX509v3ExtendedKeyUsageTSLSigning(X509Certificate x509cert) throws TSLMalformedException {

		try {
			if (x509cert == null) {
				throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.ATC_LOG005));
			} else {

				// Recuperamos las "extended key usage".
				List<String> extendedKeyUsageOIDsList = x509cert.getExtendedKeyUsage();
				if (extendedKeyUsageOIDsList == null || extendedKeyUsageOIDsList.isEmpty()) {
					throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.ATC_LOG006));
				} else {

					if (!extendedKeyUsageOIDsList.contains(ITSLOIDs.STRING_OID_TSL_SIGNING)) {
						throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.ATC_LOG007));
					}

				}

			}
		} catch (CertificateParsingException e) {
			throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.ATC_LOG008), e);
		}

	}

	/**
	 * Checks if the input X509v3 Certificate (TSL signer) is in the Trusted TSL Keystore.
	 * @param x509cert X509v3 certificate that represents the TSL signer.
	 * @throws TSLMalformedException In case of the input certificate is not included in the Trusted TSL Keystore.
	 */
	protected final void checkX509v3SigningCertificateIsInTrustStore(X509Certificate x509cert) throws TSLMalformedException {

		try {

			// Obtenemos el almacén de confianza.
		
//			IKeystoreFacade tslTrustedKeystoreFacade = KeystoreFactory.getKeystoreInstance(IKeystoreIdConstants.ID_TSL_TRUSTSTORE);
//			KeyStore tslTrustedKeystore = tslTrustedKeystoreFacade.getKeystore();
//			// Comprobamos si está el certificado firmante en el almacén de
//			// confianza.
//			String alias = tslTrustedKeystore.getCertificateAlias(x509cert);
//			if (UtilsStringChar.isNullOrEmptyTrim(alias)) {
//				throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ATC_LOG012, new Object[ ] { UtilsCertificate.getCertificateIssuerId(x509cert), x509cert.getSerialNumber().toString() }));
//			}

		} catch (Exception e) {
			throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.ATC_LOG009), e);
		}

	}

	/**
	 * Checks if the signer certificate of the TSL is in the truststore.
	 * @param fullTSLxml Byte array that represents the full TSL xml to check the signature.
	 * @throws TSLMalformedException In case of does not possible to check if the signer certificate of the TSL
	 * is in the truststore.
	 */
	private void checkSignerCertificateIsInTrustedTSLKeystore(byte[ ] fullTSLxml) throws TSLMalformedException {

		// Obtenemos el listado de certificados firmantes.
		X509Certificate cert = getSigningCertificate(fullTSLxml);
		// Si se ha encontrado, se comprueba que se confía en este.
		checkX509v3SigningCertificateIsInTrustStore(cert);

	}

	/**
	 * Gets the signing certificates of the TSL signature.
	 * @param fullTSLxml Byte array that represents the full TSL xml to check the signature.
	 * @return X509 certificate that sign the TSL.
	 * @throws TSLMalformedException In case of some error getting the signing certificates from
	 * the TSL signature.
	 */
	protected X509Certificate getSigningCertificate(byte[ ] fullTSLxml) throws TSLMalformedException {

		X509Certificate result = null;

		try (InputStream is = new ByteArrayInputStream(fullTSLxml)) {
			Document tslDocument = SecureXmlBuilder.getSecureDocumentBuilder().parse(is);

			// Obtenemos todas las firmas del documento y el SignatureValue de cada
			// una de ellas
			final NodeList signatures = tslDocument.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
			if (signatures.getLength() < 1) {
				throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.ATC_LOG010));
			}

			final Element signature = (Element) signatures.item(0);

			final NodeList certificates = signature.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate");
			if (certificates.getLength() < 1) {
				throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.ATC_LOG010));
			}

			result = getCertificate((Element) certificates.item(0));
		}
		catch (TSLMalformedException e) {
			throw e;
		}
		catch (Exception e) {
			throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.ATC_LOG010), e);
		}

		return result;
	}
	
    /** Genera un certificado X.509 a partir de un nodo de certificado de firma.
     * @param certificateElement Nodo "X509Certificate" de la firma.
     * @return Certificado de firma. */
	private static X509Certificate getCertificate(final Element certificateElement) {
        return createCert(certificateElement.getTextContent()
        		.replace("\r", "")
        		.replace("\n", "")
        		.replace(" ", "")
        		.replace("\t", ""));
    }
	
    /** Crea un X509Certificate a partir de un certificado en Base64.
     * @param b64Cert Certificado en Base64. No debe incluir <i>Bag Attributes</i>.
     * @return Certificado X509 o <code>null</code> si no se pudo crear. */
    private static X509Certificate createCert(final String b64Cert) {
        if (b64Cert == null || b64Cert.isEmpty()) {
            return null;
        }
        final X509Certificate cert;
        try (InputStream isCert = new ByteArrayInputStream(Base64.decodeBase64(b64Cert))) {
            cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(isCert);
        }
        catch (final Exception e) {
            return null;
        }
        return cert;
    }
	

	/**
	 * Generic method to parse a XML input stream or XML node to the indicated Document Class through
	 * XMLBeans. To avoid problems with class loaders (in case of different Documents with same name and
	 * namespace), the XMLBeans classloaders is built from this DocumentClass.
	 * @param is Input stream of the XML. If it is <code>null</code>, the the node parameter must be defined.
	 * @param node XML node. If it is <code>null</code>, then the input stream parameter must be defined.
	 * @param classDocument Document Class from which build the XMLBeans Class Loader and parse the input (stream or node).
	 * @return Generated document object of type T.
	 * @throws TSLParsingException In case of some error parsing the input (stream or node) to the XML document.
	 */
//	protected <T> T getDocumentBuildingNewSchemeTypeLoader(InputStream is, Node node, Class<T> classDocument) throws TSLParsingException {
//
//		try {
//
//			SchemaType sts = (SchemaType) classDocument.getDeclaredField(SCHEME_TYPE_FIELD_NAME).get(null);
//			SchemaTypeLoader stl = XmlBeans.typeLoaderUnion(new SchemaTypeLoader[ ] { sts.getTypeSystem(), XmlBeans.getContextTypeLoader() });
//			if (is != null) {
//				return classDocument.cast(stl.parse(is, sts, null));
//			} else {
//				return classDocument.cast(stl.parse(node, sts, null));
//			}
//
//		} catch (Exception e) {
//			throw new TSLParsingException(Language.getResIntegraTsl(ILogTslConstant.ATC_LOG011), e);
//		} finally {
//			UtilsResources.safeCloseInputStream(is);
//		}
//
//	}


}
