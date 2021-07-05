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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder.java.</p>
 * <b>Description:</b><p>Abstract class that represents a TSL builder with the principal functions
 * regardless it implementation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 15/06/2021.
 */
package es.gob.afirma.tsl.parsing.impl.common;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.apache.xmlbeans.SchemaType;
import org.apache.xmlbeans.SchemaTypeLoader;
import org.apache.xmlbeans.XmlBeans;
import org.w3.x2000.x09.xmldsig.SignatureType;
import org.w3c.dom.Node;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.exceptions.TSLArgumentException;
import es.gob.afirma.tsl.exceptions.TSLEncodingException;
import es.gob.afirma.tsl.exceptions.TSLParsingException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.parsing.ifaces.IAnyTypeExtension;
import es.gob.afirma.tsl.parsing.ifaces.IAnyTypeOtherCriteria;
import es.gob.afirma.tsl.parsing.ifaces.ITSLBuilder;
import es.gob.afirma.tsl.parsing.ifaces.ITSLElementsAndAttributes;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.impl.common.extensions.UnknownExtension;
import es.gob.afirma.tsl.utils.UtilsResourcesCommons;
import es.gob.afirma.tsl.utils.UtilsStringChar;

/** 
 * <p>Abstract class that represents a TSL builder with the principal functions
 * regardless it implementation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 15/06/2021.
 */
public abstract class ATSLBuilder implements ITSLBuilder {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = Logger.getLogger(ATSLBuilder.class);

    /**
     * Constant attribute that represents the token name for the Scheme Type Field.
     */
    private static final String SCHEME_TYPE_FIELD_NAME = "type";
    
    /**
     * Attribute that represents the TSL object to manage.
     */
    private ITSLObject tsl = null;

    /**
     * Constructor method for the class ATSLBuilder.java.
     */
    private ATSLBuilder() {
	super();
    }

    /**
     * Constructor method for the class ATSLBuilder.java.
     * @param tslObject TSL Object representation to manage with this builder.
     */
    protected ATSLBuilder(ITSLObject tslObject) {
	this();
	tsl = tslObject;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.ifaces.ITSLBuilder#buildTSLFromXML(java.io.InputStream)
     */
    @Override
    public final byte[ ] buildTSLFromXML(InputStream is) throws TSLArgumentException, TSLParsingException {

	// Si la entrada es nula, lanzamos excepción.
	if (is == null) {
	    throw new TSLArgumentException(Language.getResIntegraTsl(ILogTslConstant.ATB_LOG001));
	}

	byte[ ] result = null;
	try {
	    result = IOUtils.toByteArray(is);
	} catch (IOException e) {
	    throw new TSLParsingException(Language.getResIntegraTsl(ILogTslConstant.ATB_LOG002), e);
	} finally {
	    UtilsResourcesCommons.safeCloseInputStream(is);
	}

	ByteArrayInputStream bais = new ByteArrayInputStream(result);
	// Parseamos el flujo de entrada XML, y se almacena localmente.
	try {
	    parseXMLInputStream(bais);
	} finally {
	    UtilsResourcesCommons.safeCloseInputStream(bais);
	}
	// Una vez parseado, obtenemos el atributo tslTag e ID (si lo hubiera).
	buildTSLTagAndID();
	// Ahora construimos el "Scheme Information".
	buildTSLSchemeInformation();
	// Construimos la lista de prestadores declarados.
	buildTSLlistTSP();
	// Finalmente obtenemos la firma.
	buildTSLSignature();

	return result;

    }

    /**
     * Abstract method that parse the input stream and load the TSL object representation from it.
     * This must be stored in a transient attribute of the implementation class.
     * @param is Input stream of the XML representation of the TSL. This is not <code>null</code>, already checked.
     * @throws TSLParsingException In case of some error parsing the input stream.
     */
    protected abstract void parseXMLInputStream(InputStream is) throws TSLParsingException;

    /**
     * Gets the tslTag attribute and ID attribute from the parsed XML.
     * @throws TSLParsingException In case of some error getting the values.
     */
    private void buildTSLTagAndID() throws TSLParsingException {

	// Obtenemos primero el atributo tslTag.
	String tslTagString = getTSLTagString();
	if (tslTagString == null) {
	    throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.ATB_LOG003, new Object[ ] { ITSLElementsAndAttributes.ATTRIBUTE_TSL_TAG }));
	} else {
	    try {
		tsl.setTSLTag(new URI(tslTagString));
	    } catch (URISyntaxException e) {
		throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.ATB_LOG004, new Object[ ] { ITSLElementsAndAttributes.ATTRIBUTE_TSL_TAG }), e);
	    } catch (TSLArgumentException e) {
		throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.ATB_LOG004, new Object[ ] { ITSLElementsAndAttributes.ATTRIBUTE_TSL_TAG }), e);
	    }
	}

	// Obtenemos ahora el atributo ID si lo hubiera.
	tsl.setID(getTSLID());

    }

    /**
     * Gets the URI string that represents the tag attribute for the TrustServiceStatus element.
     * @return URI string that represents the tag attribute for the TrustServiceStatus element.
     * <code>null</code> if not is defined.
     */
    protected abstract String getTSLTagString();

    /**
     * Gets the string that represents the ID attribute for the TrustServiceStatus element.
     * @return string that represents the ID attribute for the TrustServiceStatus element.
     * <code>null</code> if not is defined.
     */
    protected abstract String getTSLID();

    /**
     * Gets all the Scheme information from the parsed XML.
     * @throws TSLParsingException In case of some error getting the values.
     */
    protected final void buildTSLSchemeInformation() throws TSLParsingException {

	// Establecemos el identificador de versión.
	buildSchemeInformationTSLVersionIdentifier();
	// Establecemos el número de secuencia.
	buildSchemeInformationTSLSequenceNumber();
	// Establecemos el tipo de TSL.
	buildSchemeInformationTSLType();
	// Establecemos los nombres del operador.
	buildSchemeInformationOperatorName();
	// Establecemos las direcciones del operador.
	buildSchemeInformationOperatorAddress();
	// Establecemos el nombre.
	buildSchemeInformationName();
	// Establecemos las URI informativas.
	buildSchemeInformationURI();
	// Establecemos la URI que determina el estado.
	buildSchemeInformationStatusDeterminationApproach();
	// Establecemos los type/community/rules
	buildSchemeInformationTypeCommunityRules();
	// Establecemos el territorio de la TSL.
	buildSchemeInformationTerritory();
	// Establecemos las políticas y notas legales.
	buildSchemeInformationPolicyOrLegalNotice();
	// Establecemos el periodo de información histórica.
	buildSchemeInformationHistoricalInformationPeriod();
	// Establecemos los "punteros" hacia otras TSL.
	buildSchemeInformationPointersToOtherTSL();
	// Establecemos la fecha de emisión.
	buildSchemeInformationListIssueDateTime();
	// Establecemos la fecha de caducidad (próxima emisión).
	buildSchemeInformationNextUpdate();
	// Establecemos los puntos de distribución.
	buildSchemeInformationDistributionPoints();
	// Establecemos las extensiones.
	buildSchemeInformationExtensions();

    }

    /**
     * Sets the version identifier in the scheme information.
     */
    private void buildSchemeInformationTSLVersionIdentifier() {
	BigInteger viBi = getSchemeInformationTSLVersionIdentifier();
	if (viBi != null) {
	    tsl.getSchemeInformation().setTslVersionIdentifier(viBi.intValue());
	}
    }

    /**
     * Gets the Scheme Information TSL Version Identifier.
     * @return the value for the Scheme Information TSL Version Identifier.
     */
    protected abstract BigInteger getSchemeInformationTSLVersionIdentifier();

    /**
     * Sets the sequence number in the scheme information.
     */
    private void buildSchemeInformationTSLSequenceNumber() {
	BigInteger snBi = getSchemeInformationTSLSequenceNumber();
	if (snBi != null) {
	    tsl.getSchemeInformation().setTslSequenceNumber(snBi.intValue());
	}
    }

    /**
     * Gets the Scheme Information TSL Sequence Number.
     * @return the value for the Scheme Information TSL Sequence Number.
     */
    protected abstract BigInteger getSchemeInformationTSLSequenceNumber();

    /**
     * Sets the sequence number in the scheme information TSL type.
     * @throws TSLParsingException In case of some error parsing the URI of the TSP type.
     */
    private void buildSchemeInformationTSLType() throws TSLParsingException {
	String tslType = getTSLType();
	if (tslType != null) {
	    try {
		tsl.getSchemeInformation().setTslType(new URI(tslType));
	    } catch (URISyntaxException e) {
		throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.ATB_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSL_TYPE }), e);
	    }
	}
    }

    /**
     * Gets the Scheme Information TSL Type.
     * @return the value for the Scheme Information TSL Type.
     */
    protected abstract String getTSLType();

    /**
     * Sets the operator names in the scheme information.
     */
    private void buildSchemeInformationOperatorName() {

	Map<String, List<String>> son = getTSLSchemeOperatorNamesMap();
	if (son != null) {
	    Set<String> keys = son.keySet();
	    for (String key: keys) {
		List<String> values = son.get(key);
		for (String schemeOperatorName: values) {
		    tsl.getSchemeInformation().addNewSchemeOperatorName(key, schemeOperatorName);
		}
	    }
	}

    }

    /**
     * Gets the scheme operator name of the current TSL in all the presented languages.
     * @return Map with the scheme operator names in all the presented languages: <Language, List<SchemeOperatorName>>.
     * <code>null</code> if not is defined.
     */
    protected abstract Map<String, List<String>> getTSLSchemeOperatorNamesMap();

    /**
     * Sets the operator address in the scheme information.
     * @throws TSLParsingException In case of some error parsing the URI of a electronic address.
     */
    private void buildSchemeInformationOperatorAddress() throws TSLParsingException {

	Map<String, List<PostalAddress>> postalAddresses = getTSLSCOPostalAdresses();
	Map<String, List<String>> electronicAddresses = getTSLSCOElectronicAddresses();
	Address siAddress = tsl.getSchemeInformation().getSchemeOperatorAddress();

	if (postalAddresses != null) {
	    siAddress.setPostalAddresses(postalAddresses);
	}

	Map<String, List<URI>> electronicAddressesURI = null;
	if (electronicAddresses != null) {
	    electronicAddressesURI = new HashMap<String, List<URI>>();
	    Set<String> keys = electronicAddresses.keySet();
	    for (String key: keys) {
		List<URI> uriList = new ArrayList<URI>();
		List<String> uriStringList = electronicAddresses.get(key);
		for (String uriString: uriStringList) {
		    try {
			uriList.add(new URI(uriString));
		    } catch (URISyntaxException e) {
			throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.ATB_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_SCHEME_OPERATOR_ADDRESS }), e);
		    }
		}
		electronicAddressesURI.put(key, uriList);
	    }
	} else {
	    electronicAddressesURI = new HashMap<String, List<URI>>();
	}
	siAddress.setElectronicAddresses(electronicAddressesURI);

    }

    /**
     * Gets the scheme operator postal addresses of the current TSL in all the presented languages.
     * @return map with the scheme operator postal addresses of the current TSL in all presented languages:
     * - Map<Language, List<PostalAddress>>
     * - <code>null</code> if not is defined.
     */
    protected abstract Map<String, List<PostalAddress>> getTSLSCOPostalAdresses();

    /**
     * Gets the scheme operator electronic addresses of the current TSL in all the presented languages.
     * @return map with the scheme operator electronic addresses of the current TSL in all presented languages:
     * - Map<Language, ElectronicAddresses>.
     * - <code>null</code> if not is defined.
     */
    protected abstract Map<String, List<String>> getTSLSCOElectronicAddresses();

    /**
     * Sets the name in the scheme information.
     */
    private void buildSchemeInformationName() {

	Map<String, String> sn = getTSLSchemeNameMap();
	if (sn != null) {
	    tsl.getSchemeInformation().setSchemeNames(sn);
	}

    }

    /**
     * Gets the scheme name of the current TSL in all the presented languages.
     * @return Map with the scheme name in all the presented languages: <Language, SchemeName>.
     * <code>null</code> if not is defined.
     */
    protected abstract Map<String, String> getTSLSchemeNameMap();

    /**
     * Sets the information URI in the scheme information.
     * @throws TSLParsingException In case of some error parsing the URI.
     */
    private void buildSchemeInformationURI() throws TSLParsingException {

	Map<String, String> siu = getTSLSchemeInformationURIMap();
	if (siu != null) {
	    Set<String> keys = siu.keySet();
	    for (String key: keys) {
		try {
		    tsl.getSchemeInformation().addNewSchemeInformationURI(key, new URI(siu.get(key)));
		} catch (URISyntaxException e) {
		    throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.ATB_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_SCHEME_INFORMATION_URI }), e);
		}
	    }

	}

    }

    /**
     * Gets the scheme information URI of the current TSL in all the presented languages.
     * @return Map with the scheme information URI in all the presented languages: <Language, SchemeInformationURI>.
     * <code>null</code> if not is defined.
     */
    protected abstract Map<String, String> getTSLSchemeInformationURIMap();

    /**
     * Sets the status determination approach URI in the scheme information.
     * @throws TSLParsingException In case of some error parsing the URI.
     */
    private void buildSchemeInformationStatusDeterminationApproach() throws TSLParsingException {

	String sda = getTSLStatusDeterminationApproachString();
	if (sda != null) {
	    try {
		tsl.getSchemeInformation().setStatusDeterminationApproach(new URI(sda));
	    } catch (URISyntaxException e) {
		throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.ATB_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_STATUS_DETERMINATION_APPROACH }), e);
	    }
	}

    }

    /**
     * Gets the URI that specifies the status determination approach of the current TSL.
     * @return URI string that specifies the status determination approach of the current TSL.
     * <code>null</code> if not is defined.
     */
    protected abstract String getTSLStatusDeterminationApproachString();

    /**
     * Sets the scheme information type community rules URI in the scheme information.
     * @throws TSLParsingException In case of some error parsing the URI.
     */
    private void buildSchemeInformationTypeCommunityRules() throws TSLParsingException {

	Map<String, List<String>> stcr = getTSLSchemeTypeCommunityRulesMap();

	if (stcr != null) {
	    Set<String> languageKeys = stcr.keySet();
	    for (String language: languageKeys) {
		List<String> uriStringList = stcr.get(language);
		try {
		    for (String uriString: uriStringList) {
			tsl.getSchemeInformation().addNewSchemeTypeCommunityRule(language, new URI(uriString));
		    }
		} catch (URISyntaxException e) {
		    throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.ATB_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_SCHEME_TYPE_COMMUNITY_RULES }), e);
		}
	    }
	}

    }

    /**
     * Gets the URI string that represents the scheme type community rules of the current TSL in all the presented languages.
     * @return Map with the the URI string that represents the scheme type community rules of the current TSL in
     * all the presented languages: <Language, List<SchemeTypeCommunityRuleURI>>. <code>null</code> if
     * not is defined.
     */
    protected abstract Map<String, List<String>> getTSLSchemeTypeCommunityRulesMap();

    /**
     * Sets the territory in the scheme information.
     * @throws TSLParsingException In case of some error getting the territory.
     */
    private void buildSchemeInformationTerritory() throws TSLParsingException {
	tsl.getSchemeInformation().setSchemeTerritory(getSchemeTerritory());
    }

    /**
     * Gets the territory from the TSL XML representation.
     * @return String with the territory name representation.
     * @throws TSLParsingException In case of some error getting the territory value.
     */
    protected abstract String getSchemeTerritory() throws TSLParsingException;

    /**
     * Sets the scheme policies or legal notices in the scheme information.
     * @throws TSLParsingException In case of some error parsing a policy URI.
     */
    private void buildSchemeInformationPolicyOrLegalNotice() throws TSLParsingException {

	Map<String, String> legalNotices = getTSLLegalNotice();
	if (legalNotices != null) {
	    tsl.getSchemeInformation().setLegalNotices(legalNotices);
	}

	Map<String, String> policies = getTSLPolicy();
	if (policies != null) {
	    Set<String> languageKeys = policies.keySet();
	    for (String language: languageKeys) {
		URI policyUri = null;
		try {
		    policyUri = new URI(policies.get(language));
		} catch (URISyntaxException e) {
		    throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.ATB_LOG006, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_POLICY_OR_LEGAL_NOTICE }), e);
		}
		tsl.getSchemeInformation().addNewPolicy(language, policyUri);
	    }
	}

    }

    /**
     * Gets the policies of the current TSL in all the presented languages.
     * @return map with the policies in all the presented languages: Map<Language, Policy>.
     * <code>null</code> if not is defined.
     */
    protected abstract Map<String, String> getTSLPolicy();

    /**
     * Gets the legal notices of the current TSL in all the presented languages.
     * @return map with the legal notices in all the presented languages: Map<Language, LegalNotice>.
     * <code>null</code> if not is defined.
     */
    protected abstract Map<String, String> getTSLLegalNotice();

    /**
     * Sets the historical information period in the scheme information.
     */
    private void buildSchemeInformationHistoricalInformationPeriod() {

	BigInteger hiPeriod = getTSLHistoricalInformationPeriodBigInteger();
	if (hiPeriod != null) {
	    tsl.getSchemeInformation().setHistoricalPeriod(hiPeriod.intValue());
	}

    }

    /**
     * Gets the historical information period number of the current TSL.
     * @return historical information period number of the current TSL.
     */
    protected abstract BigInteger getTSLHistoricalInformationPeriodBigInteger();

    /**
     * Sets the others TSL pointers in the scheme information.
     * @throws TSLParsingException In case of some error parsing a TSL Pointer information.
     */
    private void buildSchemeInformationPointersToOtherTSL() throws TSLParsingException {
	tsl.getSchemeInformation().setPointersToOtherTSL(getTSLPointersToOthersTSL());
    }

    /**
     * Gets the TSL pointers to others TSL included in the current TSL.
     * @return array of TSL pointers to others TSL included in the current TSL.
     * <code>null</code> if there is not defined.
     * @throws TSLParsingException In case of some error parsing a TSL Pointer information.
     */
    protected abstract List<TSLPointer> getTSLPointersToOthersTSL() throws TSLParsingException;

    /**
     * Sets the TSL Issue Date in the scheme information.
     * @throws TSLParsingException In case of some error parsing the issue date.
     */
    private void buildSchemeInformationListIssueDateTime() throws TSLParsingException {

	Calendar issueDate = getTSLIssueDateCalendar();
	if (issueDate != null) {
	    tsl.getSchemeInformation().setListIssueDateTime(issueDate.getTime());
	}

    }

    /**
     * Gets the issue date calendar of the current TSL.
     * @return The issue date calendar of the current TSL. <code>null</code> if not is defined.
     */
    protected abstract Calendar getTSLIssueDateCalendar();

    /**
     * Sets the next update date in the scheme information.
     */
    private void buildSchemeInformationNextUpdate() {

	Calendar tslNextUpdateCalendar = getTSLNextUpdateCalendar();
	if (tslNextUpdateCalendar != null) {
	    tsl.getSchemeInformation().setNextUpdate(tslNextUpdateCalendar.getTime());
	}

    }

    /**
     * Gets the next update calendar of the current TSL.
     * @return The next update calendar of the current TSL. <code>null</code> if not is defined.
     */
    protected abstract Calendar getTSLNextUpdateCalendar();

    /**
     * Sets the TSL Distribution Points in the scheme information.
     * @throws TSLParsingException In case of some error parsing the issue date.
     */
    private void buildSchemeInformationDistributionPoints() throws TSLParsingException {

	String[ ] tdp = getTSLDistributionPointsString();
	if (tdp != null) {
	    for (int index = 0; index < tdp.length; index++) {
		try {
		    tsl.getSchemeInformation().addNewDistributionPoint(new URI(tdp[index]));
		} catch (URISyntaxException e) {
		    throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.ATB_LOG007, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_DISTRIBUTION_POINTS }));
		}
	    }
	}

    }

    /**
     * Gets the URI string declared how distribution points of the current TSL.
     * @return array of URI string with the URI declared how distribution points of the current TSL.
     * <code>null</code> if there is not defined.
     */
    protected abstract String[ ] getTSLDistributionPointsString();

    /**
     * Sets the Scheme Information Extensions in the scheme information.
     * @throws TSLParsingException In case of some error parsing the extensions.
     */
    private void buildSchemeInformationExtensions() throws TSLParsingException {

	List<IAnyTypeExtension> extensions = getSchemeInformationExtensions();
	if (extensions != null && !extensions.isEmpty()) {
	    for (IAnyTypeExtension extension: extensions) {
		tsl.getSchemeInformation().addNewSchemeInformationExtension(extension);
	    }
	}

    }

    /**
     * Gets the Scheme Information Extensions of the current TSL.
     * @return List with the parsed extensions for the Scheme Information.
     * @throws TSLParsingException In case of some error parsing the extensions.
     */
    protected abstract List<IAnyTypeExtension> getSchemeInformationExtensions() throws TSLParsingException;

    /**
     * Builds an extension representation from a XML node with the knows extensions
     * for the current specification and version.
     * @param node XML node that contains and from which builds the extension representation.
     * @param isCritical represents if this extension is marked how critical (<code>true</code>) or not (<code>false</code>).
     * @param extensionType represents the extension type, refers to its location inside the XML.
     * It could be one of the following:
     * <ul>
     * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SCHEME}</li>
     * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_TSP_INFORMATION}</li>
     * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SERVICE_INFORMATION}</li>
     * </ul>
     * @return Extension object representation.
     * @throws TSLParsingException In case of some error building a extension.
     */
    protected abstract IAnyTypeExtension buildExtensionFromNode(Node node, boolean isCritical, int extensionType) throws TSLParsingException;

    /**
     * Builds an Other Criteria representation from a XML node with the knows Other Criteria Types
     * for the current specification and version.
     * @param node XML node that contains and from which builds the other criteria representation.
     * @return Other criteria object representation.
     * @throws TSLParsingException In case of some error building the other criteria.
     */
    protected abstract IAnyTypeOtherCriteria buildOtherCriteriaFromNode(Node node) throws TSLParsingException;

    /**
     * Sets all the TSP list from the parsed XML.
     * @throws TSLParsingException In case of some error getting the values.
     */
    private void buildTSLlistTSP() throws TSLParsingException {

	// Obtenemos el número de prestadores existentes en la TSL.
	int tspNumber = getTSLlistTSPsize();

	// Los recorremos y vamos construyendo uno a uno.
	for (int index = 0; index < tspNumber; index++) {
	    try {
		tsl.addNewTrustServiceProvider(buildTSP(index));
	    } catch (TSLArgumentException e) {
		throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.ATB_LOG004, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TRUST_SERVICE_PROVIDER }), e);
	    }
	}

    }

    /**
     * Gets the number of TSP declared on this TSL.
     * @return the number of TSP declared on this TSL. 0 if not is declared
     * the TSP List.
     */
    protected abstract int getTSLlistTSPsize();

    /**
     * Sets a Trust Service Provider object representation equivalent to the
     * TSP listed in a specific position.
     * @param pos Position on the TSP list.
     * @return Trust Service Provider Object representation.
     * @throws TSLParsingException In case of some error getting the values.
     */
    private TrustServiceProvider buildTSP(int pos) throws TSLParsingException {

	TrustServiceProvider tsp = new TrustServiceProvider();

	// Obtenemos la información del TSP.
	tsp.setTspInformation(buildTSPInformation(pos));

	// Obtenemos la lista de servicios asociada.
	buildTspServiceList(pos, tsp);

	return tsp;

    }

    /**
     * Sets a Trust Service Provider Information representation equivalent to the
     * TSP Information listed in a specific position.
     * @param pos Position on the TSP list.
     * @return Trust Service Provider Information Object representation.
     * @throws TSLParsingException In case of some error getting the values.
     */
    private TSPInformation buildTSPInformation(int pos) throws TSLParsingException {

	TSPInformation tspInformation = new TSPInformation();

	// Se establecen los nombres del TSP.
	buildTSPInformationNames(pos, tspInformation);
	// Se establecen los nombres de marca (trade).
	buildTSPInformationTradeNames(pos, tspInformation);
	// Se establece la dirección.
	buildTSPInformationAddress(pos, tspInformation);
	// Se establecen las URI informativas.
	buildTSPInformationURIWithExceptions(pos, tspInformation);
	// Se establecen las extensiones.
	buildTSPInformationExtensions(pos, tspInformation);

	return tspInformation;

    }

    /**
     * Sets all the names for the TSP at the position specified.
     * @param pos Position on the TSP list.
     * @param tspInformation TSP Information where to add the names.
     */
    protected abstract void buildTSPInformationNames(int pos, TSPInformation tspInformation);

    /**
     * Sets all the trade names for the TSP at the position specified.
     * @param pos Position on the TSP list.
     * @param tspInformation TSP Information where to add the trade names.
     */
    protected abstract void buildTSPInformationTradeNames(int pos, TSPInformation tspInformation);

    /**
     * Sets all the information address for the TSP at the position specified.
     * @param pos Position on the TSP list.
     * @param tspInformation TSP Information where to add the address.
     * @throws TSLParsingException In case of some error getting the values.
     */
    private void buildTSPInformationAddress(int pos, TSPInformation tspInformation) throws TSLParsingException {

	Map<String, List<PostalAddress>> postalAddresses = getTSPInformationPostalAddresses(pos);
	Map<String, List<String>> electronicAddresses = getTSPInformationElectronicAddresses(pos);
	Address tspAddress = tspInformation.getTspAddress();

	if (postalAddresses != null) {
	    tspAddress.setPostalAddresses(postalAddresses);
	}

	Map<String, List<URI>> electronicAddressesURI = null;
	if (electronicAddresses != null) {
	    electronicAddressesURI = new HashMap<String, List<URI>>();
	    Set<String> keys = electronicAddresses.keySet();
	    for (String key: keys) {
		List<URI> uriList = new ArrayList<URI>();
		List<String> uriStringList = electronicAddresses.get(key);
		for (String uriString: uriStringList) {
		    try {
			uriList.add(new URI(uriString));
		    } catch (URISyntaxException e1) {
			// En caso de no parsearse, tratamos de eliminarle los
			// espacios en blanco que pudiera contener.
			try {
			    uriList.add(new URI(uriString.replaceAll("\\s+", UtilsStringChar.EMPTY_STRING)));
			    LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.ATB_LOG008, new Object[ ] { uriString }));
			} catch (URISyntaxException e2) {
			    throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.ATB_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPINFORMATION_ADDRESS }), e1);
			}
		    }
		}
		electronicAddressesURI.put(key, uriList);
	    }
	} else {
	    electronicAddressesURI = new HashMap<String, List<URI>>();
	}
	tspAddress.setElectronicAddresses(electronicAddressesURI);

    }

    /**
     * Gets the TSP postal addresses in all the presented languages.
     * @param pos Position on the TSP list.
     * @return map with the TSP postal addresses in all presented languages:
     * - Map<Language, List<PostalAddress>>.
     * - <code>null</code> if not is defined.
     */
    protected abstract Map<String, List<PostalAddress>> getTSPInformationPostalAddresses(int pos);

    /**
     * Gets the TSP electronic addresses of in all the presented languages.
     * @param pos Position on the TSP list.
     * @return map with the TSP electronic addresses in all presented languages:
     * - Map<Language, ElectronicAddresses>.
     * - <code>null</code> if not is defined.
     */
    protected abstract Map<String, List<String>> getTSPInformationElectronicAddresses(int pos);

    /**
     * Sets all the information URI for the TSP at the position specified.
     * @param pos Position on the TSP list.
     * @param tspInformation TSP Information where to add the URI.
     * @throws TSLParsingException In case of some error parsing the URI.
     */
    private void buildTSPInformationURIWithExceptions(int pos, TSPInformation tspInformation) throws TSLParsingException {

	try {
	    buildTSPInformationURI(pos, tspInformation);
	} catch (URISyntaxException e) {
	    throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.ATB_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPINFORMATION_URI }), e);
	}

    }

    /**
     * Sets all the information URI for the TSP at the position specified.
     * @param pos Position on the TSP list.
     * @param tspInformation TSP Information where to add the URI.
     * @throws URISyntaxException In case of some error getting the values.
     */
    protected abstract void buildTSPInformationURI(int pos, TSPInformation tspInformation) throws URISyntaxException;

    /**
     * Sets all the information extensions for the TSP at the position specified.
     * @param pos Position on the TSP list.
     * @param tspInformation TSP Information where to add the extensions.
     * @throws TSLParsingException In case of some error parsing the extensions.
     */
    private void buildTSPInformationExtensions(int pos, TSPInformation tspInformation) throws TSLParsingException {

	List<IAnyTypeExtension> extensions = getTSPInformationExtensions(pos);
	if (extensions != null && !extensions.isEmpty()) {
	    for (IAnyTypeExtension extension: extensions) {
		tspInformation.addNewTSPInformationExtension(extension);
	    }
	}

    }

    /**
     * Gets the TSP Information Extensions of the current TSL.
     * @param pos Position on the TSP list.
     * @return List with the parsed extensions for the TSP Information.
     * @throws TSLParsingException In case of some error parsing the extensions.
     */
    protected abstract List<IAnyTypeExtension> getTSPInformationExtensions(int pos) throws TSLParsingException;

    /**
     * Sets all the Service List for the TSP at the position specified.
     * @param pos Position on the TSP list.
     * @param tsp Trust Service Provider where to add the Service List.
     * @throws TSLParsingException In case of some error parsing the services.
     */
    private void buildTspServiceList(int pos, TrustServiceProvider tsp) throws TSLParsingException {

	int serviceListSize = getTSPServiceListSize(pos);

	for (int index = 0; index < serviceListSize; index++) {
	    tsp.addNewTSPService(buildTSPService(pos, index));
	}

    }

    /**
     * Gets the number of the Services declared in a specific TSP on this TSL.
     * @param pos Position on the TSP list.
     * @return the number of the Services declared in a specific TSP on this TSL.
     */
    protected abstract int getTSPServiceListSize(int pos);

    /**
     * Builds a new TSP Service from the specified TSP and Service (positions).
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @return New TSP Service with all the data collected.
     * @throws TSLParsingException  In case of some error parsing the service data.
     */
    private TSPService buildTSPService(int posTSP, int posService) throws TSLParsingException {

	TSPService tspService = new TSPService();

	// Establecemos la información del servicio.
	buildTSPServiceInformation(posTSP, posService, tspService.getServiceInformation());

	// Establecemos la información histórica si es que la hubiera.
	int serviceHistoryInstSize = getTSPServiceHistoryInstanceSize(posTSP, posService);
	if (serviceHistoryInstSize > 0) {
	    for (int index = 0; index < serviceHistoryInstSize; index++) {
		tspService.addNewServiceHistory(buildTSPServiceHistoryInstance(posTSP, posService, index));
	    }
	}

	return tspService;

    }

    /**
     * Sets the values of TSP Service Information from the specified TSP and Service (positions).
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @param servInf Service Information to be modified.
     * @throws TSLParsingException  In case of some error parsing the service information data.
     */
    private void buildTSPServiceInformation(int posTSP, int posService, ServiceInformation servInf) throws TSLParsingException {

	// Establecemos el tipo de servicio.
	try {
	    servInf.setServiceTypeIdentifier(new URI(getTSPServiceInformationType(posTSP, posService)));
	} catch (URISyntaxException e) {
	    throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.ATB_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_TYPE }), e);
	}
	// Establecemos el nombre del servicio.
	buildTSPServiceInformationName(posTSP, posService, servInf);
	// Establecemos las identidades del servicio.
	buildTSPServiceInformationIdentities(posTSP, posService, servInf);
	// Establecemos el estado del servicio.
	try {
	    servInf.setServiceStatus(new URI(getTSPServiceInformationStatus(posTSP, posService)));
	} catch (URISyntaxException e) {
	    throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.ATB_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_STATUS }), e);
	}
	// Establecemos la fecha de inicio del servicio.
	servInf.setServiceStatusStartingTime(getTSPServiceInformationStatusStartingDateAndTime(posTSP, posService));
	// Establecemos las URIs de definición del servicio.
	buildTSPServiceInformationSchemeDefinitionURI(posTSP, posService, servInf);
	// Establecemos los puntos de distribución del servicio.
	buildTSPServiceInformationServiceSupplyPoints(posTSP, posService, servInf);
	// Establecemos las URI de definición de servicios del TSP.
	buildTSPServiceInformationDefinitionURI(posTSP, posService, servInf);
	// Establecemos las extensiones del servicio.
	buildTSPServiceInformationExtensions(posTSP, posService, servInf);

    }

    /**
     * Gets the Service Information Type for the TSP Service specified by positions.
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @return String representation of the URI Service Type.
     */
    protected abstract String getTSPServiceInformationType(int posTSP, int posService);

    /**
     * Sets the Service Information Name for the TSP Service specified by positions.
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @param servInf Service Information to be modified.
     */
    protected abstract void buildTSPServiceInformationName(int posTSP, int posService, ServiceInformation servInf);

    /**
     * Sets all the Service Idewntities for the TSP and Service specified by positions.
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @param servInf Service Information to be modified.
     * @throws TSLParsingException In case of some error parsing the service information data.
     */
    protected abstract void buildTSPServiceInformationIdentities(int posTSP, int posService, ServiceInformation servInf) throws TSLParsingException;

    /**
     * Gets the Service Information Status for the TSP Service specified by positions.
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @return String representation of the URI Service Status.
     */
    protected abstract String getTSPServiceInformationStatus(int posTSP, int posService);

    /**
     * Gets the Service Information Status Starting Date and Time for the TSP Service specified by positions.
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @return Date representation of the Service Status Starting Date and Time.
     */
    protected abstract Date getTSPServiceInformationStatusStartingDateAndTime(int posTSP, int posService);

    /**
     * Sets the Service Information Scheme Definition URI for the TSP Service specified by positions.
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @param servInf Service Information to be modified.
     * @throws TSLParsingException In case of some error parsing the service information data.
     */
    protected abstract void buildTSPServiceInformationSchemeDefinitionURI(int posTSP, int posService, ServiceInformation servInf) throws TSLParsingException;

    /**
     * Sets the Service Information Service Supply Points for the TSP Service specified by positions.
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @param servInf Service Information to be modified.
     * @throws TSLParsingException In case of some error parsing the service information data.
     */
    protected abstract void buildTSPServiceInformationServiceSupplyPoints(int posTSP, int posService, ServiceInformation servInf) throws TSLParsingException;

    /**
     * Sets the Service Information Definition URI for the TSP Service specified by positions.
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @param servInf Service Information to be modified.
     * @throws TSLParsingException In case of some error parsing the service information data.
     */
    protected abstract void buildTSPServiceInformationDefinitionURI(int posTSP, int posService, ServiceInformation servInf) throws TSLParsingException;

    /**
     * Sets the Service Information Extensions for the TSP Service specified by positions.
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @param servInf Service Information to be modified.
     * @throws TSLParsingException In case of some error parsing the service information data.
     */
    private void buildTSPServiceInformationExtensions(int posTSP, int posService, ServiceInformation servInf) throws TSLParsingException {

	List<IAnyTypeExtension> extensions = getTSPServiceInformationExtensions(posTSP, posService);
	if (extensions != null && !extensions.isEmpty()) {
	    for (IAnyTypeExtension extension: extensions) {
		servInf.addNewServiceInformationExtension(extension);
	    }
	}

    }

    /**
     * Gets the TSP Service Information Extensions of the current TSL.
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @return List with the parsed extensions for the TSP Service Information.
     * @throws TSLParsingException In case of some error parsing the extensions.
     */
    protected abstract List<IAnyTypeExtension> getTSPServiceInformationExtensions(int posTSP, int posService) throws TSLParsingException;

    /**
     * Gets the number of the History Instances for the TSP and service specified (by position).
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @return the number of the History Instances for the TSP and service specified (by position).
     */
    protected abstract int getTSPServiceHistoryInstanceSize(int posTSP, int posService);

    /**
     * Sets the history instances for a specific TSP Service (specified by positions).
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @param posHistory Position of the Service History Instance in its list.
     * @return New TSP Service History Instance with all the data collected.
     * @throws TSLParsingException In case of some error parsing the service information data.
     */
    private ServiceHistoryInstance buildTSPServiceHistoryInstance(int posTSP, int posService, int posHistory) throws TSLParsingException {

	ServiceHistoryInstance shi = new ServiceHistoryInstance();

	// Establecemos el tipo de servicio.
	try {
	    shi.setServiceTypeIdentifier(new URI(getTSPServiceHistoryType(posTSP, posService, posHistory)));
	} catch (URISyntaxException e) {
	    throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.ATB_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_HISTORY_TYPE }), e);
	}
	// Establecemos el nombre del servicio.
	buildTSPServiceHistoryName(posTSP, posService, posHistory, shi);
	// Establecemos las identidades del servicio.
	buildTSPServiceHistoryIdentities(posTSP, posService, posHistory, shi);
	// Establecemos el estado del servicio.
	try {
	    shi.setServiceStatus(new URI(getTSPServiceHistoryStatus(posTSP, posService, posHistory)));
	} catch (URISyntaxException e) {
	    throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.ATB_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_STATUS }), e);
	}
	// Establecemos la fecha de inicio del servicio.
	shi.setServiceStatusStartingTime(getTSPServiceHistoryStatusStartingDateAndTime(posTSP, posService, posHistory));
	// Establecemos las extensiones del servicio.
	buildTSPServiceHistoryExtensions(posTSP, posService, posHistory, shi);

	return shi;

    }

    /**
     * Gets the Service History Type for the TSP Service History Instance specified by positions.
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @param posHistory Position of the Service History Instance in its list.
     * @return String representation of the URI Service History Type.
     */
    protected abstract String getTSPServiceHistoryType(int posTSP, int posService, int posHistory);

    /**
     * Sets the Service History Name for the TSP Service History Instance specified by positions.
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @param posHistory Position of the Service History Instance in its list.
     * @param shi Service History Instance to be modified.
     */
    protected abstract void buildTSPServiceHistoryName(int posTSP, int posService, int posHistory, ServiceHistoryInstance shi);

    /**
     * Sets all the Service History Identities for the TSP and Service History specified by positions.
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @param posHistory Position of the Service History Instance in its list.
     * @param shi Service History Instance to be modified.
     * @throws TSLParsingException In case of some error parsing the service hisotry instance data.
     */
    protected abstract void buildTSPServiceHistoryIdentities(int posTSP, int posService, int posHistory, ServiceHistoryInstance shi) throws TSLParsingException;

    /**
     * Gets the Service History Status for the TSP Service History Instance specified by positions.
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @param posHistory Position of the Service History Instance in its list.
     * @return String representation of the URI Service History Status.
     */
    protected abstract String getTSPServiceHistoryStatus(int posTSP, int posService, int posHistory);

    /**
     * Gets the Service History Status Starting Date and Time for the TSP Service History Instance specified by positions.
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @param posHistory Position of the Service History Instance in its list.
     * @return Date representation of the Service History Status Starting Date and Time.
     */
    protected abstract Date getTSPServiceHistoryStatusStartingDateAndTime(int posTSP, int posService, int posHistory);

    /**
     * Gets the TSP Service History Extensions of the current TSL.
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @param posHistory Position of the Service History Instance in its list.
     * @param shi Service History Instance to modify.
     * @throws TSLParsingException In case of some error parsing the extensions.
     */
    private void buildTSPServiceHistoryExtensions(int posTSP, int posService, int posHistory, ServiceHistoryInstance shi) throws TSLParsingException {

	List<IAnyTypeExtension> extensions = getTSPServiceHistoryExtensions(posTSP, posService, posHistory);
	if (extensions != null && !extensions.isEmpty()) {
	    for (IAnyTypeExtension extension: extensions) {
		shi.addNewServiceInformationExtension(extension);
	    }
	}

    }

    /**
     * Gets the TSP Service History Extensions of the current TSL.
     * @param posTSP Position of the TSP in its list.
     * @param posService Position of the TSP Service in its list.
     * @param posHistory Position of the Service History Instance in its list.
     * @return List with the parsed extensions for the TSP Service Information.
     * @throws TSLParsingException In case of some error parsing the extensions.
     */
    protected abstract List<IAnyTypeExtension> getTSPServiceHistoryExtensions(int posTSP, int posService, int posHistory) throws TSLParsingException;

    /**
     * Build and return an Unknown Extension from the XML node.
     * @param nodeName XML node name.
     * @param isCritical Flag that indicates if the extension is critical (<code>true</code>) or not (<code>false</code>).
     * @param extensionType represents the extension type, refers to its location inside the XML.
     * @return Unknown Extension object representation builded.
     */
    protected final IAnyTypeExtension buildUnknownExtension(String nodeName, boolean isCritical, int extensionType) {
	return new UnknownExtension(isCritical, extensionType, nodeName);
    }

    /**
     * Build and set the TSL Signature.
     * @throws TSLParsingException In case of some error parsing the TSL signature.
     */
    private void buildTSLSignature() throws TSLParsingException {

	tsl.setSignature(getTSLSignature());

    }

    /**
     * Gets the TSL Signature.
     * @return TSL signature, or <code>null</code> if it does not exist.
     * @throws TSLParsingException In case of some error parsing the TSL signature.
     */
    protected abstract SignatureType getTSLSignature() throws TSLParsingException;

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
    protected <T> T getDocumentBuildingNewSchemeTypeLoader(InputStream is, Node node, Class<T> classDocument) throws TSLParsingException {

	try {

	    SchemaType sts = (SchemaType) classDocument.getDeclaredField(SCHEME_TYPE_FIELD_NAME).get(null);
	    SchemaTypeLoader stl = XmlBeans.typeLoaderUnion(new SchemaTypeLoader[ ] { sts.getTypeSystem(), XmlBeans.getContextTypeLoader() });
	    if (is != null) {
		return classDocument.cast(stl.parse(is, sts, null));
	    } else {
		return classDocument.cast(stl.parse(node, sts, null));
	    }

	} catch (Exception e) {
	    throw new TSLParsingException(Language.getResIntegraTsl(ILogTslConstant.ATB_LOG009), e);
	} finally {
	    UtilsResourcesCommons.safeCloseInputStream(is);
	}

    }

    /**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.ifaces.ITSLBuilder#buildXMLfromTSL()
	 */
	@Override
	public final byte[ ] buildXMLfromTSL() throws TSLEncodingException {
		// TODO En principio este método se terminará eliminando de la interfaz
		// al no tener sentido que la plataforma genere TSL, ya que por
		// definición,
		// una TSL debe emitirla un país/región de forma única, y debe estar
		// firmada por
		// un certificado único y concreto.
		return null;
	}

}
