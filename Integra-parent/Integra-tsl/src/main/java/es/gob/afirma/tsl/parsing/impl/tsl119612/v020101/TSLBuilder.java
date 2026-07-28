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
 * <b>File:</b><p>es.gob.afirma.tsl.access.TSLManager.java.</p>
 * <b>Description:</b><p>Class that represents a TSL Builder of TSL implementation as the
 * ETSI TS 119612 2.1.1 specification.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.2, 18/04/2022.
 */
package es.gob.afirma.tsl.parsing.impl.tsl119612.v020101;

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

import es.gob.afirma.tsl.logger.Logger;
import org.etsi.uri.x01903.v13.IdentifierType;
import org.etsi.uri.x01903.v13.ObjectIdentifierType;
import org.etsi.uri.x01903.v13.QualifierType;
import org.w3.x2000.x09.xmldsig.SignatureType;
import org.w3c.dom.Node;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.exceptions.TSLParsingException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.parsing.ifaces.IAnyTypeExtension;
import es.gob.afirma.tsl.parsing.ifaces.IAnyTypeOtherCriteria;
import es.gob.afirma.tsl.parsing.ifaces.ITSLCommonURIs;
import es.gob.afirma.tsl.parsing.ifaces.ITSLElementsAndAttributes;
import es.gob.afirma.tsl.parsing.ifaces.ITSLOIDs;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.ifaces.ITSLSpecificationsVersions;
import es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder;
import es.gob.afirma.tsl.parsing.impl.common.CertSubjectDNAttributeOtherCriteria;
import es.gob.afirma.tsl.parsing.impl.common.DigitalID;
import es.gob.afirma.tsl.parsing.impl.common.ExtendedKeyUsageOtherCriteria;
import es.gob.afirma.tsl.parsing.impl.common.PostalAddress;
import es.gob.afirma.tsl.parsing.impl.common.ServiceDigitalIdentity;
import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;
import es.gob.afirma.tsl.parsing.impl.common.ServiceInformation;
import es.gob.afirma.tsl.parsing.impl.common.TSLPointer;
import es.gob.afirma.tsl.parsing.impl.common.TSPInformation;
import es.gob.afirma.tsl.parsing.impl.common.UnknownOtherCriteria;
import es.gob.afirma.tsl.parsing.impl.common.extensions.CriteriaList;
import es.gob.afirma.tsl.parsing.impl.common.extensions.ExpiredCertsRevocationInfo;
import es.gob.afirma.tsl.parsing.impl.common.extensions.KeyUsage;
import es.gob.afirma.tsl.parsing.impl.common.extensions.KeyUsageBit;
import es.gob.afirma.tsl.parsing.impl.common.extensions.PoliciesList;
import es.gob.afirma.tsl.parsing.impl.common.extensions.QualificationElement;
import es.gob.afirma.tsl.parsing.impl.common.extensions.Qualifications;
import es.gob.afirma.tsl.parsing.impl.common.extensions.TakenOverBy;
import es.gob.afirma.tsl.utils.UtilsStringChar;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.AdditionalServiceInformationDocument;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.AdditionalServiceInformationType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.AddressType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.DigitalIdentityListType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.DigitalIdentityType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.ElectronicAddressType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.ExpiredCertsRevocationInfoDocument;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.ExtensionType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.ExtensionsListType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.InternationalNamesType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.MultiLangNormStringType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.MultiLangStringType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.NonEmptyMultiLangURIListType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.NonEmptyMultiLangURIType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.NonEmptyURIListType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.OtherTSLPointerType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.OtherTSLPointersType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.PolicyOrLegalnoticeType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.PostalAddressType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.ServiceDigitalIdentityListType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.ServiceHistoryInstanceType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.TSPInformationType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.TSPServiceInformationType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.TSPServiceType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.TSPType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.TrustServiceProviderListType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.TrustServiceStatusListDocument;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.TrustStatusListType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.additionalTypes.CertSubjectDNAttributeDocument;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.additionalTypes.CertSubjectDNAttributeType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.additionalTypes.ExtendedKeyUsageDocument;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.additionalTypes.ExtendedKeyUsageType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.additionalTypes.TakenOverByDocument;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.additionalTypes.TakenOverByType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.sie.CriteriaListType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.sie.KeyUsageBitType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.sie.KeyUsageType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.sie.PoliciesListType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.sie.QualificationElementType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.sie.QualificationsDocument;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.sie.QualificationsType;
import es.gob.afirma.xmlbeans.v230.tsl.r119612v020101.sie.QualifiersType;
/**
 * <p>Class that represents a TSL Builder of TSL implementation as the
 * ETSI TS 119612 2.1.1 specification.</p>
 * <b>Project:</b><p>Platform for detection and validation of certificates recognized in European TSL.</p>
 * @version 1.2, 18/04/2022.
 */
public class TSLBuilder extends ATSLBuilder {

	/**
	 * Attribute that represents the object that manages the log of the class.
	 */
	private static final Logger LOGGER = Logger.getLogger(TSLBuilder.class);

	/**
	 * Attribute that represents the content of the parsed TSL.
	 */
	private TrustStatusListType tsl = null;

	/**
	 * Constructor method for the class TSLBuilder.java.
	 * @param tslObject TSL Object representation to manage with this builder.
	 */
	public TSLBuilder(ITSLObject tslObject) {
		super(tslObject);
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#parseXMLInputStream(java.io.InputStream)
	 */
	@Override
	protected void parseXMLInputStream(InputStream is) throws TSLParsingException {
		tsl = getDocumentBuildingNewSchemeTypeLoader(is, null, TrustServiceStatusListDocument.class).getTrustServiceStatusList();
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSLTagString()
	 */
	@Override
	protected String getTSLTagString() {
		return tsl.getTSLTag();
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSLID()
	 */
	@Override
	protected String getTSLID() {
		return tsl.getId();
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getSchemeInformationTSLVersionIdentifier()
	 */
	@Override
	protected BigInteger getSchemeInformationTSLVersionIdentifier() {
		return tsl.getSchemeInformation().getTSLVersionIdentifier();
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getSchemeInformationTSLSequenceNumber()
	 */
	@Override
	protected BigInteger getSchemeInformationTSLSequenceNumber() {
		return tsl.getSchemeInformation().getTSLSequenceNumber();
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSLType()
	 */
	@Override
	protected String getTSLType() {
		return tsl.getSchemeInformation().getTSLType();
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSLSchemeOperatorNamesMap()
	 */
	@Override
	protected Map<String, List<String>> getTSLSchemeOperatorNamesMap() {

		Map<String, List<String>> result = null;

		InternationalNamesType intNames = tsl.getSchemeInformation().getSchemeOperatorName();
		if (intNames != null && intNames.sizeOfNameArray() > 0) {
			result = new HashMap<String, List<String>>();
			MultiLangNormStringType[ ] arrayNames = intNames.getNameArray();
			for (MultiLangNormStringType name: arrayNames) {
				List<String> namesList = result.get(name.getLang());
				if (namesList == null) {
					namesList = new ArrayList<String>();
					result.put(name.getLang(), namesList);
				}
				namesList.add(name.getStringValue());
			}
		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSLSCOPostalAdresses()
	 */
	@Override
	protected Map<String, List<PostalAddress>> getTSLSCOPostalAdresses() {

		AddressType addresses = tsl.getSchemeInformation().getSchemeOperatorAddress();
		return getPostalAddresses(addresses);

	}

	/**
	 * Gets the addresses in all the presented languages from the input parameter.
	 * @param addresses Address type object for this specification and version that must be analyzed.
	 * @return map with the postal addresses in all presented languages:
	 * - Map<Language, List<PostalAddress>>
	 * - <code>null</code> if not is defined.
	 */
	private Map<String, List<PostalAddress>> getPostalAddresses(AddressType addresses) {

		Map<String, List<PostalAddress>> result = null;
		if (addresses != null && addresses.getPostalAddresses() != null && addresses.getPostalAddresses().sizeOfPostalAddressArray() > 0) {

			PostalAddressType[ ] postalAddresses = addresses.getPostalAddresses().getPostalAddressArray();
			result = new HashMap<String, List<PostalAddress>>();
			for (PostalAddressType postalAddress: postalAddresses) {

				List<PostalAddress> paList = result.get(postalAddress.getLang());
				if (paList == null) {
					paList = new ArrayList<PostalAddress>();
				}
				PostalAddress pa = new PostalAddress(postalAddress.getStreetAddress(), postalAddress.getLocality(), postalAddress.getStateOrProvince(), postalAddress.getPostalCode(), postalAddress.getCountryName());
				paList.add(pa);
				result.put(postalAddress.getLang(), paList);

			}

		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSLSCOElectronicAddresses()
	 */
	@Override
	protected Map<String, List<String>> getTSLSCOElectronicAddresses() {

		AddressType addresses = tsl.getSchemeInformation().getSchemeOperatorAddress();
		return getElectronicAddresses(addresses);

	}

	/**
	 * Gets the electronic addresses in all the presented languages.
	 * @param addresses Address type object for this specification and version that must be analyzed.
	 * @return map with the electronic addresses in all presented languages:
	 * - Map<Language, ElectronicAddresses>.
	 * - <code>null</code> if not is defined.
	 */
	private Map<String, List<String>> getElectronicAddresses(AddressType addresses) {

		Map<String, List<String>> result = null;
		if (addresses != null && addresses.getElectronicAddress() != null && addresses.getElectronicAddress().sizeOfURIArray() > 0) {

			result = new HashMap<String, List<String>>();
			ElectronicAddressType ea = addresses.getElectronicAddress();
			for (int index = 0; index < ea.sizeOfURIArray(); index++) {

				NonEmptyMultiLangURIType eaUri = ea.getURIArray(index);
				List<String> uris = result.get(eaUri.getLang());
				if (uris == null) {
					uris = new ArrayList<String>();
				}
				uris.add(eaUri.getStringValue());
				result.put(eaUri.getLang(), uris);

			}

		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSLSchemeNameMap()
	 */
	@Override
	protected Map<String, String> getTSLSchemeNameMap() {

		Map<String, String> result = null;

		InternationalNamesType schemeNames = tsl.getSchemeInformation().getSchemeName();
		if (schemeNames != null && schemeNames.sizeOfNameArray() > 0) {

			result = new HashMap<String, String>();
			MultiLangNormStringType[ ] names = schemeNames.getNameArray();
			for (MultiLangNormStringType name: names) {

				result.put(name.getLang(), name.getStringValue());

			}

		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSLSchemeInformationURIMap()
	 */
	@Override
	protected Map<String, String> getTSLSchemeInformationURIMap() {

		Map<String, String> result = null;

		NonEmptyMultiLangURIListType schemeURIs = tsl.getSchemeInformation().getSchemeInformationURI();
		if (schemeURIs != null && schemeURIs.sizeOfURIArray() > 0) {

			result = new HashMap<String, String>();
			NonEmptyMultiLangURIType[ ] uris = schemeURIs.getURIArray();
			for (NonEmptyMultiLangURIType uri: uris) {

				result.put(uri.getLang(), uri.getStringValue());

			}

		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSLStatusDeterminationApproachString()
	 */
	@Override
	protected String getTSLStatusDeterminationApproachString() {

		String result = tsl.getSchemeInformation().getStatusDeterminationApproach();

		// Se ha decidido para poder soportar las TSL europeas (mal definidas),
		// que se interpreten
		// dos valores incorrectos que se están usando y se modifiquen por los
		// correctos de forma
		// dinámica (no en la TSL, sino en el objeto que la representa en
		// memoria).
		if (ITSLCommonURIs.TSL_STATUSDETAPPROACH_EUAPPROPIATE_INCORRECT.equals(result) || ITSLCommonURIs.TSL_STATUSDETAPPROACH_EULISTOFTHELISTS_INCORRECT.equals(result)) {
			LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.TB_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_STATUS_DETERMINATION_APPROACH, result, ITSLCommonURIs.TSL_STATUSDETAPPROACH_EUAPPROPIATE, ITSLSpecificationsVersions.SPECVERS_119612_020101 }));
			result = ITSLCommonURIs.TSL_STATUSDETAPPROACH_EUAPPROPIATE;
		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSLSchemeTypeCommunityRulesMap()
	 */
	@Override
	protected Map<String, List<String>> getTSLSchemeTypeCommunityRulesMap() {

		Map<String, List<String>> result = null;

		NonEmptyMultiLangURIListType uriList = tsl.getSchemeInformation().getSchemeTypeCommunityRules();
		if (uriList != null && uriList.sizeOfURIArray() > 0) {

			result = new HashMap<String, List<String>>();

			for (int index = 0; index < uriList.sizeOfURIArray(); index++) {

				NonEmptyMultiLangURIType uri = uriList.getURIArray(index);
				List<String> uris = result.get(uri.getLang());
				if (uris == null) {
					uris = new ArrayList<String>();
				}
				uris.add(uri.getStringValue());
				result.put(uri.getLang(), uris);

			}

		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getSchemeTerritory()
	 */
	@Override
	protected String getSchemeTerritory() throws TSLParsingException {
		return tsl.getSchemeInformation().getSchemeTerritory();
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSLPolicy()
	 */
	@Override
	protected Map<String, String> getTSLPolicy() {

		Map<String, String> result = null;

		PolicyOrLegalnoticeType poln = tsl.getSchemeInformation().getPolicyOrLegalNotice();
		if (poln != null) {
			NonEmptyMultiLangURIType[ ] policyUriArray = poln.getTSLPolicyArray();
			if (policyUriArray != null && policyUriArray.length > 0) {
				result = new HashMap<String, String>();
				for (NonEmptyMultiLangURIType policyUri: policyUriArray) {
					result.put(policyUri.getLang(), policyUri.getStringValue());
				}
			}
		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSLLegalNotice()
	 */
	@Override
	protected Map<String, String> getTSLLegalNotice() {

		Map<String, String> result = null;

		PolicyOrLegalnoticeType poln = tsl.getSchemeInformation().getPolicyOrLegalNotice();
		if (poln != null) {
			MultiLangStringType[ ] ln = poln.getTSLLegalNoticeArray();
			if (ln != null && ln.length > 0) {
				result = new HashMap<String, String>();
				for (MultiLangStringType legalNotice: ln) {
					result.put(legalNotice.getLang(), legalNotice.getStringValue());
				}
			}
		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSLHistoricalInformationPeriodBigInteger()
	 */
	@Override
	protected BigInteger getTSLHistoricalInformationPeriodBigInteger() {
		return tsl.getSchemeInformation().getHistoricalInformationPeriod();
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSLPointersToOthersTSL()
	 */
	@Override
	protected List<TSLPointer> getTSLPointersToOthersTSL() throws TSLParsingException {

		List<TSLPointer> result = null;

		OtherTSLPointersType tslPointers = tsl.getSchemeInformation().getPointersToOtherTSL();
		if (tslPointers != null && tslPointers.sizeOfOtherTSLPointerArray() > 0) {

			result = new ArrayList<TSLPointer>();
			OtherTSLPointerType[ ] tslPointersArray = tslPointers.getOtherTSLPointerArray();
			for (OtherTSLPointerType tslPointer: tslPointersArray) {
				result.add(buildTSLPointer(tslPointer));
			}

		}

		return result;

	}

	/**
	 * Private method that build a TSL Pointer from the information loaded.
	 * @param tslPointer XML TSL pointer representation.
	 * @return TSL pointer object representation no dependent from the specification or version.
	 * @throws TSLParsingException In case of some error parsing the TSL pointer.
	 */
	private TSLPointer buildTSLPointer(OtherTSLPointerType tslPointer) throws TSLParsingException {

		TSLPointer result = new TSLPointer(tslPointer.getTSLLocation());

		ServiceDigitalIdentityListType sdiList = tslPointer.getServiceDigitalIdentities();
		if (sdiList != null && sdiList.sizeOfServiceDigitalIdentityArray() > 0) {

			DigitalIdentityListType[ ] sdiArray = sdiList.getServiceDigitalIdentityArray();
			for (DigitalIdentityListType sdi: sdiArray) {
				if (sdi != null && sdi.sizeOfDigitalIdArray() > 0) {
					result.addNewServiceDigitalIdentity(buildServiceDigitalIdentity(sdi));
				}
			}

		}

		// TODO: Falta tratar el AdditionalInformation de cada TSLPointer.

		return result;

	}

	/**
	 * Private method that build a Service Digital Identity from the information loaded.
	 * @param sdi XML Service Digital Identity representation.
	 * @return Service Digital Identity object representation no dependent of the specification or version.
	 * @throws TSLParsingException In case of some error parsing the Service Digital Identity.
	 */
	private ServiceDigitalIdentity buildServiceDigitalIdentity(DigitalIdentityListType sdi) throws TSLParsingException {

		ServiceDigitalIdentity result = new ServiceDigitalIdentity();

		DigitalIdentityType[ ] diArray = sdi.getDigitalIdArray();
		for (DigitalIdentityType di: diArray) {
			result.addNewDigitalIdentity(buildDigitalID(di, false));
		}

		return result;

	}

	/**
	 * Private method that build a Digital Identity from the information loaded.
	 * @param di XML Digital Identity representation.
	 * @param isNoPKIorUnspecifiedService flag that indicates if the service is of type
	 * no PKI or a unspecified service.
	 * @return Digital Identity object representation no dependent of the specification or version.
	 * <code>null</code> if the input parameter is <code>null</code>.
	 * @throws TSLParsingException In case of some error parsing the Digital Identity.
	 */
	private DigitalID buildDigitalID(DigitalIdentityType di, boolean isNoPKIorUnspecifiedService) throws TSLParsingException {

		DigitalID result = null;

		if (di != null) {

			if (di.isSetX509Certificate()) {
				result = new DigitalID(DigitalID.TYPE_X509CERTIFICATE);
				result.setX509cert(di.getX509Certificate());
			} else if (di.isSetX509SubjectName()) {
				result = new DigitalID(DigitalID.TYPE_X509SUBJECTNAME);
				result.setX509SubjectName(di.getX509SubjectName());
			} else if (di.isSetKeyValue()) {
				result = new DigitalID(DigitalID.TYPE_KEYVALUE);
				result.setKeyValue(di.getKeyValue());
			} else if (di.isSetX509SKI()) {
				result = new DigitalID(DigitalID.TYPE_X509SKI);
				result.setSki(di.getX509SKI());
			} else if (di.isSetOther()) {
				result = new DigitalID(DigitalID.TYPE_OTHER);
				if (isNoPKIorUnspecifiedService) {
					result.setOther(searchFirstTextNodeValue(di.getOther().getDomNode()));
				} else {
					result.setOther(di.getOther().toString());
				}
			}

		}

		return result;

	}

	/**
	 * Search (in depth) the first text node value from the input node.
	 * @param node XML node from which starts the search.
	 * @return Text value of the first text node from the input node. <code>null</code> if
	 * there is no one.
	 */
	private String searchFirstTextNodeValue(Node node) {

		String result = null;

		if (node != null) {

			if (node.getNodeType() == Node.TEXT_NODE) {

				result = node.getNodeValue();

			} else {

				Node childNode = node.getFirstChild();
				result = searchFirstTextNodeValue(childNode);
				while (result == null && childNode.getNextSibling() != null) {
					childNode = childNode.getNextSibling();
					result = searchFirstTextNodeValue(childNode);
				}

			}

		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSLIssueDateCalendar()
	 */
	@Override
	protected Calendar getTSLIssueDateCalendar() {
		return tsl.getSchemeInformation().getListIssueDateTime();
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSLNextUpdateCalendar()
	 */
	@Override
	protected Calendar getTSLNextUpdateCalendar() {
		return tsl.getSchemeInformation().getNextUpdate().getDateTime();
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSLDistributionPointsString()
	 */
	@Override
	protected String[ ] getTSLDistributionPointsString() {

		String[ ] result = null;

		NonEmptyURIListType distribPoints = tsl.getSchemeInformation().getDistributionPoints();
		if (distribPoints != null) {
			result = distribPoints.getURIArray();
		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getSchemeInformationExtensions()
	 */
	@Override
	protected List<IAnyTypeExtension> getSchemeInformationExtensions() throws TSLParsingException {

		List<IAnyTypeExtension> result = null;

		ExtensionsListType elt = tsl.getSchemeInformation().getSchemeExtensions();
		if (elt != null && elt.sizeOfExtensionArray() > 0) {

			result = new ArrayList<IAnyTypeExtension>();
			for (int index = 0; index < elt.sizeOfExtensionArray(); index++) {

				ExtensionType et = elt.getExtensionArray(index);
				result.add(buildExtensionFromNode(et.getDomNode(), et.getCritical(), IAnyTypeExtension.TYPE_SCHEME));

			}

		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#buildExtensionFromNode(org.w3c.dom.Node, boolean, int)
	 */
	@Override
	protected IAnyTypeExtension buildExtensionFromNode(Node node, boolean isCritical, int extensionType) throws TSLParsingException {

		IAnyTypeExtension result = null;

		// Recorremos la lista de nodos hijos hasta encontrar el elemento a
		// analizar.
		Node childNode = node.getFirstChild();
		// Mientras no sea de tipo elemento y sea distinto de null, seguimos
		// buscando.
		while (childNode != null && childNode.getNodeType() != Node.ELEMENT_NODE) {
			childNode = childNode.getNextSibling();
		}

		// Establecemos el nombre del nodo por defecto.
		String localName = node.getLocalName();

		// Si lo hemos encontrado...
		if (childNode != null) {

			// Obtenemos su nombre local.
			localName = childNode.getLocalName();

			// Lo vamos comparando, y si alguno coincide con los reconocidos,
			// lo construimos.
			// Comprobamos si se trata de la extensión
			// AdditionalServiceInformation.
			if (ITSLElementsAndAttributes.ELEMENT_EXTENSION_ADDITIONALSERVICEINFORMATION_LOCALNAME.equalsIgnoreCase(localName)) {

				// Parseamos la extensión como AdditionalServiceInformation.
				result = buildAdditionalServiceInformationExtension(childNode, isCritical, extensionType);

			}
			// Comprobamos si se trata de la extensión
			// ExpiredCertsRevocationInfo.
			else if (ITSLElementsAndAttributes.ELEMENT_EXTENSION_EXPIREDCERTSREVOCATIONINFO_LOCALNAME.equalsIgnoreCase(localName)) {

				// Parseamos la extensión como ExpiredCertsRevocationInfo.
				result = buildExpiredCertsRevocationInfoExtension(childNode, isCritical, extensionType);

			}
			// Comprobamos si se trata de la extensión Qualifications.
			else if (ITSLElementsAndAttributes.ELEMENT_EXTENSION_QUALIFICATIONS_LOCALNAME.equalsIgnoreCase(localName)) {

				// Parseamos la extensión como Qualifications.
				result = buildQualificationsExtension(childNode, isCritical, extensionType);

			}
			// Comprobamos si se trata de la extensión TakenOverBy.
			else if (ITSLElementsAndAttributes.ELEMENT_EXTENSION_TAKENOVERBY_LOCALNAME.equalsIgnoreCase(localName)) {

				// Parseamos la extensión como Qualifications.
				result = buildTakenOverByExtension(childNode, isCritical, extensionType);

			}

		}

		// Si finalmente no hemos obtenido la extensión, la creamos como
		// desconocida.
		if (result == null) {
			result = buildUnknownExtension(localName, isCritical, extensionType);
		}

		return result;

	}

	/**
	 * Tries to build and return an AdditionalServiceInformation Extension from the XML node.
	 * @param node XML node to parse.
	 * @param isCritical Flag that indicates if the extension is critical (<code>true</code>) or not (<code>false</code>).
	 * @param extensionType represents the extension type, refers to its location inside the XML.
	 * @return AdditionalServiceInformation Extension object representation builded from the xml node. If not is possible
	 * to build, then returns <code>null</code>.
	 * @throws TSLParsingException In case of some error building an AdditionalServiceInformation Extension.
	 */
	private IAnyTypeExtension buildAdditionalServiceInformationExtension(Node node, boolean isCritical, int extensionType) throws TSLParsingException {

		AdditionalServiceInformation result = null;

		AdditionalServiceInformationType asit = null;
		try {
			asit = getDocumentBuildingNewSchemeTypeLoader(null, node, AdditionalServiceInformationDocument.class).getAdditionalServiceInformation();
		} catch (TSLParsingException e) {
			// Si se produce un error al parsear, es porque no se trata de este
			// tipo de extensión.
			return null;
		}

		String uriString = null;
		if (asit != null) {

			try {
				NonEmptyMultiLangURIType uri = asit.getURI();
				uriString = uri.getStringValue();
				URI asitUri = new URI(uriString);
				result = new AdditionalServiceInformation(asitUri, isCritical, extensionType);
				result.setInformationValue(asit.getInformationValue());
			} catch (URISyntaxException e) {
				throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.TB_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_ADDITIONALSERVICEINFORMATION_URI, uriString }));
			}

		}

		return result;

	}

	/**
	 * Tries to build and return an ExpiredCertsRevocationInfo Extension from the XML node.
	 * @param node XML node to parse.
	 * @param isCritical Flag that indicates if the extension is critical (<code>true</code>) or not (<code>false</code>).
	 * @param extensionType represents the extension type, refers to its location inside the XML.
	 * @return ExpiredCertsRevocationInfo Extension object representation builded from the xml node. If not is possible
	 * to build, then returns <code>null</code>.
	 */
	private IAnyTypeExtension buildExpiredCertsRevocationInfoExtension(Node node, boolean isCritical, int extensionType) {

		ExpiredCertsRevocationInfo result = null;

		try {
			ExpiredCertsRevocationInfoDocument ecri = getDocumentBuildingNewSchemeTypeLoader(null, node, ExpiredCertsRevocationInfoDocument.class);
			if (ecri != null) {
				result = new ExpiredCertsRevocationInfo(ecri.getExpiredCertsRevocationInfo().getTime(), isCritical, extensionType);
			}
		} catch (TSLParsingException e) {
			// Si se produce un error al parsear, es porque no se trata de este
			// tipo de extensión.
			return null;
		}

		return result;

	}

	/**
	 * Tries to build and return an Qualifications Extension from the XML node.
	 * @param node XML node to parse.
	 * @param isCritical Flag that indicates if the extension is critical (<code>true</code>) or not (<code>false</code>).
	 * @param extensionType represents the extension type, refers to its location inside the XML.
	 * @return Qualifications Extension object representation builded from the xml node. If not is possible
	 * to build, then returns <code>null</code>.
	 * @throws TSLParsingException In case of some error building an Qualifications Extension.
	 */
	private IAnyTypeExtension buildQualificationsExtension(Node node, boolean isCritical, int extensionType) throws TSLParsingException {

		Qualifications result = null;

		QualificationsType qt = null;
		try {
			qt = getDocumentBuildingNewSchemeTypeLoader(null, node, QualificationsDocument.class).getQualifications();
		} catch (TSLParsingException e) {
			// Si se ha producido un error al parsear, es que no es este tipo de
			// extensión.
			return null;
		}

		String qualifierUriString = null;
		// Si no ha fallado el parseo...
		if (qt != null) {
			// Inicializamos el objeto resultante y empezamos a construir el
			// genérico.
			result = new Qualifications(isCritical, extensionType);
			// Recorremos los QualificationsElement y los vamos creando.
			for (int index = 0; index < qt.sizeOfQualificationElementArray(); index++) {
				// Obtenemos el Qualification Element parseado.
				QualificationElementType qet = qt.getQualificationElementArray(index);
				// Inicializamos un nuevo objeto genérico QualificationElement.
				QualificationElement qe = new QualificationElement();
				// Parseamos los Qualifiers.
				QualifiersType qualifiersType = qet.getQualifiers();
				for (int subIndex = 0; subIndex < qualifiersType.sizeOfQualifierArray(); subIndex++) {
					qualifierUriString = qualifiersType.getQualifierArray(subIndex).getUri();
					try {
						URI qualifierUri = new URI(qualifierUriString);
						qe.addNewQualifier(qualifierUri);
					} catch (URISyntaxException e) {
						throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.TB_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_QUALIFICATION_QUALIFIER_URI, qualifierUriString }), e);
					}
				}
				// Parseamos los CriteriaList.
				CriteriaListType clt = qet.getCriteriaList();
				CriteriaList cl = qe.addNewCriteriaList(clt.getAssert().toString());
				setValuesOnCriteriaList(cl, clt);
				// Añadimos el Qualification Element creado.
				result.addNewQualificationElement(qe);
			}
		}

		return result;

	}

	/**
	 * Private method that parse and sets the values for the Criteria List extension element (recursive).
	 * @param cl Criteria List generic object representation (already created).
	 * @param clt Criteria List Object representation specific for ETSI TS 119612 2.1.1.
	 * @throws TSLParsingException In case of some error building the other criteria.
	 */
	private void setValuesOnCriteriaList(CriteriaList cl, CriteriaListType clt) throws TSLParsingException {

		// Parseamos los KeyUsage del CriteriaList.
		for (int index = 0; index < clt.sizeOfKeyUsageArray(); index++) {
			KeyUsageType kut = clt.getKeyUsageArray(index);
			KeyUsage ku = new KeyUsage();
			for (int subIndex = 0; subIndex < kut.sizeOfKeyUsageBitArray(); subIndex++) {
				KeyUsageBitType kubt = kut.getKeyUsageBitArray(subIndex);
				KeyUsageBit kub = new KeyUsageBit(kubt.getName().toString(), kubt.getBooleanValue());
				ku.addNewKeyUsageBit(kub);
			}
			cl.addNewKeyUsage(ku);
		}
		// Parseamos los PoliciesList del CriteriaList.
		for (int index = 0; index < clt.sizeOfPolicySetArray(); index++) {
			PoliciesListType plt = clt.getPolicySetArray(index);
			PoliciesList pl = new PoliciesList();
			for (int subIndex = 0; subIndex < plt.sizeOfPolicyIdentifierArray(); subIndex++) {
				IdentifierType it = plt.getPolicyIdentifierArray(subIndex).getIdentifier();
				String polIdentifier = getOIDfromIdentifierType(it);
				pl.addNewPolicyIdentifier(polIdentifier, PoliciesList.IDENTIFIER_OID_AS_UNSPECIFIED);
			}
			cl.addNewPolicySet(pl);
		}
		// Parseamos las Criteria List contenidas dentro de esta, y se las
		// asignamos.
		for (int index = 0; index < clt.sizeOfCriteriaListArray(); index++) {
			CriteriaListType subClt = clt.getCriteriaListArray(index);
			CriteriaList subCl = new CriteriaList(subClt.getAssert().toString());
			setValuesOnCriteriaList(subCl, subClt);
			cl.addNewCriteriaList(subCl);
		}
		// Parseamos la descripción.
		cl.setDescription(clt.getDescription());
		// Parseamos (si es que hay) el "otro criterio"
		if (clt.isSetOtherCriteriaList()) {
			cl.setOtherCriteria(buildOtherCriteriaFromNode(clt.getOtherCriteriaList().getDomNode()));
		}

	}

	/**
	 * Private method that extracts the OID string representation from a {@link IdentifierType} object.
	 * @param it Identifier Type object representation.
	 * @return OID string representation extracted from the input parameter.
	 */
	private String getOIDfromIdentifierType(IdentifierType it) {

		String result = null;

		// Por defecto consideramos que el tipo de OID es desconocido (valor 0).
		int oidRepresentationType = 0;
		// Si está definido el Qualifier que nos permite distinguir entre
		// OIDasURI y OIDasURN...
		if (it.isSetQualifier()) {

			// Lo recuperamos.
			oidRepresentationType = it.getQualifier().intValue();

		}

		// En función de su representación, obtenemos el OID en formato string.
		switch (oidRepresentationType) {
			case QualifierType.INT_OID_AS_URI:
				// TODO
				// De momento vamos a considerar que cuando viene en formato URI
				// es como si viniera el OID directamente, ya que no se han
				// encontrado casos de ejemplo.
				result = it.getStringValue();
				break;

			case QualifierType.INT_OID_AS_URN:
				result = getOIDfromOIDasURN(it.getStringValue());
				break;

			default:
				// En caso de no estar identificado el tipo, consideramos que
				// sea
				// de tipo URN, y si no, de tipo URI.
				result = getOIDfromOIDasURN(it.getStringValue());
				if (result == null) {
					result = it.getStringValue();
				}
				break;
		}

		return result;

	}

	/**
	 * Gets an OID from its representation as URN.
	 * @param oidAsURN OID as URN representation.
	 * @return OID in a string format.
	 */
	private String getOIDfromOIDasURN(String oidAsURN) {

		String result = null;

		if (oidAsURN != null && oidAsURN.length() > ITSLOIDs.TOKEN_URN_OID.length()) {

			String preffix = oidAsURN.substring(0, ITSLOIDs.TOKEN_URN_OID.length());
			if (ITSLOIDs.TOKEN_URN_OID.equalsIgnoreCase(preffix)) {
				result = oidAsURN.substring(ITSLOIDs.TOKEN_URN_OID.length(), oidAsURN.length());
			}

		}

		return result;

	}

	/**
	 * Tries to build and return an TakenOverBy Extension from the XML node.
	 * @param node XML node to parse.
	 * @param isCritical Flag that indicates if the extension is critical (<code>true</code>) or not (<code>false</code>).
	 * @param extensionType represents the extension type, refers to its location inside the XML.
	 * @return TakenOverBy Extension object representation builded from the xml node. If not is possible
	 * to build, then returns <code>null</code>.
	 * @throws TSLParsingException In case of some error building an AdditionalServiceInformation Extension.
	 */
	private IAnyTypeExtension buildTakenOverByExtension(Node node, boolean isCritical, int extensionType) throws TSLParsingException {

		TakenOverBy result = null;

		TakenOverByType tobt = null;
		try {
			tobt = getDocumentBuildingNewSchemeTypeLoader(null, node, TakenOverByDocument.class).getTakenOverBy();
		} catch (TSLParsingException e) {
			// Si se produce un error al parsear, es porque no se trata de este
			// tipo de extensión.
			return null;
		}

		if (tobt != null) {

			result = new TakenOverBy(isCritical, extensionType);

			String uriString = null;
			try {
				// Obtenemos la URI.
				NonEmptyMultiLangURIType uri = tobt.getURI();
				uriString = uri.getStringValue();
				URI tobUri = new URI(uriString);
				result.setUri(tobUri);
			} catch (URISyntaxException e) {
				throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.TB_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_TAKENOVERBY_URI, uriString }));
			}

			// Obtenemos los nombres del TSP y los asignamos.
			MultiLangNormStringType[ ] tspNames = tobt.getTSPName().getNameArray();
			for (MultiLangNormStringType tspName: tspNames) {
				result.addNewTSPName(tspName.getLang(), tspName.getStringValue());
			}

			// Obtenemos los nombres del esquema y los asignamos.
			MultiLangNormStringType[ ] schemeNames = tobt.getSchemeOperatorName().getNameArray();
			for (MultiLangNormStringType schemeName: schemeNames) {
				result.addNewSchemeOperatorName(schemeName.getLang(), schemeName.getStringValue());
			}

			// Obtenemos el territorio y lo asignamos.
			result.setSchemeTerritory(tobt.getSchemeTerritory());

		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#buildOtherCriteriaFromNode(org.w3c.dom.Node)
	 */
	@Override
	protected IAnyTypeOtherCriteria buildOtherCriteriaFromNode(Node node) throws TSLParsingException {

		IAnyTypeOtherCriteria result = null;

		// Recorremos la lista de nodos hijos hasta encontrar el elemento a
		// analizar.
		Node elementNode = node;
		// Mientras no sea de tipo elemento y sea distinto de null, seguimos
		// buscando.
		while (elementNode != null && elementNode.getNodeType() != Node.ELEMENT_NODE) {
			elementNode = elementNode.getNextSibling();
		}

		// Establecemos el nombre del nodo por defecto.
		String localName = UtilsStringChar.EMPTY_STRING;

		// Si lo hemos encontrado...
		if (elementNode != null) {

			// Establecemos el nombre del nodo por defecto.
			localName = elementNode.getLocalName();

			// Lo vamos comparando, y si alguno coincide con los reconocidos,
			// lo construimos.
			// Comprobamos si se trata del criterio ExtendedKeyUsage.
			if (ITSLElementsAndAttributes.ELEMENT_OTHER_CRITERIA_EXTENDEDKEYUSAGE_LOCALNAME.equalsIgnoreCase(localName)) {

				// Parseamos como ExtendedKeyUsage.
				result = buildExtendedKeyUsageOtherCriteria(elementNode);

			}
			// Comprobamos si se trata del criterio CertSubjectDNAttribute.
			else if (ITSLElementsAndAttributes.ELEMENT_OTHER_CRITERIA_CERTSUBJECTDNATTRIBUTE_LOCALNAME.equalsIgnoreCase(localName)) {

				// Parseamos como CertSubjectDNAttribute.
				result = buildCertSubjectDNAttributeOtherCriteria(elementNode);

			}

		}

		// Si finalmente no hemos obtenido el criterio, lo creamos como
		// desconocido.
		if (result == null) {
			result = buildUnknownOtherCriteria(localName);
		}

		return result;

	}

	/**
	 * Tries to build and return an ExtendedKeyUsage Criteria from the XML node.
	 * @param node XML node to parse.
	 * @return ExtendedKeyUsage Criteria object representation builded from the xml node. If not is possible
	 * to build, then returns <code>null</code>.
	 * @throws TSLParsingException In case of some error building an ExtendedKeyUsage Criteria.
	 */
	private IAnyTypeOtherCriteria buildExtendedKeyUsageOtherCriteria(Node node) throws TSLParsingException {

		ExtendedKeyUsageOtherCriteria result = null;

		ExtendedKeyUsageType ekut = null;
		try {
			ekut = getDocumentBuildingNewSchemeTypeLoader(null, node, ExtendedKeyUsageDocument.class).getExtendedKeyUsage();
		} catch (TSLParsingException e) {
			// Si se produce un error al parsear, es porque no se trata de este
			// tipo de extensión.
			return null;
		}

		// Una vez parseado inicializamos el objeto resultante.
		result = new ExtendedKeyUsageOtherCriteria();
		// Obtenemos el array con los identificadores.
		ObjectIdentifierType[ ] oitArray = ekut.getKeyPurposeIdArray();
		if (oitArray != null && oitArray.length > 0) {
			// Lo recorremos.
			for (ObjectIdentifierType oit: oitArray) {
				// Por cada identificador...
				IdentifierType it = oit.getIdentifier();
				// En función de su representación, obtenemos el OID en formato
				// string.
				String oid = getOIDfromIdentifierType(it);
				// Lo añadimos al objeto resultante.
				result.addNewOID(oid);
			}

		}

		return result;

	}

	/**
	 * Tries to build and return an CertSubjectDNAttribute Criteria from the XML node.
	 * @param node XML node to parse.
	 * @return CertSubjectDNAttribute Criteria object representation builded from the xml node. If not is possible
	 * to build, then returns <code>null</code>.
	 * @throws TSLParsingException In case of some error building an CertSubjectDNAttribute Criteria.
	 */
	private IAnyTypeOtherCriteria buildCertSubjectDNAttributeOtherCriteria(Node node) throws TSLParsingException {

		CertSubjectDNAttributeOtherCriteria result = null;

		CertSubjectDNAttributeType csdnat = null;
		try {
			csdnat = getDocumentBuildingNewSchemeTypeLoader(null, node, CertSubjectDNAttributeDocument.class).getCertSubjectDNAttribute();
		} catch (TSLParsingException e) {
			// Si se produce un error al parsear, es porque no se trata de este
			// tipo de extensión.
			return null;
		}

		// Una vez parseado inicializamos el objeto resultante.
		result = new CertSubjectDNAttributeOtherCriteria();
		// Obtenemos el array con los identificadores.
		ObjectIdentifierType[ ] oitArray = csdnat.getAttributeOIDArray();
		if (oitArray != null && oitArray.length > 0) {
			// Lo recorremos.
			for (ObjectIdentifierType oit: oitArray) {
				// Por cada identificador...
				IdentifierType it = oit.getIdentifier();
				// En función de su representación, obtenemos el OID en formato
				// string.
				String oid = getOIDfromIdentifierType(it);
				// Lo añadimos al objeto resultante.
				result.addNewOID(oid);
			}

		}

		return result;

	}

	/**
	 * Builds and return an Unknown Criteria from the XML node.
	 * @param localName Local name of the node that has not been detected.
	 * @return Unknown Criteria object representation.
	 */
	private IAnyTypeOtherCriteria buildUnknownOtherCriteria(String localName) {

		UnknownOtherCriteria result = new UnknownOtherCriteria(localName);
		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSLlistTSPsize()
	 */
	@Override
	protected int getTSLlistTSPsize() {

		int result = 0;
		TrustServiceProviderListType tspList = tsl.getTrustServiceProviderList();
		if (tspList != null) {
			result = tspList.sizeOfTrustServiceProviderArray();
		}
		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#buildTSPInformationNames(int, es.gob.afirma.tsl.parsing.impl.common.TSPInformation)
	 */
	@Override
	protected void buildTSPInformationNames(int pos, TSPInformation tspInformation) {

		MultiLangNormStringType[ ] names = getTSPInformationInPosition(pos).getTSPName().getNameArray();
		for (MultiLangNormStringType name: names) {
			tspInformation.addNewName(name.getLang(), name.getStringValue());
		}

	}

	/**
	 * Gets the TSP Information for a specified position in the list.
	 * @param pos Position in the List of the TSP to get.
	 * @return TSP Information representation object if it exists, otherwise <code>null</code>.
	 */
	private TSPInformationType getTSPInformationInPosition(int pos) {
		return getTSPinPosition(pos).getTSPInformation();
	}

	/**
	 * Gets the TSP for a specified position in the list.
	 * @param pos Position in the List of the TSP to get.
	 * @return TSP representation object if it exists, otherwise <code>null</code>.
	 */
	private TSPType getTSPinPosition(int pos) {
		return tsl.getTrustServiceProviderList().getTrustServiceProviderArray(pos);
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#buildTSPInformationTradeNames(int, es.gob.afirma.tsl.parsing.impl.common.TSPInformation)
	 */
	@Override
	protected void buildTSPInformationTradeNames(int pos, TSPInformation tspInformation) {

		TSPInformationType tspInf = getTSPInformationInPosition(pos);
		if (tspInf.isSetTSPTradeName()) {
			MultiLangNormStringType[ ] tradeNames = tspInf.getTSPTradeName().getNameArray();
			for (MultiLangNormStringType tradeName: tradeNames) {
				tspInformation.addNewTradeName(tradeName.getLang(), tradeName.getStringValue());
			}
		}

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSPInformationPostalAddresses(int)
	 */
	@Override
	protected Map<String, List<PostalAddress>> getTSPInformationPostalAddresses(int pos) {
		return getPostalAddresses(getTSPInformationInPosition(pos).getTSPAddress());
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSPInformationElectronicAddresses(int)
	 */
	@Override
	protected Map<String, List<String>> getTSPInformationElectronicAddresses(int pos) {
		return getElectronicAddresses(getTSPInformationInPosition(pos).getTSPAddress());
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#buildTSPInformationURI(int, es.gob.afirma.tsl.parsing.impl.common.TSPInformation)
	 */
	@Override
	protected void buildTSPInformationURI(int pos, TSPInformation tspInformation) throws URISyntaxException {

		NonEmptyMultiLangURIType[ ] infURIs = getTSPInformationInPosition(pos).getTSPInformationURI().getURIArray();
		for (NonEmptyMultiLangURIType uri: infURIs) {
			tspInformation.addNewURI(uri.getLang(), new URI(uri.getStringValue()));
		}

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSPInformationExtensions(int)
	 */
	@Override
	protected List<IAnyTypeExtension> getTSPInformationExtensions(int pos) throws TSLParsingException {

		List<IAnyTypeExtension> result = null;

		ExtensionsListType elt = getTSPInformationInPosition(pos).getTSPInformationExtensions();
		if (elt != null && elt.sizeOfExtensionArray() > 0) {

			result = new ArrayList<IAnyTypeExtension>();
			for (int index = 0; index < elt.sizeOfExtensionArray(); index++) {

				ExtensionType et = elt.getExtensionArray(index);
				result.add(buildExtensionFromNode(et.getDomNode(), et.getCritical(), IAnyTypeExtension.TYPE_TSP_INFORMATION));

			}

		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSPServiceListSize(int)
	 */
	@Override
	protected int getTSPServiceListSize(int pos) {
		return getTSPinPosition(pos).getTSPServices().sizeOfTSPServiceArray();
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSPServiceInformationType(int, int)
	 */
	@Override
	protected String getTSPServiceInformationType(int posTSP, int posService) {

		String result = getTSPServiceInformationFromTSPInPosition(posTSP, posService).getServiceTypeIdentifier();

		// Debido a un error en la especificación, publicaron erróneamente el
		// valor del
		// tipo TLIssuer (una letra errónea en la URI). En caso de tratarse de
		// esta, lo
		// modificamos internamente por la correcta.
		if (ITSLCommonURIs.TSL_SERVICETYPE_TLISSUER_BADDEFINITION.equalsIgnoreCase(result)) {

			LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.TB_LOG004, new Object[ ] { result, ITSLCommonURIs.TSL_SERVICETYPE_TLISSUER }));
			result = ITSLCommonURIs.TSL_SERVICETYPE_TLISSUER;

		}

		return result;

	}

	/**
	 * Gets the TSP Service Information from the TSP indicated by positions.
	 * @param posTSP Position of the TSP in its list.
	 * @param posService Position of the TSP Service in its list.
	 * @return TSP Service Information reprensentation object if it exists, otherwise <code>null</code>.
	 */
	private TSPServiceInformationType getTSPServiceInformationFromTSPInPosition(int posTSP, int posService) {
		return getTSPServiceFromTSPInPosition(posTSP, posService).getServiceInformation();
	}

	/**
	 * Gets the TSP Service from the TSP indicated by positions.
	 * @param posTSP Position of the TSP in its list.
	 * @param posService Position of the TSP Service in its list.
	 * @return TSP Service reprensentation object if it exists, otherwise <code>null</code>.
	 */
	private TSPServiceType getTSPServiceFromTSPInPosition(int posTSP, int posService) {
		return getTSPinPosition(posTSP).getTSPServices().getTSPServiceArray(posService);
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#buildTSPServiceInformationName(int, int, es.gob.afirma.tsl.parsing.impl.common.ServiceInformation)
	 */
	@Override
	protected void buildTSPServiceInformationName(int posTSP, int posService, ServiceInformation servInf) {

		MultiLangNormStringType[ ] serviceNames = getTSPServiceInformationFromTSPInPosition(posTSP, posService).getServiceName().getNameArray();
		for (MultiLangNormStringType serviceName: serviceNames) {
			servInf.addNewServiceName(serviceName.getLang(), serviceName.getStringValue());
		}

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#buildTSPServiceInformationIdentities(int, int, es.gob.afirma.tsl.parsing.impl.common.ServiceInformation)
	 */
	@Override
	protected void buildTSPServiceInformationIdentities(int posTSP, int posService, ServiceInformation servInf) throws TSLParsingException {

		DigitalIdentityListType serviceDigitalIdentityList = getTSPServiceInformationFromTSPInPosition(posTSP, posService).getServiceDigitalIdentity();
		if (serviceDigitalIdentityList.sizeOfDigitalIdArray() > 0) {
			DigitalIdentityType[ ] digitalIdentities = serviceDigitalIdentityList.getDigitalIdArray();
			for (DigitalIdentityType digitalIdentity: digitalIdentities) {
				try {
					servInf.addNewDigitalIdentity(buildDigitalID(digitalIdentity, checkIfServiceTypeIsNoPKIorUnspecified(servInf.getServiceTypeIdentifier().toString())));
				} catch (TSLParsingException e) {
					throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.TB_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_SERVICEDIGITALIDENTITY }), e);
				}
			}
		}

	}

	/**
	 * Checks if the input service type identifier matches with some one that represents
	 * a service that not is using the PKI public key technology, or is unspecified.
	 * @param serviceType Service type identifier to check.
	 * @return <code>true</code> if the input service type identifier matches with some one that represents
	 * a service that not is using the PKI public key technology, otherwise <code>false</code>.
	 */
	private boolean checkIfServiceTypeIsNoPKIorUnspecified(String serviceType) {

		boolean result = false;

		result = serviceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_RA_NOTHAVINGPKIID) || serviceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_ARCHIV_NOTHAVINGPKIID) || serviceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_IDV_NOTHAVINGPKIID);
		result = result || serviceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_KESCROW_NOTHAVINGPKIID) || serviceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_PPWD_NOTHAVINGPKIID);

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSPServiceInformationStatus(int, int)
	 */
	@Override
	protected String getTSPServiceInformationStatus(int posTSP, int posService) {
		return getTSPServiceInformationFromTSPInPosition(posTSP, posService).getServiceStatus();
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSPServiceInformationStatusStartingDateAndTime(int, int)
	 */
	@Override
	protected Date getTSPServiceInformationStatusStartingDateAndTime(int posTSP, int posService) {
		return getTSPServiceInformationFromTSPInPosition(posTSP, posService).getStatusStartingTime().getTime();
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#buildTSPServiceInformationSchemeDefinitionURI(int, int, es.gob.afirma.tsl.parsing.impl.common.ServiceInformation)
	 */
	@Override
	protected void buildTSPServiceInformationSchemeDefinitionURI(int posTSP, int posService, ServiceInformation servInf) throws TSLParsingException {

		TSPServiceInformationType serviceInformationType = getTSPServiceInformationFromTSPInPosition(posTSP, posService);
		if (serviceInformationType.isSetSchemeServiceDefinitionURI()) {
			NonEmptyMultiLangURIType[ ] definitionURIarray = serviceInformationType.getSchemeServiceDefinitionURI().getURIArray();
			for (NonEmptyMultiLangURIType defUri: definitionURIarray) {
				try {
					servInf.addNewSchemeServiceDefinitionURI(defUri.getLang(), new URI(defUri.getStringValue()));
				} catch (URISyntaxException e) {
					throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.TB_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_SCHEMESERVICEDEFINITIONURI }), e);
				}
			}
		}

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#buildTSPServiceInformationServiceSupplyPoints(int, int, es.gob.afirma.tsl.parsing.impl.common.ServiceInformation)
	 */
	@Override
	protected void buildTSPServiceInformationServiceSupplyPoints(int posTSP, int posService, ServiceInformation servInf) throws TSLParsingException {

		TSPServiceInformationType serviceInformationType = getTSPServiceInformationFromTSPInPosition(posTSP, posService);
		if (serviceInformationType.isSetServiceSupplyPoints()) {
			String[ ] serviceSupplyPointsArray = serviceInformationType.getServiceSupplyPoints().getServiceSupplyPointArray();
			for (String supplyPoint: serviceSupplyPointsArray) {
				try {
					servInf.addNewServiceSupplyPointURI(new URI(supplyPoint));
				} catch (URISyntaxException e) {
					throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.TB_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_SERVICESUPPLYPOINTS }), e);
				}
			}
		}

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#buildTSPServiceInformationDefinitionURI(int, int, es.gob.afirma.tsl.parsing.impl.common.ServiceInformation)
	 */
	@Override
	protected void buildTSPServiceInformationDefinitionURI(int posTSP, int posService, ServiceInformation servInf) throws TSLParsingException {

		TSPServiceInformationType serviceInformationType = getTSPServiceInformationFromTSPInPosition(posTSP, posService);
		if (serviceInformationType.isSetTSPServiceDefinitionURI()) {
			NonEmptyMultiLangURIType[ ] definitionURIarray = serviceInformationType.getTSPServiceDefinitionURI().getURIArray();
			for (NonEmptyMultiLangURIType defUri: definitionURIarray) {
				try {
					servInf.addNewServiceDefinitionURI(defUri.getLang(), new URI(defUri.getStringValue()));
				} catch (URISyntaxException e) {
					throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.TB_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_TSPSERVICEDEFINITIONURI }), e);
				}
			}
		}

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSPServiceInformationExtensions(int, int)
	 */
	@Override
	protected List<IAnyTypeExtension> getTSPServiceInformationExtensions(int posTSP, int posService) throws TSLParsingException {

		List<IAnyTypeExtension> result = null;

		TSPServiceInformationType serviceInformationType = getTSPServiceInformationFromTSPInPosition(posTSP, posService);
		ExtensionsListType elt = serviceInformationType.getServiceInformationExtensions();
		if (elt != null && elt.sizeOfExtensionArray() > 0) {

			result = new ArrayList<IAnyTypeExtension>();
			for (int index = 0; index < elt.sizeOfExtensionArray(); index++) {

				ExtensionType et = elt.getExtensionArray(index);
				result.add(buildExtensionFromNode(et.getDomNode(), et.getCritical(), IAnyTypeExtension.TYPE_SERVICE_INFORMATION));

			}

		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSPServiceHistoryInstanceSize(int, int)
	 */
	@Override
	protected int getTSPServiceHistoryInstanceSize(int posTSP, int posService) {

		int result = 0;

		TSPServiceType tspService = getTSPServiceFromTSPInPosition(posTSP, posService);
		if (tspService.isSetServiceHistory()) {
			result = tspService.getServiceHistory().sizeOfServiceHistoryInstanceArray();
		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSPServiceHistoryType(int, int, int)
	 */
	@Override
	protected String getTSPServiceHistoryType(int posTSP, int posService, int posHistory) {

		String result = null;

		ServiceHistoryInstanceType shit = getServiceHistoryInstanceFromTSPInPosition(posTSP, posService, posHistory);
		if (shit != null) {
			result = shit.getServiceTypeIdentifier();

			// Debido a un error en la especificación, publicaron erróneamente
			// el valor del
			// tipo TLIssuer (una letra errónea en la URI). En caso de tratarse
			// de esta, lo
			// modificamos internamente por la correcta.
			if (ITSLCommonURIs.TSL_SERVICETYPE_TLISSUER_BADDEFINITION.equalsIgnoreCase(result)) {

				LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.TB_LOG004, new Object[ ] { result, ITSLCommonURIs.TSL_SERVICETYPE_TLISSUER }));
				result = ITSLCommonURIs.TSL_SERVICETYPE_TLISSUER;

			}

		}

		return result;

	}

	/**
	 * Gets the Service History Instance from the TSP indicated by positions.
	 * @param posTSP Position of the TSP in its list.
	 * @param posService Position of the TSP Service in its list.
	 * @param posHistory Position of the Service History Instance in its list.
	 * @return TSP Service History representation object if it exists, otherwise <code>null</code>.
	 */
	private ServiceHistoryInstanceType getServiceHistoryInstanceFromTSPInPosition(int posTSP, int posService, int posHistory) {

		ServiceHistoryInstanceType result = null;

		TSPServiceType tspServiceType = getTSPServiceFromTSPInPosition(posTSP, posService);
		if (tspServiceType.isSetServiceHistory()) {
			result = tspServiceType.getServiceHistory().getServiceHistoryInstanceArray(posHistory);
		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#buildTSPServiceHistoryName(int, int, int, es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance)
	 */
	@Override
	protected void buildTSPServiceHistoryName(int posTSP, int posService, int posHistory, ServiceHistoryInstance shi) {

		ServiceHistoryInstanceType shit = getServiceHistoryInstanceFromTSPInPosition(posTSP, posService, posHistory);
		if (shit != null) {

			MultiLangNormStringType[ ] serviceNames = shit.getServiceName().getNameArray();
			for (MultiLangNormStringType serviceName: serviceNames) {
				shi.addNewServiceName(serviceName.getLang(), serviceName.getStringValue());
			}

		}

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#buildTSPServiceHistoryIdentities(int, int, int, es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance)
	 */
	@Override
	protected void buildTSPServiceHistoryIdentities(int posTSP, int posService, int posHistory, ServiceHistoryInstance shi) throws TSLParsingException {

		ServiceHistoryInstanceType shit = getServiceHistoryInstanceFromTSPInPosition(posTSP, posService, posHistory);
		if (shit != null) {

			DigitalIdentityListType serviceDigitalIdentityList = shit.getServiceDigitalIdentity();
			if (serviceDigitalIdentityList.sizeOfDigitalIdArray() > 0) {
				DigitalIdentityType[ ] digitalIdentities = serviceDigitalIdentityList.getDigitalIdArray();
				for (DigitalIdentityType digitalIdentity: digitalIdentities) {
					try {
						shi.addNewDigitalIdentity(buildDigitalID(digitalIdentity, checkIfServiceTypeIsNoPKIorUnspecified(shi.getServiceTypeIdentifier().toString())));
					} catch (TSLParsingException e) {
						throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.TB_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TSPSERVICE_INFORMATION_SERVICEDIGITALIDENTITY }), e);
					}
				}
			}

		}

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSPServiceHistoryStatus(int, int, int)
	 */
	@Override
	protected String getTSPServiceHistoryStatus(int posTSP, int posService, int posHistory) {

		String result = null;

		ServiceHistoryInstanceType shit = getServiceHistoryInstanceFromTSPInPosition(posTSP, posService, posHistory);
		if (shit != null) {

			result = shit.getServiceStatus();

		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSPServiceHistoryStatusStartingDateAndTime(int, int, int)
	 */
	@Override
	protected Date getTSPServiceHistoryStatusStartingDateAndTime(int posTSP, int posService, int posHistory) {

		Date result = null;

		ServiceHistoryInstanceType shit = getServiceHistoryInstanceFromTSPInPosition(posTSP, posService, posHistory);
		if (shit != null) {

			result = shit.getStatusStartingTime().getTime();

		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSPServiceHistoryExtensions(int, int, int)
	 */
	@Override
	protected List<IAnyTypeExtension> getTSPServiceHistoryExtensions(int posTSP, int posService, int posHistory) throws TSLParsingException {

		List<IAnyTypeExtension> result = null;

		ServiceHistoryInstanceType shit = getServiceHistoryInstanceFromTSPInPosition(posTSP, posService, posHistory);
		ExtensionsListType elt = shit.getServiceInformationExtensions();
		if (elt != null && elt.sizeOfExtensionArray() > 0) {

			result = new ArrayList<IAnyTypeExtension>();
			for (int index = 0; index < elt.sizeOfExtensionArray(); index++) {

				ExtensionType et = elt.getExtensionArray(index);
				result.add(buildExtensionFromNode(et.getDomNode(), et.getCritical(), IAnyTypeExtension.TYPE_SERVICE_INFORMATION));

			}

		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.ATSLBuilder#getTSLSignature()
	 */
	@Override
	protected SignatureType getTSLSignature() throws TSLParsingException {

		SignatureType signature = tsl.getSignature();
		// Para esta especificación, la firma es obligatoria.
		if (signature == null) {
			throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.TB_LOG001, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_SIGNATURE }));
		}
		return signature;

	}


}
