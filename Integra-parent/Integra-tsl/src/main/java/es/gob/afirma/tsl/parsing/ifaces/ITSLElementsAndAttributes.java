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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.ifaces.ITSLElementsAndAttributes.java.</p>
 * <b>Description:</b><p>Interface that contains the tokens of the differents elements and attributes used
 * in the XML implementations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 11/11/2020.
 */
package es.gob.afirma.tsl.parsing.ifaces;


/** 
 * <p>Interface that contains the tokens of the differents elements and attributes used
 * in the XML implementations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 11/11/2020.
 */
public interface ITSLElementsAndAttributes {

	/**
	 * Constant attribute that represents the attribute 'TSLTag'.
	 */
	String ATTRIBUTE_TSL_TAG = "TSLTag";

	/**
	 * Constant attribute that represents the element 'TSLVersionIdentifier'.
	 */
	String ELEMENT_TSL_VERSION_IDENTIFIER = "TSLVersionIdentifier";

	/**
	 * Constant attribute that represents the element 'TSLSequenceNumber'.
	 */
	String ELEMENT_TSL_SEQUENCE_NUMBER = "TSLSequenceNumber";

	/**
	 * Constant attribute that represents the element 'TSLType'.
	 */
	String ELEMENT_TSL_TYPE = "TSLType";

	/**
	 * Constant attribute that represents the element 'SchemeOperatorName'.
	 */
	String ELEMENT_SCHEME_OPERATOR_NAME = "SchemeOperatorName";

	/**
	 * Constant attribute that represents the element 'SchemeOperatorAddress'.
	 */
	String ELEMENT_SCHEME_OPERATOR_ADDRESS = "SchemeOperatorAddress";

	/**
	 * Constant attribute that represents the element 'PostalAddresses'.
	 */
	String ELEMENT_ADDRESS_POSTALADDRESSES = "PostalAddresses";

	/**
	 * Constant attribute that represents the element 'PostalAddress'.
	 */
	String ELEMENT_ADDRESS_POSTALADDRESS = "PostalAddress";

	/**
	 * Constant attribute that represents the element 'ElectronicAddress'.
	 */
	String ELEMENT_ADDRESS_ELECTRONICADDRESS = "ElectronicAddress";

	/**
	 * Constant attribute that represents the element 'SchemeName'.
	 */
	String ELEMENT_SCHEME_NAME = "SchemeName";

	/**
	 * Constant attribute that represents the element 'SchemeInformation'.
	 */
	String ELEMENT_SCHEME_INFORMATION = "SchemeInformation";

	/**
	 * Constant attribute that represents the element 'SchemeInformationURI'.
	 */
	String ELEMENT_SCHEME_INFORMATION_URI = "SchemeInformationURI";

	/**
	 * Constant attribute that represents the element 'StatusDeterminationApproach'.
	 */
	String ELEMENT_STATUS_DETERMINATION_APPROACH = "StatusDeterminationApproach";

	/**
	 * Constant attribute that represents the element 'SchemeTypeCommunityRules'.
	 */
	String ELEMENT_SCHEME_TYPE_COMMUNITY_RULES = "SchemeTypeCommunityRules";

	/**
	 * Constant attribute that represents the element 'SchemeTerritory'.
	 */
	String ELEMENT_SCHEME_TERRITORY = "SchemeTerritory";

	/**
	 * Constant attribute that represents the element 'PolicyOrLegalNotice'.
	 */
	String ELEMENT_POLICY_OR_LEGAL_NOTICE = "PolicyOrLegalNotice";

	/**
	 * Constant attribute that represents the element 'HistoricalInformationPeriod'.
	 */
	String ELEMENT_HISTORICAL_INFORMATION_PERIOD = "HistoricalInformationPeriod";

	/**
	 * Constant attribute that represents the element 'PointersToOtherTSL'.
	 */
	String ELEMENT_POINTER_TO_OTHER_TSL = "PointersToOtherTSL";

	/**
	 * Constant attribute that represents the element 'PointersToOtherTSL-TSLLocation'.
	 */
	String ELEMENT_POINTER_TO_OTHER_TSL_TSLLOCATION = "PointersToOtherTSL-TSLLocation";

	/**
	 * Constant attribute that represents the element 'ListIssueDateTime'.
	 */
	String ELEMENT_LIST_ISSUE_DATE_TIME = "ListIssueDateTime";

	/**
	 * Constant attribute that represents the element 'NextUpdate'.
	 */
	String ELEMENT_NEXT_UPDATE = "NextUpdate";

	/**
	 * Constant attribute that represents the element 'DistributionPoints'.
	 */
	String ELEMENT_DISTRIBUTION_POINTS = "DistributionPoints";

	/**
	 * Constant attribute that represents the element 'TrustServiceProvider'.
	 */
	String ELEMENT_TRUST_SERVICE_PROVIDER = "TrustServiceProvider";

	/**
	 * Constant attribute that represents the element 'TSPInformation-TSPAddress'.
	 */
	String ELEMENT_TSPINFORMATION_ADDRESS = "TSPInformation-TSPAddress";

	/**
	 * Constant attribute that represents the element 'TSPInformation-TSPInformationURI'.
	 */
	String ELEMENT_TSPINFORMATION_URI = "TSPInformation-TSPInformationURI";

	/**
	 * Constant attribute that represents the element 'TSPInformation-TSPName'.
	 */
	String ELEMENT_TSPINFORMATION_NAME = "TSPInformation-TSPName";

	/**
	 * Constant attribute that represents the element 'TSPInformation-TSPTradeName'.
	 */
	String ELEMENT_TSPINFORMATION_TRADENAME = "TSPInformation-TSPTradeName";

	/**
	 * Constant attribute that represents the element 'TSPInformation-TSPInformationExtensions'.
	 */
	String ELEMENT_TSPINFORMATION_EXTENSIONS = "TSPInformation-TSPInformationExtensions";

	/**
	 * Constant attribute that represents the element 'TSPServices'.
	 */
	String ELEMENT_TSPSERVICE_LIST = "TSPServices";

	/**
	 * Constant attribute that represents the element 'TSPServiceInformation-ServiceTypeIdentifier'.
	 */
	String ELEMENT_TSPSERVICE_INFORMATION_TYPE = "TSPServiceInformation-ServiceTypeIdentifier";

	/**
	 * Constant attribute that represents the element 'TSPServiceInformation-ServiceName'.
	 */
	String ELEMENT_TSPSERVICE_INFORMATION_NAMES = "TSPServiceInformation-ServiceName";

	/**
	 * Constant attribute that represents the element 'TSPServiceInformation-ServiceDigitalIdentity'.
	 */
	String ELEMENT_TSPSERVICE_INFORMATION_SERVICEDIGITALIDENTITY = "TSPServiceInformation-ServiceDigitalIdentity";

	/**
	 * Constant attribute that represents the element 'TSPServiceInformation-Status'.
	 */
	String ELEMENT_TSPSERVICE_INFORMATION_STATUS = "TSPServiceInformation-Status";

	/**
	 * Constant attribute that represents the element 'TSPServiceInformation-StatusStartingTime'.
	 */
	String ELEMENT_TSPSERVICE_INFORMATION_STATUS_STARTINGTIME = "TSPServiceInformation-StatusStartingTime";

	/**
	 * Constant attribute that represents the element 'TSPServiceInformation-SchemeServiceDefinitionURI'.
	 */
	String ELEMENT_TSPSERVICE_INFORMATION_SCHEMESERVICEDEFINITIONURI = "TSPServiceInformation-SchemeServiceDefinitionURI";

	/**
	 * Constant attribute that represents the element 'TSPServiceInformation-ServiceSupplyPoints'.
	 */
	String ELEMENT_TSPSERVICE_INFORMATION_SERVICESUPPLYPOINTS = "TSPServiceInformation-ServiceSupplyPoints";

	/**
	 * Constant attribute that represents the element 'TSPServiceInformation-TSPServiceDefinitionURI'.
	 */
	String ELEMENT_TSPSERVICE_INFORMATION_TSPSERVICEDEFINITIONURI = "TSPServiceInformation-TSPServiceDefinitionURI";

	/**
	 * Constant attribute that represents the element 'TSPServiceInformation-ServiceHistoryInstance-ServiceTypeIdentifier'.
	 */
	String ELEMENT_TSPSERVICE_HISTORY_TYPE = "TSPServiceInformation-ServiceHistoryInstance-ServiceTypeIdentifier";

	/**
	 * Constant attribute that represents the element 'TSPServiceInformation-ServiceHistoryInstance-Status'.
	 */
	String ELEMENT_TSPSERVICE_HISTORY_STATUS = "TSPServiceInformation-ServiceHistoryInstance-Status";

	/**
	 * Constant attribute that represents the element 'TSPServiceInformation-ServiceHistoryInstance-ServiceName'.
	 */
	String ELEMENT_TSPSERVICE_HISTORY_NAMES = "TSPServiceInformation-ServiceHistoryInstance-ServiceName";

	/**
	 * Constant attribute that represents the element 'TSPServiceInformation-ServiceHistoryInstance-StatusStartingTime'.
	 */
	String ELEMENT_TSPSERVICE_HISTORY_STATUS_STARTINGTIME = "TSPServiceInformation-ServiceHistoryInstance-StatusStartingTime";

	/**
	 * Constant attribute that represents the element 'TSPServiceInformation-ServiceHistoryInstance-ServiceDigitalIdentity'.
	 */
	String ELEMENT_TSPSERVICE_HISTORY_SERVICEDIGITALIDENTITY = "TSPServiceInformation-ServiceHistoryInstance-ServiceDigitalIdentity";

	/**
	 * Constant attribute that represents the element 'Extension-ExpiredCertsRevocationInfo'.
	 */
	String ELEMENT_EXTENSION_EXPIREDCERTSREVOCATIONINFO = "Extension-ExpiredCertsRevocationInfo";

	/**
	 * Constant attribute that represents the element 'ExpiredCertsRevocationInfo'.
	 */
	String ELEMENT_EXTENSION_EXPIREDCERTSREVOCATIONINFO_LOCALNAME = "ExpiredCertsRevocationInfo";

	/**
	 * Constant attribute that represents the element 'Extension-AdditionalServiceInformation'.
	 */
	String ELEMENT_EXTENSION_ADDITIONALSERVICEINFORMATION = "Extension-AdditionalServiceInformation";

	/**
	 * Constant attribute that represents the element 'AdditionalServiceInformation'.
	 */
	String ELEMENT_EXTENSION_ADDITIONALSERVICEINFORMATION_LOCALNAME = "AdditionalServiceInformation";

	/**
	 * Constant attribute that represents the element 'Extension-AdditionalServiceInformation-URI'.
	 */
	String ELEMENT_EXTENSION_ADDITIONALSERVICEINFORMATION_URI = "Extension-AdditionalServiceInformation-URI";

	/**
	 * Constant attribute that represents the element 'Extension-Qualifications'.
	 */
	String ELEMENT_EXTENSION_QUALIFICATIONS = "Extension-Qualifications";

	/**
	 * Constant attribute that represents the element 'Qualifications'.
	 */
	String ELEMENT_EXTENSION_QUALIFICATIONS_LOCALNAME = "Qualifications";

	/**
	 * Constant attribute that represents the element 'Extension-QualificationElement'.
	 */
	Object ELEMENT_EXTENSION_QUALIFICATIONS_QUALIFICATION = "Extension-QualificationElement";

	/**
	 * Constant attribute that represents the element 'Extension-QualificationElement-Qualifier'.
	 */
	String ELEMENT_EXTENSION_QUALIFICATION_QUALIFIER = "Extension-QualificationElement-Qualifier-URI";

	/**
	 * Constant attribute that represents the element 'Extension-QualificationElement-Qualifier'.
	 */
	String ELEMENT_EXTENSION_QUALIFICATION_QUALIFIER_URI = "Extension-QualificationElement-Qualifier-URI";

	/**
	 * Constant attribute that represents the element 'Extension-QualificationElement-CriteriaList'.
	 */
	String ELEMENT_EXTENSION_QUALIFICATION_CRITERIALIST = "Extension-QualificationElement-CriteriaList";

	/**
	 * Constant attribute that represents the element 'Extension-QualificationElement-CriteriaList-Assert'.
	 */
	String ELEMENT_EXTENSION_QUALIFICATION_CRITERIALIST_ASSERT = "Extension-QualificationElement-CriteriaList-Assert";

	/**
	 * Constant attribute that represents the element 'Extension-QualificationElement-CriteriaList-KeyUsage'.
	 */
	String ELEMENT_EXTENSION_QUALIFICATION_CRITERIALIST_KEYUSAGE = "Extension-QualificationElement-CriteriaList-KeyUsage";

	/**
	 * Constant attribute that represents the element 'Extension-QualificationElement-CriteriaList-KeyUsage-Name'.
	 */
	String ELEMENT_EXTENSION_QUALIFICATION_CRITERIALIST_KEYUSAGE_NAME = "Extension-QualificationElement-CriteriaList-KeyUsage-Name";

	/**
	 * Constant attribute that represents the element 'Extension-QualificationElement-CriteriaList-PolicySet'.
	 */
	String ELEMENT_EXTENSION_QUALIFICATION_CRITERIALIST_POLICYSET = "Extension-QualificationElement-CriteriaList-PolicySet";

	/**
	 * Constant attribute that represents the element 'TakenOverBy'.
	 */
	String ELEMENT_EXTENSION_TAKENOVERBY_LOCALNAME = "TakenOverBy";

	/**
	 * Constant attribute that represents the element 'Extension-TakenOverBy-URI'.
	 */
	String ELEMENT_EXTENSION_TAKENOVERBY_URI = "Extension-TakenOverBy-URI";

	/**
	 * Constant attribute that represents the element 'Extension-TakenOverBy-TSPName'.
	 */
	String ELEMENT_EXTENSION_TAKENOVERBY_TSPNAME = "Extension-TakenOverBy-TSPName";

	/**
	 * Constant attribute that represents the element 'Extension-TakenOverBy-SchemeOperatorName'.
	 */
	String ELEMENT_EXTENSION_TAKENOVERBY_SCHEMEOPERATORNAME = "Extension-TakenOverBy-SchemeOperatorName";

	/**
	 * Constant attribute that represents the element 'Extension-TakenOverBy-SchemeTerritory'.
	 */
	String ELEMENT_EXTENSION_TAKENOVERBY_SCHEMETERRITORY = "Extension-TakenOverBy-SchemeTerritory";

	/**
	 * Constant attribute that represents the element 'DigitalId'.
	 */
	String ELEMENT_DIGITAL_IDENTITY = "DigitalId";

	/**
	 * Constant attribute that represents the element 'ExtendedKeyUsage'.
	 */
	String ELEMENT_OTHER_CRITERIA_EXTENDEDKEYUSAGE_LOCALNAME = "ExtendedKeyUsage";

	/**
	 * Constant attribute that represents the element 'CertSubjectDNAttribute'.
	 */
	String ELEMENT_OTHER_CRITERIA_CERTSUBJECTDNATTRIBUTE_LOCALNAME = "CertSubjectDNAttribute";

	/**
	 * Constant attribute that represents the element 'Signature'.
	 */
	String ELEMENT_SIGNATURE = "Signature";
}
