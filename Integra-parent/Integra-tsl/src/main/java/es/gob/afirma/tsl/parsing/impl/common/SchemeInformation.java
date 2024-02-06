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
 * <b>File:</b><p>SchemeInformation.SchemeInformation.java.</p>
 * <b>Description:</b><p>Class that defines the TSL Scheme Information with all its information not dependent
 * of the specification or TSL version.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/11/2020.
 */
package es.gob.afirma.tsl.parsing.impl.common;

import java.io.Serializable;
import java.net.URI;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import es.gob.afirma.tsl.parsing.ifaces.IAnyTypeExtension;


/** 
 * <p>Class that defines the TSL Scheme Information with all its information not dependent
 * of the specification or TSL version.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2020.
 */
public class SchemeInformation implements Serializable {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = -3434179278892168917L;

    
	/**
	 * Attribute that represents the version of the TSL format.
	 */
	private int tslVersionIdentifier = -1;

	/**
	 * Attribute that represents the sequence number of the TSL.
	 */
	private int tslSequenceNumber = -1;

	/**
	 * Attribute that represents the type of the TSL.
	 */
	private URI tslType = null;

	/**
	 * Attribute that represents the formal name under which the scheme operator
	 * does business or is given its mandate in all presented languages.
	 */
	private Map<String, List<String>> schemeOperatorNames = null;

	/**
	 * Attribute that represents specify the address of the legal identity, for both
	 * postal and electronic communications. Users (subscribers, relying parties)
	 * should use this address as the contact point for enquiries, complaints, etc.
	 * to the scheme operator.
	 */
	private Address schemeOperatorAddress = null;

	/**
	 * Attribute that represents the name under which the scheme operates.
	 */
	private Map<String, String> schemeNames = null;

	/**
	 * Attribute that represents he URI(s) where users (subscribers, relying parties)
	 * can obtain scheme-specific information in all presented languages.
	 */
	private Map<String, List<URI>> schemeInformationURIs = null;

	/**
	 * Attribute that represents the identifier of the status determination approach.
	 */
	private URI statusDeterminationApproach = null;

	/**
	 * Attribute that contain one or more registered URIs in all presented languages.
	 */
	private Map<String, List<URI>> schemeTypeCommunityRules = null;

	/**
	 * Attribute that represents he country or territory in which the
	 * scheme is established.
	 */
	private String schemeTerritory = null;

	/**
	 * Attribute that represents the scheme's policy concerning legal requirements met
	 * by the scheme for the jurisdiction in which the scheme is established and/or any
	 * constraints and conditions under which the TSL is maintained and offered, in all
	 * presented languages.
	 */
	private Map<String, URI> policies = null;

	/**
	 * Attribute that represents the scheme's notices concerning the legal status of
	 * the scheme or legal requirements met by the scheme for the jurisdiction in which
	 * the scheme is established and/or any constraints and conditions under which
	 * the TSL is maintained and offered, in all presented languages.
	 */
	private Map<String, String> legalNotices = null;

	/**
	 * Attribute that represents duration over which historical information in the
	 * TSL is provided.
	 */
	private int historicalPeriod = -1;

	/**
	 * Attribute that represents a list with pointers to other TSL.
	 */
	private List<TSLPointer> pointersToOtherTSL = null;

	/**
	 * Attribute that represents the date and time on which the list was issued.
	 */
	private Date listIssueDateTime = null;

	/**
	 * Attribute that represents the latest date and time by which the next TSL will
	 * be issued or be null to indicate a closed TSL.
	 */
	private Date nextUpdate = null;

	/**
	 * Attribute that represents locations where the current TSL is published
	 * and where updates to the current TSL can be found. If multiple distribution points are specified,
	 * they all must provide identical copies of the current TSL or its updated versions.
	 */
	private List<URI> distributionPoints = null;

	/**
	 * Attribute that represents a list with all the extensions associated to this Scheme Information.
	 */
	private List<IAnyTypeExtension> schemeInformationExtensions = null;

	/**
	 * Constructor method for the class SchemeInformation.java.
	 */
	public SchemeInformation() {
		super();
		schemeOperatorNames = new HashMap<String, List<String>>();
		schemeOperatorAddress = new Address();
		schemeNames = new HashMap<String, String>();
		schemeInformationURIs = new HashMap<String, List<URI>>();
		schemeTypeCommunityRules = new HashMap<String, List<URI>>();
		policies = new HashMap<String, URI>();
		legalNotices = new HashMap<String, String>();
		pointersToOtherTSL = new ArrayList<TSLPointer>();
		distributionPoints = new ArrayList<URI>();
		schemeInformationExtensions = new ArrayList<IAnyTypeExtension>();
	}

	/**
	 * Gets the value of the attribute {@link #tslVersionIdentifier}.
	 * @return the value of the attribute {@link #tslVersionIdentifier}.
	 */
	public final int getTslVersionIdentifier() {
		return tslVersionIdentifier;
	}

	/**
	 * Sets the value of the attribute {@link #tslVersionIdentifier}.
	 * @param tslVersionIdentifierParam The value for the attribute {@link #tslVersionIdentifier}.
	 */
	public final void setTslVersionIdentifier(int tslVersionIdentifierParam) {
		this.tslVersionIdentifier = tslVersionIdentifierParam;
	}

	/**
	 * Gets the value of the attribute {@link #tslSequenceNumber}.
	 * @return the value of the attribute {@link #tslSequenceNumber}.
	 */
	public final int getTslSequenceNumber() {
		return tslSequenceNumber;
	}

	/**
	 * Sets the value of the attribute {@link #tslSequenceNumber}.
	 * @param tslSequenceNumberParam The value for the attribute {@link #tslSequenceNumber}.
	 */
	public final void setTslSequenceNumber(int tslSequenceNumberParam) {
		this.tslSequenceNumber = tslSequenceNumberParam;
	}

	/**
	 * Gets the value of the attribute {@link #tslType}.
	 * @return the value of the attribute {@link #tslType}.
	 */
	public final URI getTslType() {
		return tslType;
	}

	/**
	 * Sets the value of the attribute {@link #tslType}.
	 * @param tslTypeParam The value for the attribute {@link #tslType}.
	 */
	public final void setTslType(URI tslTypeParam) {
		this.tslType = tslTypeParam;
	}

	/**
	 * Gets the value of the attribute {@link #schemeOperatorNames}.
	 * @return the value of the attribute {@link #schemeOperatorNames}.
	 */
	public final Map<String, List<String>> getSchemeOperatorNames() {
		return schemeOperatorNames;
	}

	/**
	 * Gets the scheme operator name for the specified language.
	 * @param language Language from which gets the scheme operator name.
	 * @return the scheme operator name for the specified language, or <code>null</code>
	 * if not exists for that language.
	 */
	public final List<String> getSchemeOperatorNameInLanguage(String language) {
		return schemeOperatorNames.get(language);
	}

	/**
	 * Adds a new scheme operator name for the specified language.
	 * @param language language to which associate the new scheme operator name. If
	 * it is <code>null</code>, then this method do nothing.
	 * @param schemeOperatorName Scheme operator name.
	 */
	public final void addNewSchemeOperatorName(String language, String schemeOperatorName) {
		if (language != null) {
			List<String> schemeOperatorNameList = getSchemeOperatorNameInLanguage(language);
			if (schemeOperatorNameList == null) {
				schemeOperatorNameList = new ArrayList<String>();
			}
			schemeOperatorNameList.add(schemeOperatorName);
			schemeOperatorNames.put(language, schemeOperatorNameList);
		}
	}

	/**
	 * Gets the value of the attribute {@link #schemeOperatorAddress}.
	 * @return the value of the attribute {@link #schemeOperatorAddress}.
	 */
	public final Address getSchemeOperatorAddress() {
		return schemeOperatorAddress;
	}

	/**
	 * Sets the value of the attribute {@link #schemeOperatorAddress}.
	 * @param schemeOperatorAddressParam The value for the attribute {@link #schemeOperatorAddress}.
	 */
	public final void setSchemeOperatorAddress(Address schemeOperatorAddressParam) {
		this.schemeOperatorAddress = schemeOperatorAddressParam;
	}

	/**
	 * Gets the value of the attribute {@link #schemeNames}.
	 * @return the value of the attribute {@link #schemeNames}.
	 */
	public final Map<String, String> getSchemeNames() {
		return schemeNames;
	}

	/**
	 * Gets the scheme name for the specified language.
	 * @param language Language from which gets the scheme name.
	 * @return Scheme name for the specified language, or <code>null</code>
	 * if not exists for that language.
	 */
	public final String getSchemeName(String language) {
		return schemeNames.get(language);
	}

	/**
	 * Adds a new scheme name for the specified language.
	 * @param language language to which associate the new scheme name. If
	 * it is <code>null</code>, then this method do nothing.
	 * @param schemeName Scheme name.
	 */
	public final void addNewSchemeName(String language, String schemeName) {
		if (language != null) {
			schemeNames.put(language, schemeName);
		}
	}

	/**
	 * Sets the value of the attribute {@link #schemeNames}.
	 * @param schemeNamesParam The value for the attribute {@link #schemeNames}.
	 */
	public final void setSchemeNames(Map<String, String> schemeNamesParam) {
		this.schemeNames = schemeNamesParam;
	}

	/**
	 * Checks if there is at least one scheme name added.
	 * @return <code>true</code> if there is, otherwise <code>false</code>.
	 */
	public final boolean isThereSomeSchemeName() {
		return !schemeNames.isEmpty();
	}

	/**
	 * Gets the value of the attribute {@link #schemeInformationURIs}.
	 * @return the value of the attribute {@link #schemeInformationURIs}.
	 */
	public final Map<String, List<URI>> getSchemeInformationURIs() {
		return schemeInformationURIs;
	}

	/**
	 * Gets the scheme information URI list for the specified language.
	 * @param language Language from which gets the scheme information URI.
	 * @return Scheme information URI list for the specified language, or
	 * <code>null</code> if not exists for that language.
	 */
	public final List<URI> getSchemeInformationURIinLanguage(String language) {
		return schemeInformationURIs.get(language);
	}

	/**
	 * Adds a new scheme information URI for the specified language.
	 * @param language language to which associate the new scheme information URI.
	 * If it is <code>null</code>, then this method do nothing.
	 * @param schemeInformationURI Scheme information URI.
	 */
	public final void addNewSchemeInformationURI(String language, URI schemeInformationURI) {
		if (language != null && schemeInformationURI != null) {
			List<URI> uriList = schemeInformationURIs.get(language);
			if (uriList == null) {
				uriList = new ArrayList<URI>();
			}
			uriList.add(schemeInformationURI);
			schemeInformationURIs.put(language, uriList);
		}
	}

	/**
	 * Checks if there is at least one scheme information URI.
	 * @return <code>true</code> if there is, otherwise <code>false</code>.
	 */
	public final boolean isThereSomeSchemeInformationURI() {
		return !schemeInformationURIs.isEmpty();
	}

	/**
	 * Gets the value of the attribute {@link #statusDeterminationApproach}.
	 * @return the value of the attribute {@link #statusDeterminationApproach}.
	 */
	public final URI getStatusDeterminationApproach() {
		return statusDeterminationApproach;
	}

	/**
	 * Sets the value of the attribute {@link #statusDeterminationApproach}.
	 * @param statusDeterminationApproachParam The value for the attribute {@link #statusDeterminationApproach}.
	 */
	public final void setStatusDeterminationApproach(URI statusDeterminationApproachParam) {
		this.statusDeterminationApproach = statusDeterminationApproachParam;
	}

	/**
	 * Gets the value of the attribute {@link #schemeTypeCommunityRules}.
	 * @return the value of the attribute {@link #schemeTypeCommunityRules}.
	 */
	public final Map<String, List<URI>> getSchemeTypeCommunityRules() {
		return schemeTypeCommunityRules;
	}

	/**
	 * Gets the scheme type community rules for the specified language.
	 * @param language Language from which gets the scheme type community rules.
	 * @return Scheme type community rules for the specified language, or
	 * <code>null</code> if not exists for that language.
	 */
	public final List<URI> getSchemeTypeCommunityRulesInLanguage(String language) {
		return schemeTypeCommunityRules.get(language);
	}

	/**
	 * Adds a new scheme type community rule URI for the specified language.
	 * @param language language to which associate the new scheme type community rule URI.
	 * If it is <code>null</code>, then this method do nothing.
	 * @param stcrUri scheme type community rule URI.
	 */
	public final void addNewSchemeTypeCommunityRule(String language, URI stcrUri) {
		if (language != null && stcrUri != null) {
			List<URI> uriList = schemeTypeCommunityRules.get(language);
			if (uriList == null) {
				uriList = new ArrayList<URI>();
			}
			uriList.add(stcrUri);
			schemeTypeCommunityRules.put(language, uriList);
		}
	}

	/**
	 * Checks if there is at least one scheme type community rule.
	 * @return <code>true</code> if there is, otherwise <code>false</code>.
	 */
	public final boolean isThereSomeSchemeTypeCommunityRule() {
		return !schemeTypeCommunityRules.isEmpty();
	}

	/**
	 * Gets the value of the attribute {@link #schemeTerritory}.
	 * @return the value of the attribute {@link #schemeTerritory}.
	 */
	public final String getSchemeTerritory() {
		return schemeTerritory;
	}

	/**
	 * Sets the value of the attribute {@link #schemeTerritory}.
	 * @param schemeTerritoryParam The value for the attribute {@link #schemeTerritory}.
	 */
	public final void setSchemeTerritory(String schemeTerritoryParam) {
		this.schemeTerritory = schemeTerritoryParam;
	}

	/**
	 * Gets the value of the attribute {@link #policies}.
	 * @return the value of the attribute {@link #policies}.
	 */
	public final Map<String, URI> getPolicies() {
		return policies;
	}

	/**
	 * Gets the policy assigned to the input language.
	 * @param language language to search (ISO 639).
	 * @return URI that represents the searched policy.
	 */
	public final URI getPolicyInLanguage(String language) {
		return policies.get(language);
	}

	/**
	 * Adds a new scheme policy in a specific language.
	 * @param language Language to which add the policy.
	 * @param policyUri scheme policy URI to add.
	 */
	public final void addNewPolicy(String language, URI policyUri) {
		if (language != null && policyUri != null) {
			policies.put(language, policyUri);
		}
	}

	/**
	 * Sets the value of the attribute {@link #policies}.
	 * @param policiesParam The value for the attribute {@link #policies}.
	 */
	public final void setPolicies(Map<String, URI> policiesParam) {
		this.policies = policiesParam;
	}

	/**
	 * Checks if there is at least one scheme policy.
	 * @return <code>true</code> if there is, otherwise <code>false</code>.
	 */
	public final boolean isThereSomePolicy() {
		return !policies.isEmpty();
	}

	/**
	 * Gets the value of the attribute {@link #legalNotices}.
	 * @return the value of the attribute {@link #legalNotices}.
	 */
	public final Map<String, String> getLegalNotices() {
		return legalNotices;
	}

	/**
	 * Gets the notice from the input language.
	 * @param language Language to search (ISO 639).
	 * @return Legal notice for the input language.
	 */
	public final String getLegalNoticeInLanguage(String language) {
		return legalNotices.get(language);
	}

	/**
	 * Adds a new scheme legal notice in a specific language.
	 * @param language Language to which add the legal notice.
	 * @param legalNotice legal notice to add.
	 */
	public final void addNewLegalNotice(String language, String legalNotice) {
		if (language != null && legalNotice != null) {
			legalNotices.put(language, legalNotice);
		}
	}

	/**
	 * Sets the value of the attribute {@link #legalNotices}.
	 * @param legalNoticesParam The value for the attribute {@link #legalNotices}.
	 */
	public final void setLegalNotices(Map<String, String> legalNoticesParam) {
		this.legalNotices = legalNoticesParam;
	}

	/**
	 * Checks if there is at least one scheme legal notice.
	 * @return <code>true</code> if there is, otherwise <code>false</code>.
	 */
	public final boolean isThereSomeLegalNotice() {
		return !legalNotices.isEmpty();
	}

	/**
	 * Gets the value of the attribute {@link #historicalPeriod}.
	 * @return the value of the attribute {@link #historicalPeriod}.
	 */
	public final int getHistoricalPeriod() {
		return historicalPeriod;
	}

	/**
	 * Sets the value of the attribute {@link #historicalPeriod}.
	 * @param historicalPeriodParam The value for the attribute {@link #historicalPeriod}.
	 */
	public final void setHistoricalPeriod(int historicalPeriodParam) {
		this.historicalPeriod = historicalPeriodParam;
	}

	/**
	 * Gets the value of the attribute {@link #pointersToOtherTSL}.
	 * @return the value of the attribute {@link #pointersToOtherTSL}.
	 */
	public final List<TSLPointer> getPointersToOtherTSL() {
		return pointersToOtherTSL;
	}

	/**
	 * Adds a new pointer to other TSL.
	 * @param pointer pointer to other TSL object representation.
	 */
	public final void addNewPointerToOtherTSL(TSLPointer pointer) {
		if (pointer != null) {
			pointersToOtherTSL.add(pointer);
		}
	}

	/**
	 * Sets the value of the attribute {@link #pointersToOtherTSL}.
	 * @param pointersToOtherTSLParam The value for the attribute {@link #pointersToOtherTSL}.
	 */
	public final void setPointersToOtherTSL(List<TSLPointer> pointersToOtherTSLParam) {
		this.pointersToOtherTSL = pointersToOtherTSLParam;
	}

	/**
	 * Checks if there is at least one pointer to other TSL.
	 * @return <code>true</code> if there is, otherwise <code>false</code>.
	 */
	public final boolean isThereSomePointerToOtherTSL() {
		return !pointersToOtherTSL.isEmpty();
	}

	/**
	 * Gets the value of the attribute {@link #listIssueDateTime}.
	 * @return the value of the attribute {@link #listIssueDateTime}.
	 */
	public final Date getListIssueDateTime() {
		return listIssueDateTime;
	}

	/**
	 * Sets the value of the attribute {@link #listIssueDateTime}.
	 * @param listIssueDateTimeParam The value for the attribute {@link #listIssueDateTime}.
	 */
	public final void setListIssueDateTime(Date listIssueDateTimeParam) {
		this.listIssueDateTime = listIssueDateTimeParam;
	}

	/**
	 * Gets the value of the attribute {@link #nextUpdate}.
	 * @return the value of the attribute {@link #nextUpdate}.
	 */
	public final Date getNextUpdate() {
		return nextUpdate;
	}

	/**
	 * Sets the value of the attribute {@link #nextUpdate}.
	 * @param nextUpdateParam The value for the attribute {@link #nextUpdate}.
	 */
	public final void setNextUpdate(Date nextUpdateParam) {
		this.nextUpdate = nextUpdateParam;
	}

	/**
	 * Gets the value of the attribute {@link #distributionPoints}.
	 * @return the value of the attribute {@link #distributionPoints}.
	 */
	public final List<URI> getDistributionPoints() {
		return distributionPoints;
	}

	/**
	 * Adds a new distribution point.
	 * @param dpUri Distribution point to add.
	 */
	public final void addNewDistributionPoint(URI dpUri) {
		if (dpUri != null) {
			distributionPoints.add(dpUri);
		}
	}

	/**
	 * Sets the value of the attribute {@link #distributionPoints}.
	 * @param distributionPointsParam The value for the attribute {@link #distributionPoints}.
	 */
	public final void setDistributionPoints(List<URI> distributionPointsParam) {
		this.distributionPoints = distributionPointsParam;
	}

	/**
	 * Checks if there is at least one distribution point.
	 * @return <code>true</code> if there is, otherwise <code>false</code>.
	 */
	public final boolean isThereSomeDistributionPoint() {
		return !distributionPoints.isEmpty();
	}

	/**
	 * Gets the value of the attribute {@link #schemeInformationExtensions}.
	 * @return the value of the attribute {@link #schemeInformationExtensions}.
	 */
	public final List<IAnyTypeExtension> getSchemeInformationExtensions() {
		return schemeInformationExtensions;
	}

	/**
	 * Adds a new extension if it is not <code>null</code>.
	 * @param extension extension to add.
	 */
	public final void addNewSchemeInformationExtension(IAnyTypeExtension extension) {
		if (extension != null) {
			schemeInformationExtensions.add(extension);
		}
	}

	/**
	 * Checks if there is at least one scheme information extension.
	 * @return <code>true</code> if there is at least one scheme information extension, otherwise <code>false</code>.
	 */
	public final boolean isThereSomeSchemeInformationExtension() {
		return !schemeInformationExtensions.isEmpty();
	}

}
