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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.extensions.QualificationElement.java.</p>
 * <b>Description:</b><p>Class that represents a field bundles a list of assertions that specifies the attributes
 * a certificate must have (e.g. certain key-usage-bits set) and a list of qualifiers that
 * specify some certificate properties (e.g. it is a qualified certificate).</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 15/06/2021.
 */
package es.gob.afirma.tsl.parsing.impl.common.extensions;

import java.io.Serializable;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.exceptions.TSLMalformedException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.parsing.ifaces.ITSLCommonURIs;
import es.gob.afirma.tsl.parsing.ifaces.ITSLElementsAndAttributes;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;


/** 
 * <p>Class that represents a field bundles a list of assertions that specifies the attributes
 * a certificate must have (e.g. certain key-usage-bits set) and a list of qualifiers that
 * specify some certificate properties (e.g. it is a qualified certificate).</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 15/06/2021.
 */
public class QualificationElement implements Serializable {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = 5817413499929636602L;

	/**
	 * Attribute that represents a list of URI with the qualifiers.
	 */
	private List<URI> qualifiersList = null;

	/**
	 * Attribute that represents the Criteria List element.
	 */
	private CriteriaList criteriaList = null;

	/**
	 * Constructor method for the class QualificationElement.java.
	 */
	public QualificationElement() {
		qualifiersList = new ArrayList<URI>();
	}

	/**
	 * Gets the value of the attribute {@link #qualifiersList}.
	 * @return the value of the attribute {@link #qualifiersList}.
	 */
	public final List<URI> getQualifiersList() {
		return qualifiersList;
	}

	/**
	 * Adds new Qualifier URI.
	 * @param qualifierUri Qualifier URI to add.
	 */
	public final void addNewQualifier(URI qualifierUri) {
		if (qualifierUri != null) {
			qualifiersList.add(qualifierUri);
		}
	}

	/**
	 * Checks if there is at least one qualifier uri.
	 * @return <code>true</code> if there is at least one qualifier uri, otherwise <code>false</code>.
	 */
	public final boolean isThereSomeQualifierUri() {
		return !qualifiersList.isEmpty();
	}

	/**
	 * Gets the value of the attribute {@link #criteriaList}.
	 * @return the value of the attribute {@link #criteriaList}.
	 */
	public final CriteriaList getCriteriaList() {
		return criteriaList;
	}

	/**
	 * Adds a new criteria list with the assert type specified.
	 * @param assertType Assert type to assing to the Criteria List.
	 * @return Criteria List created.
	 */
	public final CriteriaList addNewCriteriaList(String assertType) {
		criteriaList = new CriteriaList(assertType);
		return criteriaList;
	}

	/**
	 * Checks if the qualification element has an appropiate value in the TSL for the specification ETSI 119612
	 * and version 2.1.1.
	 * @param tsl TSL Object representation that contains the service and the extension.
	 * @param shi Service Information (or service history information) in which is declared the extension.
	 * @param isCritical Indicates if the extension is critical (<code>true</code>) or not (<code>false</code>).
	 * @throws TSLMalformedException In case of the qualification element has not a correct value.
	 */
	protected final void checkExtensionValueSpec119612Vers020101(ITSLObject tsl, ServiceHistoryInstance shi, boolean isCritical) throws TSLMalformedException {

		// Comprobamos primero los Qualifiers.
		if (qualifiersList.isEmpty()) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.EXT_LOG004, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_QUALIFICATION_QUALIFIER }));
		} else {
			for (URI qualifierUri: qualifiersList) {
				String qualifierUriString = qualifierUri.toString();
				boolean isValid = qualifierUriString.equals(ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCWITHSSCD) || qualifierUriString.equals(ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCNOSSCD);
				isValid = isValid || qualifierUriString.equals(ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCSTATUSASINCERT) || qualifierUriString.equals(ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCWITHQSCD);
				isValid = isValid || qualifierUriString.equals(ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCNOQSCD) || qualifierUriString.equals(ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCQSCDSTATUSASINCERT);
				isValid = isValid || qualifierUriString.equals(ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCQSCDMANAGEDONBEHALF) || qualifierUriString.equals(ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCFORLEGALPERSON);
				isValid = isValid || qualifierUriString.equals(ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCFORESIG) || qualifierUriString.equals(ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCFORESEAL);
				isValid = isValid || qualifierUriString.equals(ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCFORWSA) || qualifierUriString.equals(ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_NOTQUALIFIED);
				isValid = isValid || qualifierUriString.equals(ITSLCommonURIs.TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCSTATEMENT);
				if (!isValid) {
					throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.EXT_LOG007, new Object[ ] { qualifierUriString }));
				}
			}
		}

		// Comprobamos el CriteriaList.
		if (criteriaList == null) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.EXT_LOG006, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_QUALIFICATIONS_QUALIFICATION, ITSLElementsAndAttributes.ELEMENT_EXTENSION_QUALIFICATION_CRITERIALIST }));
		} else {
			criteriaList.checkExtensionValueSpec119612Vers020101(tsl, shi, isCritical);
		}

	}

}
