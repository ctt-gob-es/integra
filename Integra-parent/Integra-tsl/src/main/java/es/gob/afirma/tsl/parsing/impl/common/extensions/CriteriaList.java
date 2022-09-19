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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.extensions.CriteriaList.java.</p>
 * <b>Description:</b><p>Class that represents a list of assertions related to certificate contents
 * (e.g. key usage) and status (e.g. additional assessment) used to filter certificates.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.2, 19/09/2022.
 */
package es.gob.afirma.tsl.parsing.impl.common.extensions;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import es.gob.afirma.tsl.exceptions.TSLCertificateValidationException;
import es.gob.afirma.tsl.exceptions.TSLMalformedException;
import es.gob.afirma.tsl.exceptions.TSLQualificationEvalProcessException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.parsing.ifaces.IAnyTypeOtherCriteria;
import es.gob.afirma.tsl.parsing.ifaces.ITSLElementsAndAttributes;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;
import es.gob.afirma.tsl.utils.UtilsStringChar;

/** 
 * <p>Class that represents a list of assertions related to certificate contents
 * (e.g. key usage) and status (e.g. additional assessment) used to filter certificates.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 19/09/2022.
 */
public class CriteriaList implements Serializable {

    /**
     * Constant attribute that represents the serial version UID. 
     */
    private static final long serialVersionUID = -482573694318194287L;

    /**
     * Constant attribute that represents the assertion 'all'.
     */
    public static final String ASSERT_ALL = "all";

    /**
     * Constant attribute that represents the assertion 'atLeastOne'.
     */
    public static final String ASSERT_ATLEASTONE = "atLeastOne";

    /**
     * Constant attribute that represents the assertion 'none'.
     */
    public static final String ASSERT_NONE = "none";

    /**
     * Attribute that represents the assert type (all, atLeastOne or none).
     */
    private String assertType = null;

    /**
     * Attribute that represents the key usage list.
     */
    private List<KeyUsage> keyUsageList = null;

    /**
     * Attribute that represents the policy set list.
     */
    private List<PoliciesList> policySetList = null;

    /**
     * Attribute that represents the sublist of criteria list.
     */
    private List<CriteriaList> criteriaListList = null;

    /**
     * Attribute that represents the description of the criteria list.
     */
    private String description = null;

    /**
     * Attribute that represents an optional other criteria.
     */
    private IAnyTypeOtherCriteria otherCriteria = null;

    /**
     * Constructor method for the class CriteriaList.java.
     */
    private CriteriaList() {
	super();
	keyUsageList = new ArrayList<KeyUsage>();
	policySetList = new ArrayList<PoliciesList>();
	criteriaListList = new ArrayList<CriteriaList>();
    }

    /**
     * Constructor method for the class CriteriaList.java.
     * @param assertTypeParam Assert type to assing to this object.
     */
    public CriteriaList(String assertTypeParam) {
	this();
	assertType = assertTypeParam;
    }

    /**
     * Gets the value of the attribute {@link #assertType}.
     * @return the value of the attribute {@link #assertType}.
     */
    public final String getAssertType() {
	return assertType;
    }

    /**
     * Gets the value of the attribute {@link #keyUsageList}.
     * @return the value of the attribute {@link #keyUsageList}.
     */
    public final List<KeyUsage> getKeyUsageList() {
	return keyUsageList;
    }

    /**
     * Adds a new Key Usage to the Criteria List.
     * @param ku Key Usage to add. If it is <code>null</code>, then do nothing.
     */
    public final void addNewKeyUsage(KeyUsage ku) {
	if (ku != null) {
	    keyUsageList.add(ku);
	}
    }

    /**
     * Check if exists at least one key usage.
     * @return <code>true</code> if exists at least one key usage, otherwise <code>false</code>.
     */
    public final boolean isThereSomeKeyUsage() {
	return !keyUsageList.isEmpty();
    }

    /**
     * Gets the value of the attribute {@link #policySetList}.
     * @return the value of the attribute {@link #policySetList}.
     */
    public final List<PoliciesList> getPolicySetList() {
	return policySetList;
    }

    /**
     * Add new policy set to the Criteria List.
     * @param pl Policy Set to add. If it is <code>null</code>, then do nothing.
     */
    public final void addNewPolicySet(PoliciesList pl) {
	if (pl != null) {
	    policySetList.add(pl);
	}
    }

    /**
     * Checks if there is at least one policy set.
     * @return <code>true</code> if there is at least one policy set, otherwise <code>false</code>.
     */
    public final boolean isThereSomePolicySet() {
	return !policySetList.isEmpty();
    }

    /**
     * Gets the value of the attribute {@link #criteriaListList}.
     * @return the value of the attribute {@link #criteriaListList}.
     */
    public final List<CriteriaList> getCriteriaListList() {
	return criteriaListList;
    }

    /**
     * Add new sub Criteria List to this Criteria List.
     * @param cl Criteria List to add. If it is <code>null</code>, then do nothing.
     */
    public final void addNewCriteriaList(CriteriaList cl) {
	if (cl != null) {
	    criteriaListList.add(cl);
	}
    }

    /**
     * Checks if there is at least one sub criteria list.
     * @return <code>true</code> if there is at least one sub criteria list, otherwise <code>false</code>.
     */
    public final boolean isThereSomeCriteriaList() {
	return !criteriaListList.isEmpty();
    }

    /**
     * Gets the value of the attribute {@link #description}.
     * @return the value of the attribute {@link #description}.
     */
    public final String getDescription() {
	return description;
    }

    /**
     * Sets the value of the attribute {@link #description}.
     * @param descriptionParam The value for the attribute {@link #description}.
     */
    public final void setDescription(String descriptionParam) {
	this.description = descriptionParam;
    }

    /**
     * Gets the value of the attribute {@link #otherCriteria}.
     * @return the value of the attribute {@link #otherCriteria}.
     */
    public final IAnyTypeOtherCriteria getOtherCriteria() {
	return otherCriteria;
    }

    /**
     * Sets the value of the attribute {@link #otherCriteria}.
     * @param otherCriteriaParam The value for the attribute {@link #otherCriteria}.
     */
    public final void setOtherCriteria(IAnyTypeOtherCriteria otherCriteriaParam) {
	this.otherCriteria = otherCriteriaParam;
    }

    /**
     * Checks if the criteria list has an appropiate value in the TSL for the specification ETSI 119612
     * and version 2.1.1.
     * @param tsl TSL Object representation that contains the service and the extension.
     * @param shi Service Information (or service history information) in which is declared the extension.
     * @param isCritical Indicates if the extension is critical (<code>true</code>) or not (<code>false</code>).
     * @throws TSLMalformedException In case of the criteria list has not a correct value.
     */
    protected final void checkExtensionValueSpec119612Vers020101(ITSLObject tsl, ServiceHistoryInstance shi, boolean isCritical) throws TSLMalformedException {

	// Comprobamos que el tipo se encuentre entre los válidos.
	if (UtilsStringChar.isNullOrEmptyTrim(assertType)) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.CL_LOG001, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_QUALIFICATION_CRITERIALIST, ITSLElementsAndAttributes.ELEMENT_EXTENSION_QUALIFICATION_CRITERIALIST_ASSERT }));
	} else if (!assertType.equals(ASSERT_ALL) && !assertType.equals(ASSERT_ATLEASTONE) && !assertType.equals(ASSERT_NONE)) {
	    throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.CL_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_QUALIFICATION_CRITERIALIST_ASSERT, assertType }));
	}

	// Comprobamos la lista de KeyUsage, la cual podría estar vacía.
	if (!keyUsageList.isEmpty()) {
	    for (KeyUsage keyUsage: keyUsageList) {
		keyUsage.checkExtensionValueSpec119612Vers020101(tsl, shi, isCritical);
	    }
	}

	// Comprobamos la lista de identificadores de política, la cual podría
	// estar vacía.
	if (!policySetList.isEmpty()) {
	    for (PoliciesList policiesList: policySetList) {
		policiesList.checkExtensionValueSpec119612Vers020101(tsl, shi, isCritical);
	    }
	}

	// Comprobamos la lista de subcriterios.
	if (!criteriaListList.isEmpty()) {
	    for (CriteriaList cl: criteriaListList) {
		cl.checkExtensionValueSpec119612Vers020101(tsl, shi, isCritical);
	    }
	}

	// Comprobamos el elemento 'otro criterio'.
	if (otherCriteria != null) {
	    otherCriteria.checkOtherCriteriaValue(tsl);
	}

    }

    /**
     * Checks if the input certificate is accomplished with this Criteria List.
     * @param cert X509v3 certificate to check.
     * @return <code>true</code> if the input certificate is accomplished with this Criteria List,
     * otherwise <code>false</code>.
     * @throws TSLQualificationEvalProcessException In case of some error evaluating the input certificate
     * with the criteria lists.
     */
    public final boolean checkCertificate(X509Certificate cert) throws TSLQualificationEvalProcessException {

	boolean result = false;

	// Hacemos la comprobación según el tipo.
	if (assertType.equals(CriteriaList.ASSERT_ALL)) {

	    result = checkAllCriteriasInCert(cert);

	} else if (assertType.equals(CriteriaList.ASSERT_ATLEASTONE)) {

	    result = checkAtLeastOneInCert(cert);

	} else if (assertType.equals(CriteriaList.ASSERT_NONE)) {

	    result = checkNoneInCert(cert);

	}

	// Si no se ha pasado la validación, comprobamos la sublista de
	// criterios.
	if (!result && isThereSomeCriteriaList()) {
	    result = resultCheckCertificateWithSubCriteriaLists(cert);
	}

	return result;

    }

    /**
     * Checks if the input certificate is accomplished with all defined criteria.
     * @param cert X509v3 certificate to check.
     * @return <code>true</code> if the input certificate is accomplished with all defined criteria.,
     * otherwise <code>false</code>.
     * @throws TSLQualificationEvalProcessException In case of some error evaluating the input certificate
     * with all defined criteria.
     */
    private boolean checkAllCriteriasInCert(X509Certificate cert) throws TSLQualificationEvalProcessException {

	boolean result = true;

	// Comprobamos primero los KeyUsage, si es que hay.
	if (isThereSomeKeyUsage()) {

	    // Los recorremos y comprobamos que todos están en el certificado.
	    for (int index = 0; result && index < keyUsageList.size(); index++) {

		result = keyUsageList.get(index).checkCertificate(cert);

	    }

	}

	// Si hemos pasado la comprobación de los KeyUsage, hacemos ahora
	// la de las políticas de certificación.
	if (result && isThereSomePolicySet()) {

	    // Los recorremos y comprobamos que todos están en el
	    // certificado.
	    for (int index = 0; result && index < policySetList.size(); index++) {
		result = policySetList.get(index).checkCertificate(cert);
	    }

	}

	if (result && otherCriteria != null)

	{

	    try {
		result = otherCriteria.checkCertificateWithThisCriteria(cert);
	    } catch (TSLCertificateValidationException e) {
		throw new TSLQualificationEvalProcessException(Language.getResIntegraTsl(ILogTslConstant.CL_LOG003), e);
	    }

	}

	return result;

    }

    /**
     * Checks if the input certificate is accomplished with at least one defined criteria.
     * @param cert X509v3 certificate to check.
     * @return <code>true</code> if the input certificate is accomplished with at least one defined criteria.,
     * otherwise <code>false</code>.
     * @throws TSLQualificationEvalProcessException In case of some error evaluating the input certificate
     * with at least one defined criteria.
     */
    private boolean checkAtLeastOneInCert(X509Certificate cert) throws TSLQualificationEvalProcessException {

	boolean result = false;

	// Comprobamos primero los KeyUsage, si es que hay.
	if (isThereSomeKeyUsage()) {

	    // Los recorremos y comprobamos que al menos uno lo cumple el
	    // certificado.
	    for (int index = 0; !result && index < keyUsageList.size(); index++) {

		result = keyUsageList.get(index).checkCertificate(cert);

	    }

	}

	// Si NO hemos pasado la comprobación de los KeyUsage, hacemos ahora
	// la de las políticas de certificación.
	if (!result && isThereSomePolicySet()) {

	    // Los recorremos y comprobamos que al menos uno está en el
	    // certificado.
	    for (int index = 0; !result && index < policySetList.size(); index++) {
		result = policySetList.get(index).checkCertificate(cert);
	    }

	}

	if (!result && otherCriteria != null) {

	    try {
		result = otherCriteria.checkCertificateWithThisCriteria(cert);
	    } catch (TSLCertificateValidationException e) {
		throw new TSLQualificationEvalProcessException(Language.getResIntegraTsl(ILogTslConstant.CL_LOG003), e);
	    }

	}

	return result;

    }

    /**
     * Checks if the input certificate does not accomplished with any defined criteria.
     * @param cert X509v3 certificate to check.
     * @return <code>true</code> if the input certificate does not accomplished with any defined criteria,
     * otherwise <code>false</code>.
     * @throws TSLQualificationEvalProcessException In case of some error evaluating the input certificate
     * with any defined criteria.
     */
    private boolean checkNoneInCert(X509Certificate cert) throws TSLQualificationEvalProcessException {

	// Que no cumpla ninguna es lo mismo a que no exista al menos una que sí
	// lo cumpla.
	return !checkAtLeastOneInCert(cert);

    }

    /**
     * Checks if the input certificate accomplished with sub criterias.
     * @param cert X509v3 certificate to check.
     * @return <code>true</code> if the input certificate accomplished with sub criterias,
     * otherwise <code>false</code>.
     * @throws TSLQualificationEvalProcessException In case of some error processing the
     * input certificate with the criteria list.
     */
    private boolean resultCheckCertificateWithSubCriteriaLists(X509Certificate cert) throws TSLQualificationEvalProcessException {

	boolean result = false;

	for (int index = 0; !result && index < criteriaListList.size(); index++) {
	    result = criteriaListList.get(index).checkCertificate(cert);
	}

	return result;

    }

}
