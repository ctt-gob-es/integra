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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.ExtendedKeyUsageOtherCriteria.java.</p>
 * <b>Description:</b><p>Class that represents a implementation for a specific Other Criteria
 * Any Type: ExtendedKeyUsage element.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 11/11/2020.
 */
package es.gob.afirma.tsl.parsing.impl.common;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import es.gob.afirma.i18n.Language;
import es.gob.afirma.tsl.exceptions.TSLCertificateValidationException;
import es.gob.afirma.tsl.exceptions.TSLMalformedException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.parsing.ifaces.ITSLElementsAndAttributes;


/** 
 * <p>Class that represents a implementation for a specific Other Criteria
 * Any Type: ExtendedKeyUsage element.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 11/11/2020.
 */
public class ExtendedKeyUsageOtherCriteria extends OtherCriteria {

	/**
	 * Constant attribute that represents the serial version UID.
	 */
    private static final long serialVersionUID = -7209732270626956833L;

	/**
	 * Constant attribute that represents the token 'urn:oid'.
	 */
	public static final String TOKEN_URN_OID = "urn:oid";

	/**
	 * Attribute that represents the list of Extended Key Usage OID.
	 */
	private List<String> oidList = null;

	/**
	 * Constructor method for the class ExtendedKeyUsageOtherCriteria.java.
	 */
	public ExtendedKeyUsageOtherCriteria() {
		oidList = new ArrayList<String>();
	}

	/**
	 * Adds a new OID.
	 * @param oid OID string representation.
	 */
	public final void addNewOID(String oid) {
		if (oid != null) {
			oidList.add(oid);
		}
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.OtherCriteria#getOtherCriteriaType()
	 */
	@Override
	protected final String getOtherCriteriaType() {
		return ITSLElementsAndAttributes.ELEMENT_OTHER_CRITERIA_EXTENDEDKEYUSAGE_LOCALNAME;
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.ifaces.IAnyTypeOtherCriteria#isUnknownOtherCriteria()
	 */
	@Override
	public final boolean isUnknownOtherCriteria() {
		// Esta implementación hace referencia a un elemento conocido,
		// por lo que devolvemos false.
		return false;
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.ifaces.IAnyTypeOtherCriteria#checkCertificateWithThisCriteria(java.security.cert.X509Certificate)
	 */
	@Override
	public final boolean checkCertificateWithThisCriteria(X509Certificate x509cert) throws TSLCertificateValidationException {

		// Inicializamos el resultado por defecto a que el certificado no cumple
		// las restricciones necesarias.
		boolean result = false;

		// Ahora comprobamos que el certificado contiene es su extensión de
		// claves todas y cada una
		// de las definidas en los distintos OID.
		List<String> extendedKeyUsageList = null;
		try {
			extendedKeyUsageList = x509cert.getExtendedKeyUsage();
		} catch (CertificateParsingException e) {
			throw new TSLCertificateValidationException(Language.getResIntegraTsl(ILogTslConstant.EKVOC_LOG001), e);
		}
		if (extendedKeyUsageList != null && extendedKeyUsageList.containsAll(oidList)) {
			result = true;
		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.OtherCriteria#checkOtherCriteriaValueSpec119612Vers020101()
	 */
	@Override
	protected final void checkOtherCriteriaValueSpec119612Vers020101() throws TSLMalformedException {

		// Debe existir al menos un OID.
		if (oidList.isEmpty()) {
			throw new TSLMalformedException(Language.getResIntegraTsl(ILogTslConstant.EKVOC_LOG002));
		}

	}

}
