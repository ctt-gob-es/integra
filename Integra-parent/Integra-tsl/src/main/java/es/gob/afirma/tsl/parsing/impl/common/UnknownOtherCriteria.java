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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.UnknownOtherCriteria.java.</p>
 * <b>Description:</b><p>Class that represents a implementation for a specific Other Criteria
 * Any Type: Unknown element.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 11/11/2020.
 */
package es.gob.afirma.tsl.parsing.impl.common;

import java.security.cert.X509Certificate;

import es.gob.afirma.tsl.exceptions.TSLCertificateValidationException;
import es.gob.afirma.tsl.exceptions.TSLMalformedException;


/** 
 * <p>Class that represents a implementation for a specific Other Criteria
 * Any Type: Unknown element.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 11/11/2020.
 */
public class UnknownOtherCriteria extends OtherCriteria {

    /**
	 * Constant attribute that represents the serial version UID.
	 */
    private static final long serialVersionUID = 8451655192276226238L;

	/**
	 * Attribute that represents element local name of this unknown other criteria.
	 */
	private String elementLocalName = null;

	/**
	 * Constructor method for the class UnknownOtherCriteria.java.
	 */
	private UnknownOtherCriteria() {
		super();
	}

	/**
	 * Constructor method for the class UnknownOtherCriteria.java.
	 * @param elementName Element local name for the unknown other criteria.
	 */
	public UnknownOtherCriteria(String elementName) {
		this();
		elementLocalName = elementName;
	}

	/**
	 * Gets the value of the attribute {@link #elementLocalName}.
	 * @return the value of the attribute {@link #elementLocalName}.
	 */
	public final String getElementLocalName() {
		return elementLocalName;
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.OtherCriteria#getOtherCriteriaType()
	 */
	@Override
	protected final String getOtherCriteriaType() {
		return elementLocalName;
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.ifaces.IAnyTypeOtherCriteria#isUnknownOtherCriteria()
	 */
	@Override
	public final boolean isUnknownOtherCriteria() {
		// Esta implementación es genérica y hace referencia a que se ha
		// encontrado un "Other Criteria"
		// de tipo desconocido.
		return true;
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.ifaces.IAnyTypeOtherCriteria#checkCertificateWithThisCriteria(java.security.cert.X509Certificate)
	 */
	@Override
	public final boolean checkCertificateWithThisCriteria(X509Certificate x509cert) throws TSLCertificateValidationException {

		// Al ser desconocida, no se sabe como tratar el certificado.
		return false;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.OtherCriteria#checkOtherCriteriaValueSpec119612Vers020101()
	 */
	@Override
	protected final void checkOtherCriteriaValueSpec119612Vers020101() throws TSLMalformedException {
		return;
	}


}
