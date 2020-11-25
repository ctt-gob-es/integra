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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.ifaces.IAnyTypeOtherCriteria.java.</p>
 * <b>Description:</b><p>Interface that defines the common method for any type other criteria
 * in a Criteria List.</p>
 * <b>Project:</b><p>Platform for detection and validation of certificates recognized in European TSL.</p>
 * <b>Date:</b><p>11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 11/11/2020.
 */
package es.gob.afirma.tsl.parsing.ifaces;

import java.io.Serializable;
import java.security.cert.X509Certificate;

import es.gob.afirma.tsl.exceptions.TSLCertificateValidationException;
import es.gob.afirma.tsl.exceptions.TSLMalformedException;

/**
 * <p>Interface that defines the common method for any type other criteria
 * in a Criteria List.</p>
 * <b>Project:</b><p>Platform for detection and validation of certificates recognized in European TSL.</p>
 * @version 1.0, 11/11/2020.
 */
public interface IAnyTypeOtherCriteria extends Serializable {

	/**
	 * Checks if the Other Criteria has an appropiate value in the TSL.
	 * @param tsl TSL Object representation that contains this Other Criteria.
	 * @throws TSLMalformedException In case of the Criteria Value has not a correct value.
	 */
	void checkOtherCriteriaValue(ITSLObject tsl) throws TSLMalformedException;

	/**
	 * Checks if the input certificate verified this criteria.
	 * @param x509cert X509v3 certificate to check.
	 * @return <code>true</code> if this criteria is accomplished by the input certificate,
	 * otherwise <code>false</code>.
	 * @throws TSLCertificateValidationException In case of the certificate does not pass
	 * the validation process.
	 */
	boolean checkCertificateWithThisCriteria(X509Certificate x509cert) throws TSLCertificateValidationException;

	/**
	 * Checks if this criteria is unknown. In that case must be ignored.
	 * @return <code>true</code> if it is unknown, otherwise <code>false</code>.
	 */
	boolean isUnknownOtherCriteria();

}
