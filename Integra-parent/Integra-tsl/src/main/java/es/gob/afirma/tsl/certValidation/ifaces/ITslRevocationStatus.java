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
 * <b>File:</b><p>es.gob.afirma.tsl.certValidation.ifaces.ITslRevocationStatus.java.</p>
 * <b>Description:</b><p>Interface that defines the constants for the result of revocation status of a certificate.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 19/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 15/06/2021.
 */
package es.gob.afirma.tsl.certValidation.ifaces;

import es.gob.afirma.tsl.utils.NumberConstants;

/** 
 * <p>Interface that defines the constants for the result of revocation status of a certificate.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 15/06/2021.
 */
public interface ITslRevocationStatus {
    /**
	 * Constant attribute that represents a revocation status of a certificate:
	 * The certificate has been detected by the TSL, but its revocation status is unknown.
	 */
	int RESULT_DETECTED_REVSTATUS_UNKNOWN = 1;

	/**
	 * Constant attribute that represents a revocation status of a certificate:
	 * The certificate has been detected by the TSL and its revocation status is valid.
	 */
	int RESULT_DETECTED_REVSTATUS_VALID = 2;

	/**
	 * Constant attribute that represents a revocation status of a certificate:
	 * The certificate has been detected by the TSL and its revocation status is revoked.
	 */
	int RESULT_DETECTED_REVSTATUS_REVOKED = NumberConstants.INT_3;

	/**
	 * Constant attribute that represents a revocation status of a certificate:
	 * The certificate has been detected by the TSL and its certificate chain is not valid (expired).
	 */
	int RESULT_DETECTED_REVSTATUS_CERTCHAIN_NOTVALID = NumberConstants.INT_4;

	/**
	 * Constant attribute that represents a revocation status of a certificate:
	 * The certificate has been detected by the TSL and the service status is revoked.
	 */
	int RESULT_DETECTED_REVSTATUS_REVOKED_SERVICESTATUS = NumberConstants.INT_5;

	/**
	 * Constant attribute that represents a revocation status of a certificate:
	 * The certificate has been detected by the TSL and the service status is not valid.
	 */
	int RESULT_DETECTED_REVSTATUS_CERTCHAIN_NOTVALID_SERVICESTATUS = NumberConstants.INT_6;
}
