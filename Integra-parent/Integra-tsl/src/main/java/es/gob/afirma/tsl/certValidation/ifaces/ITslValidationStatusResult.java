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
 * <b>File:</b><p>es.gob.afirma.tsl.certValidation.ifaces.ITslValidationStatusResult.java.</p>
 * <b>Description:</b><p>Interface that defines the constants for the result status of the services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 19/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 19/11/2020.
 */
package es.gob.afirma.tsl.certValidation.ifaces;

import es.gob.afirma.utils.NumberConstants;

/** 
 * <p>Interface that defines the constants for the result status of the services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 19/11/2020.
 */
public interface ITslValidationStatusResult {
    /**
	 * Constant attribute that represents the value for the general result status service
	 * when there is an error checking the input parameters.
	 */
	int STATUS_ERROR_INPUT_PARAMETERS = 0;

	/**
	 * Constant attribute that represents the value for the general result status service
	 * when there is an error executing the service.
	 */
	int STATUS_ERROR_EXECUTING_SERVICE = 1;

	/**
	 * Constant attribute that represents the value for the result status service
	 * 'getTslInformation' when the TSL information has been finded.
	 */
	int STATUS_SERVICE_GETTSLINFORMATION_TSL_INFORMATION_FINDED = NumberConstants.INT_10;

	/**
	 * Constant attribute that represents the value for the result status service
	 * 'getTslInformation' when the TSL information has NOT been finded.
	 */
	int STATUS_SERVICE_GETTSLINFORMATION_TSL_INFORMATION_NOT_FINDED = NumberConstants.INT_11;

	/**
	 * Constant attribute that represents the value for the result status service
	 * 'detectCertInTslInfoAndValidation' when there is not a TSL to use with
	 * the input certificate.
	 */
	int STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_NOT_FINDED = NumberConstants.INT_20;

	/**
	 * Constant attribute that represents the value for the result status service
	 * 'detectCertInTslInfoAndValidation' when there is a TSL to use with
	 * the input certificate and the service has been executed.
	 */
	int STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED = NumberConstants.INT_21;

	/**
	 * Constant attribute that represents the value for the result status service
	 * 'detectCertInTslInfoAndValidation' when there is a TSL to use with
	 * the input certificate but it has not been detected.
	 */
	int STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_NOT_DETECTED = NumberConstants.INT_22;

	/**
	 * Constant attribute that represents the value for the result status service
	 * 'detectCertInTslInfoAndValidation' when there is a TSL to use with
	 * the input certificate and it has been detected.
	 */
	int STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_DETECTED = NumberConstants.INT_23;

	/**
	 * Constant attribute that represents the value for the result status service
	 * 'detectCertInTslInfoAndValidation' when there is a TSL to use with
	 * the input certificate and it has been detected. The certificate mapping
	 * information has NOT been collected.
	 */
	int STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_DETECTED_INFO_NOT_COLLECTED = NumberConstants.INT_24;

	/**
	 * Constant attribute that represents the value for the result status service
	 * 'detectCertInTslInfoAndValidation' when there is a TSL to use with
	 * the input certificate and it has been detected. The certificate mapping
	 * information has been collected.
	 */
	int STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_DETECTED_INFO_COLLECTED = NumberConstants.INT_25;

	/**
	 * Constant attribute that represents the value for the result status service
	 * 'detectCertInTslInfoAndValidation' when there is a TSL to use with
	 * the input certificate and it has been detected. The revocation status
	 * information has NOT been collected.
	 */
	int STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_DETECTED_REVSTATUS_NOT_COLLECTED = NumberConstants.INT_26;

	/**
	 * Constant attribute that represents the value for the result status service
	 * 'detectCertInTslInfoAndValidation' when there is a TSL to use with
	 * the input certificate and it has been detected. The revocation status
	 * information has been collected.
	 */
	int STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_DETECTED_REVSTATUS_COLLECTED = NumberConstants.INT_27;

	/**
	 * Constant attribute that represents the value for the result status service
	 * 'detectCertInTslInfoAndValidation' when there is a TSL to use with
	 * the input certificate and it has been detected. The certificate mapping
	 * information has NOT been collected. The revocation status
	 * information has NOT been collected.
	 */
	int STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_DETECTED_INFO_NOT_COLLECTED_REVSTATUS_NOT_COLLECTED = NumberConstants.INT_28;

	/**
	 * Constant attribute that represents the value for the result status service
	 * 'detectCertInTslInfoAndValidation' when there is a TSL to use with
	 * the input certificate and it has been detected. The certificate mapping
	 * information has NOT been collected. The revocation status
	 * information has been collected.
	 */
	int STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_DETECTED_INFO_NOT_COLLECTED_REVSTATUS_COLLECTED = NumberConstants.INT_29;

	/**
	 * Constant attribute that represents the value for the result status service
	 * 'detectCertInTslInfoAndValidation' when there is a TSL to use with
	 * the input certificate and it has been detected. The certificate mapping
	 * information has been collected. The revocation status
	 * information has NOT been collected.
	 */
	int STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_DETECTED_INFO_COLLECTED_REVSTATUS_NOT_COLLECTED = NumberConstants.INT_30;

	/**
	 * Constant attribute that represents the value for the result status service
	 * 'detectCertInTslInfoAndValidation' when there is a TSL to use with
	 * the input certificate and it has been detected. The certificate mapping
	 * information has been collected. The revocation status
	 * information has been collected.
	 */
	int STATUS_SERVICE_DETECTCERTINTSLINFOVALIDATION_TSL_FINDED_CERT_DETECTED_INFO_COLLECTED_REVSTATUS_COLLECTED = NumberConstants.INT_31;

}
