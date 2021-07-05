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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.ifaces.ITSLValidatorResult.java.</p>
 * <b>Description:</b><p>Interface that represents a validation result using TSL..</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 13/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 15/06/2021.
 */
package es.gob.afirma.tsl.certValidation.ifaces;



import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.BasicOCSPResponse;

import java.util.Date;
import java.util.Map;



import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;
import es.gob.afirma.tsl.parsing.impl.common.TSLCertificateExtensionAnalyzer;
import es.gob.afirma.tsl.parsing.impl.common.TSPService;
import es.gob.afirma.tsl.parsing.impl.common.TrustServiceProvider;
import es.gob.afirma.tsl.utils.NumberConstants;


/** 
 * <p>Interface that represents a validation result using TSL. .</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 15/06/2021.
 */
public interface ITSLValidatorResult {
	/**
	 * Constant attribute that represents a validation result:
	 * The certificate has not been detected with the TSL.
	 */
	int RESULT_NOT_DETECTED = 0;

	/**
	 * Constant attribute that represents a validation result:
	 * The certificate has been detected by the TSL, but its state is unknown.
	 */
	int RESULT_DETECTED_STATE_UNKNOWN = 1;

	/**
	 * Constant attribute that represents a validation result:
	 * The certificate has been detected by the TSL and its state is valid.
	 */
	int RESULT_DETECTED_STATE_VALID = 2;

	/**
	 * Constant attribute that represents a validation result:
	 * The certificate has been detected by the TSL and its state is revoked.
	 */
	int RESULT_DETECTED_STATE_REVOKED = NumberConstants.INT_3;

	/**
	 * Constant attribute that represents a validation result:
	 * The certificate has been detected by the TSL and its certificate chain is not valid (expired).
	 */
	int RESULT_DETECTED_STATE_CERTCHAIN_NOTVALID = NumberConstants.INT_4;

	/**
	 * Constant attribute that represents a validation result:
	 * The certificate has been detected by the TSL and the service status is revoked.
	 */
	int RESULT_DETECTED_STATE_REVOKED_SERVICESTATUS = NumberConstants.INT_5;

	/**
	 * Constant attribute that represents a validation result:
	 * The certificate has been detected by the TSL and the service status is not valid.
	 */
	int RESULT_DETECTED_STATE_CERTCHAIN_NOTVALID_SERVICESTATUS = NumberConstants.INT_6;

	/**
	 * Gets the TSL Country/Region Code.
	 * @return the TSL Country/Region Code.
	 */
	String getTslCountryRegionCode();

	/**
	 * Gets the TSL Sequence Number.
	 * @return the value of the TSL Sequence Number.
	 */
	int getTslSequenceNumber();

	/**
	 * Gets the TSL ETSI TS Specification and Version.
	 * @return the TSL ETSI TS Specification and Version.
	 */
	String getTslEtsiSpecificationAndVersion();

	/**
	 * Gets the TSL Issue Date.
	 * @return the TSL Issue Date.
	 */
	Date getTslIssueDate();

	/**
	 * Gets the TSL Next Update Date.
	 * @return the TSL Next Update Date.
	 */
	Date getTslNextUpdate();

	/**
	 * Gets the extension analyzer for the certificate to validate.
	 * @return the extension analyzer for the certificate to validate.
	 */
	TSLCertificateExtensionAnalyzer getTslCertificateExtensionAnalyzer();

	/**
	 * Gets the validation result. It only can be one of the following:<br>
	 * <ul>
	 *   <li>{@link ITSLValidatorResult#RESULT_NOT_DETECTED}</li>
	 *   <li>{@link ITSLValidatorResult#RESULT_DETECTED_STATE_UNKNOWN}</li>
	 *   <li>{@link ITSLValidatorResult#RESULT_DETECTED_STATE_VALID}</li>
	 *   <li>{@link ITSLValidatorResult#RESULT_DETECTED_STATE_REVOKED}</li>
	 *   <li>{@link ITSLValidatorResult#RESULT_DETECTED_STATE_CERTCHAIN_NOTVALID}</li>
	 *   <li>{@link ITSLValidatorResult#RESULT_DETECTED_STATE_REVOKED_SERVICESTATUS}</li>
	 *   <li>{@link ITSLValidatorResult#RESULT_DETECTED_STATE_CERTCHAIN_NOTVALID_SERVICESTATUS}</li>
	 * </ul>
	 * @return int that represents the validation result.
	 */
	int getResult();

	/**
	 * Checks if the validation result value is obtained from a TSL-Service status.
	 * @return <code>null</code> if the certificate has not been detected or its status is unknown. <code>true</code>
	 * if the status has been determined by a TSL-Service status, otherwise <code>false</code>.
	 */
	Boolean isResultFromServiceStatus();

	/**
	 * Checks if the validation result value is obtained from a DP or AIA.
	 * @return <code>null</code> if the certificate has not been detected or its status is unknown. <code>true</code>
	 * if the status has been determined by a DP or AIA, otherwise <code>false</code>.
	 */
	Boolean isResultFromDPorAIA();

	/**
	 * Checks if the result is different of {@link ITSLValidatorResult#RESULT_NOT_DETECTED}.
	 * @return <code>true</code> if the result is different of {@link ITSLValidatorResult#RESULT_NOT_DETECTED},
	 * otherwise <code>false</code>.
	 */
	boolean hasBeenDetectedTheCertificate();

	/**
	 * Checks if the result is equal to {@link ITSLValidatorResult#RESULT_DETECTED_STATE_UNKNOWN}.
	 * @return <code>true</code> if the result is equal to {@link ITSLValidatorResult#RESULT_DETECTED_STATE_UNKNOWN},
	 * otherwise <code>false</code>.
	 */
	boolean hasBeenDetectedTheCertificateWithUnknownState();

	/**
	 * Check if the TSL used is from an European member.
	 * @return <code>true</code> if the TSL is from an European member, otherwise <code>false</code>.
	 */
	boolean isEuropean();

	/**
	 * Gets the name of the TSP which has detected the certificate.
	 * @return the name of the TSP which has detected the certificate, or <code>null</code> if
	 * the certificate has not been detected.
	 */
	String getTSPName();

	/**
	 * Gets the TSP which has detected the certificate.
	 * @return TSP which has detected the certificate, or <code>null</code> if
	 * the certificate has not been detected.
	 */
	TrustServiceProvider getTSP();

	/**
	 * Gets the name of the TSP Service which has detected the certificate.
	 * @return the name of the TSP Service which has detected the certificate, or <code>null</code> if
	 * the certificate has not been detected.
	 */
	String getTSPServiceNameForDetect();

	/**
	 * Gets the TSP Service which has detected the certificate.
	 * @return TSP Service which has detected the certificate, or <code>null</code> if
	 * the certificate has not been detected.
	 */
	TSPService getTSPServiceForDetect();

	/**
	 * Gets the name of the TSP Service History-Information which has detected the certificate.
	 * @return the name of the TSP Service History-Information which has detected the certificate,
	 * or <code>null</code> if the certificate has not been detected.
	 */
	String getTSPServiceHistoryInformationInstanceNameForDetect();

	/**
	 * Gets the TSP Service History-Information which has detected the certificate.
	 * @return TSP Service History-Information which has detected the certificate, or
	 * <code>null</code> if the certificate has not been detected.
	 */
	ServiceHistoryInstance getTSPServiceHistoryInformationInstanceForDetect();

	/**
	 * Gets the name of the TSP Service which has validate the certificate.
	 * @return the name of the TSP Service which has validate the certificate, or <code>null</code> if
	 * the certificate has not been validated.
	 */
	String getTSPServiceNameForValidate();

	/**
	 * Gets the TSP Service which has validate the certificate.
	 * @return the TSP Service which has validate the certificate, or <code>null</code> if
	 * the certificate has not been validated.
	 */
	TSPService getTSPServiceForValidate();

	/**
	 * Gets the name of the TSP Service History-Information which has validate the certificate.
	 * @return the name of the TSP Service History-Information which has validate the
	 * certificate, or <code>null</code> if the certificate has not been validated.
	 */
	String getTSPServiceHistoryInformationInstanceNameForValidate();

	/**
	 * Gets the TSP Service History-Information which has validate the certificate.
	 * @return the TSP Service History-Information which has validate the certificate,
	 * or <code>null</code> if the certificate has not been validated.
	 */
	ServiceHistoryInstance getTSPServiceHistoryInformationInstanceForValidate();

	/**
	 * Constant attribute that represents the value for a mapping certificate type unknown.
	 */
	int MAPPING_TYPE_UNKNOWN = 0;

	/**
	 * Constant attribute that represents the value for a mapping certificate type non qualified.
	 */
	int MAPPING_TYPE_NONQUALIFIED = 1;

	/**
	 * Constant attribute that represents the value for a mapping certificate type qualified.
	 */
	int MAPPING_TYPE_QUALIFIED = 2;

	/**
	 * Gets the mapping type of the validated certificate. It only can be one of the following:<br>
	 * <ul>
	 *   <li>{@link ITSLValidatorResult#MAPPING_TYPE_UNKNOWN}</li>
	 *   <li>{@link ITSLValidatorResult#MAPPING_TYPE_NONQUALIFIED}</li>
	 *   <li>{@link ITSLValidatorResult#MAPPING_TYPE_QUALIFIED}</li>
	 * </ul>
	 * @return the mapping type of the validated certificate.
	 */
	int getMappingType();

	/**
	 * Constant attribute that represents the value for a mapping certificate classification other/unknown.
	 */
	int MAPPING_CLASSIFICATION_OTHER_UNKNOWN = 0;

	/**
	 * Constant attribute that represents the value for a mapping certificate classification natural person.
	 */
	int MAPPING_CLASSIFICATION_NATURAL_PERSON = 1;

	/**
	 * Constant attribute that represents the value for a mapping certificate classification legal person.
	 */
	int MAPPING_CLASSIFICATION_LEGALPERSON = 2;

	/**
	 * Constant attribute that represents the value for a mapping certificate classification ESEAL.
	 */
	int MAPPING_CLASSIFICATION_ESEAL = NumberConstants.INT_3;

	/**
	 * Constant attribute that represents the value for a mapping certificate classification ESIG.
	 */
	int MAPPING_CLASSIFICATION_ESIG = NumberConstants.INT_4;

	/**
	 * Constant attribute that represents the value for a mapping certificate classification WSA.
	 */
	int MAPPING_CLASSIFICATION_WSA = NumberConstants.INT_5;

	/**
	 * Constant attribute that represents the value for a mapping certificate classification TSA.
	 */
	int MAPPING_CLASSIFICATION_TSA = NumberConstants.INT_6;

	/**
	 * Gets the mapping classification of the validated certificate. It only can be one of the following:<br>
	 * <ul>
	 *   <li>{@link ITSLValidatorResult#MAPPING_CLASSIFICATION_OTHER_UNKNOWN}</li>
	 *   <li>{@link ITSLValidatorResult#MAPPING_CLASSIFICATION_PERSON}</li>
	 *   <li>{@link ITSLValidatorResult#MAPPING_CLASSIFICATION_LEGALPERSON}</li>
	 *   <li>{@link ITSLValidatorResult#MAPPING_CLASSIFICATION_ESEAL}</li>
	 *   <li>{@link ITSLValidatorResult#MAPPING_CLASSIFICATION_ESIG}</li>
	 *   <li>{@link ITSLValidatorResult#MAPPING_CLASSIFICATION_WSA}</li>
	 *   <li>{@link ITSLValidatorResult#MAPPING_CLASSIFICATION_TSA}</li>
	 * </ul>
	 * @return the mapping classification of the validated certificate.
	 */
	int getMappingClassification();

	/**
	 * Constant attribute that represents the value for a mapping certificate QSCD unknown.
	 */
	int MAPPING_QSCD_UNKNOWN = 0;

	/**
	 * Constant attribute that represents the value for a mapping certificate no QSCD.
	 */
	int MAPPING_QSCD_NO = 1;

	/**
	 * Constant attribute that represents the value for a mapping certificate QSCD.
	 */
	int MAPPING_QSCD_YES = 2;

	/**
	 * Constant attribute that represents the value for a mapping certificate QSCD specified in the attributes.
	 */
	int MAPPING_QSCD_ASINCERT = NumberConstants.INT_3;

	/**
	 * Constant attribute that represents the value for a mapping certificate QSCD managed by TSP.
	 */
	int MAPPING_QSCD_YES_MANAGEDONBEHALF = NumberConstants.INT_4;

	/**
	 * Gets the mapping QSCD of the validated certificate. It only can be one of the following:<br>
	 * <ul>
	 *   <li>{@link ITSLValidatorResult#MAPPING_QSCD_UNKNOWN}</li>
	 *   <li>{@link ITSLValidatorResult#MAPPING_QSCD_NO}</li>
	 *   <li>{@link ITSLValidatorResult#MAPPING_QSCD_YES}</li>
	 *   <li>{@link ITSLValidatorResult#MAPPING_QSCD_ASINCERT}</li>
	 *   <li>{@link ITSLValidatorResult#MAPPING_QSCD_YES_MANAGEDONBEHALF}</li>
	 * </ul>
	 * @return the mapping SSCD of the validated certificate.
	 */
	int getMappingQSCD();

	/**
	 * Gets all the mappings information calculated for the validated certificate.
	 * @return Map with the pairs <MappingName, MappingValue> calculated for the validated certificate.
	 */
	Map<String, String> getMappings();

	/**
	 * Sets the mappings calculated for the validated certificate.
	 * @param mappings Map with the pairs <MappingName, MappingValue> calculated for the validated certificate.
	 */
	void setMappings(Map<String, String> mappings);

	/**
	 * Gets the X509 Certificate of the issuer of the certificate to validate (if this has been found).
	 * @return the X509 Certificate of the issuer of the certificate to validate (if this has been found),
	 * otherwise <code>null</code>.
	 */
	X509Certificate getIssuerCert();

	/**
	 * Gets the Basic OCSP Response selected how revocation value.
	 * @return Basic OCSP Response selected how revocation value, <code>null</code> if there is not.
	 */
	BasicOCSPResponse getRevocationValueBasicOCSPResponse();

	/**
	 * Sets the selected revocation value of type Basic OCSP Response.
	 * @param bor Basic OCSP Response to assign how the selected revocation value.
	 */
	void setRevocationValueBasicOCSPResponse(BasicOCSPResponse bor);

	/**
	 * Gets the CRL selected how revocation value.
	 * @return CRL selected how revocation value, <code>null</code> if there is not.
	 */
	X509CRL getRevocationValueCRL();

	/**
	 * Sets the selected revocation value of type CRL.
	 * @param crl CRL to assign how the selected revocation value.
	 */
	void setRevocationValueCRL(X509CRL crl);

	/**
	 * Gets the URL from which the revocation value has been obtained.
	 * @return the URL from which the revocation value has been obtained.
	 */
	String getRevocationValueURL();

	/**
	 * Sets the URL from which the revocation value has been obtained.
	 * @param revValueUrl the URL from which the revocation value has been obtained.
	 */
	void setRevocationValueURL(String revValueUrl);

	/**
	 * Gets the revocation date of the certificate validate (if it is revoked).
	 * @return the revocation date of the certificate validate (if it is revoked), otherwise <code>null</code>.
	 */
	Date getRevocationDate();

	/**
	 * Gets the Revocation Reason for the certificate that has been validated.
	 * @return Revocation Reason integer representation for the certificate validated,
	 * or -1 if was not possible to validate or the certificate is not revoked.
	 */
	int getRevocationReason();
}
