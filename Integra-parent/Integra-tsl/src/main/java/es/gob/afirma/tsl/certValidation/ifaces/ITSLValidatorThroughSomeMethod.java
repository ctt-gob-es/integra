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
 * <b>File:</b><p>es.gob.afirma.tsl.certValidation.ifaces.ITSLValidatorThroughSomeMethod.java.</p>
 * <b>Description:</b><p> Interface that represents a certificate validation using TSL through some specific method.</p>.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 16/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.2, 19/09/2022.
 */
package es.gob.afirma.tsl.certValidation.ifaces;


import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import es.gob.afirma.tsl.certValidation.impl.common.TSLValidatorResult;
import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;
import es.gob.afirma.tsl.parsing.impl.common.TSPService;

/** 
 * <p>Interface that represents a certificate validation using TSL through some specific method.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 19/09/2022.
 */
public interface ITSLValidatorThroughSomeMethod {
    /**
	 * Method that validates the input X509v3 certificate using a TSL - TSP Service (CRL or OCSP).
	 * @param cert Certificate X509v3 to validate its revocation.
	 * @param validationDate Validation date to check the certificate status revocation.
	 * @param tspService TSL - TSP Service from which extract the information to validate the certificate.
	 * @param shi TSL - TSP Service History Instance from which extract the information to validate the certificate.
	 * @param isHistoricServiceInf Flag that indicates if the input Service Information is from an Historic Service (<code>true</code>)
	 * or not (<code>false</code>).
	 * @param validationResult Object where must be stored the validation result data.
	 */
	void validateCertificate(X509Certificate cert, Date validationDate, TSPService tspService, ServiceHistoryInstance shi, boolean isHistoricServiceInf, TSLValidatorResult validationResult);

	/**
	 * Method that searchs if some of the input revocation values are verified by the input service, and
	 * then use it for check the revocation status of the certificate.
	 * @param cert Certificate X509v3 to validate its revocation.
	 * @param basicOcspResponse Basic OCSP response to check if it is compatible with the TSL.
	 * @param crl CRL to check if is compatible with the TSL to check the revocation status of the certificate.
	 * @param validationDate Validation date to check the certificate status revocation.
	 * @param shi TSL - TSP Service History Information from which extract the information to validate the certificate.
	 * @param validationResult Object where must be stored the validation result data.
	 */
	void searchRevocationValueCompatible(X509Certificate cert, BasicOCSPResp basicOcspResponse, X509CRL crl, Date validationDate, ServiceHistoryInstance shi, TSLValidatorResult validationResult);
}
