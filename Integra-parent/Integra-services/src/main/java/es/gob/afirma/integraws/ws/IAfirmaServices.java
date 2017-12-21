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
 * <b>File:</b><p>es.gob.afirma.integraws.ws.IAfirmaServices.java.</p>
 * <b>Description:</b><p> Interface that contains afirma service methods.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.ws;

import es.gob.afirma.integraws.beans.RequestServerArchive;
import es.gob.afirma.integraws.beans.RequestServerBatchVerifyCertificate;
import es.gob.afirma.integraws.beans.RequestServerBatchVerifySignature;
import es.gob.afirma.integraws.beans.RequestServerCoSign;
import es.gob.afirma.integraws.beans.RequestServerCounterSign;
import es.gob.afirma.integraws.beans.RequestServerPending;
import es.gob.afirma.integraws.beans.RequestServerSign;
import es.gob.afirma.integraws.beans.RequestServerUpgradeSignature;
import es.gob.afirma.integraws.beans.RequestValidateOCSP;
import es.gob.afirma.integraws.beans.RequestServerVerifyCertificate;
import es.gob.afirma.integraws.beans.RequestServerVerifySignature;
import es.gob.afirma.integraws.beans.ResponseServerArchive;
import es.gob.afirma.integraws.beans.ResponseServerAsynchronous;
import es.gob.afirma.integraws.beans.ResponseServerBatchVerifyCertificate;
import es.gob.afirma.integraws.beans.ResponseServerBatchVerifySignature;
import es.gob.afirma.integraws.beans.ResponseServerSign;
import es.gob.afirma.integraws.beans.ResponseValidateOCSP;
import es.gob.afirma.integraws.beans.ResponseServerVerifyCertificate;
import es.gob.afirma.integraws.beans.ResponseServerVerifySignature;


/** 
 * <p>Interface of afirma services provided in Integra WS.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public interface IAfirmaServices {
    
    /**
     * Method that validates a certificate against an OCSP responder.
     * @param request Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseValidateOCSP serverValidateCertificateOcsp(RequestValidateOCSP request);
    
    /**
     * Method that obtains the response of the server signature service.
     * @param request Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseServerSign serverSign(RequestServerSign request);
    
    /**
     * Method that obtains the response of the server co-signature service.
     * @param coSigReq Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseServerSign serverCoSign(RequestServerCoSign coSigReq);
    
    /**
     * Method that obtains the response of the server counter-signature service.
     * @param couSigReq 
     * @return Result object of service request.
     */
    ResponseServerSign serverCounterSign(RequestServerCounterSign couSigReq);
    
    /**
     * Method that obtains the response of the upgrade signature service.
     * @param upgSigReq Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseServerSign serverUpgradeSignature(RequestServerUpgradeSignature upgSigReq);
    
    /**
     * Method that obtains the response of the async processes service.
     * @param pendingRequest Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseServerAsynchronous serverAsynchronousRequest(RequestServerPending pendingRequest);
    
    /**
     * Method that obtains the response of the verify certificates on batch service.
     * @param batVerCerReq Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseServerBatchVerifyCertificate serverBatchVerifyCertificate(RequestServerBatchVerifyCertificate batVerCerReq);
    
    /**
     * Method that obtains the response of the verify signatures on batch service.
     * @param batVerSigReq Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseServerBatchVerifySignature serverBatchVerifySignature(RequestServerBatchVerifySignature batVerSigReq);
    
    /**
     * Method that obtains the response of the archive signatures retrieve service.
     * @param archiveRequest Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseServerArchive serverGetArchiveRetrieval(RequestServerArchive archiveRequest);
    
    /**
     * Method that obtains the response of the verify signature service.
     * @param verSigReq Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseServerVerifySignature serverVerifySignature(RequestServerVerifySignature verSigReq);
    
    /**
     * Method that obtains the response of the verify certificate service.
     * @param verCerReq Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseServerVerifyCertificate serverVerifyCertificate(RequestServerVerifyCertificate verCerReq);
    
}
