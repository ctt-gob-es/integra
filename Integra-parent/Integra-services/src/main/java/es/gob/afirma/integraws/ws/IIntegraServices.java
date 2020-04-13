// Copyright (C) 2020 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.integraws.ws.IIntegraServices.java.</p>
 * <b>Description:</b><p> Interface that contains integra sign service methods.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.1, 13/04/2020.
 */
package es.gob.afirma.integraws.ws;

import es.gob.afirma.integraws.beans.RequestGetSignedData;
import es.gob.afirma.integraws.beans.RequestPAdESRubricSign;
import es.gob.afirma.integraws.beans.RequestSign;
import es.gob.afirma.integraws.beans.RequestUpgradeSign;
import es.gob.afirma.integraws.beans.RequestVerifySign;
import es.gob.afirma.integraws.beans.ResponseGetSignedData;
import es.gob.afirma.integraws.beans.ResponseSign;
import es.gob.afirma.integraws.beans.ResponseUpgradeSign;
import es.gob.afirma.integraws.beans.ResponseVerifySign;

/** 
 * <p>Interface of sign services provided in Integra WS.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 13/04/2020.
 */
public interface IIntegraServices {

    /**
     * Method that generates a signature.
     * @param request Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseSign generateSignature(RequestSign request);
    
    /**
     * Method that generates a signature.
     * @param request Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseSign generateSignaturePAdESRubric(RequestPAdESRubricSign request);
    
    /**
     * Method that generates a signature.
     * @param request Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseSign generateMultiSignaturePAdESRubric(RequestPAdESRubricSign request);

    /**
     * Method that generates a co-signature.
     * @param request Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseSign generateCoSignature(RequestSign request);

    /**
     * Method that generates a counter-signature over a signature.
     * @param request Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseSign generateCounterSignature(RequestSign request);
    
    /**
     * Method that upgrades a signature adding a timestamp to all of the signers indicated. If the list of signers is null or empty, the timestamp
     * will be added to all of the signers of the signature. The timestamp will be added only to those signers that don't have a previous timestamp.
     * If the signature has a PDF format (PAdES-Basic, PAdES-BES, PAdES-EPES or PAdES-LTV), this method adds a Document Time-stamp dictionary and the
     * signature form will be PAdES-LTV.
     * @param request Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseUpgradeSign upgradeSignature(RequestUpgradeSign request);
    
    /**
     * Method that validates the signers of a signature.
     * @param request Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseVerifySign verifySignature(RequestVerifySign request);

    /**
     * Method that obtains the data originally signed from a signature.
     * @param request Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseGetSignedData getSignedData(RequestGetSignedData request);
    
}
