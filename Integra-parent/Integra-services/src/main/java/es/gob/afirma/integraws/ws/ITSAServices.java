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
 * <b>File:</b><p>es.gob.afirma.integraws.ws.ITSAServices.java.</p>
 * <b>Description:</b><p> Interface that contains tsa service methods.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.ws;

import es.gob.afirma.integraws.beans.RequestTimestamp;
import es.gob.afirma.integraws.beans.ResponseTimestamp;

/** 
 * <p>Interface of tsa services provided in Integra WS.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public interface ITSAServices {

    /**
     * Method that obtains the response of the timestamp generate service.
     * @param timestampReq Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseTimestamp generateTimestamp(RequestTimestamp timestampReq);

    /**
     * Method that obtains the response of the timestamp verify service.
     * @param timestampReq Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseTimestamp verifyTimestamp(RequestTimestamp timestampReq);

    /**
     * Method that obtains the response of the timestamp renove service.
     * @param timestampReq Object that represents request to service.
     * @return Result object of service request.
     */
    ResponseTimestamp renewTimestamp(RequestTimestamp timestampReq);

}
