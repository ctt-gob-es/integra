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
 * <b>File:</b><p>es.gob.afirma.integraFacade.TSAFacadeBind.java.</p>
 * <b>Description:</b><p> Class to bind protected methods of TSAFacadeBind.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraFacade;

import es.gob.afirma.integraFacade.pojo.TimestampRequest;
import es.gob.afirma.integraFacade.pojo.TimestampResponse;



/** 
 * <p>Class to bind protected methods of TSAFacadeBind.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public final class TSAFacadeBind {

    /**
     * Attribute that represents the instance of the class.
     */
    private static TSAFacadeBind instance;

    /**
     * Constructor method for the class TSAFacadeBind.java.
     */
    private TSAFacadeBind() {
    }
    
    /**
     * Method that obtains an instance of the class.
     * @return the unique instance of the class.
     */
    public static TSAFacadeBind getInstance() {
	if (instance == null) {
	    instance = new TSAFacadeBind();
	}
	return instance;
    }
    
    /**
     * Method that obtains the response of the timestamp generate service.
     * @param timestampReq Parameter that represents the request of the server signature service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the server signature service.
     */
    public TimestampResponse generateTimestamp(TimestampRequest timestampReq, String idClient) {
	return TsaIntegraFacadeWSDSS.getInstance().generateTimestamp(timestampReq, idClient);
    }

    /**
     * Method that obtains the response of the timestamp verify service.
     * @param timestampReq Parameter that represents the request of the server signature service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the server signature service.
     */
    public TimestampResponse verifyTimestamp(TimestampRequest timestampReq, String idClient) {
	return TsaIntegraFacadeWSDSS.getInstance().verifyTimestamp(timestampReq, idClient);
    }

    /**
     * Method that obtains the response of the timestamp renove service.
     * @param timestampReq Parameter that represents the request of the server signature service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the server signature service.
     */    
    public TimestampResponse renewTimestamp(TimestampRequest timestampReq, String idClient) {
	return TsaIntegraFacadeWSDSS.getInstance().renewTimestamp(timestampReq, idClient);
    }
}
