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
 * <b>File:</b><p>es.gob.afirma.integraws.beans.RequestServerSign.java.</p>
 * <b>Description:</b><p> Class that represents the request object for SERVERSIGN service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.beans;

import es.gob.afirma.integraFacade.pojo.ServerSignerRequest;

/** 
 * <p>Class that represents the request object for SERVERSIGN service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public class RequestServerSign extends ServerSignerRequest{
    
    /**
     * Attribute that represents serialVersionUID. 
     */
    private static final long serialVersionUID = 1391652685269452554L;
    
    /**
     * Attribute that represents id of WS client. 
     */
    private String idClient;
   
    
    /**
     * Constructor method for the class RequestServerSign.java. 
     */
    public RequestServerSign(){
	super();
    }

    /**
     * Gets the value of the attribute {@link #idClient}.
     * @return the value of the attribute {@link #idClient}.
     */
    public final String getIdClient() {
        return idClient;
    }

    /**
     * Sets the value of the attribute {@link #idClient}.
     * @param idClientParam The value for the attribute {@link #idClient}.
     */
    public final void setIdClient(String idClientParam) {
        this.idClient = idClientParam;
    }

}
