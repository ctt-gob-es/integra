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
 * <b>File:</b><p>es.gob.afirma.integraws.beans.RequestUpgradeSign.java.</p>
 * <b>Description:</b><p> Class that represents the request object for UPGRADESIGN service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.beans;

import java.util.List;

/** 
 * <p>Class that represents the request object for UPGRADESIGN service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public class RequestUpgradeSign {

    /**
     * Attribute that represents signature to upgrade. 
     */
    private byte[ ] signature; 
    
    /**
     * Attribute that represents the list of signers to upgrade. 
     */
    private List<SignerToUpgrade> listSigners;
    
    /**
     * Attribute that represents id of WS client. 
     */
    private String idClient;

    /**
     * Gets the value of the attribute {@link #signature}.
     * @return the value of the attribute {@link #signature}.
     */
    public final byte[ ] getSignature() {
        return signature;
    }

    /**
     * Sets the value of the attribute {@link #signature}.
     * @param signatureParam The value for the attribute {@link #signature}.
     */
    public final void setSignature(byte[ ] signatureParam) {
        this.signature = signatureParam;
    }

    /**
     * Gets the value of the attribute {@link #listSigners}.
     * @return the value of the attribute {@link #listSigners}.
     */
    public final List<SignerToUpgrade> getListSigners() {
        return listSigners;
    }

    /**
     * Sets the value of the attribute {@link #listSigners}.
     * @param listSignersParam The value for the attribute {@link #listSigners}.
     */
    public final void setListSigners(List<SignerToUpgrade> listSignersParam) {
        this.listSigners = listSignersParam;
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
