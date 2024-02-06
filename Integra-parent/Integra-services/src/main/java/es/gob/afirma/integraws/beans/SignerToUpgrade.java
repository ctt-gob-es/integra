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
// https://eupl.eu/1.1/es/

/** 
 * <b>File:</b><p>es.gob.afirma.integraws.beans.SignerToUpgrade.java.</p>
 * <b>Description:</b><p> Class that represents the request object for signer needed in upgrade signature service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.beans;

/** 
 * <p>Class that represents the request object for signer needed in upgrade signature service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public class SignerToUpgrade {

    /**
     * Attribute that represents signer. 
     */
    private byte[] signer;

    /**
     * Constructor method for the class SignerToUpgrade.java. 
     */
    public SignerToUpgrade() {
	super();
    }

    /**
     * Gets the value of the attribute {@link #signer}.
     * @return the value of the attribute {@link #signer}.
     */
    public final byte[ ] getSigner() {
        return signer;
    }

    /**
     * Sets the value of the attribute {@link #signer}.
     * @param signerParam The value for the attribute {@link #signer}.
     */
    public final void setSigner(byte[ ] signerParam) {
        this.signer = signerParam;
    }
    
    
}
