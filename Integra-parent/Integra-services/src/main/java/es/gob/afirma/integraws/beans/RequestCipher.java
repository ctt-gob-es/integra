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
 * <b>File:</b><p>es.gob.afirma.integraws.beans.RequestCipher.java.</p>
 * <b>Description:</b><p> Class that represents the request object for cipher service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.beans;

import es.gob.afirma.encryption.AlgorithmCipherEnum;


/** 
 * <p>Class that represents the request object for cipher service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public class RequestCipher {

    /**
     * Attribute that represents alias of private key. 
     */
    private String alias;
    
    /**
     * Attribute that represents id of WS client. 
     */
    private String idClient;
    
    /**
     * Attribute that represents the text to encrypt/decrypt. 
     */
    private String text;
    
    /**
     * Attribute that represents the algorithm used to cipher. 
     */
    private AlgorithmCipherEnum algorithmCipher;
    
    /**
     * Gets the value of the attribute {@link #alias}.
     * @return the value of the attribute {@link #alias}.
     */
    public final String getAlias() {
        return alias;
    }

    /**
     * Sets the value of the attribute {@link #alias}.
     * @param aliasParam The value for the attribute {@link #alias}.
     */
    public final void setAlias(String aliasParam) {
        this.alias = aliasParam;
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

    
    /**
     * Gets the value of the attribute {@link #text}.
     * @return the value of the attribute {@link #text}.
     */
    public final String getText() {
        return text;
    }

    
    /**
     * Sets the value of the attribute {@link #text}.
     * @param textParam The value for the attribute {@link #text}.
     */
    public final void setText(String textParam) {
        this.text = textParam;
    }

    /**
     * Gets the value of the attribute {@link #algorithmCipher}.
     * @return the value of the attribute {@link #algorithmCipher}.
     */
    public final AlgorithmCipherEnum getAlgorithmCipher() {
	return algorithmCipher;
    }
    
    /**
     * Sets the value of the attribute {@link #algorithmCipher}.
     * @param algorithmCipherParam The value for the attribute {@link #algorithmCipher}.
     */
    public final void setAlgorithmCipher(AlgorithmCipherEnum algorithmCipherParam) {
        this.algorithmCipher = algorithmCipherParam;
    }

    
    
    
}
