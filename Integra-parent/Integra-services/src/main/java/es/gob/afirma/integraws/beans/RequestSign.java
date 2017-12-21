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
 * <b>File:</b><p>es.gob.afirma.integraws.beans.RequestSign.java.</p>
 * <b>Description:</b><p> Class that represents the request object for SIGN service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.beans;

import es.gob.afirma.integraFacade.pojo.SignatureFormatEnum;

/** 
 * <p>Class that represents the request object for SIGN service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public class RequestSign {

    /**
     * Attribute that represents data to sign. 
     */
    private byte[ ] dataToSign; 
    
    /**
     * Attribute that represents signature. 
     */
    private byte[ ] signature; 
    
    /**
     * Attribute that represents alias of signer certificate. 
     */
    private String alias;
    
    /**
     * Attribute that indicates if signature policy will be include. 
     */
    private boolean includeSignaturePolicy;
    
    /**
     * Attribute that represents id of WS client. 
     */
    private String idClient;
    
    /**
     * Attribute that represents signature format.
     */
    private SignatureFormatEnum signatureFormat;

    /**
     * Gets the value of the attribute {@link #dataToSign}.
     * @return the value of the attribute {@link #dataToSign}.
     */
    public final byte[ ] getDataToSign() {
        return dataToSign;
    }

    /**
     * Sets the value of the attribute {@link #dataToSign}.
     * @param dataToSignParam The value for the attribute {@link #dataToSign}.
     */
    public final void setDataToSign(byte[ ] dataToSignParam) {
        this.dataToSign = dataToSignParam;
    }


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
     * Gets the value of the attribute {@link #includeSignaturePolicy}.
     * @return the value of the attribute {@link #includeSignaturePolicy}.
     */
    public final boolean isIncludeSignaturePolicy() {
        return includeSignaturePolicy;
    }

    /**
     * Sets the value of the attribute {@link #includeSignaturePolicy}.
     * @param includeSignaturePolicyParam The value for the attribute {@link #includeSignaturePolicy}.
     */
    public final void setIncludeSignaturePolicy(boolean includeSignaturePolicyParam) {
        this.includeSignaturePolicy = includeSignaturePolicyParam;
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
     * Gets the value of the attribute {@link #signatureFormat}.
     * @return the value of the attribute {@link #signatureFormat}.
     */
    public final SignatureFormatEnum getSignatureFormat() {
	return signatureFormat;
    }

    /**
     * Sets the value of the attribute {@link #signatureFormat}.
     * @param signatureFormatParam The value for the attribute {@link #signatureFormat}.
     */
    public final void setSignatureFormat(SignatureFormatEnum signatureFormatParam) {
	this.signatureFormat = signatureFormatParam;
    }
    
}
