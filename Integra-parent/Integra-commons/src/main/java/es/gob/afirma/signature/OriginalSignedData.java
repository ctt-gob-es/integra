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
 * <b>File:</b><p>es.gob.afirma.signature.OriginalSignedData.java.</p>
 * <b>Description:</b><p> .</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>11/03/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 11/03/2016.
 */
package es.gob.afirma.signature;

import java.io.Serializable;

/** 
 * <p>Class that contains information about the originally signed data.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 11/03/2016.
 */

public class OriginalSignedData implements Serializable {

    /**
     * Attribute that represents class serial version. 
     */
    private static final long serialVersionUID = -2979498625765849674L;

    /**
     * Attribute that represents the originally signed data.
     */
    private byte[ ] signedData;

    /**
     * Attribute that represents the hash of the signed data.
     */
    private byte[ ] hashSignedData;

    /**
     * Attribute that indicates the hash algorithm to be used.
     */
    private String hashAlgorithm;

    /**
     * Attribute that represents the value of mimetype.
     */
    private String mimetype;

    /**
     * Gets the value of the attribute {@link #signedData}.
     * @return the value of the attribute {@link #signedData}.
     */
    public final byte[ ] getSignedData() {
	return signedData;
    }

    /**
     * Sets the value of the attribute {@link #signedData}.
     * @param signedDataParam The value for the attribute {@link #signedData}.
     */
    public final void setSignedData(byte[ ] signedDataParam) {
	this.signedData = signedDataParam;
    }

    /**
     * Gets the value of the attribute {@link #hashSignedData}.
     * @return the value of the attribute {@link #hashSignedData}.
     */
    public final byte[ ] getHashSignedData() {
	return hashSignedData;
    }

    /**
     * Sets the value of the attribute {@link #hashSignedData}.
     * @param hashSignedDataParam The value for the attribute {@link #hashSignedData}.
     */
    public final void setHashSignedData(byte[ ] hashSignedDataParam) {
	this.hashSignedData = hashSignedDataParam;
    }

    /**
     * Gets the value of the attribute {@link #hashAlgorithm}.
     * @return the value of the attribute {@link #hashAlgorithm}.
     */
    public final String getHashAlgorithm() {
	return hashAlgorithm;
    }

    /**
     * Sets the value of the attribute {@link #hashAlgorithm}.
     * @param hashAlgorithmParam The value for the attribute {@link #hashAlgorithm}.
     */
    public final void setHashAlgorithm(String hashAlgorithmParam) {
	this.hashAlgorithm = hashAlgorithmParam;
    }

    /**
     * Gets the value of the attribute {@link #mimetype}.
     * @return the value of the attribute {@link #mimetype}.
     */
    public final String getMimetype() {
	return mimetype;
    }

    /**
     * Sets the value of the attribute {@link #mimetype}.
     * @param mimetypeParam The value for the attribute {@link #mimetype}.
     */
    public final void setMimetype(String mimetypeParam) {
	this.mimetype = mimetypeParam;
    }
}
