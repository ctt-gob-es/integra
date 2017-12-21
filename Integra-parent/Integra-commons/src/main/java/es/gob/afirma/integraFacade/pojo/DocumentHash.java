// Copyright (C) 2012-13 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.DocumentHash.java.</p>
 * <b>Description:</b><p>Class that contains the summary or hash of the original data for verification with respect to the data included in the signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>21/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 21/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;

/**
 * <p>Class that contains the summary or hash of the original data for verification with respect to the data included in the signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 21/11/2014.
 */
public class DocumentHash implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 1806706655384393914L;

    /**
     * Attribute that represents the digest algorithm.
     */
    private HashAlgorithmEnum digestMethod;

    /**
     * Attributes that contains the value of the summary or hash.
     */
    private byte[ ] digestValue;

    /**
     * Attribute that represents the transforms.
     */
    private TransformData transform;

    /**
     * Constructor method for the class DocumentHash.java.
     */
    public DocumentHash() {
    }

    /**
     * Gets the value of the attribute {@link #digestMethod}.
     * @return the value of the attribute {@link #digestMethod}.
     */
    public final HashAlgorithmEnum getDigestMethod() {
	return digestMethod;
    }

    /**
     * Sets the value of the attribute {@link #digestMethod}.
     * @param digestMethodParam The value for the attribute {@link #digestMethod}.
     */
    public final void setDigestMethod(HashAlgorithmEnum digestMethodParam) {
	this.digestMethod = digestMethodParam;
    }

    /**
     * Gets the value of the attribute {@link #digestValue}.
     * @return the value of the attribute {@link #digestValue}.
     */
    public final byte[ ] getDigestValue() {
	return digestValue;
    }

    /**
     * Sets the value of the attribute {@link #digestValue}.
     * @param digestValueParam The value for the attribute {@link #digestValue}.
     */
    public final void setDigestValue(byte[ ] digestValueParam) {
	if (digestValueParam != null) {
	    this.digestValue = digestValueParam.clone();
	}
    }

    /**
     * Gets the value of the attribute {@link #transform}.
     * @return the value of the attribute {@link #transform}.
     */
    public final TransformData getTransform() {
	return transform;
    }

    /**
     * Sets the value of the attribute {@link #transform}.
     * @param transformParam The value for the attribute {@link #transform}.
     */
    public final void setTransform(TransformData transformParam) {
	this.transform = transformParam;
    }

}
