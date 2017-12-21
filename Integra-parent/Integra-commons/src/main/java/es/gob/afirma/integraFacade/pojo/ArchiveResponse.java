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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.ArchiveResponse.java.</p>
 * <b>Description:</b><p>Class that represents the response from the archive signatures retrieve service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>24/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 24/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;

/**
 * <p>Class that represents the response from the archive signatures retrieve service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 24/11/2014.
 */
public class ArchiveResponse implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = -1011256500488044265L;

    /**
     * Attribute that represents result of process.
     */
    private Result result;

    /**
     * Attribute that represents signature that has recovered.
     */
    private byte[ ] signature;

    /**
     * Constructor method for the class ArchiveResponse.java.
     */
    public ArchiveResponse() {
    }

    /**
     * Gets the value of the attribute {@link #result}.
     * @return the value of the attribute {@link #result}.
     */
    public final Result getResult() {
	return result;
    }

    /**
     * Sets the value of the attribute {@link #result}.
     * @param resultParam The value for the attribute {@link #result}.
     */
    public final void setResult(Result resultParam) {
	this.result = resultParam;
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
	if (signatureParam != null) {
	    this.signature = signatureParam.clone();
	}

    }

}
