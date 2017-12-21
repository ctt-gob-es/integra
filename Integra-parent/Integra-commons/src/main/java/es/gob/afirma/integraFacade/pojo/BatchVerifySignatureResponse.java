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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.BatchVerifySignatureResponse.java.</p>
 * <b>Description:</b><p>Class that represents the response from the verify signatures on batch service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>24/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 24/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;
import java.util.List;

/**
 * <p>Class that represents the response from the verify signatures on batch service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 24/11/2014.
 */
public class BatchVerifySignatureResponse implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 894715469229824242L;

    /**
     * Attribute that represents result of process.
     */
    private Result result;

    /**
     * Attribute that represents the "Asynchronous Process ID" to get the result associated with the request.
     */
    private String asyncResponse;

    /**
     * Attribute that contains the set of individual response to validate signature.
     */
    private List<VerifySignatureResponse> listVerifyResponse;

    /**
     * Constructor method for the class BatchVerifySignatureResponse.java.
     */
    public BatchVerifySignatureResponse() {
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
     * Gets the value of the attribute {@link #asyncResponse}.
     * @return the value of the attribute {@link #asyncResponse}.
     */
    public final String getAsyncResponse() {
	return asyncResponse;
    }

    /**
     * Sets the value of the attribute {@link #asyncResponse}.
     * @param asyncResponseParam The value for the attribute {@link #asyncResponse}.
     */
    public final void setAsyncResponse(String asyncResponseParam) {
	this.asyncResponse = asyncResponseParam;
    }

    /**
     * Gets the value of the attribute {@link #listVerifyResponse}.
     * @return the value of the attribute {@link #listVerifyResponse}.
     */
    public final List<VerifySignatureResponse> getListVerifyResponse() {
	return listVerifyResponse;
    }

    /**
     * Sets the value of the attribute {@link #listVerifyResponse}.
     * @param listVerifyResponseParam The value for the attribute {@link #listVerifyResponse}.
     */
    public final void setListVerifyResponse(List<VerifySignatureResponse> listVerifyResponseParam) {
	this.listVerifyResponse = listVerifyResponseParam;
    }

}
