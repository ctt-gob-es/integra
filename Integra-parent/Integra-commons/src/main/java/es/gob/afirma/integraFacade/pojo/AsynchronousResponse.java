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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.AsynchronousResponse.java.</p>
 * <b>Description:</b><p>Class that represents the response from the asynchronous processes of sign and verify service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>15/12/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 15/12/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;

/**
 * <p>Class that represents the response from the asynchronous processes of sign and verify service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 15/12/2014.
 */
public class AsynchronousResponse implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 3581645969760538207L;

    /**
     * Attribute that represents the object obtained from the invocation of processes (signature, co-signature, countersignature or update signature)
     * asynchronously.
     */
    private ServerSignerResponse serSigRes;

    /**
     * Attribute that represents the object obtained by invoking the process "batch certificate verification" asynchronously.
     */
    private BatchVerifyCertificateResponse batVerCerRes;

    /**
     * Attribute that represents the object obtained by invoking the process "batch signature verification" asynchronously.
     */
    private BatchVerifySignatureResponse batVerSigRes;

    /**
     * Attribute that represents the object obtained if the request is not successful.
     */
    private InvalidAsyncResponse invAsyRes;

    /**
     * Constructor method for the class AsynchronousResponse.java.
     */
    public AsynchronousResponse() {
    }

    /**
     * Gets the value of the attribute {@link #serSigRes}.
     * @return the value of the attribute {@link #serSigRes}.
     */
    public final ServerSignerResponse getSerSigRes() {
	return serSigRes;
    }

    /**
     * Sets the value of the attribute {@link #serSigRes}.
     * @param serSigResParam The value for the attribute {@link #serSigRes}.
     */
    public final void setSerSigRes(ServerSignerResponse serSigResParam) {
	this.serSigRes = serSigResParam;
    }

    /**
     * Gets the value of the attribute {@link #batVerCerRes}.
     * @return the value of the attribute {@link #batVerCerRes}.
     */
    public final BatchVerifyCertificateResponse getBatVerCerRes() {
	return batVerCerRes;
    }

    /**
     * Sets the value of the attribute {@link #batVerCerRes}.
     * @param batVerCerResParam The value for the attribute {@link #batVerCerRes}.
     */
    public final void setBatVerCerRes(BatchVerifyCertificateResponse batVerCerResParam) {
	this.batVerCerRes = batVerCerResParam;
    }

    /**
     * Gets the value of the attribute {@link #batVerSigRes}.
     * @return the value of the attribute {@link #batVerSigRes}.
     */
    public final BatchVerifySignatureResponse getBatVerSigRes() {
	return batVerSigRes;
    }

    /**
     * Sets the value of the attribute {@link #batVerSigRes}.
     * @param batVerSigResParam The value for the attribute {@link #batVerSigRes}.
     */
    public final void setBatVerSigRes(BatchVerifySignatureResponse batVerSigResParam) {
	this.batVerSigRes = batVerSigResParam;
    }

    /**
     * Gets the value of the attribute {@link #invAsyRes}.
     * @return the value of the attribute {@link #invAsyRes}.
     */
    public final InvalidAsyncResponse getInvAsyRes() {
	return invAsyRes;
    }

    /**
     * Sets the value of the attribute {@link #invAsyRes}.
     * @param invAsyResParam The value for the attribute {@link #invAsyRes}.
     */
    public final void setInvAsyRes(InvalidAsyncResponse invAsyResParam) {
	this.invAsyRes = invAsyResParam;
    }

}
