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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.VerifyCertificateResponse.java.</p>
 * <b>Description:</b><p>Class that represents the response from the service to verify a certificate.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>24/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 24/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;
import java.util.Map;

/**
 * <p>Class that represents the response from the service to verify a certificate.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 24/11/2014.
 */
public class VerifyCertificateResponse implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 8811235494188383802L;

    /**
     * Attribute that represents the result of the process.
     */
    private Result result;

    /**
     * Attribute that contains details of the signer certificate.
     */
    private Map<String, String> readableCertificateInfo;

    /**
     * Attribute that contains information about the verification of a certificate chain.
     */
    private CertificatePathValidity certificatePathValidity;

    /**
     * Constructor method for the class VerifyCertificateResponse.java.
     */
    public VerifyCertificateResponse() {
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
     * Gets the value of the attribute {@link #readableCertificateInfo}.
     * @return the value of the attribute {@link #readableCertificateInfo}.
     */
    public final Map<String, String> getReadableCertificateInfo() {
	return readableCertificateInfo;
    }

    /**
     * Sets the value of the attribute {@link #readableCertificateInfo}.
     * @param readableCertificateInfoParam The value for the attribute {@link #readableCertificateInfo}.
     */
    public final void setReadableCertificateInfo(Map<String, String> readableCertificateInfoParam) {
	this.readableCertificateInfo = readableCertificateInfoParam;
    }

    /**
     * Gets the value of the attribute {@link #certificatePathValidity}.
     * @return the value of the attribute {@link #certificatePathValidity}.
     */
    public final CertificatePathValidity getCertificatePathValidity() {
	return certificatePathValidity;
    }

    /**
     * Sets the value of the attribute {@link #certificatePathValidity}.
     * @param certificatePathValidityParam The value for the attribute {@link #certificatePathValidity}.
     */
    public final void setCertificatePathValidity(CertificatePathValidity certificatePathValidityParam) {
	this.certificatePathValidity = certificatePathValidityParam;
    }

}
