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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.CertificateInfoResponse.java.</p>
 * <b>Description:</b><p>Class that represents the response from the service to get certificate information.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>14/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 14/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;
import java.util.Map;

/**
 * <p>Class that represents the response from the service to get certificate information.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 14/11/2014.
 */
public class CertificateInfoResponse implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 5020666841582859139L;

    /**
     * Attribute that represents a map containing the attributes of a certificate with its corresponding value.
     */
    private Map<String, Object> mapInfoCertificate;

    /**
     * Attribute that represents the information about the error response returned.
     */
    private ErrorResponse error;

    /**
     * Constructor method for the class CertificateInfoResponse.java.
     */
    public CertificateInfoResponse() {
    }

    /**
     * Gets the value of the attribute {@link #mapInfoCertificate}.
     * @return the value of the attribute {@link #mapInfoCertificate}.
     */
    public final Map<String, Object> getMapInfoCertificate() {
	return mapInfoCertificate;
    }

    /**
     * Sets the value of the attribute {@link #mapInfoCertificate}.
     * @param mapInfoCertificateParam The value for the attribute {@link #mapInfoCertificate}.
     */
    public final void setMapInfoCertificate(Map<String, Object> mapInfoCertificateParam) {
	this.mapInfoCertificate = mapInfoCertificateParam;
    }

    /**
     * Gets the value of the attribute {@link #error}.
     * @return the value of the attribute {@link #error}.
     */
    public final ErrorResponse getError() {
	return error;
    }

    /**
     * Sets the value of the attribute {@link #error}.
     * @param errorParam The value for the attribute {@link #error}.
     */
    public final void setError(ErrorResponse errorParam) {
	this.error = errorParam;
    }

}
