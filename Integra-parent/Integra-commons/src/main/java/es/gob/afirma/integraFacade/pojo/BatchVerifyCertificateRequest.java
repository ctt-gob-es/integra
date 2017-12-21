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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.BatchVerifyCertificateRequest.java.</p>
 * <b>Description:</b><p>Class that represents the request for the verify certificates on batch service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>24/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 24/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;
import java.util.List;

/**
 * <p>Class that represents the request for the verify certificates on batch service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 24/11/2014.
 */
public class BatchVerifyCertificateRequest implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 4357677871387064518L;

    /**
     * Attribute that represents application identifier.
     */
    private String applicationId;

    /**
     * Attribute that represents the list of certificates being verified.
     */
    private List<VerifyCertificateRequest> listVerifyCertificate;

    /**
     * Constructor method for the class BatchVerifyCertificateRequest.java.
     */
    public BatchVerifyCertificateRequest() {
    }

    /**
     * Gets the value of the attribute {@link #listVerifyCertificate}.
     * @return the value of the attribute {@link #listVerifyCertificate}.
     */
    public final List<VerifyCertificateRequest> getListVerifyCertificate() {
	return listVerifyCertificate;
    }

    /**
     * Sets the value of the attribute {@link #listVerifyCertificate}.
     * @param listVerifyCertificateParam The value for the attribute {@link #listVerifyCertificate}.
     */
    public final void setListVerifyCertificate(List<VerifyCertificateRequest> listVerifyCertificateParam) {
	this.listVerifyCertificate = listVerifyCertificateParam;
    }

    /**
     * Gets the value of the attribute {@link #applicationId}.
     * @return the value of the attribute {@link #applicationId}.
     */
    public final String getApplicationId() {
	return applicationId;
    }

    /**
     * Sets the value of the attribute {@link #applicationId}.
     * @param applicationIdParam The value for the attribute {@link #applicationId}.
     */
    public final void setApplicationId(String applicationIdParam) {
	this.applicationId = applicationIdParam;
    }

}
