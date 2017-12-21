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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.ArchiveRequest.java.</p>
 * <b>Description:</b><p>Class that represents the request for the archive signatures retrieve service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>24/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 24/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;

/**
 * <p>Class that represents the request for the archive signatures retrieve service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 24/11/2014.
 */
public class ArchiveRequest implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 1507873916026872683L;

    /**
     * Attribute that represents application identifier.
     */
    private String applicationId;

    /**
     * Attribute that represents transaction identifier of the signature to recover.
     */
    private String transactionId;

    /**
     * Constructor method for the class ArchiveRequest.java.
     */
    public ArchiveRequest() {
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

    /**
     * Gets the value of the attribute {@link #transactionId}.
     * @return the value of the attribute {@link #transactionId}.
     */
    public final String getTransactionId() {
	return transactionId;
    }

    /**
     * Sets the value of the attribute {@link #transactionId}.
     * @param transactionIdParam The value for the attribute {@link #transactionId}.
     */
    public final void setTransactionId(String transactionIdParam) {
	this.transactionId = transactionIdParam;
    }

}
