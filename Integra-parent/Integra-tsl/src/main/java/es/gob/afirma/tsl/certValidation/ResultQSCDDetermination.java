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
 * <b>File:</b><p>es.gob.afirma.tsl.certValidation.ResultQSCDDetermination.java.</p>
 * <b>Description:</b><p>Class that represents the result obtained when executing the procedure
 * 4.5.QSCD determination of ETSI TS 119 615 v.1.1.1.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 25/09/2023.</p>
 * @author Gobierno de España.
 * @version 1.0, 25/09/2023.
 */
package es.gob.afirma.tsl.certValidation;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/** 
 * <p>Class that represents the result obtained when executing the procedure
 * 4.5.QSCD determination of ETSI TS 119 615 v.1.1.1.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 25/09/2023.
 */
public class ResultQSCDDetermination implements Serializable {

    /**
     * Attribute that represents . 
     */
    private static final long serialVersionUID = -665972916625551589L;
    /**
     * Attribute that indicates whether CERT had its private key residing in a
     * QSCD in accordance with the trusted lists, through one of the following
     * values: a) "QSCD_YES" to indicate that CERT had its private key residing
     * in a QSCD at Date-time according to the EUMS trusted lists; b) "QSCD_NO"
     * to indicate that CERT did not have its private key residing in a QSCD at
     * Date-time according to the EUMS trusted lists; c) "QSCD_INDETERMINATE" to
     * indicate that the EUMS trusted lists cannot be used to confirm whether
     * CERT had its private key residing in a QSCD at Date-time; d) Void.
     * QSCD-Status The status
     */
    private String qscdResult;

    /**
     * Attribute that represents the status indication of the process.
     */
    private String qscdStatus;

    /**
     * Attribute that represents a list of indications supplementing qscdStaus indication.
     */
    private List<String> qscdSubStatus;

    /**
     * Constructor method for the class ResultQSCDDetermination.java.
     */
    public ResultQSCDDetermination() {
	qscdSubStatus = new ArrayList<String>();
    }

    /**
     * Gets the value of the attribute {@link #qscdResult}.
     * @return the value of the attribute {@link #qscdResult}.
     */
    public String getQscdResult() {
	return qscdResult;
    }

    /**
     * Sets the value of the attribute {@link #qscdResult}.
     * @param qscdResult The value for the attribute {@link #qscdResult}.
     */
    public void setQscdResult(String qscdResult) {
	this.qscdResult = qscdResult;
    }

    /**
     * Gets the value of the attribute {@link #qscdStatus}.
     * @return the value of the attribute {@link #qscdStatus}.
     */
    public String getQscdStatus() {
	return qscdStatus;
    }

    /**
     * Sets the value of the attribute {@link #qscdStatus}.
     * @param qscdStatus The value for the attribute {@link #qscdStatus}.
     */
    public void setQscdStatus(String qscdStatus) {
	this.qscdStatus = qscdStatus;
    }

    /**
     * Gets the value of the attribute {@link #qscdSubStatus}.
     * @return the value of the attribute {@link #qscdSubStatus}.
     */
    public List<String> getQscdSubStatus() {
	return qscdSubStatus;
    }

    /**
     * Sets the value of the attribute {@link #qscdSubStatus}.
     * @param qscdSubStatus The value for the attribute {@link #qscdSubStatus}.
     */
    public void setQscdSubStatus(List<String> qscdSubStatus) {
	this.qscdSubStatus = qscdSubStatus;
    }

}
