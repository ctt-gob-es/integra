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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.VerifySignatureResponse.java.</p>
 * <b>Description:</b><p>Class that represents the response from the service to verify a signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>24/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 24/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;
import java.util.List;

/**
 * <p>Class that represents the response from the service to verify a signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 24/11/2014.
 */
public class VerifySignatureResponse implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 6160947120910511084L;

    /**
     * Attribute that represents the result of the process.
     */
    private Result result;

    /**
     * Attribute that contains detailed information on verification processes performed.
     */
    private List<IndividualSignatureReport> verificationReport;

    /**
     * Attribute that represents signature format.
     */
    private String signatureFormat;

    /**
     * attribute that contains data information signed by an individual signature contained inside of the verified signature.
     */
    private List<DataInfo> signedDataInfo;

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
     * Gets the value of the attribute {@link #verificationReport}.
     * @return the value of the attribute {@link #verificationReport}.
     */
    public final List<IndividualSignatureReport> getVerificationReport() {
	return verificationReport;
    }

    /**
     * Sets the value of the attribute {@link #verificationReport}.
     * @param verificationReportParam The value for the attribute {@link #verificationReport}.
     */
    public final void setVerificationReport(List<IndividualSignatureReport> verificationReportParam) {
	this.verificationReport = verificationReportParam;
    }

    /**
     * Gets the value of the attribute {@link #signatureFormat}.
     * @return the value of the attribute {@link #signatureFormat}.
     */
    public final String getSignatureFormat() {
	return signatureFormat;
    }

    /**
     * Sets the value of the attribute {@link #signatureFormat}.
     * @param signatureFormatParam The value for the attribute {@link #signatureFormat}.
     */
    public final void setSignatureFormat(String signatureFormatParam) {
	this.signatureFormat = signatureFormatParam;
    }

    /**
     * Gets the value of the attribute {@link #signedDataInfo}.
     * @return the value of the attribute {@link #signedDataInfo}.
     */
    public final List<DataInfo> getSignedDataInfo() {
	return signedDataInfo;
    }

    /**
     * Sets the value of the attribute {@link #signedDataInfo}.
     * @param signedDataInfoParam The value for the attribute {@link #signedDataInfo}.
     */
    public final void setSignedDataInfo(List<DataInfo> signedDataInfoParam) {
	this.signedDataInfo = signedDataInfoParam;
    }
}
