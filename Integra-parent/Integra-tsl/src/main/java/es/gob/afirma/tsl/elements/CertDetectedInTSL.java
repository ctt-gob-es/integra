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
// https://eupl.eu/1.1/es/

/** 
 * <b>File:</b><p>es.gob.afirma.tsl.elements.CertDetectedInTSL.java.</p>
 * <b>Description:</b><p>Class that represents structure of a certificated detected in TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/10/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/10/2020.
 */
package es.gob.afirma.tsl.elements;

import java.io.Serializable;
import java.util.Map;



/** 
 * <p>Class that represents structure of a certificated detected in TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/10/2020.
 */
public class CertDetectedInTSL implements Serializable {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = 6710710132988800415L;
	/**
	 * Attribute that represents the TSP name in certificated detected in TSL.
	 */
	private String tspName;

	/**
	 * Attribute that represents the TSP Service Information which has detected the certificate.
	 */
	private TspServiceInformation tspServiceInformation;

	/**
	 * Attribute that represents the certificate information in certificated detected in TSL.
	 */
	private Map<String, String> certInfo;

	/**
	 * Attribute that represents the TSL revocation status in certificated detected in TSL.
	 */
	private TslRevocationStatus tslRevocStatus;

	/**
	 * Gets the value of the attribute {@link #tspName}.
	 * @return the value of the attribute {@link #tspName}.
	 */
	public String getTspName() {
		return tspName;
	}

	/**
	 * Sets the value of the attribute {@link #tspName}.
	 * @param tspNameParam The value for the attribute {@link #tspName}.
	 */
	public void setTspName(final String tspNameParam) {
		this.tspName = tspNameParam;
	}

	/**
	 * Gets the value of the attribute {@link #tspServiceInformation}.
	 * @return the value of the attribute {@link #tspServiceInformation}.
	 */
	public final TspServiceInformation getTspServiceInformation() {
		return tspServiceInformation;
	}

	/**
	 * Sets the value of the attribute {@link #tspServiceInformation}.
	 * @param tspServiceInformationParam The value for the attribute {@link #tspServiceInformation}.
	 */
	public final void setTspServiceInformation(TspServiceInformation tspServiceInformationParam) {
		this.tspServiceInformation = tspServiceInformationParam;
	}

	/**
	 * Gets the value of the attribute {@link #certInfo}.
	 * @return the value of the attribute {@link #certInfo}.
	 */
	public Map<String, String> getCertInfo() {
		return certInfo;
	}

	/**
	 * Sets the value of the attribute {@link #certInfo}.
	 * @param certInfoParam The value for the attribute {@link #certInfo}.
	 */
	public void setCertInfo(final Map<String, String> certInfoParam) {
		this.certInfo = certInfoParam;
	}

	/**
	 * Gets the value of the attribute {@link #tslRevocStatus}.
	 * @return the value of the attribute {@link #tslRevocStatus}.
	 */
	public TslRevocationStatus getTslRevocStatus() {
		return tslRevocStatus;
	}

	/**
	 * Sets the value of the attribute {@link #tslRevocStatus}.
	 * @param tslRevocStatusParam The value for the attribute {@link #tslRevocStatus}.
	 */
	public void setTslRevocStatus(final TslRevocationStatus tslRevocStatusParam) {
		this.tslRevocStatus = tslRevocStatusParam;
	}

}
