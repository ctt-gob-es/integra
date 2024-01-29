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
 * <b>File:</b><p>es.gob.afirma.mreport.items.ValidationData.java.</p>
 * <b>Description:</b><p>Class that represents the individual signature validation result parameters.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>18/08/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 18/08/2020.
 */
package es.gob.afirma.mreport.items;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;

/**
 * <p>Class that represents the individual signature validation result parameters.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 18/08/2020.
 */

public class IndividualSignature {
	
	/**
	 * Attribute that represents the result major of the individual signature validation.
	 */
	private String resultMajor;
	
	/**
	 * Attribute that represents the result minor of the individual signature validation.
	 */
	private String resultMinor;
	
	/**
	 * Attribute that represents the result message of the individual signature validation.
	 */
	private String resultMessage;
	
	/**
	 * Attribute that represents the timestamp of the individual signature validation.
	 */
	private LocalDateTime timestamp;
	
	/**
	 * Attribute that represents the certificate information of the individual signature.
	 */
	LinkedHashMap<String, String> certInfo = new LinkedHashMap<String,String>();

	
	/**
	 * Constructor with parameters for the IndividualSignature class
	 * @param resultMajor the value of the attribute {@link #resultMajor}.
	 * @param resultMinor the value of the attribute {@link #resultMinor}.
	 * @param resultMessage the value of the attribute {@link #resultMessage}.
	 * @param localDateTime the value of the attribute {@link #timestamp}.
	 * @param certInfo the value of the attribute {@link #certInfo}.
	 */
	public IndividualSignature(String resultMajor, String resultMinor, String resultMessage,
			LocalDateTime localDateTime, LinkedHashMap<String, String> certInfo) {
		super();
		this.resultMajor = resultMajor;
		this.resultMinor = resultMinor;
		this.resultMessage = resultMessage;
		this.timestamp = localDateTime;
		this.certInfo = certInfo;
	}

	/**
	 * Gets the value of the attribute {@link #resultMajor}.
	 * @return the value of the attribute {@link #resultMajor}.
	 */
	public String getResultMajor() {
		return resultMajor;
	}

	/**
	 * Sets the value of the attribute {@link #resultMajor}.
	 * @param resultMajorParam the value for the attribute {@link #resultMajor} to set.
	 */
	public void setResultMajor(String resultMajorParam) {
		this.resultMajor = resultMajorParam;
	}

	/**
	 * Gets the value of the attribute {@link #resultMinor}.
	 * @return the value of the attribute {@link #resultMinor}.
	 */
	public String getResultMinor() {
		return resultMinor;
	}

	/**
	 * Sets the value of the attribute {@link #resultMinor}.
	 * @param resultMinorParam the value for the attribute {@link #resultMinor} to set.
	 */
	public void setResultMinor(String resultMinorParam) {
		this.resultMinor = resultMinorParam;
	}

	/**
	 * Gets the value of the attribute {@link #resultMessage}.
	 * @return the value of the attribute {@link #resultMessage}.
	 */
	public String getResultMessage() {
		return resultMessage;
	}

	/**
	 * Sets the value of the attribute {@link #resultMessage}.
	 * @param resultMessageParam the value for the attribute {@link #resultMessage} to set.
	 */
	public void setResultMessage(String resultMessageParam) {
		this.resultMessage = resultMessageParam;
	}

	/**
	 * Gets the value of the attribute {@link #timestamp}.
	 * @return the value of the attribute {@link #timestamp}.
	 */
	public LocalDateTime getTimestamp() {
		return timestamp;
	}

	/**
	 * Sets the value of the attribute {@link #timestamp}.
	 * @param timestampParam the value for the attribute {@link #timestamp} to set.
	 */
	public void setTimestamp(LocalDateTime timestampParam) {
		this.timestamp = timestampParam;
	}

	/**
	 * Gets the value of the attribute {@link #timestamp}.
	 * @return the value of the attribute {@link #timestamp}.
	 */
	public LinkedHashMap<String, String> getCertInfo() {
		return certInfo;
	}

	/**
	 * Sets the value of the attribute {@link #certInfo}.
	 * @param certInfoParam the value for the attribute {@link #certInfo} to set.
	 */
	public void setCertInfo(LinkedHashMap<String, String> certInfoParam) {
		certInfo = certInfoParam;
	}
	
	

}
