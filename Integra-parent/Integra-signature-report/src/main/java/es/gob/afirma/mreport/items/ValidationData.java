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
// https://eupl.eu/1.1/es/

/**
 * <b>File:</b><p>es.gob.afirma.mreport.items.ValidationData.java.</p>
 * <b>Description:</b><p>Class that represents the signature validation parameters.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>18/08/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 18/08/2020.
 */
package es.gob.afirma.mreport.items;

import java.util.List;

/**
 * <p>Class that represents the signature validation result parameters.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 18/08/2020.
 */
public class ValidationData {
	
	/**
	 * Attribute that represents the result major of the signature validation.
	 */
	private String resultMajor;
	
	/**
	 * Attribute that represents the result minor of the signature validation.
	 */
	private String resultMinor;
	
	/**
	 * Attribute that represents the result message of the signature validation.
	 */
	private String resultMessage;
	
	/**
	 * Attribute that represents the date format of each individual signature validation timestamp.
	 */
	private String timestampFormat;
	
	/**
	 * Attribute that represents the list of individual signature validations.
	 */
	private List<IndividualSignature> signatures;

	/**
	 * Constructor with parameters for ValidationData class
	 * @param resultMajor Result major parameter
	 * @param resultMinor Result minor parameter
	 * @param resultMessage Result message parameter
	 * @param signatures List of IndividualSignature parameter
	 */
	public ValidationData(String resultMajor, String resultMinor, String resultMessage,
			List<IndividualSignature> signatures) {
		super();
		this.resultMajor = resultMajor;
		this.resultMinor = resultMinor;
		this.resultMessage = resultMessage;
		this.signatures = signatures;
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
	 * Gets the value of the attribute {@link #timestampFormat}.
	 * @return the value of the attribute {@link #timestampFormat}.
	 */
	public String getTimestampFormat() {
		return timestampFormat;
	}

	/**
	 * Sets the value of the attribute {@link #timestampFormat}.
	 * @param timestampFormatParam the value for the attribute {@link #timestampFormat} to set.
	 */
	public void setTimestampFormat(String timestampFormatParam) {
		this.timestampFormat = timestampFormatParam;
	}

	/**
	 * Gets the value of the attribute {@link #signatures}.
	 * @return the value of the attribute {@link #signatures}.
	 */
	public List<IndividualSignature> getSignatures() {
		return signatures;
	}

	/**
	 * Sets the value of the attribute {@link #signatures}.
	 * @param signaturesParam the value for the attribute {@link #signatures} to set.
	 */
	public void setSignatures(List<IndividualSignature> signaturesParam) {
		this.signatures = signaturesParam;
	}	
	

}
