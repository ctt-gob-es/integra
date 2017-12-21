// Copyright (C) 2016 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.signature.validation.TimestampValidationInfo.java.</p>
 * <b>Description:</b><p>Class that contains information related to the validation of a time-stamp.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>25/07/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 25/07/2016.
 */
package es.gob.afirma.signature.validation;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * <p>Class that contains information related to the validation of a time-stamp.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 25/07/2016.
 */
public class TimestampValidationResult implements Serializable {

	/**
	 * Attribute that represents .
	 */
	private static final long serialVersionUID = -6279176710839576800L;

	/**
	 * Attribute that indicates if the time-stamp is XML type.
	 */
	private boolean isXML;

	/**
	 * Attribute that indicates if the time-stamp is correct.
	 */
	private boolean isCorrect;

	/**
	 * Attribute that represents the signing certificate.
	 */
	private X509Certificate signingCertificate;

	/**
	 * Attribute that represents the list with the information about the validation applied over the time-stamp.
	 */
	private List<TimeStampValidationInfo> listValidations;

	/**
	 * Gets the value of the attribute {@link #isXML}.
	 * @return the value of the attribute {@link #isXML}.
	 */
	public final boolean isXML() {
		return isXML;
	}

	/**
	 * Sets the value of the attribute {@link #isXML}.
	 * @param isXMLParam The value for the attribute {@link #isXML}.
	 */
	public final void setXML(boolean isXMLParam) {
		this.isXML = isXMLParam;
	}

	/**
	 * Gets the value of the attribute {@link #isCorrect}.
	 * @return the value of the attribute {@link #isCorrect}.
	 */
	public final boolean isCorrect() {
		return isCorrect;
	}

	/**
	 * Sets the value of the attribute {@link #isCorrect}.
	 * @param isCorrectParam The value for the attribute {@link #isCorrect}.
	 */
	public final void setCorrect(boolean isCorrectParam) {
		this.isCorrect = isCorrectParam;
	}

	/**
	 * Gets the value of the attribute {@link #signingCertificate}.
	 * @return the value of the attribute {@link #signingCertificate}.
	 */
	public final X509Certificate getSigningCertificate() {
		return signingCertificate;
	}

	/**
	 * Sets the value of the attribute {@link #signingCertificate}.
	 * @param signingCertificateParam The value for the attribute {@link #signingCertificate}.
	 */
	public final void setSigningCertificate(X509Certificate signingCertificateParam) {
		this.signingCertificate = signingCertificateParam;
	}

	/**
	 * Gets the value of the attribute {@link #listValidations}.
	 * @return the value of the attribute {@link #listValidations}.
	 */
	public final List<TimeStampValidationInfo> getListValidations() {
		return listValidations;
	}

	/**
	 * Sets the value of the attribute {@link #listValidations}.
	 * @param listValidationsParam The value for the attribute {@link #listValidations}.
	 */
	public final void setListValidations(List<TimeStampValidationInfo> listValidationsParam) {
		this.listValidations = listValidationsParam;
	}

}
