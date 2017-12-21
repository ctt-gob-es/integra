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
 * <b>File:</b><p>es.gob.afirma.signature.CAdESSignerInfo.java.</p>
 * <b>Description:</b><p>Class that represents the principal information related to a signer of a CAdES signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>14/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 14/11/2014.
 */
package es.gob.afirma.signature.cades;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;

/**
 * <p>Class that represents the principal information related to a signer of a CAdES signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 14/11/2014.
 */
public class CAdESSignerInfo implements Serializable {

	/**
	 * Attribute that represents .
	 */
	private static final long serialVersionUID = 7423581287764619651L;

	/**
	 * Attribute that represents the signing certificate for the signer.
	 */
	private X509Certificate signingCertificate;

	/**
	 * Attribute that represents an expanded SignerInfo block from a CMS Signed message.
	 */
	private SignerInformation signerInformation;

	/**
	 * Attribute that represents the list of counter signers associated to this signer.
	 */
	private List<CAdESSignerInfo> listCounterSigners;

	/**
	 * Attribute that represents the error occurred trying to obtain the signing certificate.
	 */
	private String errorMsg;

	/**
	 * Attribute that represents the list with the time-stamps contained inside of the <code>signature-time-stamp</code> attributes, ordered ascendant by generation time. 
	 */
	private List<TimeStampToken> listTimeStamps;

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
	 * Gets the value of the attribute {@link #signerInformation}.
	 * @return the value of the attribute {@link #signerInformation}.
	 */
	public final SignerInformation getSignerInformation() {
		return signerInformation;
	}

	/**
	 * Sets the value of the attribute {@link #signerInformation}.
	 * @param signerInformationParam The value for the attribute {@link #signerInformation}.
	 */
	public final void setSignerInformation(SignerInformation signerInformationParam) {
		this.signerInformation = signerInformationParam;
	}

	/**
	 * Gets the value of the attribute {@link #listCounterSigners}.
	 * @return the value of the attribute {@link #listCounterSigners}.
	 */
	public final List<CAdESSignerInfo> getListCounterSigners() {
		return listCounterSigners;
	}

	/**
	 * Sets the value of the attribute {@link #listCounterSigners}.
	 * @param listCounterSignersParam The value for the attribute {@link #listCounterSigners}.
	 */
	public final void setListCounterSigners(List<CAdESSignerInfo> listCounterSignersParam) {
		this.listCounterSigners = listCounterSignersParam;
	}

	/**
	 * Gets the value of the attribute {@link #errorMsg}.
	 * @return the value of the attribute {@link #errorMsg}.
	 */
	public final String getErrorMsg() {
		return errorMsg;
	}

	/**
	 * Sets the value of the attribute {@link #errorMsg}.
	 * @param errorMsgParam The value for the attribute {@link #errorMsg}.
	 */
	public final void setErrorMsg(String errorMsgParam) {
		this.errorMsg = errorMsgParam;
	}

	/**
	 * Gets the value of the attribute {@link #listTimeStamps}.
	 * @return the value of the attribute {@link #listTimeStamps}.
	 */
	public final List<TimeStampToken> getListTimeStamps() {
		return listTimeStamps;
	}

	/**
	 * Sets the value of the attribute {@link #listTimeStamps}.
	 * @param listTimeStampsParam The value for the attribute {@link #listTimeStamps}.
	 */
	public final void setListTimeStamps(List<TimeStampToken> listTimeStampsParam) {
		this.listTimeStamps = listTimeStampsParam;
	}

}
