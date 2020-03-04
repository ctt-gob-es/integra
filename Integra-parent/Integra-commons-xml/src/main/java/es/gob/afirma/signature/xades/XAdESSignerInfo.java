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
 * <b>File:</b><p>es.gob.afirma.signature.xades.XAdESSignerInfo.java.</p>
 * <b>Description:</b><p>Class that represents the principal information related to a signer of a XAdES signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>17/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.2, 04/03/2020.
 */
package es.gob.afirma.signature.xades;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.List;

import org.w3c.dom.Element;

import es.gob.afirma.utils.XAdESTimeStampType;
import org.apache.xml.security.signature.XMLSignature;

/**
 * <p>Class that represents the principal information related to a signer of a XAdES signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 04/03/2020.
 */
public class XAdESSignerInfo implements Serializable {

	/**
	 * Class serial version.
	 */
	private static final long serialVersionUID = 6843200193209306995L;

	/**
	 * Attribute that represents the value of the <code>Id</code> attribute.
	 */
	private String id;

	/**
	 * Attribute that represents the signing certificate for the signer.
	 */
	private X509Certificate signingCertificate;

	/**
	 * Attribute that represents the list of counter signers associated to this signer.
	 */
	private List<XAdESSignerInfo> listCounterSigners;

	/**
	 * Attribute that represents the error processing the signer.
	 */
	private String errorMsg;

	/**
	 * Attribute that represents the list with the information about the time-stamps contained inside of the <code>xades:SignatureTimeStamp</code> elements, ordered ascendant
	 * by generation time.
	 */
	private List<XAdESTimeStampType> listTimeStamps;

	/**
	 * Attribute that represents the Signature element.
	 */
	private XMLSignature signature;

	/**
	 * Attribute that represents the Signature element as XML element.
	 */
	private Element elementSignature;

	/**
	 * Attribute that indicates whether the signer contains ArchiveTimeStamp element (true) or not (false).
	 */
	private boolean hasArchiveTimeStampElement;
	
	/**
	 * Attribute that represents the <code>xades:QualifyingProperties</code> element as XML element.
	 */
	private Element qualifyingPropertiesElement;

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
	 * Gets the value of the attribute {@link #listCounterSigners}.
	 * @return the value of the attribute {@link #listCounterSigners}.
	 */
	public final List<XAdESSignerInfo> getListCounterSigners() {
		return listCounterSigners;
	}

	/**
	 * Sets the value of the attribute {@link #listCounterSigners}.
	 * @param listCounterSignersParam The value for the attribute {@link #listCounterSigners}.
	 */
	public final void setListCounterSigners(List<XAdESSignerInfo> listCounterSignersParam) {
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
	 * Gets the value of the attribute {@link #signature}.
	 * @return the value of the attribute {@link #signature}.
	 */
	public final XMLSignature getSignature() {
		return signature;
	}

	/**
	 * Sets the value of the attribute {@link #signature}.
	 * @param signatureParam The value for the attribute {@link #signature}.
	 */
	public final void setSignature(XMLSignature signatureParam) {
		this.signature = signatureParam;
	}

	/**
	 * Gets the value of the attribute {@link #elementSignature}.
	 * @return the value of the attribute {@link #elementSignature}.
	 */
	public final Element getElementSignature() {
		return elementSignature;
	}

	/**
	 * Sets the value of the attribute {@link #elementSignature}.
	 * @param elementSignatureParam The value for the attribute {@link #elementSignature}.
	 */
	public final void setElementSignature(Element elementSignatureParam) {
		this.elementSignature = elementSignatureParam;
	}

	/**
	 * Gets the value of the attribute {@link #hasArchiveTimeStampElement}.
	 * @return the value of the attribute {@link #hasArchiveTimeStampElement}.
	 */
	public final boolean isHasArchiveTimeStampElement() {
		return hasArchiveTimeStampElement;
	}

	/**
	 * Sets the value of the attribute {@link #hasArchiveTimeStampElement}.
	 * @param hasArchiveTimeStampElementParam The value for the attribute {@link #hasArchiveTimeStampElement}.
	 */
	public final void setHasArchiveTimeStampElement(boolean hasArchiveTimeStampElementParam) {
		this.hasArchiveTimeStampElement = hasArchiveTimeStampElementParam;
	}

	/**
	 * Gets the value of the attribute {@link #listTimeStamps}.
	 * @return the value of the attribute {@link #listTimeStamps}.
	 */
	public final List<XAdESTimeStampType> getListTimeStamps() {
		return listTimeStamps;
	}

	/**
	 * Sets the value of the attribute {@link #listTimeStamps}.
	 * @param listTimeStampsParam The value for the attribute {@link #listTimeStamps}.
	 */
	public final void setListTimeStamps(List<XAdESTimeStampType> listTimeStampsParam) {
		this.listTimeStamps = listTimeStampsParam;
	}

	/**
	 * Gets the value of the attribute {@link #id}.
	 * @return the value of the attribute {@link #id}.
	 */
	public final String getId() {
		return id;
	}

	/**
	 * Sets the value of the attribute {@link #id}.
	 * @param idParam The value for the attribute {@link #id}.
	 */
	public final void setId(String idParam) {
		this.id = idParam;
	}

	
	/**
	 * Gets the value of the attribute {@link #qualifyingPropertiesElement}.
	 * @return the value of the attribute {@link #qualifyingPropertiesElement}.
	 */
	public final Element getQualifyingPropertiesElement() {
		return qualifyingPropertiesElement;
	}

	
	/**
	 * Sets the value of the attribute {@link #qualifyingPropertiesElement}.
	 * @param qualifyingPropertiesElementParam The value for the attribute {@link #qualifyingPropertiesElement}.
	 */
	public final void setQualifyingPropertiesElement(Element qualifyingPropertiesElementParam) {
		this.qualifyingPropertiesElement = qualifyingPropertiesElementParam;
	}

	
}
