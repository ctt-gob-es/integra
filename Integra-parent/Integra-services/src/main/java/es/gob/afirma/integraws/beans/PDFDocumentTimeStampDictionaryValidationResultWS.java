// Copyright (C) 2016 MINHAP, Gobierno de Espa�a
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
 * <b>File:</b><p>es.gob.afirma.integraws.beans.PDFDocumentTimeStampDictionaryValidationResultWS.java.</p>
 * <b>Description:</b><p>Class that contains all the information related to the result of a document time-stamp dictionary validation process for a PDF document executed via web
 * service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>23/12/2016.</p>
 * @author Gobierno de España.
 * @version 1.1, 13/01/2017.
 */
package es.gob.afirma.integraws.beans;

import java.security.cert.CertificateEncodingException;
import java.util.List;

import es.gob.afirma.signature.validation.PDFDocumentTimeStampDictionaryValidationResult;
import es.gob.afirma.signature.validation.TimeStampValidationInfo;

/**
 * <p>Class that contains all the information related to the result of a document time-stamp dictionary validation process for a PDF document executed via web
 * service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 13/01/2017.
 */
public class PDFDocumentTimeStampDictionaryValidationResultWS {

	/**
	 * Attribute that indicates if the document time-stamp dictionary is correct.
	 */
	private boolean isCorrect;

	/**
	 * Attribute that represents the error message when the document time-stamp dictionary isn't correct.
	 */
	private String errorMsg;

	/**
	 * Attribute that represents the signing certificate of the time-stamp contained inside.
	 */
	private byte[ ] signingCertificate;

	/**
	 * Attribute that represents the name of the document time-stamp dictionary.
	 */
	private String dictionaryName;

	/**
	 * Attribute that represents the list with the information about the validation applied over the document time-stamp dictionary.
	 */
	private List<TimeStampValidationInfo> listValidations;

	/**
	 * Constructor method for the class PDFDocumentTimeStampDictionaryValidationResultWS.java.
	 */
	public PDFDocumentTimeStampDictionaryValidationResultWS() {
		super();
	}

	/**
	 * Constructor method for the class PDFDocumentTimeStampDictionaryValidationResultWS.java.
	 * @param pdfDocumentTimeStampDictionaryValidationResult Parameter that represents the information related to the result of a document time-stamp dictionary validation
	 * process for a PDF document.
	 */
	public PDFDocumentTimeStampDictionaryValidationResultWS(PDFDocumentTimeStampDictionaryValidationResult pdfDocumentTimeStampDictionaryValidationResult) {
		if (pdfDocumentTimeStampDictionaryValidationResult != null) {
			isCorrect = pdfDocumentTimeStampDictionaryValidationResult.isCorrect();
			errorMsg = pdfDocumentTimeStampDictionaryValidationResult.getErrorMsg();
			dictionaryName = pdfDocumentTimeStampDictionaryValidationResult.getDictionaryName();
			if (pdfDocumentTimeStampDictionaryValidationResult.getSigningCertificate() != null) {
				try {
					signingCertificate = pdfDocumentTimeStampDictionaryValidationResult.getSigningCertificate().getEncoded();
				} catch (CertificateEncodingException e) {
					signingCertificate = null;
				}
			}
			listValidations = pdfDocumentTimeStampDictionaryValidationResult.getListValidations();
		}
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
	 * Gets the value of the attribute {@link #signingCertificate}.
	 * @return the value of the attribute {@link #signingCertificate}.
	 */
	public final byte[ ] getSigningCertificate() {
		return signingCertificate;
	}

	/**
	 * Sets the value of the attribute {@link #signingCertificate}.
	 * @param signingCertificateParam The value for the attribute {@link #signingCertificate}.
	 */
	public final void setSigningCertificate(byte[ ] signingCertificateParam) {
		if (signingCertificateParam != null) {
			this.signingCertificate = signingCertificateParam.clone();
		}
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

	/**
	 * Gets the value of the attribute {@link #dictionaryName}.
	 * @return the value of the attribute {@link #dictionaryName}.
	 */
	public final String getDictionaryName() {
		return dictionaryName;
	}

	/**
	 * Sets the value of the attribute {@link #dictionaryName}.
	 * @param dictionaryNameParam The value for the attribute {@link #dictionaryName}.
	 */
	public final void setDictionaryName(String dictionaryNameParam) {
		this.dictionaryName = dictionaryNameParam;
	}

}
