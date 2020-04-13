// Copyright (C) 2020 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.signature.validation.PDFValidationResult.java.</p>
 * <b>Description:</b><p>Class that contains all the information related to the result of a PDF document validation process.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>11/08/2016.</p>
 * @author Gobierno de España.
 * @version 1.3, 13/04/2020.
 */
package es.gob.afirma.signature.validation;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

/**
 * <p>Class that contains all the information related to the result of a PDF document validation process.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.3, 13/04/2020.
 */
public class PDFValidationResult implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = -5783011950681960546L;

    /**
     * Attribute that indicates if the signed PDF document is integrally correct.
     */
    private boolean isIntegrallyCorrect;

    /**
     * Attribute that represents the error message when the signed PDF document isn't correct.
     */
    private String errorMsg;

    /**
     * Attribute that indicates if the signed PDF document, and all the signature dictionaries and all the document time-stamp dictionaries are correct.
     */
    private boolean isCorrect;

    /**
     * Attribute that represents the list with information related to the validation of each signature dictionary.
     */
    private List<PDFSignatureDictionaryValidationResult> listPDFSignatureDictionariesValidationResults;

    /**
     * Attribute that represents the list with information related to the validation of each Document Time-stamp dictionary.
     */
    private List<PDFDocumentTimeStampDictionaryValidationResult> listPDFDocumentTimeStampDictionariesValidationResults;

    /**
     * Attribute that represents the signature format associated to the signed PDF document.
     */
    private String signatureFormat;

    /**
     * Attribute that represents the expiration date of the PDF signature.
     */
    private Date expirationDate;

    /**
     * Gets the value of the attribute {@link #isIntegrallyCorrect}.
     * @return the value of the attribute {@link #isIntegrallyCorrect}.
     */
    public final boolean isIntegrallyCorrect() {
	return isIntegrallyCorrect;
    }

    /**
     * Sets the value of the attribute {@link #isIntegrallyCorrect}.
     * @param isIntegrallyCorrectParam The value for the attribute {@link #isIntegrallyCorrect}.
     */
    public final void setIntegrallyCorrect(boolean isIntegrallyCorrectParam) {
	this.isIntegrallyCorrect = isIntegrallyCorrectParam;
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
     * Gets the value of the attribute {@link #listPDFSignatureDictionariesValidationResults}.
     * @return the value of the attribute {@link #listPDFSignatureDictionariesValidationResults}.
     */
    public final List<PDFSignatureDictionaryValidationResult> getListPDFSignatureDictionariesValidationResults() {
	return listPDFSignatureDictionariesValidationResults;
    }

    /**
     * Sets the value of the attribute {@link #listPDFSignatureDictionariesValidationResults}.
     * @param listPDFSignatureDictionariesValidationResultsParam The value for the attribute {@link #listPDFSignatureDictionariesValidationResults}.
     */
    public final void setListPDFSignatureDictionariesValidationResults(List<PDFSignatureDictionaryValidationResult> listPDFSignatureDictionariesValidationResultsParam) {
	this.listPDFSignatureDictionariesValidationResults = listPDFSignatureDictionariesValidationResultsParam;
    }

    /**
     * Gets the value of the attribute {@link #listPDFDocumentTimeStampDictionariesValidationResults}.
     * @return the value of the attribute {@link #listPDFDocumentTimeStampDictionariesValidationResults}.
     */
    public final List<PDFDocumentTimeStampDictionaryValidationResult> getListPDFDocumentTimeStampDictionariesValidationResults() {
	return listPDFDocumentTimeStampDictionariesValidationResults;
    }

    /**
     * Sets the value of the attribute {@link #listPDFDocumentTimeStampDictionariesValidationResults}.
     * @param listPDFDocumentTimeStampDictionariesValidationResultsParam The value for the attribute {@link #listPDFDocumentTimeStampDictionariesValidationResults}.
     */
    public final void setListPDFDocumentTimeStampDictionariesValidationResults(List<PDFDocumentTimeStampDictionaryValidationResult> listPDFDocumentTimeStampDictionariesValidationResultsParam) {
	this.listPDFDocumentTimeStampDictionariesValidationResults = listPDFDocumentTimeStampDictionariesValidationResultsParam;
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
     * Gets the value of the attribute {@link #expirationDate}.
     * @return the value of the attribute {@link #expirationDate}.
     */
    public Date getExpirationDate() {
        return expirationDate;
    }

    /**
     * Sets the value of the attribute {@link #expirationDate}.
     * @param expirationDate The value for the attribute {@link #expirationDate}.
     */
    public void setExpirationDate(Date expirationDate) {
        this.expirationDate = expirationDate;
    }
    
}
