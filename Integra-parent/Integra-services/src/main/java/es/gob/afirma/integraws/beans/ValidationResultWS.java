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
 * <b>File:</b><p>es.gob.afirma.integraws.beans.ValidationResultWS.java.</p>
 * <b>Description:</b><p>Class that contains all the information related to the result of a signature validation process executed via web service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/05/2016.</p>
 * @author Gobierno de España.
 * @version 1.3, 13/04/2020.
 */
package es.gob.afirma.integraws.beans;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import es.gob.afirma.signature.validation.PDFDocumentTimeStampDictionaryValidationResult;
import es.gob.afirma.signature.validation.PDFSignatureDictionaryValidationResult;
import es.gob.afirma.signature.validation.PDFValidationResult;
import es.gob.afirma.signature.validation.SignerValidationResult;
import es.gob.afirma.signature.validation.ValidationResult;

/**
 * <p>Class that contains all the information related to the result of a signature validation process executed via web service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.3, 13/04/2020.
 */
public class ValidationResultWS {

    /**
     * Attribute that represents description of error if exists.
     */
    private String errorMsg;

    /**
     * Attribute that indicates if the signature is integrally correct.
     */
    private boolean isIntegrallyCorrect;

    /**
     * Attribute that represents the list with information related to the validation of each signer contained inside of the signature, when the signature is ASN.1, XML or ASiC-S.
     */
    private List<SignerValidationResultWS> signersList;

    /**
     * Attribute that represents the result of the validation, <code>true</code> if the validation was correct, or <code>false</code> if the validation fails.
     */
    private boolean isCorrect;

    /**
     * Attribute that indicates if the signature validated was a signed PDF document (true) or not (false).
     */
    private boolean isPDF = false;

    /**
     * Attribute that represents the signature format associated to the PDF document when the signature validated was a signed PDF document. 
     */
    private String pdfSignatureFormat;

    /**
     * Attribute that represents the list with information related to the validation of each signature dictionary, when the signature has PDF form.
     */
    private List<PDFSignatureDictionaryValidationResultWS> listPDFSignatureDictionariesValidationResults;

    /**
     * Attribute that represents the list with information related to the validation of each Document Time-stamp dictionary, when the signature has PDF form.
     */
    private List<PDFDocumentTimeStampDictionaryValidationResultWS> listPDFDocumentTimeStampDictionariesValidationResults;

    /**
     * Attribute that represents the expiration date of the signature.
     */
    private Date expirationDate;

    /**
     * Constructor method for the class ValidationResultWS.java.
     */
    public ValidationResultWS() {
	super();
    }

    /**
     * Constructor method for the class ValidationResultWS.java.
     * @param pdfValidationResult Parameter that represents the information related to the result of a PDF document validation process.
     */
    public ValidationResultWS(PDFValidationResult pdfValidationResult) {
	if (pdfValidationResult != null) {
	    errorMsg = pdfValidationResult.getErrorMsg();
	    isIntegrallyCorrect = pdfValidationResult.isIntegrallyCorrect();
	    signersList = null;
	    isCorrect = pdfValidationResult.isCorrect();
	    isPDF = true;
	    pdfSignatureFormat = pdfValidationResult.getSignatureFormat();
	    expirationDate = pdfValidationResult.getExpirationDate();
	    if (pdfValidationResult.getListPDFSignatureDictionariesValidationResults() != null && !pdfValidationResult.getListPDFSignatureDictionariesValidationResults().isEmpty()) {
		listPDFSignatureDictionariesValidationResults = new ArrayList<PDFSignatureDictionaryValidationResultWS>();
		for (PDFSignatureDictionaryValidationResult pdfSignatureDictionaryValidationResult: pdfValidationResult.getListPDFSignatureDictionariesValidationResults()) {
		    listPDFSignatureDictionariesValidationResults.add(new PDFSignatureDictionaryValidationResultWS(pdfSignatureDictionaryValidationResult));
		}
	    }
	    if (pdfValidationResult.getListPDFDocumentTimeStampDictionariesValidationResults() != null && !pdfValidationResult.getListPDFDocumentTimeStampDictionariesValidationResults().isEmpty()) {
		listPDFDocumentTimeStampDictionariesValidationResults = new ArrayList<PDFDocumentTimeStampDictionaryValidationResultWS>();
		for (PDFDocumentTimeStampDictionaryValidationResult pdfDocumentTimeStampDictionaryValidationResult: pdfValidationResult.getListPDFDocumentTimeStampDictionariesValidationResults()) {
		    listPDFDocumentTimeStampDictionariesValidationResults.add(new PDFDocumentTimeStampDictionaryValidationResultWS(pdfDocumentTimeStampDictionaryValidationResult));
		}
	    }
	}
    }

    /**
     * Constructor method for the class ValidationResultWS.java.
     * @param validationResult Parameter that represents the the information related to the result of a signature validation process.
     */
    public ValidationResultWS(ValidationResult validationResult) {
	if (validationResult != null) {
	    errorMsg = validationResult.getErrorMsg();
	    isIntegrallyCorrect = validationResult.isIntegrallyCorrect();
	    if (validationResult.getListSignersValidationResults() != null && !validationResult.getListSignersValidationResults().isEmpty()) {
		signersList = new ArrayList<SignerValidationResultWS>();
		for (SignerValidationResult signerValidationResult: validationResult.getListSignersValidationResults()) {
		    signersList.add(new SignerValidationResultWS(signerValidationResult));
		}
	    }
	    isCorrect = validationResult.isCorrect();
	    expirationDate = validationResult.getExpirationDate();
	    isPDF = false;
	    pdfSignatureFormat = null;
	    listPDFSignatureDictionariesValidationResults = null;
	    listPDFDocumentTimeStampDictionariesValidationResults = null;
	}
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
     * Gets the value of the attribute {@link #signersList}.
     * @return the value of the attribute {@link #signersList}.
     */
    public final List<SignerValidationResultWS> getSignersList() {
	return signersList;
    }

    /**
     * Sets the value of the attribute {@link #signersList}.
     * @param signersListParam The value for the attribute {@link #signersList}.
     */
    public final void setSignersList(List<SignerValidationResultWS> signersListParam) {
	this.signersList = signersListParam;
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
     * Gets the value of the attribute {@link #isPDF}.
     * @return the value of the attribute {@link #isPDF}.
     */
    public final boolean isPDF() {
	return isPDF;
    }

    /**
     * Sets the value of the attribute {@link #isPDF}.
     * @param isPDFParam The value for the attribute {@link #isPDF}.
     */
    public final void setPDF(boolean isPDFParam) {
	this.isPDF = isPDFParam;
    }

    /**
     * Gets the value of the attribute {@link #listPDFSignatureDictionariesValidationResults}.
     * @return the value of the attribute {@link #listPDFSignatureDictionariesValidationResults}.
     */
    public final List<PDFSignatureDictionaryValidationResultWS> getListPDFSignatureDictionariesValidationResults() {
	return listPDFSignatureDictionariesValidationResults;
    }

    /**
     * Sets the value of the attribute {@link #listPDFSignatureDictionariesValidationResults}.
     * @param listPDFSignatureDictionariesValidationResultsParam The value for the attribute {@link #listPDFSignatureDictionariesValidationResults}.
     */
    public final void setListPDFSignatureDictionariesValidationResults(List<PDFSignatureDictionaryValidationResultWS> listPDFSignatureDictionariesValidationResultsParam) {
	this.listPDFSignatureDictionariesValidationResults = listPDFSignatureDictionariesValidationResultsParam;
    }

    /**
     * Gets the value of the attribute {@link #listPDFDocumentTimeStampDictionariesValidationResults}.
     * @return the value of the attribute {@link #listPDFDocumentTimeStampDictionariesValidationResults}.
     */
    public final List<PDFDocumentTimeStampDictionaryValidationResultWS> getListPDFDocumentTimeStampDictionariesValidationResults() {
	return listPDFDocumentTimeStampDictionariesValidationResults;
    }

    /**
     * Sets the value of the attribute {@link #listPDFDocumentTimeStampDictionariesValidationResults}.
     * @param listPDFDocumentTimeStampDictionariesValidationResultsParam The value for the attribute {@link #listPDFDocumentTimeStampDictionariesValidationResults}.
     */
    public final void setListPDFDocumentTimeStampDictionariesValidationResults(List<PDFDocumentTimeStampDictionaryValidationResultWS> listPDFDocumentTimeStampDictionariesValidationResultsParam) {
	this.listPDFDocumentTimeStampDictionariesValidationResults = listPDFDocumentTimeStampDictionariesValidationResultsParam;
    }

    /**
     * Gets the value of the attribute {@link #pdfSignatureFormat}.
     * @return the value of the attribute {@link #pdfSignatureFormat}.
     */
    public final String getPdfSignatureFormat() {
	return pdfSignatureFormat;
    }

    /**
     * Sets the value of the attribute {@link #pdfSignatureFormat}.
     * @param pdfSignatureFormatParam The value for the attribute {@link #pdfSignatureFormat}.
     */
    public final void setPdfSignatureFormat(String pdfSignatureFormatParam) {
	this.pdfSignatureFormat = pdfSignatureFormatParam;
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
     * @param expirationDateParam The value for the attribute {@link #expirationDate}.
     */
    public void setExpirationDate(Date expirationDateParam) {
        this.expirationDate = expirationDateParam;
    }
    
}
