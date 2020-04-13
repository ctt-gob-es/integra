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
 * <b>File:</b><p>es.gob.afirma.signature.validation.SignerValidationResult.java.</p>
 * <b>Description:</b><p>Class that contains all the information related to the result of a signer or counter-signer validation process.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>25/07/2016.</p>
 * @author Gobierno de España.
 * @version 1.1, 13/04/2020.
 */
package es.gob.afirma.signature.validation;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * <p>Class that contains all the information related to the result of a signer or counter-signer validation process.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 13/04/2020.
 */
public class SignerValidationResult implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = -8616718355149372904L;

    /**
     * Attribute that represents the signature format associated to the signer/counter-signer.
     */
    private String format;

    /**
     * Attribute that indicates if the signer/counter-signer is correct.
     */
    private boolean isCorrect;

    /**
     * Attribute that represents the signing certificate.
     */
    private X509Certificate signingCertificate;

    /**
     * Attribute that represents the error message when the validation of the signer was incorrect.
     */
    private String errorMsg;

    /**
     * Attribute that represents the list with the information about the validations applied over the signer.
     */
    private List<ValidationInfo> listValidations;

    /**
     * Attribute that represents the list with the information about the validations applied over the time-stamps associated to the signer. The time-stamps are sorted ascendant by
     * generation time.
     */
    private List<TimestampValidationResult> listTimestampsValidations;

    /**
     * Attribute that represents the list with the information about the validations applied over the counter-signers of this signer.
     */
    private List<SignerValidationResult> listCounterSignersValidationsResults;

    /**
     * Attribute that represents the signing certificate of the last archive timestamp.
     */
    private X509Certificate lastArchiveTst;

    /**
     * Gets the value of the attribute {@link #format}.
     * @return the value of the attribute {@link #format}.
     */
    public final String getFormat() {
	return format;
    }

    /**
     * Sets the value of the attribute {@link #format}.
     * @param formatParam The value for the attribute {@link #format}.
     */
    public final void setFormat(String formatParam) {
	this.format = formatParam;
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
    public final List<ValidationInfo> getListValidations() {
	return listValidations;
    }

    /**
     * Sets the value of the attribute {@link #listValidations}.
     * @param listValidationsParam The value for the attribute {@link #listValidations}.
     */
    public final void setListValidations(List<ValidationInfo> listValidationsParam) {
	this.listValidations = listValidationsParam;
    }

    /**
     * Gets the value of the attribute {@link #listTimestampsValidations}.
     * @return the value of the attribute {@link #listTimestampsValidations}.
     */
    public final List<TimestampValidationResult> getListTimestampsValidations() {
	return listTimestampsValidations;
    }

    /**
     * Sets the value of the attribute {@link #listTimestampsValidations}.
     * @param listTimestampsValidationsParam The value for the attribute {@link #listTimestampsValidations}.
     */
    public final void setListTimestampsValidations(List<TimestampValidationResult> listTimestampsValidationsParam) {
	this.listTimestampsValidations = listTimestampsValidationsParam;
    }

    /**
     * Gets the value of the attribute {@link #listCounterSignersValidationsResults}.
     * @return the value of the attribute {@link #listCounterSignersValidationsResults}.
     */
    public final List<SignerValidationResult> getListCounterSignersValidationsResults() {
	return listCounterSignersValidationsResults;
    }

    /**
     * Sets the value of the attribute {@link #listCounterSignersValidationsResults}.
     * @param listCounterSignersValidationsResultsParam The value for the attribute {@link #listCounterSignersValidationsResults}.
     */
    public final void setListCounterSignersValidationsResults(List<SignerValidationResult> listCounterSignersValidationsResultsParam) {
	this.listCounterSignersValidationsResults = listCounterSignersValidationsResultsParam;
    }

    /**
     * Gets the value of the attribute {@link #lastArchiveTst}.
     * @return the value of the attribute {@link #lastArchiveTst}.
     */
    public X509Certificate getLastArchiveTst() {
	return lastArchiveTst;
    }

    /**
     * Sets the value of the attribute {@link #lastArchiveTst}.
     * @param lastArchiveTst The value for the attribute {@link #lastArchiveTst}.
     */
    public void setLastArchiveTst(X509Certificate lastArchiveTst) {
	this.lastArchiveTst = lastArchiveTst;
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

}
