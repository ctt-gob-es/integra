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
 * <b>File:</b><p>es.gob.afirma.signature.validation.ValidationInfo.java.</p>
 * <b>Description:</b><p>Class that contains information related to a validation task of a signer or counter-signer.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>25/07/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 25/07/2016.
 */
package es.gob.afirma.signature.validation;

import java.io.Serializable;

/**
 * <p>Class that contains information related to a validation task of a signer or counter-signer.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 25/07/2016.
 */
public class ValidationInfo implements Serializable {

	/**
	 * Class serial version.
	 */
	private static final long serialVersionUID = 8237266539327112665L;

	/**
	 * Attribute that represents the identifier of the validation task. The identifier must be a value defined into {@link ISignatureValidationTaskID}.
	 */
	private Long idValidationTask;

	/**
	 * Attribute that indicates if the result of the validation task was success.
	 */
	private boolean isSucess;

	/**
	 * Attribute that represents the error message when the validation task failed.
	 */
	private String errorMsg;

	/**
	 * Gets the value of the attribute {@link #idValidationTask}.
	 * @return the value of the attribute {@link #idValidationTask}.
	 */
	public final Long getIdValidationTask() {
		return idValidationTask;
	}

	/**
	 * Sets the value of the attribute {@link #idValidationTask}.
	 * @param idValidationTaskParam The value for the attribute {@link #idValidationTask}.
	 */
	public final void setIdValidationTask(Long idValidationTaskParam) {
		this.idValidationTask = idValidationTaskParam;
	}

	/**
	 * Gets the value of the attribute {@link #isSucess}.
	 * @return the value of the attribute {@link #isSucess}.
	 */
	public final boolean isSucess() {
		return isSucess;
	}

	/**
	 * Sets the value of the attribute {@link #isSucess}.
	 * @param isSucessParam The value for the attribute {@link #isSucess}.
	 */
	public final void setSucess(boolean isSucessParam) {
		this.isSucess = isSucessParam;
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
