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
 * <b>File:</b><p>es.gob.afirma.signature.validation.ITimestampValidationTaskID.java.</p>
 * <b>Description:</b><p>Interface that defines all the identifiers of the validation task supported to execute over a time-stamp.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>04/08/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 04/08/2016.
 */
package es.gob.afirma.signature.validation;


/** 
 * <p>Interface that defines all the identifiers of the validation task supported to execute over a time-stamp.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 04/08/2016.
 */
public interface ITimestampValidationTaskID {

	/**
	 * Constant attribute that identifies the validation of the signature of a time-stamp. 
	 */
	Long ID_TIMESTAMP_SIGNATURE_VALIDATION = 1L;
	
	/**
	 * Constant attribute that identifies the validation of the data stamped by a time-stamp. 
	 */
	Long ID_STAMPED_DATA_VALIDATION = 2L;
	
	/**
	 * Constant attribute that identifies the validation of the signing certificate of a time-stamp.
	 */
	Long ID_SIGNING_CERTIFICATE_VALIDATION = 3L;
	
	/**
	 * Constant attribute that identifies the validation of the references included into a XML time-stamp. 
	 */
	Long ID_REFERENCES_VALIDATION = 4L;
	
	/**
	 * Constant attribute that identifies the information about the validation of the structure of a Document Time-stamp dictionary of a PDF document. 
	 */
	Long ID_PDF_STRUCTURALLY_VALIDATION = 5L;
	
	/**
	 * Constant attribute that identifies the information about the validation of the generation date for a time-stamp contained inside of a Document Time-stamp 
	 * dictionary of a PDF document. 
	 */
	Long ID_SIGNING_TIME_VALIDATION = 6L;
}
