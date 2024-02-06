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
// https://eupl.eu/1.1/es/

/** 
 * <b>File:</b><p>es.gob.afirma.signature.validation.ISignatureValidationTaskID.java.</p>
 * <b>Description:</b><p>Interface that defines all the identifiers of the validation task supported to execute over a signer of a signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>03/08/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 03/08/2016.
 */
package es.gob.afirma.signature.validation;

/** 
 * <p>Interface that defines all the identifiers of the validation task supported to execute over a signer of a signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 03/08/2016.
 */
public interface ISignatureValidationTaskID {

	/**
	 * Constant attribute that identifies the validation of the core of a signature for a signer. 
	 */
	Long ID_SIGNATURE_CORE_VALIDATION = 1L;

	/**
	 * Constant attribute that identifies the information about the validation of the public key of a signature for a signer. 
	 */
	Long ID_PUBLIC_KEY_INFO_VALIDATION = 2L;
	
	/**
	 * Constant attribute that identifies the information about the validation of the signing time for a signer. 
	 */
	Long ID_SIGNING_TIME_VALIDATION = 3L;
	
	/**
	 * Constant attribute that identifies the information about the validation of the signature by the signature policy associated to a signer. 
	 */
	Long ID_SIGNATURE_POLICY_VALIDATION = 4L;
	
	/**
	 * Constant attribute that identifies the information about the validation of the certificate of a signer. 
	 */
	Long ID_SIGNING_CERTIFICATE_VALIDATION = 5L;
	
	/**
	 * Constant attribute that identifies the information about the validation of the <code>signature-time-stamp</code> attributes associated to a signer. 
	 */
	Long ID_SIGNATURE_TIME_STAMP_ATTRIBUTES_VALIDATION = 6L;
	
	/**
	 * Constant attribute that identifies the information about the validation of the <code>xades:SignatureTimeStamo</code> elements associated to a signer. 
	 */
	Long ID_SIGNATURE_TIME_STAMP_ELEMENTS_VALIDATION = 7L;
	
	/**
	 * Constant attribute that identifies the information about the validation of the structure of a signature dictionary of a PDF document. 
	 */
	Long ID_PDF_STRUCTURALLY_VALIDATION = 8L;

}
