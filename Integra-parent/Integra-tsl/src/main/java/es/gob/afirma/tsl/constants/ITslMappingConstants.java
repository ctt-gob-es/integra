// Copyright (C) 2012-15 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.tsl.constants.ITslMappingConstants.java.</p>
 * <b>Description:</b><p>Interface that defines all the commons constants related with the mappings.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 17/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 22/03/2023.
 */
package es.gob.afirma.tsl.constants;


/** 
 * <p>Interface that defines all the commons constants related with the mappings.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 22/03/2023.
 */
public interface ITslMappingConstants {
	/**
	 * Constant attribute that represents the mapping key 'clasificacion'.
	 */
	String MAPPING_KEY_CERT_CLASIFICACION = "clasificacion";

	/**
	 * Constant attribute that represents the mapping key 'certQualified'.
	 */
	String MAPPING_KEY_CERT_QUALIFIED = "certQualified";

	/**
	 * Constant attribute that represents the mapping key 'certClassification'.
	 */
	String MAPPING_KEY_CERT_CLASSIFICATION = "certClassification";

	/**
	 * Constant attribute that represents the mapping key 'ETSI_Result'.
	 */
	String MAPPING_KEY_ETSI_RESULT = "ETSI_Result";

	/**
	 * Constant attribute that represents the mapping key 'qscd'.
	 */
	String MAPPING_KEY_QSCD = "qscd";

	/**
	 * Constant attribute that represents the mapping value 'YES'.
	 */
	String MAPPING_VALUE_YES = "YES";

	/**
	 * Constant attribute that represents the mapping value 'NO'.
	 */
	String MAPPING_VALUE_NO = "NO";

	/**
	 * Constant attribute that represents the mapping value 'UNKNOWN'.
	 */
	String MAPPING_VALUE_UNKNOWN = "UNKNOWN";

	/**
	 * Constant attribute that represents the mapping value 'NATURAL_PERSON'.
	 */
	String MAPPING_VALUE_CLASSIFICATION_NATURAL_PERSON = "NATURAL_PERSON";

	/**
	 * Constant attribute that represents the mapping value 'LEGAL_PERSON'.
	 */
	String MAPPING_VALUE_CLASSIFICATION_LEGALPERSON = "LEGAL_PERSON";

	/**
	 * Constant attribute that represents the mapping value 'ESEAL'.
	 */
	String MAPPING_VALUE_CLASSIFICATION_ESEAL = "ESEAL";

	/**
	 * Constant attribute that represents the mapping value 'ESIG'.
	 */
	String MAPPING_VALUE_CLASSIFICATION_ESIG = "ESIG";

	/**
	 * Constant attribute that represents the mapping value 'WSA'.
	 */
	String MAPPING_VALUE_CLASSIFICATION_WSA = "WSA";

	/**
	 * Constant attribute that represents the mapping value 'TSA'.
	 */
	String MAPPING_VALUE_CLASSIFICATION_TSA = "TSA";

	/**
	 * Constant attribute that represents the mapping value 'ASINCERT'.
	 */
	String MAPPING_VALUE_ASINCERT = "ASINCERT";

	/**
	 * Constant attribute that represents the mapping value 'YES_MANAGED_ON_BEHALF'.
	 */
	String MAPPING_VALUE_QSCD_YES_MANAGEDONBEHALF = "YES_MANAGED_ON_BEHALF";

	/**
	 * Constant attribute that represents the mapping value 'Not_Qualified_For_eSig'.
	 */
	String MAPPING_VALUE_ETSI_RESULT_NQ_ESIG = "Not_Qualified_For_eSig";

	/**
	 * Constant attribute that represents the mapping value 'Not_Qualified_For_eSeal'.
	 */
	String MAPPING_VALUE_ETSI_RESULT_NQ_ESEAL = "Not_Qualified_For_eSeal";

	/**
	 * Constant attribute that represents the mapping value 'Not_QWAC'.
	 */
	String MAPPING_VALUE_ETSI_RESULT_NQ_WSA = "Not_QWAC";
	/**
	 * Constant attribute that represents the mapping value 'QC_For_eSig'.
	 */
	String MAPPING_VALUE_ETSI_RESULT_Q_ESIG = "QC_For_eSig";

	/**
	 * Constant attribute that represents the mapping value 'QC_For_eSeal'.
	 */
	String MAPPING_VALUE_ETSI_RESULT_Q_ESEAL = "QC_For_eSeal";

	/**
	 * Constant attribute that represents the mapping value 'QWAC'.
	 */
	String MAPPING_VALUE_ETSI_RESULT_Q_WSA = "QWAC";
	/**
	 * Constant attribute that represents the mapping value 'INDET_QC_For_eSig'.
	 */
	String MAPPING_VALUE_ETSI_RESULT_INDET_ESIG = "INDET_QC_For_eSig";

	/**
	 * Constant attribute that represents the mapping value 'INDET_QC_For_eSeal'.
	 */
	String MAPPING_VALUE_ETSI_RESULT_INDET_ESEAL = "INDET_QC_For_eSeal";

	/**
	 * Constant attribute that represents the mapping value 'INDET_QWAC'.
	 */
	String MAPPING_VALUE_ETSI_RESULT_INDET_WSA = "INDET_QWAC";
	/**
	 * Constant attribute that represents the mapping value 'INDETERMINATE'.
	 */
	String MAPPING_VALUE_ETSI_RESULT_INDET = "INDETERMINATE";
	/**
	 * Constant attribute that represents the symbol '-'.
	 */
	String HYPHEN_SYMBOL = " - ";
	
	/**
	 * Constant attribute that represents the mapping value 'INDET_QC_For_eSig - INDET_QC_For_eSeal - INDET_QWAC '.
	 */
	String MAPPING_VALUE_ETSI_RESULT_ALL_INDET = MAPPING_VALUE_ETSI_RESULT_INDET_ESIG+HYPHEN_SYMBOL+MAPPING_VALUE_ETSI_RESULT_INDET_ESIG+HYPHEN_SYMBOL+MAPPING_VALUE_ETSI_RESULT_NQ_WSA;
	
	/**
	 * Constant attribute that represents the mapping value 'Not_Qualified_For_eSig - Not_Qualified_For_eSeal - Not_QWAC '.
	 */
	String MAPPING_VALUE_ETSI_RESULT_ALL_NQ = MAPPING_VALUE_ETSI_RESULT_NQ_ESIG+HYPHEN_SYMBOL+MAPPING_VALUE_ETSI_RESULT_NQ_ESEAL+HYPHEN_SYMBOL+MAPPING_VALUE_ETSI_RESULT_INDET_WSA;

			
}
