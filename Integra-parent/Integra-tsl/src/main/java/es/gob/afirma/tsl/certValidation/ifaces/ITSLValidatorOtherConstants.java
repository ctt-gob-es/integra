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
 * <b>File:</b><p>es.gob.afirma.tsl.certValidation.ifaces.ITSLValidatorOtherConstants.java.</p>
 * <b>Description:</b><p>Interface that defines all the constants needed for validation and mapping process in TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 17/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.2, 19/09/2022.
 */
package es.gob.afirma.tsl.certValidation.ifaces;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;

import es.gob.afirma.tsl.parsing.ifaces.ITSLOIDs;

/** 
 * <p>Interface that defines all the constants needed for validation and mapping process in TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 19/09/2022.
 */

public interface ITSLValidatorOtherConstants {
    /**
	 * Constant attribute that represents an array with the OIDs (String) of the QCStatements
	 * that qualifies a certificate how qualified.
	 */
	String[ ] QCSTATEMENTS_OIDS_FOR_QUALIFIED_CERTS_STRING_ARRAY = new String[ ] { ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance.getId() };

	/**
	 * Constant attribute that represents a list with the OIDs (String) of the QCStatements
	 * that qualifies a certificate how qualified.
	 */
	List<String> QCSTATEMENTS_OIDS_FOR_QUALIFIED_CERTS_LIST = new ArrayList<String>(Arrays.asList(QCSTATEMENTS_OIDS_FOR_QUALIFIED_CERTS_STRING_ARRAY));

	/**
	 * Constant attribute that represents an array with the OIDs (String) of the Policy Identifiers
	 * that qualifies a certificate how qualified.
	 */
	String[ ] POLICYIDENTIFIERS_OIDS_FOR_QUALIFIED_CERTS_STRING_ARRAY = new String[ ] { ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_PUBLIC_WITH_SSCD.getId(), ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_PUBLIC.getId(), ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_NATURAL.getId(), ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_LEGAL.getId(), ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_NATURAL_QSCD.getId(), ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_LEGAL_QSCD.getId(), ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_WEB.getId() };
	/**
	 * Constant attribute that represents a list with the OIDs (String) of the Policy Identifiers
	 * that qualifies a certificate how qualified.
	 */
	List<String> POLICYIDENTIFIERS_OIDS_FOR_QUALIFIED_CERTS_LIST = new ArrayList<String>(Arrays.asList(POLICYIDENTIFIERS_OIDS_FOR_QUALIFIED_CERTS_STRING_ARRAY));

	/**
	 * Constant attribute that represents an array with the OIDs (String) of the Policy Identifiers
	 * that qualifies a certificate for ESig.
	 */
	String[ ] POLICYIDENTIFIERS_OIDS_FOR_ESIG_CERTS_STRING_ARRAY = new String[ ] { ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_PUBLIC_WITH_SSCD.getId(), ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_PUBLIC.getId(), ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_NATURAL.getId(), ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_NATURAL_QSCD.getId() };

	/**
	 * Constant attribute that represents a list with the OIDs (String) of the Policy Identifiers
	 * that qualifies a certificate how ESig.
	 */
	List<String> POLICYIDENTIFIERS_OIDS_FOR_ESIG_CERTS_LIST = new ArrayList<String>(Arrays.asList(POLICYIDENTIFIERS_OIDS_FOR_ESIG_CERTS_STRING_ARRAY));

	/**
	 * Constant attribute that represents an array with the OIDs (String) of the Policy Identifiers
	 * that qualifies a certificate for ESeal.
	 */
	String[ ] POLICYIDENTIFIERS_OIDS_FOR_ESEAL_CERTS_STRING_ARRAY = new String[ ] { ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_LEGAL.getId(), ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_LEGAL_QSCD.getId() };

	/**
	 * Constant attribute that represents a list with the OIDs (String) of the Policy Identifiers
	 * that qualifies a certificate how ESeal.
	 */
	List<String> POLICYIDENTIFIERS_OIDS_FOR_ESEAL_CERTS_LIST = new ArrayList<String>(Arrays.asList(POLICYIDENTIFIERS_OIDS_FOR_ESEAL_CERTS_STRING_ARRAY));

	/**
	 * Constant attribute that represents an array with the OIDs (String) of the Policy Identifiers
	 * that qualifies a certificate for WSA.
	 */
	String[ ] POLICYIDENTIFIERS_OIDS_FOR_WSA_CERTS_STRING_ARRAY = new String[ ] { ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_WEB.getId() };

	/**
	 * Constant attribute that represents a list with the OIDs (String) of the Policy Identifiers
	 * that qualifies a certificate how WSA.
	 */
	List<String> POLICYIDENTIFIERS_OIDS_FOR_WSA_CERTS_LIST = new ArrayList<String>(Arrays.asList(POLICYIDENTIFIERS_OIDS_FOR_WSA_CERTS_STRING_ARRAY));

	/**
	 * Constant attribute that represents an array with the OIDs (String) of the Policy Identifiers
	 * that sets a certificate in a QSCD.
	 */
	String[ ] POLICYIDENTIFIERS_OIDS_FOR_CERTS_IN_QSCD_STRING_ARRAY = new String[ ] { ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_PUBLIC_WITH_SSCD.getId(), ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_LEGAL_QSCD.getId(), ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_NATURAL_QSCD.getId() };

	/**
	 * Constant attribute that represents a list with the OIDs (String) of the Policy Identifiers
	 * that sets a certificate in a QSCD.
	 */
	List<String> POLICYIDENTIFIERS_OIDS_FOR_CERTS_IN_QSCD_LIST = new ArrayList<String>(Arrays.asList(POLICYIDENTIFIERS_OIDS_FOR_CERTS_IN_QSCD_STRING_ARRAY));

	/**
	 * Constant attribute that represents an array with the OIDs (String) of the Policy Identifiers
	 * that sets a certificate in a QSCD.
	 */
	String[ ] POLICYIDENTIFIERS_OIDS_FOR_CERTS_IN_NO_QSCD_STRING_ARRAY = new String[ ] { ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_PUBLIC.getId(), ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_LEGAL.getId(), ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_NATURAL.getId(), ITSLOIDs.OID_POLICY_IDENTIFIER_QCP_WEB.getId() };

	/**
	 * Constant attribute that represents a list with the OIDs (String) of the Policy Identifiers
	 * that sets a certificate in a QSCD.
	 */
	List<String> POLICYIDENTIFIERS_OIDS_FOR_CERTS_IN_NO_QSCD_LIST = new ArrayList<String>(Arrays.asList(POLICYIDENTIFIERS_OIDS_FOR_CERTS_IN_NO_QSCD_STRING_ARRAY));

}
