/*
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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.ifaces.ITSLOIDs.java.</p>
 * <b>Description:</b><p>Interface that defines all the constants OIDs for the TSL.</p>
 * <b>Project:</b><p>Platform for detection and validation of certificates recognized in European TSL.</p>
 * <b>Date:</b><p>11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 15/06/2021.
 */
package es.gob.afirma.tsl.parsing.ifaces;

import iaik.asn1.ObjectID;

/**
 * <p>Interface that defines all the constants OIDs for the TSL.</p>
 * <b>Project:</b><p>Platform for detection and validation of certificates recognized in European TSL.</p>
 * @version 1.1, 15/06/2021.
 */
public interface ITSLOIDs {

	/**
	 * Constant attribute that represents the token 'urn:oid:'.
	 */
	String TOKEN_URN_OID = "urn:oid:";

	/**
	 * Constant attribute that represents the string OID for the X509v3 extended key usage extension
	 * for TSL signing.
	 */
	String STRING_OID_TSL_SIGNING = "0.4.0.2231.3.0";

	/**
	 * Constant attribute that represents the OID for the X509v3 extended key usage extension
	 * for TSL signing.
	 */
	ObjectID OID_TSL_SIGNING = new ObjectID(STRING_OID_TSL_SIGNING);
	/**
	 * Constant attribute that represents the OID for the X509v3 extension QCStatement - QcCompliance.
	 */
	ObjectID OID_QCSTATEMENT_EXT_COMPLIANCE = new ObjectID("0.4.0.1862.1.1", "QcCompliance");

	/**
	 * Constant attribute that represents the token representation for the X509v3 extension QCStatement - QcCompliance.
	 */
	String OID_QCSTATEMENT_EXT_COMPLIANCE_TOKEN = "QcCompliance";

	/**
	 * Constant attribute that represents the OID for the X509v3 extension QCStatement - EuType.
	 */
	ObjectID OID_QCSTATEMENT_EXT_EUTYPE = new ObjectID("0.4.0.1862.1.6", "QcType");

	/**
	 * Constant attribute that represents the token representation for the X509v3 extension QCStatement - EuType.
	 */
	String OID_QCSTATEMENT_EXT_EUTYPE_TOKEN = "QcType";

	/**
	 * Constant attribute that represents the OID for the X509v3 extension QCStatement - EuType - ESign.
	 */
	ObjectID OID_QCSTATEMENT_EXT_EUTYPE_ESIGN = new ObjectID("0.4.0.1862.1.6.1", "id-etsi-qct-esign");

	/**
	 * Constant attribute that represents the token representation for the X509v3 extension QCStatement - EuType - ESign.
	 */
	String OID_QCSTATEMENT_EXT_EUTYPE_ESIGN_TOKEN = "id-etsi-qct-esign";

	/**
	 * Constant attribute that represents the OID for the X509v3 extension QCStatement - EuType - ESeal.
	 */
	ObjectID OID_QCSTATEMENT_EXT_EUTYPE_ESEAL = new ObjectID("0.4.0.1862.1.6.2", "id-etsi-qct-eseal");

	/**
	 * Constant attribute that represents the token representation for the X509v3 extension QCStatement - EuType - ESeal.
	 */
	String OID_QCSTATEMENT_EXT_EUTYPE_ESEAL_TOKEN = "id-etsi-qct-eseal";

	/**
	 * Constant attribute that represents the OID for the X509v3 extension QCStatement - EuType - Web.
	 */
	ObjectID OID_QCSTATEMENT_EXT_EUTYPE_WEB = new ObjectID("0.4.0.1862.1.6.3", "id-etsi-qct-web");

	/**
	 * Constant attribute that represents the token representation for the X509v3 extension QCStatement - EuType - Web.
	 */
	String OID_QCSTATEMENT_EXT_EUTYPE_WEB_TOKEN = "id-etsi-qct-web";

	/**
	 * Constant attribute that represents the OID for the Policy Identifier for qcp-public-with-sscd.
	 */
	ObjectID OID_POLICY_IDENTIFIER_QCP_PUBLIC_WITH_SSCD = new ObjectID("0.4.0.1456.1.1", "qcp-public-with-sscd");

	/**
	 * Constant attribute that represents the token representation for the Policy Identifier for qcp-public-with-sscd.
	 */
	String OID_POLICY_IDENTIFIER_QCP_PUBLIC_WITH_SSCD_TOKEN = "qcp-public-with-sscd";

	/**
	 * Constant attribute that represents the OID for the Policy Identifier for qcp-public.
	 */
	ObjectID OID_POLICY_IDENTIFIER_QCP_PUBLIC = new ObjectID("0.4.0.1456.1.2", "qcp-public");
	/**
	 * Constant attribute that represents the token representation for the Policy Identifier for qcp-public.
	 */
	String OID_POLICY_IDENTIFIER_QCP_PUBLIC_TOKEN = "qcp-public";

	/**
	 * Constant attribute that represents the OID for the Policy Identifier for qcp-natural.
	 */
	ObjectID OID_POLICY_IDENTIFIER_QCP_NATURAL = new ObjectID("0.4.0.194112.1.0", "qcp-natural");
	/**
	 * Constant attribute that represents the token representation for the Policy Identifier for qcp-natural.
	 */
	String OID_POLICY_IDENTIFIER_QCP_NATURAL_TOKEN = "qcp-natural";

	/**
	 * Constant attribute that represents the OID for the Policy Identifier for qcp-legal.
	 */
	ObjectID OID_POLICY_IDENTIFIER_QCP_LEGAL = new ObjectID("0.4.0.194112.1.1", "qcp-legal");

	/**
	 * Constant attribute that represents the token representation for the Policy Identifier for qcp-legal.
	 */
	String OID_POLICY_IDENTIFIER_QCP_LEGAL_TOKEN = "qcp-legal";

	/**
	 * Constant attribute that represents the OID for the Policy Identifier for qcp-natural-qscd.
	 */
	ObjectID OID_POLICY_IDENTIFIER_QCP_NATURAL_QSCD = new ObjectID("0.4.0.194112.1.2", "qcp-natural-qscd");

	/**
	 * Constant attribute that represents the token representation for the Policy Identifier for qcp-natural-qscd.
	 */
	String OID_POLICY_IDENTIFIER_QCP_NATURAL_QSCD_TOKEN = "qcp-natural-qscd";

	/**
	 * Constant attribute that represents the OID for the Policy Identifier for qcp-legal-qscd.
	 */
	ObjectID OID_POLICY_IDENTIFIER_QCP_LEGAL_QSCD = new ObjectID("0.4.0.194112.1.3", "qcp-legal-qscd");

	/**
	 * Constant attribute that represents the token representation for the Policy Identifier for qcp-legal-qscd.
	 */
	String OID_POLICY_IDENTIFIER_QCP_LEGAL_QSCD_TOKEN = "qcp-legal-qscd";

	/**
	 * Constant attribute that represents the OID for the Policy Identifier for qcp-web.
	 */
	ObjectID OID_POLICY_IDENTIFIER_QCP_WEB = new ObjectID("0.4.0.194112.1.4", "qcp-web");

	/**
	 * Constant attribute that represents the token representation for the Policy Identifier for qcp-web.
	 */
	String OID_POLICY_IDENTIFIER_QCP_WEB_TOKEN = "qcp-web";

}
