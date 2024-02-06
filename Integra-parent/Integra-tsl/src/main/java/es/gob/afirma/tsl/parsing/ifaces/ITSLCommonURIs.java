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
// https://eupl.eu/1.1/es/


/**
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.ifaces.ITSLCommonURIs.java.</p>
 * <b>Description:</b><p>Interface that contains the string representation of the differents URI used
 * in the XML implementations of the TSL.</p>
 * <b>Project:</b><p>Platform for detection and validation of certificates recognized in European TSL.</p>
 * <b>Date:</b><p>06/11/2018.</p>
 * @author Gobierno de España.
 * @version 1.1, 21/08/2019.
 */
package es.gob.afirma.tsl.parsing.ifaces;

/**
 * <p>Interface that contains the string representation of the differents URI used
 * in the XML implementations of the TSL.</p>
 * <b>Project:</b><p>Platform for detection and validation of certificates recognized in European TSL.</p>
 * @version 1.0, 10/11/2020.
 */
public interface ITSLCommonURIs {

	/**
	 * Constant attribute that represents the URI for the ETSI TS 119612 1.1.1 specification.
	 */
	String ETSI_TS_119612_010101 = "http://uri.etsi.org/19612/v1.1.1";

	/**
	 * Constant attribute that represents the URI for the ETSI TS 119612 2.1.1 specification.
	 */
	String ETSI_TS_119612_020101 = "http://uri.etsi.org/19612/v2.1.1";

	/**
	 * Constant attribute that represents the namespace URI for the ETSI TS 102231 3.1.1 specification.
	 */
	String ETSI_TS_102231_030101_NAMESPACE = "http://uri.etsi.org/02231/v2#";

	/**
	 * Constant attribute that represents the namespace URI for the ETSI TS 119612 1.1.1 specification.
	 */
	String ETSI_TS_119612_010101_NAMESPACE = "http://uri.etsi.org/02231/v2#";

	/**
	 * Constant attribute that represents the namespace URI for the ETSI TS 119612 2.1.1 specification.
	 */
	String ETSI_TS_119612_020101_NAMESPACE = "http://uri.etsi.org/02231/v2#";

	/**
	 * Constant attribute that represents TSLTag URI for the ETSI TS 102231 3.1.1 specification.
	 */
	String TSL_TAG_02231 = "http://uri.etsi.org/02231/TSLTag";

	/**
	 * Constant attribute that represents TSLTag URI for the ETSI TS 119612 1.1.1 and 2.1.1 specifications.
	 */
	String TSL_TAG_19612 = "http://uri.etsi.org/19612/TSLTag";

	/**
	 * Constant attribute that represents a qualifier for web pages that contain one or more TDPs which
	 * can be used as a value of the attribute "profile" for the "head" element of the web page
	 * (ETSI TS 119612 2.1.1).
	 */
	String TSL_TDP_119612_020101 = "http://uri.etsi.org/19612/TDPContainer";

	/**
	 * Indicates a "generic" TSL that exclusively contains trust services which are
	 * approved or recognized by the scheme operator owning the TSL through a
	 * process of direct oversight (whether voluntary or regulatory).
	 */
	String TSL_TYPE_GENERIC = "http://uri.etsi.org/TrstSvc/TSLType/generic";

	/**
	 * Indicates a "schemes" TSL that exclusively contains TSL Issuers, independently
	 * responsible for the approval or recognition by a community of trust services
	 * through a process of direct oversight (whether voluntary or regulatory).
	 */
	String TSL_TYPE_SCHEMES = "http://uri.etsi.org/TrstSvc/TSLType/schemes";

	/**
	 * A TSL implementation of a supervision/accreditation status list of certification
	 * services from certification service providers which are supervised/accredited by
	 * the referenced Member State owning the TSL implementation for compliance
	 * with the relevant provisions laid down in the Directive 1999/93/EC [1] of the
	 * European Parliament and of the Council of 13 December 1999 on a Community
	 * framework for electronic signatures, through a process of direct oversight
	 * (whether voluntary or regulatory).
	 */
	String TSL_TYPE_ESIGDIR1999_GENERIC = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/TSLType/generic";

	/**
	 * A TSL implementation of a compiled list of pointers towards Member States
	 * supervision/accreditation status lists of certification services from certification
	 * service providers which are supervised/accredited by the referenced Member
	 * State owning the pointed TSL implementation for compliance with the relevant
	 * provisions laid down in the eSignature Directive 1999/93/EC [1] of the
	 * European Parliament and of the Council of 13 December 1999 on a Community
	 * framework for electronic signatures, through a process of direct oversight
	 * (whether voluntary or regulatory).
	 */
	String TSL_TYPE_ESIGDIR1999_SCHEMES = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/TSLType/schemes";

	/**
	 * A TL implementation of a supervision/accreditation status list of trust services from
	 * trust service providers which are supervised/accredited by the referenced Member
	 * State owning the TL implementation for compliance with the relevant provisions laid
	 * down in the applicable European legislation, through a process of direct oversight
	 * (whether voluntary or regulatory).
	 */
	String TSL_TYPE_EUGENERIC = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric";

	/**
	 * A TL implementation of a compiled list of pointers towards Member States
	 * supervision/accreditation status lists of trust services from trust service providers
	 * which are supervised/accredited by the referenced Member State owning the pointed
	 * TL implementation for compliance with the relevant provisions laid down in the
	 * applicable European legislation, through a process of direct oversight (whether
	 * voluntary or regulatory).
	 */
	String TSL_TYPE_EULISTOFTHELIST = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists";

	/**
	 *  Indicates a trusted list providing assessment scheme based approval status
	 *  information about trust services from trust service providers which are approved
	 *  by the competent trusted list scheme operator or by the State or body in charge
	 *  from which the scheme operator depends or by which it is mandated, for
	 *  compliance with the relevant provisions of the applicable approval scheme
	 *  and/or the applicable legislation.
	 */
	String TSL_TYPE_NONEUGENERIC = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/CClist";

	/**
	 *  Preffix for {@link ITSLCommonURIs#TSL_TYPE_NONEUGENERIC}.
	 */
	String TSL_TYPE_NONEUGENERIC_PREFFIX = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/";

	/**
	 *  Suffix for {@link ITSLCommonURIs#TSL_TYPE_NONEUGENERIC}.
	 */
	String TSL_TYPE_NONEUGENERIC_SUFFIX = "list";

	/**
	 *  Indicates a compiled list of pointers towards community members' lists of trust
	 *  services from trust service providers which are approved by the competent
	 *  trusted list scheme operator or by the State or body in charge from which the
	 *  scheme operator depends or by which it is mandated, for compliance with the
	 *  relevant provisions of the applicable approval scheme and/or the applicable
	 *  legislation.
	 */
	String TSL_TYPE_NONEULISTOFTHELISTS = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/CClistofthelists";

	/**
	 *  Preffix for {@link ITSLCommonURIs#TSL_TYPE_NONEULISTOFTHELISTS}.
	 */
	String TSL_TYPE_NONEULISTOFTHELISTS_PREFFIX = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/";

	/**
	 *  Suffix for {@link ITSLCommonURIs#TSL_TYPE_NONEULISTOFTHELISTS}.
	 */
	String TSL_TYPE_NONEULISTOFTHELISTS_SUFFIX = "listofthelists";

	/**
	 * Services listed have their status determined after assessment by or on behalf of
	 * the scheme operator against the scheme's criteria (active approval/recognition).
	 */
	String TSL_STATUSDETAPPROACH_ACTIVE = "http://uri.etsi.org/TrstSvc/TSLType/StatusDetn/active";

	/**
	 * Services listed have been nominated by their provider or are known to be
	 * operating in the marketplace, but have not undergone assessment by or on
	 * behalf of the scheme operator for initial approval (passive approval/recognition).
	 */
	String TSL_STATUSDETAPPROACH_PASSIVE = "http://uri.etsi.org/TrstSvc/TSLType/StatusDetn/passive";

	/**
	 * Services listed have been deemed to be non-compliant with scheme criteria.
	 */
	String TSL_STATUSDETAPPROACH_DELINQUENT = "http://uri.etsi.org/TrstSvc/TSLType/StatusDetn/delinquent";

	/**
	 * No predetermined criteria. The TSL is just a collection of pointers to other TSLs.
	 * The issuer will not necessarily take any responsibility or even liability for the
	 * content of TSLs pointed to.
	 */
	String TSL_STATUSDETAPPROACH_LIST = "http://uri.etsi.org/TrstSvc/TSLType/StatusDetn/list";

	/**
	 * Services listed have their status determined by or on behalf of the Scheme
	 * Operator under an appropriate system for a referenced Member State that
	 * allows for ‘supervision' (and when applicable for ‘voluntary accreditation') of
	 * certification service providers who are established on its territory (or established
	 * in a third country in the case of ‘voluntary' accreditation') and issue qualified
	 * certificates to the public according to Art. 3.3 (respectively Art. 3.2 or Art. 7.1(a))
	 * of the Directive 1999/93/EC [1] of the European Parliament and of the Council of
	 * 13 December 1999 on a Community framework for electronic signatures, and,
	 * when applicable, that allows for the ‘supervision' / ‘voluntary accreditation' of
	 * certification service providers not issuing qualified certificates, according to a
	 * nationally defined and established "recognized approval scheme(s)"
	 * implemented on a national basis for the supervision of compliance of services
	 * from certification service providers not issuing Qualified Certificates with the
	 * provisions laid down in Directive 1999/93/EC [1] and potentially extended by
	 * national provisions with regards to the provision of such certification services.
	 */
	String TSL_STATUSDETAPPROACH_ESIGDIR1999_APPROPIATE = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/StatusDetn/appropriate";

	/**
	 * Services listed have their status determined by or on behalf of the Scheme
	 * Operator under an appropriate system as defined by the Member State
	 * implementation of the applicable European legislation and further described in
	 * the 'Scheme information URI' pointed-to information.
	 */
	String TSL_STATUSDETAPPROACH_EUAPPROPIATE = "http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUappropriate";

	/**
	 * Constant that represents an incorrect way for the constant {@link #TSL_STATUSDETAPPROACH_EUAPPROPIATE}.
	 * It is used in the ETSI TS 119612 1.1.1 implementation to support bad definitions in European TSL.
	 */
	String TSL_STATUSDETAPPROACH_EUAPPROPIATE_INCORRECT = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/StatusDetn/EUappropriate";

	/**
	 * Constant that represents an incorrect way for the constant {@link #TSL_STATUSDETAPPROACH_EUAPPROPIATE}.
	 * It is used in the ETSI TS 119612 1.1.1 implementation to support bad definitions in European TSL.
	 */
	String TSL_STATUSDETAPPROACH_EULISTOFTHELISTS_INCORRECT = "http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUlistofthelists";

	/**
	 * Preffix for {@link ITSLCommonURIs#TSL_STATUSDETAPPROACH_BADNONEU}.
	 */
	String TSL_STATUSDETAPPROACH_BADNONEU_PREFFIX = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/StatusDetn/";

	/**
	 * Services listed have their status determined after assessment by or on behalf of
	 * the scheme operator against the scheme's criteria (active approval/recognition)
	 * and as further described in the 'Scheme information URI' pointed-to information.
	 */
	String TSL_STATUSDETAPPROACH_BADNONEU = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/StatusDetn/CCdetermination";

	/**
	 * Suffix for {@link ITSLCommonURIs#TSL_STATUSDETAPPROACH_BADNONEU}.
	 */
	String TSL_STATUSDETAPPROACH_BADNONEU_SUFFIX = "determination";

	/**
	 * Preffix for {@link ITSLCommonURIs#TSL_STATUSDETAPPROACH_NONEU}.
	 */
	String TSL_STATUSDETAPPROACH_NONEU_PREFFIX = "http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/";

	/**
	 * Services listed have their status determined after assessment by or on behalf of
	 * the scheme operator against the scheme's criteria (active approval/recognition)
	 * and as further described in the 'Scheme information URI' pointed-to information.
	 */
	String TSL_STATUSDETAPPROACH_NONEU = "http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/CCdetermination";

	/**
	 * Suffix for {@link ITSLCommonURIs#TSL_STATUSDETAPPROACH_NONEU}.
	 */
	String TSL_STATUSDETAPPROACH_NONEU_SUFFIX = "determination";

	/**
	 * A Certification authority issuing public key certificates.
	 */
	String TSL_SERVICETYPE_CA_PKC = "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC";

	/**
	 * A Certification authority issuing Qualified Certificates.
	 */
	String TSL_SERVICETYPE_CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";

	/**
	 * A Time stamping authority.
	 */
	String TSL_SERVICETYPE_TSA = "http://uri.etsi.org/TrstSvc/Svctype/TSA";

	/**
	 * A time-stamping generation service creating and signing time-stamps tokens.
	 */
	String TSL_SERVICETYPE_TSA_QTST = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST";

	/**
	 * A time stamping service as part of a service from a trust service provider issuing
	 * qualified certificates that issues time-stamp tokens (TST) that can be used in the
	 * validation process of qualified signature or advanced signatures supported by
	 * qualified certificates to ascertain and extend the signature validity when the
	 * qualified certificate is (will be) revoked or expired (will expire).
	 */
	String TSL_SERVICETYPE_TSA_TSSQC = "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC";

	/**
	 * A time stamping service as part of a service from a trust service provider that
	 * issues time-stamp tokens (TST) that can be used in the validation process of
	 * qualified signature or advanced signatures supported by qualified certificates to
	 * ascertain and extend the signature validity when the qualified certificate is (will be)
	 * revoked or expired (will expire).
	 */
	String TSL_SERVICETYPE_TSA_TSS_ADESQC_AND_QES = "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-AdESQCandQES";

	/**
	 * A Certificate status provider operating an OCSP-server.
	 */
	String TSL_SERVICETYPE_CERTSTATUS_OCSP = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP";

	/**
	 * A certificate validity status services issuing Online Certificate Status Protocol
	 * (OCSP) signed responses and operating an OCSP-server as part of a service from
	 * a trust service provider issuing qualified certificates.
	 */
	String TSL_SERVICETYPE_CERTSTATUS_OCSP_QC = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC";

	/**
	 * A Certificate status provider operating a CRL.
	 */
	String TSL_SERVICETYPE_CERTSTATUS_CRL = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL";

	/**
	 * A certificate validity status services issuing CRLs.
	 */
	String TSL_SERVICETYPE_CERTSTATUS_CRL_QC = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL/QC";

	/**
	 * A registration service that verifies the identity and, if applicable, any specific
	 * attributes of a subject for which a certificate is applied for, and whose results are
	 * passed to the relevant certificate generation service.
	 */
	String TSL_SERVICETYPE_RA = "http://uri.etsi.org/TrstSvc/Svctype/RA";

	/**
	 * A registration service that verifies the identity and, if applicable, any specific
	 * attributes of a subject for which a certificate is applied for, and whose results are
	 * passed to the relevant certificate generation service.
	 * Such a registration service cannot be identified by a specific PKI-based public key.
	 */
	String TSL_SERVICETYPE_RA_NOTHAVINGPKIID = "http://uri.etsi.org/TrstSvc/Svctype/RA/nothavingPKIid";

	/**
	 * A service responsible for issuing, publishing or maintenance of signature policies.
	 */
	String TSL_SERVICETYPE_SIGNATURE_POLICY_AUTHORITY = "http://uri.etsi.org/TrstSvc/Svctype/SignaturePolicyAuthority";

	/**
	 * A national root signing CA issuing root-signing or qualified certificates to trust
	 * service providers and related certification or trust services that are accredited
	 * against a national voluntary accreditation scheme or supervised under national law
	 * in accordance with the applicable European legislation.
	 */
	String TSL_SERVICETYPE_NATIONALROOTCA = "http://uri.etsi.org/TrstSvc/Svctype/NationalRootCA-QC";

	/**
	 * An Identity verification service.
	 */
	String TSL_SERVICETYPE_IDV = "http://uri.etsi.org/TrstSvc/Svctype/IdV";

	/**
	 * A Certificate generation service which responds to requests for certificate
	 * generation from an authenticated source of identity information.
	 */
	String TSL_SERVICETYPE_CGEN = "http://uri.etsi.org/TrstSvc/Svctype/CGen";

	/**
	 * An attribute certificate generation service creating and signing attribute certificates
	 * based on the identity and other attributes verified by the relevant registration
	 * services.
	 */
	String TSL_SERVICETYPE_ACA = "http://uri.etsi.org/TrstSvc/Svctype/ACA";

	/**
	 * An Archival service.
	 */
	String TSL_SERVICETYPE_ARCHIV = "http://uri.etsi.org/TrstSvc/Svctype/Archiv";

	/**
	 * A Registered Electronic Mail service.
	 */
	String TSL_SERVICETYPE_REM = "http://uri.etsi.org/TrstSvc/Svctype/REM";

	/**
	 * An electronic delivery service.
	 */
	String TSL_SERVICETYPE_EDS = "http://uri.etsi.org/TrstSvc/Svctype/EDS";

	/**
	 * An electronic delivery service providing qualified electronic deliveries.
	 */
	String TSL_SERVICETYPE_EDS_Q = "http://uri.etsi.org/TrstSvc/Svctype/EDS/Q";

	/**
	 * A qualified electronic registered mail delivery service providing qualified
	 * electronic registered mail deliveries in accordance with the applicable
	 * national legislation in the territory identified by the TL Scheme territory
	 * or with Regulation (EU) No 910/2014 [i.10] whichever is in force at the time
	 * of provision.
	 */
	String TSL_SERVICETYPE_EDS_REM_Q = "http://uri.etsi.org/TrstSvc/Svctype/EDS/REM/Q";

	/**
	 * A preservation service for electronic signatures.
	 */
	String TSL_SERVICETYPE_PSES = "http://uri.etsi.org/TrstSvc/Svctype/PSES";

	/**
	 * A preservation service for qualified electronic signatures.
	 */
	String TSL_SERVICETYPE_PSES_Q = "http://uri.etsi.org/TrstSvc/Svctype/PSES/Q";

	/**
	 * A Key escrow service.
	 */
	String TSL_SERVICETYPE_KESCROW = "http://uri.etsi.org/TrstSvc/Svctype/KEscrow";

	/**
	 * Issuer of PIN- or password-based identity credentials.
	 */
	String TSL_SERVICETYPE_PPWD = "http://uri.etsi.org/TrstSvc/Svctype/PPwd";

	/**
	 * A service issuing trusted lists.
	 */
	String TSL_SERVICETYPE_TLISSUER = "http://uri.etsi.org/TrstSvc/Svctype/TLIssuer";

	/**
	 * A service issuing trusted lists (bad definition).
	 */
	String TSL_SERVICETYPE_TLISSUER_BADDEFINITION = "http://uri.etsi.org/TrstSvd/Svctype/TLIssuer";

	/**
	 * Service responsible for issuing, publishing or maintenance of signature policies.
	 */
	String TSL_SERVICETYPE_SIGNPOLAUTH = "http://uri.etsi.org/02231/Svctype/SignaturePolicyAuthority";

	/**
	 * An assessment scheme which is a system of supervision as defined in, and
	 * which complies with all applicable requirements of Directive 1999/93/EC [1].
	 */
	String TSL_SERVICETYPE_SUPERVISION = "http://uri.etsi.org/TrstSvc/Svctype/supervision";

	/**
	 * An assessment scheme which is a voluntary approval [accreditation] scheme as
	 * defined in, and which complies with all applicable requirements of Directive
	 * 1999/93/EC [1].
	 */
	String TSL_SERVICETYPE_VOLUNTARY = "http://uri.etsi.org/TrstSvc/Svctype/voluntary";

	/**
	 * An issuer of TSLs.
	 */
	String TSL_SERVICETYPE_TSLISSUER = "http://uri.etsi.org/TrstSvd/Svctype/TSLIssuer";

	/**
	 * A qualified validation service for qualified electronic signatures and/or
	 * qualified electronic seals in accordance with the applicable national legislation
	 * in the territory identified by the TL Scheme territory or with Regulation (EU)
	 * No 910/2014 [i.10] whichever is in force at the time of provision.
	 */
	String TSL_SERVICETYPE_QESVALIDATION_Q = "http://uri.etsi.org/TrstSvc/Svctype/QESValidation/Q";

	/**
	 * A not qualified validation service for advanced electronic signatures and/or advanced electronic seals.
	 */
	String TSL_SERVICETYPE_ADESVALIDATION = "http://uri.etsi.org/TrstSvc/Svctype/AdESValidation";

	/**
	 * A not qualified generation service for advanced electronic signatures and/or advanced electronic seals.
	 */
	String TSL_SERVICETYPE_ADESGENERATION = "http://uri.etsi.org/TrstSvc/Svctype/AdESGeneration";

	/**
	 * An Archival service that cannot be identified by a specific PKI-based public key.
	 */
	String TSL_SERVICETYPE_ARCHIV_NOTHAVINGPKIID = "http://uri.etsi.org/TrstSvc/Svctype/Archiv/nothavingPKIid";

	/**
	 * An Identity verification service that cannot be identified by a specific PKI-based public key.
	 */
	String TSL_SERVICETYPE_IDV_NOTHAVINGPKIID = "http://uri.etsi.org/TrstSvc/Svctype/IdV/nothavingPKIid";

	/**
	 * A Key escrow service that cannot be identified by a specific PKI-based public key.
	 */
	String TSL_SERVICETYPE_KESCROW_NOTHAVINGPKIID = "http://uri.etsi.org/TrstSvc/Svctype/KEscrow/nothavingPKIid";

	/**
	 * Issuer of PIN- or password-based identity credentials that cannot be identified by a specific
	 * PKI-based public key.
	 */
	String TSL_SERVICETYPE_PPWD_NOTHAVINGPKIID = "http://uri.etsi.org/TrstSvc/Svctype/PPwd/nothavingPKIid";

	/**
	 * A trust service of an unspecified type.
	 */
	String TSL_SERVICETYPE_UNSPECIFIED = "http://uri.etsi.org/TrstSvc/Svctype/unspecified";

	/**
	 * The subject service is in accordance with the scheme's specific status
	 * determination criteria (only for use in positive approval schemes).
	 */
	String TSL_SERVICECURRENTSTATUS_INNACORD = "http://uri.etsi.org/TrstSvc/Svcstatus/inaccord";

	/**
	 * The subject service is no longer overseen by the scheme, e.g. due to nonrenewal
	 * or withdrawal by the TSP, or cessation of the service or the scheme's
	 * operations.
	 */
	String TSL_SERVICECURRENTSTATUS_EXPIRED = "http://uri.etsi.org/TrstSvc/Svcstatus/expired";

	/**
	 * The subject service's status is temporarily uncertain whilst checks are made by
	 * the scheme operator (typically e.g. while a revocation request is being
	 * investigated or if action is required to resolve a deficiency in the service fulfilling
	 * the scheme's criteria.
	 */
	String TSL_SERVICECURRENTSTATUS_SUSPENDED = "http://uri.etsi.org/TrstSvc/Svcstatus/suspended";

	/**
	 * The subject service's approved status has been revoked because it is no longer
	 * in accordance with the scheme's specific status determination criteria (only for
	 * use in positive approval schemes).
	 */
	String TSL_SERVICECURRENTSTATUS_REVOKED = "http://uri.etsi.org/TrstSvc/Svcstatus/revoked";

	/**
	 * The subject service is not in accordance with the scheme's specific status
	 * determination criteria (only for use in negative approval schemes).
	 */
	String TSL_SERVICECURRENTSTATUS_NOTINACCORD = "http://uri.etsi.org/TrstSvc/Svcstatus/notinaccord";

	/**
	 * The service identified in "Service digital identity" provided by the trust
	 * service provider identified in "TSP name" is currently under supervision, for
	 * compliance with the provisions laid down in the applicable European legislation, by the
	 * Member State identified in the "Scheme territory" in which the trust
	 * service provider is established.
	 */
	String TSL_SERVICECURRENTSTATUS_UNDERSUPERVISION = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision";

	/**
	 * The service identified in "Service digital identity" provided by the trust
	 * service provider identified in "TSP name" is currently in a cessation phase
	 * but still supervised until supervision is ceased or revoked. In the event a different person than
	 * the one identified in "TSP name" has taken over the responsibility of ensuring this cessation
	 * phase, the identification of this new or fallback person (fallback trust service provider) shall
	 * be provided in "Scheme service definition URI" and in the "TakenOverBy"
	 * extension of the service entry.
	 * "Supervision of Service in Cessation" status shall be used when a TSP directly ceases its
	 * related services under supervision; it shall not be used when supervision has been revoked.
	 */
	String TSL_SERVICECURRENTSTATUS_SUPERVISIONINCESSATION = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation";

	/**
	 * The validity of the supervision assessment has lapsed without the service identified in
	 * "Service digital identity" being re-assessed. The service is currently not
	 * under supervision any more from the date of the current status as the service is understood
	 * to have ceased operations.
	 * "Supervision Ceased" status shall be used when a TSP directly ceases its related services
	 * under supervision; it shall not be used when supervision has been revoked.
	 */
	String TSL_SERVICECURRENTSTATUS_SUPERVISIONCEASED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionceased";

	/**
	 * Having been previously supervised, the trust service provider's service and potentially the
	 * trust service provider itself has failed to continue to comply with the provisions laid down in
	 * the applicable European legislation, as determined by the Member State identified in the
	 * "Scheme territory" (see clause 5.3.10) in which the trust service provider is established.
	 * Accordingly the service has been required to cease its operations and shall be considered by
	 * relying parties as ceased for the above reason.
	 * The status value "Supervision Revoked" may be a definitive status, even if the trust service
	 * provider then completely ceases its activity; it shall not be migrated (without any
	 * intermediate status) to either "Supervision of Service in Cessation" or to "Supervision
	 * Ceased" status in this case. The only way to change the "Supervision Revoked" status is to
	 * recover from non-compliance to compliance with the provisions laid down in the applicable
	 * European legislation according the appropriate supervision system in force in the Member
	 * State owing the trusted list, and regaining "Under Supervision" status. "Supervision of
	 * Service in Cessation" status, or "Supervision Ceased" status shall be used when a TSP
	 * directly ceases its related services under supervision; they shall not be used when
	 * supervision has been revoked.
	 */
	String TSL_SERVICECURRENTSTATUS_SUPERVISIONREVOKED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionrevoked";

	/**
	 * An accreditation assessment has been performed by the Accreditation Body on behalf of the
	 * Member State identified in the "Scheme territory" and the service
	 * identified in "Service digital identity" provided by the trust service provider
	 * identified in "TSP name" is found to be in compliance with the provisions
	 * laid down in Directive 1999/93/EC [i.3].
	 * This accredited trust service provider may be established in another Member State than the
	 * one identified in the "Scheme territory" (see clause 5.3.10) of the trusted list or in a non-EU
	 * country (see article 7.1(a) of Directive 1999/93/EC [i.3]).
	 */
	String TSL_SERVICECURRENTSTATUS_ACCREDITED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited";

	/**
	 * The validity of the accreditation assessment has lapsed without the service identified in
	 * "Service digital identity" being re-assessed.
	 */
	String TSL_SERVICECURRENTSTATUS_ACCREDITATIONCEASED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationceased";

	/**
	 * Having been previously found to be in conformance with the scheme criteria, the service
	 * identified in "Service digital identity" (see clause 5.5.3) provided by the trust service provider
	 * identified in "TSP name" (see clause 5.4.1) and potentially the trust service provider itself
	 * have failed to continue to comply with the provisions laid down in Directive 1999/93/EC [i.3].
	 */
	String TSL_SERVICECURRENTSTATUS_ACCREDITATIONREVOKED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked";

	/**
	 * Following ex ante and active approval activities, in compliance with the provisions laid
	 * down in the applicable national legislation and Regulation (EU) No 910/2014 [i.10], it
	 * indicates that the Supervisory Body identified in the "Scheme operator name" on behalf
	 * of the Member State identified in the "Scheme territory" has granted a qualified status:
	 * to the corresponding trust service being of a service type specified in clause 5.5.1.1
	 * and identified in "Service digital identity", and to the trust service provider
	 * identified in "TSP name" for the provision of that service.
	 */
	String TSL_SERVICECURRENTSTATUS_GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";

	/**
	 * In compliance with the provisions laid down in the applicable national legislation and
	 * Regulation (EU) No 910/2014 [i.10], it indicates that the qualified status has not been
	 * initially granted or has been withdrawn by the Supervisory Body on behalf of the Member
	 * State identified in the "Scheme territory": from the trust service being of a service
	 * type specified in clause 5.5.1.1 and identified in "Service digital identity", and from
	 * its trust service provider identified in "TSP name" for the provisison of that service.
	 */
	String TSL_SERVICECURRENTSTATUS_WITHDRAWN = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn";

	/**
	 *  The service identified in "Service digital identity" provided by
	 *  the Certification Service Provider (CSP) identified in "TSP name"
	 *  is currently under supervision, for compliance with the provisions laid down
	 *  in Directive 1999/93/EC [1], by the Member State identified in the "Scheme
	 *  territory" (see clause 5.3.10) in which the CSP is established.
	 */
	String TSL_SERVICECURRENTSTATUS_ESIGDIR1999_UNDERSUPERVISION = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/Svcstatus/undersupervision";

	/**
	 *  The service identified in "Service digital identity" provided by
	 *  the Certification Service Provider (CSP) identified in "TSP name"
	 *  is currently in a cessation phase but still supervised until supervision is
	 *  ceased or revoked. In the event a different legal person than the one identified in
	 *  "TSP name" has taken over the responsibility of ensuring this cessation phase,
	 *  the identification of this new or fallback legal person (fallback CSP) shall be
	 *  provided in clause 5.5.6 of the service entry.
	 */
	String TSL_SERVICECURRENTSTATUS_ESIGDIR1999_SUPERVISIONINCESSATION = "http: //uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/Svcstatus/supervisionincessation";

	/**
	 *  The validity of the supervision assessment has lapsed without the service
	 *  identified in "Service digital identity" being re-assessed. The
	 *  service is currently not under supervision any more from the date of the current
	 *  status as the service is understood to have ceased operations.
	 */
	String TSL_SERVICECURRENTSTATUS_ESIGDIR1999_SUPERVISIONCEASED = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/Svcstatus/supervisionceased";

	/**
	 *  Having been previously supervised, the Certification Service Provider (CSP)'s
	 *  service and potentially the CSP itself has failed to continue to comply with the
	 *  provisions laid down in Directive 1999/93/EC, as determined by the Member State
	 *  identified in the "Scheme territory" in which the CSP is
	 *  established. Accordingly the service has been required to cease its operations
	 *  and must be considered as ceased for the above reason.
	 */
	String TSL_SERVICECURRENTSTATUS_ESIGDIR1999_SUPERVISIONREVOKED = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/Svcstatus/supervisionrevoked";

	/**
	 *  An accreditation assessment has been performed by the Accreditation Body on
	 *  behalf of the Member State identified in the "Scheme territory"
	 *  and the service identified in "Service digital identity" provided
	 *  by the Certification Service Provider (CSP) identified in "TSP name"
	 *  is found to be in compliance with the provisions laid down in Directive
	 *  1999/93/EC [1].
	 */
	String TSL_SERVICECURRENTSTATUS_ESIGDIR1999_ACCREDITED = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/Svcstatus/accredited";

	/**
	 *  The validity of the accreditation assessment has lapsed without the service
	 *  identified in "Service digital identity" being re-assessed.
	 */
	String TSL_SERVICECURRENTSTATUS_ESIGDIR1999_ACCREDITATIONCEASED = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/Svcstatus/accreditationceased";

	/**
	 *  Having been previously found to be in conformance with the scheme criteria, the
	 *  service identified in "Service digital identity" provided by the
	 *  Certification Service Provider (CSP) identified in "TSP name"
	 *  and potentially the CSP itself have failed to continue to comply with the provisions
	 *  laid down in Directive 1999/93/EC [1].
	 */
	String TSL_SERVICECURRENTSTATUS_ESIGDIR1999_ACCREDITATIONREVOKED = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/Svcstatus/accreditationrevoked";

	/**
	 * The service is set by national law in accordance with the applicable European
	 * legislation and operated by the responsible national body issuing root-signing or
	 * qualified certificates to accredited trust service providers.
	 */
	String TSL_SERVICECURRENTSTATUS_SETBYNATIONALLAW = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/setbynationallaw";

	/**
	 * The service is deprecated by national law in accordance with the applicable European
	 * legislation and by the responsible national body issuing root-signing or qualified
	 * certificates to accredited trust service providers.
	 */
	String TSL_SERVICECURRENTSTATUS_DEPRECATEDBYNATIONALLAW = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedbynationallaw";

	/**
	 * For trust services listed under a service type specified in clause 5.5.1.2: In
	 * compliance with the provisions laid down in the applicable national legislation,
	 * it indicates that the Supervisory Body identified in the "Scheme operator name"
	 * on behalf of the Member State identified in the "Scheme territory" has granted
	 * an "approved" status, as recognized at national level, to the corresponding trust
	 * service identified in "Service digital identity" and to the trust service provider
	 * identified in "TSP name" for the provision of that service, as both the TSP and
	 * the trust service it provides meet the provisions laid down in Regulation (EU)
	 * No 910/2014 [i.10] and the applicable national legislation.
	 * For NationalRootCA-QC type: The service is set by national law in accordance with
	 * the applicable European legislation and operated by the responsible national body
	 * issuing root-signing or qualified certificates to accredited trust service providers.
	 * For other trust services listed under a service type specified in clause 5.5.1.3:
	 * In compliance with the provisions laid down in the applicable national legislation,
	 * it indicates that the Supervisory Body identified in the "Scheme operator name"
	 * on behalf of the Member State identified in the "Scheme territory" has granted an
	 * "approved" status, as recognized at national level, to the corresponding trust
	 * service identified in "Service digital identity" and to the trust service provider
	 * identified in "TSP name" for the provision of that service, as both the TSP and
	 * the trust service it provides meet the provisions laid down in the applicable
	 * national legislation.
	 */
	String TSL_SERVICECURRENTSTATUS_RECOGNISEDATNATIONALLEVEL = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel";

	/**
	 * For NationalRootCA-QC type: The service is deprecated by national law in accordance
	 * with the applicable European legislation and by the responsible national body issuing
	 * root-signing or qualified certificates to accredited trust service providers.
	 * For other trust services listed under a service type specified in clause 5.5.1.2 or
	 * in clause 5.5.1.3: In compliance with the provisions laid down in the applicable EU
	 * or national legislation, it indicates that the previously "approved" status has been
	 * withdrawn by the Supervisory Body on behalf of the Member State identified in the
	 * "Scheme territory" from the trust service identified in "Service digital identity"
	 * and from its trust service provider identified in "TSP name" for the provisison of
	 * that service.
	 */
	String TSL_SERVICECURRENTSTATUS_DEPRECATEDATNATIONALLEVEL = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel";

	/**
	 * An assessment scheme which is a system of supervision as defined in, and
	 * which complies with all applicable requirements of Directive 1999/93/EC [1].
	 */
	String TSL_SCHEMECOMUNITYRULES_SUPERVISION = "http://uri.etsi.org/TrstSvc/schemerules/Dir-1999-93-EC/supervision";

	/**
	 * An assessment scheme which is a voluntary approval [accreditation] scheme as
	 * defined in, and which complies with all applicable requirements of
	 * Directive 1999/93/EC [1].
	 */
	String TSL_SCHEMECOMUNITYRULES_VOLAPPROVAL = "http://uri.etsi.org/TrstSvc/schemerules/Dir-1999-93-EC/volapproval";

	/**
	 * A URI common to all Member States' Trusted Lists pointing towards a
	 * descriptive text that SHALL be applicable to all Trusted Lists:
	 * • By which participation is denoted of the Member State's scheme
	 * (identified via the "TSL type" and "Scheme name") in a scheme of
	 * schemes (i.e. a TSL listing pointers to all
	 * Member States publishing and maintaining a Trusted List in the form of a
	 * TSL);
	 * • Where users can obtain policy/rules against which services included in
	 * the list SHALL be assessed and from which the type of the TSL
	 * (see clause 5.3.3) can be determined;
	 * • Where users can obtain description about how to use and interpret the
	 * content of the TSL implementation of the Trusted List. These usage rules
	 * SHALL be common to all Member States' Trusted Lists whatever the type
	 * of listed service and whatever the supervision/accreditation system(s) is
	 * (are).
	 */
	String TSL_SCHEMECOMUNITYRULES_ESIGDIR1999_COMMON = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/schemerules/common";

	/**
	 * A URI specific to each Member State's Trusted List pointing towards a
	 * descriptive text that SHALL be applicable to this Member State's Trusted List:
	 * • Where users can obtain the referenced Member State's specific
	 * policy/rules against which services included in the list SHALL be
	 * assessed in compliance with the Member State's appropriate supervision
	 * system and voluntary accreditation schemes.
	 * • Where users can obtain a referenced Member State's specific description
	 * about how to use and interpret the content of the TSL implementation of
	 * the Trusted List with regard to the certification services not related to the
	 * issuing of Qualified Certificates. This may be used to indicate a potential
	 * granularity in the national supervision/accreditation systems related to
	 * certification service providers not issuing Qualified Certificates and how
	 * the "Scheme service definition URI" (see clause 5.5.6) and the "Service
	 * information extension" field (see clause 5.5.9) are used for this purpose.
	 */
	String TSL_SCHEMECOMUNITYRULES_ESIGDIR1999_CC = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/schemerules/CC";

	/**
	 * A URI pointing towards a descriptive text where users can obtain information
	 * about the scheme of schemes type (i.e. a TSL listing pointers to all Member
	 * States' Trusted Lists published and maintained in the form of a TSL) and the
	 * relevant driving rules and policy.
	 */
	String TSL_SCHEMECOMUNITYRULES_ESIGDIR1999_COMPILEDLIST = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-ECTrustedList/schemerules/CompiledList";

	/**
	 *  Preffix for {@link ITSLCommonURIs#TSL_SCHEMECOMUNITYRULES_CC}.
	 */
	String TSL_SCHEMECOMUNITYRULES_CC_PREFFIX = "http://uri.etsi.org/TrstSvc/TrustedList/schemerules/";

	/**
	 *  A URI specific to CC's trusted list pointing towards a descriptive text that shall be
	 *  applicable to this CC's trusted list:
	 *  • Where users can obtain the referenced CC's specific policy/rules against
	 *  which services included in the list shall be assessed in compliance with the
	 *  CC's appropriate approval schemes.
	 *  • Where users can obtain a referenced CC's specific description about how to
	 *  use and interpret the content of the trusted list (e.g. in the EU with regard to
	 *  the trust services not related to the issuing of qualified certificates, where this
	 *  may be used to indicate a potential granularity in the national
	 *  supervision/accreditation systems related to trust service providers not issuing
	 *  qualified certificates and how the "Scheme service definition URI"
	 *  and the "Service information extension" field are used for this purpose).
	 */
	String TSL_SCHEMECOMUNITYRULES_CC = "http://uri.etsi.org/TrstSvc/TrustedList/schemerules/CC";

	/**
	 * A URI pointing towards a descriptive text where users can obtain information about
	 * the scheme of schemes type (i.e. a compiled list listing pointers to all trusted lists
	 * published as part of the scheme of schemes and maintained in the form of a TL) and
	 * the relevant driving rules and policy.
	 */
	String TSL_SCHEMECOMUNITYRULES_EULISTOFTHELISTS = "http://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUlistofthelists";

	/**
	 *  A URI pointing towards a descriptive text that applies to all EU Member States'
	 *  trusted lists:
	 *  • By which participation of the Member States' trusted lists is denoted in the
	 *  general scheme of the EU Member States trusted lists;
	 *  • Where users can obtain policy/rules against which services included in the
	 *  trusted list are assessed;
	 *  • Where users can obtain description about how to use and interpret the
	 *  content of the EU Member States' trusted list. These usage rules are
	 *  common to all EU Member States' trusted lists whatever the type of listed
	 *  services.
	 */
	String TSL_SCHEMECOMUNITYRULES_EUCOMMON = "http://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUcommon";

	/**
	 * A Root Certification Authority from which a certification path can be
	 * established down to a Certification Authority issuing qualified certificates.
	 * This value shall not be used if the service type is not
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC
	 */
	String TSL_SERVINFEXT_ADDSERVINFEXT_ROOTCAQC = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/RootCA-QC";

	/**
	 * A certificate status provider operating an OCSP-server as part of a service from
	 * a certification service provider issuing Qualified Certificates. Only to be used as
	 * an extension, if the servicetype is
	 * http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP
	 */
	String TSL_SERVINFEXT_ADDSERVINFEXT_ESIGDIR1999_OCSPQC = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/SvcInfoExt/OCSP-QC";

	/**
	 * A certificate status provider operating a CRL as part of a service from a
	 * certification service provider issuing Qualified Certificates. Only to be used as an
	 * extension, if the servicetype is
	 * http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL
	 */
	String TSL_SERVINFEXT_ADDSERVINFEXT_ESIGDIR1999_CRLQC = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/SvcInfoExt/CRL-QC";

	/**
	 * A Root Certification Authority from which a certification path can be established
	 * down to a Certification Authority issuing Qualified Certificates. Only to be used
	 * as an extension, if the servicetype is
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC
	 */
	String TSL_SERVINFEXT_ADDSERVINFEXT_ESIGDIR1999_ROOTCAQC = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/SvcInfoExt/RootCA-QC";

	/**
	 * A time stamping service as part of a service from a certification service
	 * provider issuing Qualified Certificates that issue TST that can be used in
	 * the qualified signature verification process to ascertain and extend the
	 * signature validity when the QC is revoked or expired.
	 */
	String TSL_SERVINFEXT_ADDSERVINFEXT_ESIGDIR1999_TSSQC = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/SvcInfoExt/TSS-QC";

	/**
	 * Further specifies the "Service type identifier" identified service as being provided for electronic signatures.
	 */
	String TSL_SERVINFEXT_ADDSERVINFEXT_FORESIGNATURES = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures";

	/**
	 * Further specifies the "Service type identifier" identified service as being provided for electronic seals.
	 */
	String TSL_SERVINFEXT_ADDSERVINFEXT_FORESEALS = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals";

	/**
	 * Further specifies the "Service type identifier" identified service as being provided for web site authentication.
	 */
	String TSL_SERVINFEXT_ADDSERVINFEXT_FORWEBSITEAUTHENTICATION = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication";

	/**
	 * it is ensured by the trust service provider and controlled (supervision model) or
	 * audited (accreditation model) by the referenced Member State (respectively its
	 * Supervisory Body or Accreditation Body) that all Qualified Certificates issued
	 * under the service identified in "Service digital identity" and further identified by
	 * the filters information used to further identify under the "Sdi" identified trust
	 * service that precise set of Qualified Certificates for which this additional
	 * information is required with regards to the presence or absence of Secure
	 * Signature Creation Device (SSCD) support ARE supported by an SSCD (i.e.
	 * that that the private key associated with the public key in the certificate is stored
	 * in a Secure Signature Creation Device conformant with the applicable European
	 * legislation);
	 * This value shall not be used if the service type is not
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC
	 */
	String TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCWITHSSCD = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD";

	/**
	 * it is ensured by the trust service provider and controlled (supervision model) or
	 * audited (accreditation model) by the referenced Member State (respectively its
	 * Supervisory Body or Accreditation Body) that all Qualified Certificates issued
	 * under the service identified in "Service digital identity" and further identified by
	 * the filters information used to further identify under the "Sdi" identified trust
	 * service that precise set of Qualified Certificates for which this additional
	 * information is required with regards to the presence or absence of Secure
	 * Signature Creation Device (SSCD) support ARE NOT supported by an SSCD
	 * (i.e. that that the private key associated with the public key in the certificate is
	 * not stored in a Secure Signature Creation Device conformant with the applicable
	 * European legislation).
	 * This value shall not be used if the service type is not
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC
	 */
	String TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCNOSSCD = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoSSCD";

	/**
	 * it is ensured by the trust service provider and controlled (supervision model) or
	 * audited (accreditation model) by the referenced Member State (respectively its
	 * Supervisory Body or Accreditation Body) that all Qualified Certificates issued
	 * under the service (RootCA/QC or CA/QC) identified in "Service digital identity"
	 * and further identified by the filters information used to further identify under the
	 * "Sdi" identified trust service that precise set of Qualified Certificates for which
	 * this additional information is required with regards to the presence or absence of
	 * Secure Signature Creation Device (SSCD) support DO contain the machineprocessable
	 * information indicating whether or not the Qualified Certificate
	 * is supported by an SSCD.
	 * This value shall not be used if the service type is not
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC.
	 */
	String TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCSTATUSASINCERT = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCSSCDStatusAsInCert";

	/**
	 * it is ensured by the trust service provider and controlled (supervision model) or
	 * audited (accreditation model) by the referenced Member State (respectively its
	 * Supervisory Body or Accreditation Body) that all Qualified Certificates issued
	 * under the service (RootCA/QC or CA/QC) identified in "Service digital identity"
	 * and further identified by the filters information used to further identify under the
	 * "Sdi" identified trust service that precise set of Qualified Certificates for which
	 * this additional information is required with regards to the issuance to Legal
	 * Person ARE issued to Legal Persons.
	 * This value shall not be used as an extension, if the service type is not
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC
	 */
	String TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCFORLEGALPERSON = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForLegalPerson";

	/**
	 * It is ensured by the certification service provider and controlled (supervision
	 * model) or audited (accreditation model) by the referenced Member State
	 * (respectively its Supervisory Body or Accreditation Body) that any Qualified
	 * Certificate issued under the service (RootCA/QC or CA/QC) identified in
	 * "Service digital identity" and further identified by the filters information used to
	 * further identify under the "Sdi" identified certification service that precise set of
	 * Qualified Certificates for which this additional information is required with
	 * regards to the presence or absence of Secure Signature Creation Device
	 * (SSCD) support ARE supported by an SSCD (i.e. that that the private key
	 * associated with the public key in the certificate is stored in a Secure Signature
	 * Creation Device conformant with annex III of Directive 1999/93/EC [1]);
	 * Only to be used as an extension, if the servicetype is
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC
	 */
	String TSL_SERVINFEXT_QUALEXT_QUALIFIER_ESIGDIR1999_QCWITHSSCD = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-ECTrustedList/SvcInfoExt/QCWithSSCD";

	/**
	 * It is ensured by the certification service provider and controlled (supervision
	 * model) or audited (accreditation model) by the referenced Member State
	 * (respectively its Supervisory Body or Accreditation Body) that any Qualified
	 * Certificate issued under the service (RootCA/QC or CA/QC) identified in
	 * "Service digital identity" and further identified by the filters information used to
	 * further identify under the "Sdi" identified certification service that precise set of
	 * Qualified Certificates for which this additional information is required with
	 * regards to the presence or absence of Secure Signature Creation Device
	 * (SSCD) support ARE NOT supported by an SSCD (i.e. that that the private key
	 * associated with the public key in the certificate is not stored in a Secure
	 * Signature Creation Device conformant with annex III of the Directive 1999/93/EC
	 * [1]).
	 * Only to be used as an extension, if the servicetype is
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC
	 */
	String TSL_SERVINFEXT_QUALEXT_QUALIFIER_ESIGDIR1999_QCNOSSCD = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/SvcInfoExt/QCNoSSCD";

	/**
	 * It is ensured by the certification service provider and controlled (supervision
	 * model) or audited (accreditation model) by the referenced Member State
	 * (respectively its Supervisory Body or Accreditation Body) that any Qualified
	 * Certificate issued under the service (RootCA/QC or CA/QC) identified in
	 * "Service digital identity" and further identified by the filters information used to
	 * further identify under the "Sdi" identified certification service that precise set of
	 * Qualified Certificates for which this additional information is required with
	 * regards to the presence or absence of Secure Signature Creation Device
	 * (SSCD) support SHALL contain the machine-processable information indicating
	 * whether or not the Qualified Certificate is supported by an SSCD.
	 * Only to be used as an extension, if the servicetype is
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC.
	 */
	String TSL_SERVINFEXT_QUALEXT_QUALIFIER_ESIGDIR1999_QCSSCDSTATUSASINCERT = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-ECTrustedList/SvcInfoExt/QCSSCDStatusAsInCert";

	/**
	 * It is ensured by the certification service provider and controlled (supervision
	 * model) or audited (accreditation model) by the referenced Member State
	 * (respectively its Supervisory Body or Accreditation Body) that any Qualified
	 * Certificate issued under the service (RootCA/QC or CA/QC) identified in
	 * "Service digital identity" and further identified by the filters information used to
	 * further identify under the "Sdi" identified certification service that precise set of
	 * Qualified Certificates for which this additional information is required with
	 * regards to the issuance to Legal Person ARE issued to Legal Persons.
	 * Only to be used as an extension, if the servicetype is
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC
	 */
	String TSL_SERVINFEXT_QUALEXT_QUALIFIER_ESIGDIR1999_QCFORLEGALPERSON = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-ECTrustedList/SvcInfoExt/QCForLegalPerson";

	/**
	 * It is ensured by the CSP and controlled (supervision model) or audited
	 * (accreditation model) by the Member State (respectively its Supervisory Body or
	 * Accreditation Body) that all certificates issued under the service (CA/QC)
	 * identified in 'Service digital identity' (clause 5.5.3) and further identified by the
	 * above (filters) information used to further identify under the 'Sdi' identified trust
	 * service that precise set of certificates for which this additional information is
	 * required with regard to the issuance of such certificates is issued as a
	 * Qualified Certificate.
	 * This value shall not be used as an extension, if the service type is not
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC
	 */
	String TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCSTATEMENT = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement";

	/**
	 * It is ensured by the trust service provider and supervised by the Member State
	 * Supervisory Body that all Qualified Certificates issued under the service identified
	 * in "Service digital identity" and further identified by the filters information used
	 * to further identify under the "Sdi" identified trust service that precise set of
	 * Qualified Certificates for which this additional information is required with
	 * regards to the presence or absence of Qualified Signature or Seal Creation Device
	 * (QSCD) support ARE supported by a QSCD (i.e. that means that the private key
	 * associated with the public key in the certificate resides in a QSCD conformant with
	 * the applicable European legislation).
	 * This value shall not be used if the service type is not
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC.
	 */
	String TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCWITHQSCD = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD";

	/**
	 * It is ensured by the trust service provider and supervised by the Member State
	 * Supervisory Body that all Qualified Certificates issued under the service identified
	 * in "Service digital identity" and further identified by the filters information used
	 * to further identify under the "Sdi" identified trust service that precise set of
	 * Qualified Certificates for which this additional information is required with
	 * regards to the presence or absence of Qualified Signature or Seal Creation Device
	 * (QSCD) support ARE NOT supported by a QSCD (i.e. that means that the private key
	 * associated with the public key in the certificate does not reside in a QSCD
	 * conformant with the applicable European legislation).
	 * This value shall not be used if the service type is not
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC.
	 */
	String TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCNOQSCD = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoQSCD";

	/**
	 * It is ensured by the trust service provider and supervised by the Member State
	 * Supervisory Body that all Qualified Certificates issued under the service identified
	 * in "Service digital identity" and further identified by the filters information used
	 * to further identify under the "Sdi" identified trust service that precise set of
	 * Qualified Certificates for which this additional information is required with regards
	 * to the presence or absence of Qualified Signature or Seal Creation Device (QSCD)
	 * support DO contain the machine-processable information indicating whether or not
	 * the Qualified Certificate is supported by a QSCD.
	 * This value shall not be used if the service type is not
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC.
	 */
	String TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCQSCDSTATUSASINCERT = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDStatusAsInCert";

	/**
	 * It is ensured by the trust service provider and supervised by the Member State
	 * Supervisory Body that all Qualified Certificates issued under the service identified
	 * in "Service digital identity" and further identified by the filters information used
	 * to further identify under the "Sdi" identified trust service that precise set of
	 * Qualified Certificates for which this additional information is required with regards
	 * to the presence or absence of Qualified Signature or Seal Creation Device (QSCD)
	 * support DO contain the machine-processable information indicating whether or not
	 * the Qualified Certificate is supported by a QSCD.
	 * This value shall not be used if the service type is not
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC.
	 */
	String TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCQSCDMANAGEDONBEHALF = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDManagedOnBehalf";

	/**
	 * It is ensured by the trust service provider and supervised by the Member State
	 * Supervisory Body that all Qualified Certificates issued under the service identified
	 * in "Service digital identity" and further identified by the filters information used
	 * to further identify under the "Sdi" identified trust service that precise set of
	 * qualified certificates for which this additional information is required with regards
	 * to the nature of the qualified certificate ARE qualified certificates for electronic
	 * signatures in accordance with the applicable legislation.
	 * This value shall not be used if the service type is not
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC
	 */
	String TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCFORESIG = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig";

	/**
	 * It is ensured by the trust service provider and supervised by the Member State
	 * Supervisory Body that all Qualified Certificates issued under the service identified
	 * in "Service digital identity" and further identified by the filters information used
	 * to further identify under the "Sdi" identified trust service that precise set of
	 * qualified certificates for which this additional information is required with regards
	 * to the nature of the qualified certificate ARE qualified certificates for electronic
	 * seals in accordance with the applicable legislation.
	 * This value shall not be used if the service type is not
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC
	 */
	String TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCFORESEAL = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESeal";

	/**
	 * It is ensured by the trust service provider and supervised by the Member State
	 * Supervisory Body that all Qualified Certificates issued under the service identified
	 * in "Service digital identity" and further identified by the filters information used
	 * to further identify under the "Sdi" identified trust service that precise set of
	 * qualified certificates for which this additional information is required with regards
	 * to the nature of the qualified certificate ARE qualified certificates for web site
	 * authentication in accordance with the applicable legislation.
	 * This value shall not be used if the service type is not
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC
	 */
	String TSL_SERVINFEXT_QUALEXT_QUALIFIER_QCFORWSA = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForWSA";

	/**
	 * It is ensured by the CSP, and supervised by the Member State Supervisory Body that
	 * all certificates issued under the service identified in 'Service digital identity'
	 * and further identified by the filters information used to further
	 * identify under the 'Sdi' identified trust service that precise set of certificates
	 * are not to be considered as qualified certificates.
	 * This value shall not be used, if the service type is not
	 * http://uri.etsi.org/TrstSvc/Svctype/CA/QC
	 */
	String TSL_SERVINFEXT_QUALEXT_QUALIFIER_NOTQUALIFIED = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/NotQualified";

	/**
	 * Constant attribute that represents the HTTP protocol preffix.
	 */
	String HTTP_PROTOCOL_PREFFIX = "http://";

	/**
	 * Constant attribute that represents the URI to the EU list of the lists.
	 */
	String TSL_EU_LIST_OF_THE_LISTS_1 = "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml";

	/**
	 * Constant attribute that represents the URI to the EU list of the lists.
	 */
	String TSL_EU_LIST_OF_THE_LISTS_2 = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";

}
