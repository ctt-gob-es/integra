// Copyright (C) 2017 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.integraFacade.GenerateMessageRequest.java.</p>
 * <b>Description:</b><p>Class that manages the generation of request messages to invoke the DSS web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>26/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.4, 04/03/2020.
 */
package es.gob.afirma.integraFacade;

import static es.gob.afirma.signature.SignatureConstants.SIGN_FORMAT_XADES_DETACHED;
import static es.gob.afirma.signature.SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED;
import static es.gob.afirma.signature.SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING;
import static es.gob.afirma.signature.SignatureConstants.SIGN_FORMAT_XADES_EXTERNALLY_DETACHED;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.xml.crypto.MarshalException;
import org.apache.xml.crypto.dsig.Reference;
import org.apache.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.integraFacade.pojo.ArchiveRequest;
import es.gob.afirma.integraFacade.pojo.BatchVerifyCertificateRequest;
import es.gob.afirma.integraFacade.pojo.BatchVerifySignatureRequest;
import es.gob.afirma.integraFacade.pojo.CoSignRequest;
import es.gob.afirma.integraFacade.pojo.CounterSignRequest;
import es.gob.afirma.integraFacade.pojo.OptionalParameters;
import es.gob.afirma.integraFacade.pojo.PendingRequest;
import es.gob.afirma.integraFacade.pojo.ServerSignerRequest;
import es.gob.afirma.integraFacade.pojo.TimestampRequest;
import es.gob.afirma.integraFacade.pojo.UpgradeSignatureRequest;
import es.gob.afirma.integraFacade.pojo.VerificationReport;
import es.gob.afirma.integraFacade.pojo.VerifyCertificateRequest;
import es.gob.afirma.integraFacade.pojo.VerifySignatureRequest;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.signature.SignatureConstants;
import es.gob.afirma.signature.SignatureFormatDetectorCommons;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.signature.xades.IXMLConstants;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.utils.Base64CoderCommons;
import es.gob.afirma.utils.CryptoUtilXML;
import es.gob.afirma.utils.DSSConstants;
import es.gob.afirma.utils.DSSConstants.DSSTagsRequest;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.utils.NumberConstants;
import es.gob.afirma.utils.UtilsFileSystemCommons;
import net.java.xades.security.xml.XMLSignatureElement;
import net.java.xades.util.XMLUtils;

/**
 * <p>Class that manages the generation of request messages to invoke the DSS web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.4, 04/03/2020.
 */
public final class GenerateMessageRequest {

    /**
     *  Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(GenerateMessageRequest.class);

    /**
     * Attribute that represents signature node name (ds:signature).
     */
    private static final String DS_SIGNATURE_NODE_NAME = IXMLConstants.DS_PREFIX + ":Signature";

    /**
     * Attribute that represents coSignature root name.
     */
    private static final String ROOT_TAG = "ROOT_COSIGNATURES";

    /**
     * Attribute that represents tag name used in Manifest objects (&lt;ds:Manifest&gt;).
     */
    private static final String MANIFEST_TAG_NAME = "ds:Manifest";

    /**
     * Constant attribute that identifies the URI corresponding to identifier level of detail "FORMAL_DOCUMENT".
     */
    public static final String FORMAL_DOCUMENT = "urn:afirma:dss:1.0:profile:XSS:SigPolicyDocument:FormalDocument";

    /**
     * Constant attribute that identifies the URI corresponding to identifier level of detail "SIGNATURE_TIMESTAMP".
     */
    public static final String SIGNATURE_TIMESTAMP = "urn:afirma:dss:1.0:profile:XSS:SignatureProperty:SignatureTimeStamp:IncludeTST";

    /**
     * Constructor method for the class GenerateMessageRequest.java.
     */
    private GenerateMessageRequest() {
    }

    /**
     * Method that generates a XML request message to invoke the server signature service.
     * @param serSigReq Parameter that allows to generate the sign request.
     * @return a map with the parameters related to the server signature request.
     */
    public static Map<String, Object> generateServerSignerRequest(ServerSignerRequest serSigReq) {
	// se crea el mensaje de petición a partir del párametro de entrada
	Map<String, Object> inputParameters = new HashMap<String, Object>();

	// documento a firmar.
	byte[ ] document = serSigReq.getDocument();
	if (document != null) {
	    String encodedDocumentToSign = null;
	    try {
		encodedDocumentToSign = new String(Base64CoderCommons.encodeBase64(document));
	    } catch (TransformersException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG044), e);
	    }
	    if (XMLUtils.isXMLFormat(document)) {
		// si es xml, se incluye en dss:Base64XML, codificado en base64
		inputParameters.put(DSSTagsRequest.BASE64XML, encodedDocumentToSign);
	    } else {
		// si no es xml
		inputParameters.put(DSSTagsRequest.BASE64DATA, encodedDocumentToSign);
	    }
	} else if (serSigReq.getDocumentHash() != null) {
	    inputParameters.put(DSSTagsRequest.DIGEST_METHOD_ATR_ALGORITHM, serSigReq.getDocumentHash().getDigestMethod().getUri());
	    try {
		inputParameters.put(DSSTagsRequest.DOCUMENTHASH_VALUE, new String(Base64CoderCommons.encodeBase64(serSigReq.getDocumentHash().getDigestValue())));
	    } catch (TransformersException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG051), e);
	    }
	} else {
	    inputParameters.put(DSSTagsRequest.DOCUMENT_ARCHIVE_ID, serSigReq.getDocumentId());
	    inputParameters.put(DSSTagsRequest.INPUTDOC_GETCONTENTSTREAM_REPOID, serSigReq.getDocumentRepository().getId());
	    inputParameters.put(DSSTagsRequest.INPUTDOC_GETCONTENTSTREAM_OBJECTID, serSigReq.getDocumentRepository().getObject());
	}

	inputParameters.put(DSSTagsRequest.CLAIMED_IDENTITY, serSigReq.getApplicationId());
	inputParameters.put(DSSTagsRequest.KEY_SELECTOR, serSigReq.getKeySelector());

	// se trata el campo signatureFormat
	if (serSigReq.getSignatureFormat() != null) {
	    inputParameters.put(DSSTagsRequest.SIGNATURE_TYPE, serSigReq.getSignatureFormat().getUriType());
	    inputParameters.put(DSSTagsRequest.SIGNATURE_FORM, serSigReq.getSignatureFormat().getUriFormat() == null ? "" : serSigReq.getSignatureFormat().getUriFormat());
	}

	// hashAlgorithm
	if (serSigReq.getHashAlgorithm() != null) {
	    inputParameters.put(DSSTagsRequest.HASH_ALGORITHM, serSigReq.getHashAlgorithm().getUri());
	}

	// signaturePolicyIdentifier
	if (GenericUtilsCommons.assertStringValue(serSigReq.getSignaturePolicyIdentifier())) {
	    inputParameters.put(DSSTagsRequest.SIGPOL_SIGNATURE_POLICY_IDENTIFIER, serSigReq.getSignaturePolicyIdentifier());
	}

	// xmlSignatureMode
	if (serSigReq.getXmlSignatureMode() != null) {
	    inputParameters.put(DSSTagsRequest.XML_SIGNATURE_MODE, serSigReq.getXmlSignatureMode().getMode() == null ? "" : serSigReq.getXmlSignatureMode().getMode());
	}

	// ignoreGracePeriod
	if (serSigReq.isIgnoreGracePeriod()) {
	    inputParameters.put(DSSTagsRequest.IGNORE_GRACE_PERIOD, "");
	}

	return inputParameters;

    }

    /**
     * Method that generates a XML request message to invoke the server co-signature service.
     * @param coSigReq Parameter that allows to generate the cosign request.
     * @return a map with the parameters related to the server co-signature request.
     */
    public static Map<String, Object> generateCoSignRequest(CoSignRequest coSigReq) {
	// se crea el mensaje de petición a partir del párametro de entrada
	Map<String, Object> inputParameters = new HashMap<String, Object>();

	// transactionId
	if (GenericUtilsCommons.assertStringValue(coSigReq.getTransactionId())) {
	    inputParameters.put(DSSTagsRequest.DOCUMENT_ARCHIVE_ID, coSigReq.getTransactionId());
	} else if (GenericUtilsCommons.assertArrayValid(coSigReq.getSignature())) {
	    String encodedDoc = null;
	    try {
		encodedDoc = new String(Base64CoderCommons.encodeBase64(coSigReq.getDocument()));
	    } catch (TransformersException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG044), e);
	    }
	    if (encodedDoc != null) {

		List<Map<String, Object>> documentList = new ArrayList<Map<String, Object>>();
		Map<String, Object> docMap = new HashMap<String, Object>();

		if (XMLUtils.isXMLFormat(coSigReq.getDocument())) {

		    docMap.put(DSSTagsRequest.BASE64XML_LAST, encodedDoc);
		    documentList.add(docMap);
		    incorporateSignatureImplicitCoCounterSign(inputParameters, coSigReq.getSignature(), documentList);

		} else {

		    docMap.put(DSSTagsRequest.BASE64DATA_LAST, encodedDoc);
		    documentList.add(docMap);
		    incorporateSignatureImplicitCoCounterSign(inputParameters, coSigReq.getSignature(), documentList);

		}

		Map<String, Object>[ ] documents = documentList.toArray(new HashMap[documentList.size()]);
		inputParameters.put(DSSTagsRequest.DOCUMENT, documents);
	    }

	} else {
	    // localización de la firma en gestor documental
	    inputParameters.put(DSSTagsRequest.INPUTDOC_GETCONTENTSTREAM_REPOID, coSigReq.getDocumentRepository().getId());
	    inputParameters.put(DSSTagsRequest.INPUTDOC_GETCONTENTSTREAM_OBJECTID, coSigReq.getDocumentRepository().getObject());
	    inputParameters.put(DSSTagsRequest.INPUTDOC_SIGNATURE_GETCONTENTSTREAM_REPOID, coSigReq.getSignatureRepository().getId());
	    inputParameters.put(DSSTagsRequest.INPUTDOC_SIGNATURE_GETCONTENTSTREAM_OBJECTID, coSigReq.getSignatureRepository().getObject());
	}
	inputParameters.put(DSSTagsRequest.CLAIMED_IDENTITY, coSigReq.getApplicationId());
	inputParameters.put(DSSTagsRequest.KEY_SELECTOR, coSigReq.getKeySelector());
	inputParameters.put(DSSTagsRequest.PARALLEL_SIGNATURE, "");

	// hashAlgorithm
	if (coSigReq.getHashAlgorithm() != null) {
	    inputParameters.put(DSSTagsRequest.HASH_ALGORITHM, coSigReq.getHashAlgorithm().getUri());
	}

	// signaturePolicyIdentifier
	if (GenericUtilsCommons.assertStringValue(coSigReq.getSignaturePolicyIdentifier())) {
	    inputParameters.put(DSSTagsRequest.SIGPOL_SIGNATURE_POLICY_IDENTIFIER, coSigReq.getSignaturePolicyIdentifier());
	}
	// ignoreGracePeriod
	if (coSigReq.isIgnoreGracePeriod()) {
	    inputParameters.put(DSSTagsRequest.IGNORE_GRACE_PERIOD, "");
	}

	return inputParameters;

    }

    /**
     * Method that generates a XML request message to invoke the server counter-signature service.
     * @param couSigReq Parameter that allows to generate the countersign request.
     * @return a map with the parameters related to the server counter-signature request.
     */
    public static Map<String, Object> generateCounterSignRequest(CounterSignRequest couSigReq) {
	// se crea el mensaje de petición a partir del párametro de entrada
	Map<String, Object> inputParameters = new HashMap<String, Object>();

	// localización de la firma origen en @firma
	if (GenericUtilsCommons.assertStringValue(couSigReq.getTransactionId())) {
	    inputParameters.put(DSSTagsRequest.DOCUMENT_ARCHIVE_ID, couSigReq.getTransactionId());
	} else if (GenericUtilsCommons.assertArrayValid(couSigReq.getSignature())) {
	    List<Map<String, Object>> documentList = new ArrayList<Map<String, Object>>();

	    incorporateSignatureImplicitCoCounterSign(inputParameters, couSigReq.getSignature(), documentList);
	    if (documentList.size() > 0) {
		Map<String, Object>[ ] documents = documentList.toArray(new HashMap[documentList.size()]);
		inputParameters.put(DSSTagsRequest.DOCUMENT, documents);
	    }
	} else {
	    // localización de la firma en gestor documental
	    inputParameters.put(DSSTagsRequest.INPUTDOC_SIGNATURE_GETCONTENTSTREAM_REPOID, couSigReq.getSignatureRepository().getId());
	    inputParameters.put(DSSTagsRequest.INPUTDOC_SIGNATURE_GETCONTENTSTREAM_OBJECTID, couSigReq.getSignatureRepository().getObject());
	}
	inputParameters.put(DSSTagsRequest.CLAIMED_IDENTITY, couSigReq.getApplicationId());
	inputParameters.put(DSSTagsRequest.KEY_SELECTOR, couSigReq.getKeySelector());
	inputParameters.put(DSSTagsRequest.COUNTER_SIGNATURE, "");

	// hashAlgorithm
	if (couSigReq.getHashAlgorithm() != null) {
	    inputParameters.put(DSSTagsRequest.HASH_ALGORITHM, couSigReq.getHashAlgorithm().getUri());
	}

	// signaturePolicyIdentifier
	if (GenericUtilsCommons.assertStringValue(couSigReq.getSignaturePolicyIdentifier())) {
	    inputParameters.put(DSSTagsRequest.SIGPOL_SIGNATURE_POLICY_IDENTIFIER, couSigReq.getSignaturePolicyIdentifier());
	}
	// ignoreGracePeriod
	if (couSigReq.isIgnoreGracePeriod()) {
	    inputParameters.put(DSSTagsRequest.IGNORE_GRACE_PERIOD, "");
	}

	// targetSigner
	if (couSigReq.getTargetSigner() != null) {
	    String encodedTargetSigner = null;
	    try {
		encodedTargetSigner = new String(Base64CoderCommons.encodeBase64(couSigReq.getTargetSigner()));
	    } catch (TransformersException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG045), e);
	    }
	    inputParameters.put(DSSTagsRequest.TARGET_SIGNER, encodedTargetSigner);
	}

	return inputParameters;

    }

    /**
     * Method that adds to a XML request message to invoke the verify signature service the original signed document.
     * @param inputParameters Parameter that represents a map with the parameters related to the verify signature request.
     * @param verSigReq Parameter that allows to generate the verify signature request.
     */
    private static void encodeOriginalSignedDocument(Map<String, Object> inputParameters, VerifySignatureRequest verSigReq) {
	byte[ ] document = verSigReq.getDocument();
	if (document != null) {
	    String encodedSignedDocument = null;
	    try {
		encodedSignedDocument = new String(Base64CoderCommons.encodeBase64(document));
	    } catch (TransformersException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG046), e);
	    }
	    if (XMLUtils.isXMLFormat(document)) {
		// si es xml, se incluye en dss:base64XML el documento
		// codificado en Base64
		inputParameters.put(DSSTagsRequest.BASE64XML, encodedSignedDocument);
	    } else {
		// si no es xml, se incluye en dss:base64DATA el documento
		// codificado en Base64
		inputParameters.put(DSSTagsRequest.BASE64DATA, encodedSignedDocument);
	    }

	} else {
	    if (verSigReq.getDocumentRepository() != null) {
		inputParameters.put(DSSTagsRequest.INPUTDOC_GETCONTENTSTREAM_REPOID, verSigReq.getDocumentRepository().getId());
		inputParameters.put(DSSTagsRequest.INPUTDOC_GETCONTENTSTREAM_OBJECTID, verSigReq.getDocumentRepository().getObject());
	    }
	}
    }

    /**
     * Method that generates a XML request message to invoke the verify signature service.
     * @param verSigReq Parameter that allows to generate the verify signature request.
     * @return a map with the parameters related to the verify signature request.
     */
    public static Map<String, Object> generateVerifySignRequest(VerifySignatureRequest verSigReq) {
	// se crea el mensaje de petición a partir del párametro de entrada
	Map<String, Object> inputParameters = new HashMap<String, Object>();

	// signatureObject
	// si es firma implícita
	String encodedDoc = null;
	if (verSigReq.getSignature() != null) {
	    if (verSigReq.getDocument() == null) {
		incorporateSignatureImplicit(inputParameters, verSigReq.getSignature());
	    } else {

		try {
		    encodedDoc = new String(Base64CoderCommons.encodeBase64(verSigReq.getDocument()));
		} catch (TransformersException e) {
		    LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG044), e);
		}
		if (encodedDoc != null) {

		    List<Map<String, Object>> documentList = new ArrayList<Map<String, Object>>();
		    Map<String, Object> docMap = new HashMap<String, Object>();

		    if (XMLUtils.isXMLFormat(verSigReq.getDocument())) {

			docMap.put(DSSTagsRequest.BASE64XML_LAST, encodedDoc);
			documentList.add(docMap);
			incorporateSignatureImplicitVerifySign(inputParameters, verSigReq.getSignature(), documentList);

		    } else {

			docMap.put(DSSTagsRequest.BASE64DATA_LAST, encodedDoc);
			documentList.add(docMap);
			incorporateSignatureImplicitVerifySign(inputParameters, verSigReq.getSignature(), documentList);

		    }

		    Map<String, Object>[ ] documents = documentList.toArray(new HashMap[documentList.size()]);
		    inputParameters.put(DSSTagsRequest.DOCUMENT, documents);
		}
	    }
	} else {
	    // se encuentra en un repositorio
	    inputParameters.put(DSSTagsRequest.SIGNATURE_OTHER_GETCONTENTSTREAM_REPOID, verSigReq.getSignatureRepository().getId());
	    inputParameters.put(DSSTagsRequest.SIGNATURE_OTHER_GETCONTENTSTREAM_OBJECTID, verSigReq.getSignatureRepository().getObject());
	}

	// inputDocuments
	// documento original firmado
	if (encodedDoc == null) {
	    encodeOriginalSignedDocument(inputParameters, verSigReq);
	}

	// documentHash
	if (verSigReq.getDocumentHash() != null) {
	    if (verSigReq.getDocumentHash().getDigestMethod() != null) {
		inputParameters.put(DSSTagsRequest.DIGEST_METHOD_ATR_ALGORITHM, verSigReq.getDocumentHash().getDigestMethod().getUri());
	    }
	    String encodedSignedDocumentHash = null;
	    try {
		encodedSignedDocumentHash = new String(Base64CoderCommons.encodeBase64(verSigReq.getDocumentHash().getDigestValue()));
	    } catch (TransformersException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG047), e);
	    }

	    inputParameters.put(DSSTagsRequest.DOCUMENTHASH_VALUE, encodedSignedDocumentHash);
	}

	// applicationId
	inputParameters.put(DSSTagsRequest.CLAIMED_IDENTITY, verSigReq.getApplicationId());

	// returnVerificationReport
	if (verSigReq.getVerificationReport() != null) {
	    inputParameters.put(DSSTagsRequest.INCLUDE_CERTIFICATE, verSigReq.getVerificationReport().getIncludeCertificateValues().toString());
	    inputParameters.put(DSSTagsRequest.INCLUDE_REVOCATION, verSigReq.getVerificationReport().getIncludeRevocationValues().toString());
	    if (verSigReq.getVerificationReport().getReportDetailLevel() != null) {
		inputParameters.put(DSSTagsRequest.REPORT_DETAIL_LEVEL, verSigReq.getVerificationReport().getReportDetailLevel().getUri());
	    }
	}

	// optionalParameters
	OptionalParameters optParam = verSigReq.getOptionalParameters();
	if (optParam != null) {
	    incorporateOptionalParameter(inputParameters, optParam);
	}

	return inputParameters;

    }

    /**
     * Method that generates a XML request message to invoke the upgrade signature service.
     * @param upgSigReq Parameter that allows to generate the upgrade signature request.
     * @return a map with the parameters related to the upgrade signature request.
     */
    public static Map<String, Object> generateUpgradeSignatureRequest(UpgradeSignatureRequest upgSigReq) {
	Map<String, Object> inputParameters = new HashMap<String, Object>();

	// signatureObject
	// si es firma implícita
	if (upgSigReq.getSignature() != null) {
	    incorporateSignatureImplicit(inputParameters, upgSigReq.getSignature());
	} else {
	    // se encuentra en un repositorio
	    // se tiene la localización de la firma en el repositorio y la
	    // id de la transacción
	    inputParameters.put(DSSTagsRequest.SIGNATURE_ARCHIVE_ID, upgSigReq.getTransactionId());
	    inputParameters.put(DSSTagsRequest.SIGNATURE_OTHER_GETCONTENTSTREAM_REPOID, upgSigReq.getSignatureRepository().getId());
	    inputParameters.put(DSSTagsRequest.SIGNATURE_OTHER_GETCONTENTSTREAM_OBJECTID, upgSigReq.getSignatureRepository().getObject());
	}

	// applicationId
	inputParameters.put(DSSTagsRequest.CLAIMED_IDENTITY, upgSigReq.getApplicationId());

	// si signatureFormat no es nula, se indica el formato en el elemento
	// ReturnUpdatedSignature
	if (upgSigReq.getSignatureFormat() != null) {
	    inputParameters.put(DSSTagsRequest.RETURN_UPDATED_SIGNATURE_ATR_TYPE, upgSigReq.getSignatureFormat().getUriFormat());
	}

	// targetSigner
	if (upgSigReq.getTargetSigner() != null) {
	    String encodedTargetSigner = null;
	    try {
		encodedTargetSigner = new String(Base64CoderCommons.encodeBase64(upgSigReq.getTargetSigner()));
	    } catch (TransformersException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG045), e);
	    }

	    inputParameters.put(DSSTagsRequest.TARGET_SIGNER, encodedTargetSigner);
	}

	// ignoreGracePeriod
	if (upgSigReq.isIgnoreGracePeriod()) {
	    inputParameters.put(DSSTagsRequest.IGNORE_GRACE_PERIOD, "");
	}
	
	// processAsNotBaseline
	if (upgSigReq.isProcessAsNotBaseline()) {
	    inputParameters.put(DSSTagsRequest.PROCESS_AS_NOT_BASELINE, "");
	}

	return inputParameters;
    }

    /**
     * Method that generates a XML request message to invoke the verify certificate service.
     * @param verCerReq Parameter that allows to generate the verify certificate request.
     * @return a map with the parameters related to the verify certificate request.
     */
    public static Map<String, Object> generateVerifyCertificateRequest(VerifyCertificateRequest verCerReq) {
	Map<String, Object> inputParameters = new HashMap<String, Object>();

	// optionalInputs/ dss:ClaimedIdentity (applicationId)
	if (verCerReq.getApplicationId() != null) {
	    inputParameters.put(DSSTagsRequest.CLAIMED_IDENTITY, verCerReq.getApplicationId());
	}

	// optionalInputs/ afxp:ReturnReadableCertificateInfo
	// (returnRedeableCertificateInfo)
	if (verCerReq.getReturnReadableCertificateInfo()) {
	    inputParameters.put(DSSTagsRequest.RETURN_READABLE_CERT_INFO, "");
	}

	// optionalInputs/
	// vr:ReturnVerificationReport
	VerificationReport verRep = verCerReq.getReturnVerificationReport();
	if (verRep != null) {
	    // vr:ReturnVerificationReport/vr:CheckOptions/vr:checkCertificateStatus
	    if (verRep.getCheckCertificateStatus()) {
		inputParameters.put(DSSTagsRequest.CHECK_CERTIFICATE_STATUS, Boolean.TRUE.toString());
	    }
	    // vr:ReportOptions/vr:includeCertificateValues
	    if (verRep.getIncludeCertificateValues()) {
		inputParameters.put(DSSTagsRequest.INCLUDE_CERTIFICATE, Boolean.TRUE.toString());
	    }
	    // vr:ReportOptions/vr:includeRevocationValue
	    if (verRep.getIncludeRevocationValues()) {
		inputParameters.put(DSSTagsRequest.INCLUDE_REVOCATION, Boolean.TRUE.toString());
	    }
	    // vr:ReportOptions/vr:ReportDetailLevel
	    if (verRep.getReportDetailLevel() != null) {
		inputParameters.put(DSSTagsRequest.REPORT_DETAIL_LEVEL, verRep.getReportDetailLevel().getUri());
	    }
	}

	// dss:signatureObject/dss:other/ds:x5090Data
	if (verCerReq.getCertificate() != null) {
	    // inputParameters.put(DSSTagsRequest.X509_CERTIFICATE, new
	    // String(UtilsBase64.encodeBytes(verCerReq.getSignature())));
	    inputParameters.put(DSSTagsRequest.X509_CERTIFICATE, UtilsFileSystemCommons.getFileBase64Encoded(verCerReq.getCertificate()));
	} else {
	    inputParameters.put(DSSTagsRequest.X509_DATA_GETCONTENTSTREAM_REPOID, verCerReq.getCertificateRepository().getId());
	    inputParameters.put(DSSTagsRequest.X509_DATA_GETCONTENTSTREAM_OBJECTID, verCerReq.getCertificateRepository().getObject());
	}
	return inputParameters;
    }

    /**
     * Method that generates a XML request message to invoke the verify signatures on batch service.
     * @param batVerSigReq Parameter that allows to generate the verify signatures on batch request.
     * @return a map with the parameters related to the verify signatures on batch request.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> generateBatchVerifySignatureRequest(BatchVerifySignatureRequest batVerSigReq) {
	Map<String, Object> inputParameters = new HashMap<String, Object>();

	// afxp:Request/dss:VerifyRequest
	List<VerifySignatureRequest> listSignatures = batVerSigReq.getListVerifySignature();

	Map<String, Object>[ ] listSigMap = new HashMap[listSignatures.size()];

	int i = 0;
	for (VerifySignatureRequest verSigReq: listSignatures) {
	    Map<String, Object> mapSig = generateVerifySignRequest(verSigReq);
	    // se quita la aplicación si estuviera en la petición
	    if (mapSig.containsKey(DSSTagsRequest.CLAIMED_IDENTITY)) {
		mapSig.remove(DSSTagsRequest.CLAIMED_IDENTITY);
	    }
	    // se le añade idRequest para identificar la firma
	    mapSig.put(DSSTagsRequest.VERIFY_REQUEST_ATTR_REQUEST_ID, String.valueOf(Math.random() * NumberConstants.INT_9999));
	    listSigMap[i] = mapSig;
	    i++;
	}

	inputParameters.put(DSSTagsRequest.VERIFY_REQUEST, listSigMap);

	// optionalInputs/ dss:ClaimedIdentity (applicationId)
	inputParameters.put(DSSTagsRequest.CLAIMED_IDENTITY, batVerSigReq.getApplicationId());

	// se indica el tipo de petición en lote realizada.
	inputParameters.put(DSSTagsRequest.BATCH_REQUEST_ATTR_TYPE, DSSTagsRequest.BATCH_VERIFY_SIGN_TYPE);

	return inputParameters;
    }

    /**
     * Method that generates a XML request message to invoke the verify certificates on batch service.
     * @param batVerCerReq Parameter that allows to generate the verify certificates on batch request.
     * @return a map with the parameters related to the verify certificates on batch request.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> generateBatchVerifyCertificateRequest(BatchVerifyCertificateRequest batVerCerReq) {
	Map<String, Object> inputParameters = new HashMap<String, Object>();

	// afxp:Request/dss:VerifyRequest
	List<VerifyCertificateRequest> listCertificates = batVerCerReq.getListVerifyCertificate();
	Map<String, Object>[ ] listCertMap = new HashMap[listCertificates.size()];

	int i = 0;
	for (VerifyCertificateRequest verCerReq: listCertificates) {
	    Map<String, Object> mapCer = generateVerifyCertificateRequest(verCerReq);
	    // se quita la aplicación si estuviera en la petición
	    if (mapCer.containsKey(DSSTagsRequest.CLAIMED_IDENTITY)) {
		mapCer.remove(DSSTagsRequest.CLAIMED_IDENTITY);
	    }
	    // se le añade idRequest para identificar el certificado
	    mapCer.put(DSSTagsRequest.VERIFY_REQUEST_ATTR_REQUEST_ID, String.valueOf(Math.random() * NumberConstants.INT_9999));
	    listCertMap[i] = mapCer;
	    i++;
	}

	inputParameters.put(DSSTagsRequest.VERIFY_REQUEST, listCertMap);

	// optionalInputs/ dss:ClaimedIdentity (applicationId)
	inputParameters.put(DSSTagsRequest.CLAIMED_IDENTITY, batVerCerReq.getApplicationId());

	// se indica el tipo de petición en lote realizada.
	inputParameters.put(DSSTagsRequest.BATCH_REQUEST_ATTR_TYPE, DSSTagsRequest.BATCH_VERIFY_CERT_TYPE);
	return inputParameters;
    }

    /**
     * Method that generates a XML request message to invoke the asynchronous processes of sign and verify service.
     * @param pendingRequest Parameter that allows to generate the asynchronous processes of sign and verify request.
     * @return a map with the parameters related to the async processes of sign and verify request.
     */
    public static Map<String, Object> generatePendingRequest(PendingRequest pendingRequest) {
	Map<String, Object> inputParameters = new HashMap<String, Object>();

	// optionalInputs/ dss:ClaimedIdentity (applicationId)
	inputParameters.put(DSSTagsRequest.CLAIMED_IDENTITY, pendingRequest.getApplicationId());

	// optionalInputs/ dss: async:ResponseID
	inputParameters.put(DSSTagsRequest.ASYNC_RESPONSE_ID, pendingRequest.getResponseId());

	return inputParameters;
    }

    /**
     * Method that generates a XML request message to invoke the archive signatures retrieve service.
     * @param archiveRequest Parameter that allows to generate the archive signatures retrieve request.
     * @return a map with the parameters related to the archive signatures retrieve request.
     */
    public static Map<String, Object> generateArchiveRequest(ArchiveRequest archiveRequest) {
	Map<String, Object> inputParameters = new HashMap<String, Object>();

	// optionalInputs/ dss:ClaimedIdentity (applicationId)
	inputParameters.put(DSSTagsRequest.CLAIMED_IDENTITY, archiveRequest.getApplicationId());

	// optionalInputs/ dss: async:ResponseID
	inputParameters.put(DSSTagsRequest.ARCHIVE_IDENTIFIER, archiveRequest.getTransactionId());

	return inputParameters;
    }

    /**
     * Method that adds an implicit signature to a request message.
     * @param inputParameters Parameter that represents the request as a map of elements.
     * @param signature Parameter that represents the signature.
     */
    private static void incorporateSignatureImplicit(Map<String, Object> inputParameters, byte[ ] signature) {
	try {

	    // si no es XML, se guarda en Base64Signature codificado en base 64
	    if (!SignatureFormatDetectorCommons.isXMLFormat(signature)) {
		inputParameters.put(DSSTagsRequest.SIGNATURE_BASE64, new String(Base64CoderCommons.encodeBase64(signature)));
		// inputParameters.put(DSSTagsRequest.SIGNATURE_PTR_ATR_WHICH,
		// String.valueOf(Math.random() * NumberConstants.INT_9999));
		// inputParameters.put(DSSTagsRequest.DOCUMENT_ATR_ID,
		// String.valueOf(Math.random() * NumberConstants.INT_9999));
	    } else {
		// se comprueba si es enveloping, enveloped o detached
		DocumentBuilderFactory dBFactory = DocumentBuilderFactory.newInstance();
		dBFactory.setNamespaceAware(true);

		// Lectura y parseo de la firma xml.
		Document signDoc;
		signDoc = dBFactory.newDocumentBuilder().parse(new ByteArrayInputStream(signature));
		String typeOfESignature = getTypeOfESignature(signDoc);

		if (SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING.equals(typeOfESignature)) {
		    // si es enveloping, sin codificar en ds:Signature
		    inputParameters.put(DSSTagsRequest.SIGNATURE_OBJECT, new String(signature));
		} else if (SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED.equals(typeOfESignature) || SignatureConstants.SIGN_FORMAT_XADES_DETACHED.equals(typeOfESignature)) {
		    // si es enveloped o detached, se incluye en ds:SignaturePtr
		    // referencia al elemento dss:BaseXML
		    String idSignaturePtr = String.valueOf(Math.random() * NumberConstants.INT_9999);
		    inputParameters.put(DSSTagsRequest.SIGNATURE_PTR_ATR_WHICH, idSignaturePtr);
		    inputParameters.put(DSSTagsRequest.DOCUMENT_ATR_ID, idSignaturePtr);
		    // en dss:document/dss:base64XML se guarda la firma
		    // codificada en base64
		    inputParameters.put(DSSTagsRequest.BASE64XML, new String(org.apache.axis2.util.XMLUtils.base64encode(signature)));

		}

	    }

	} catch (SAXException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG030, new Object[ ] { e.getMessage() }));
	} catch (IOException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG030, new Object[ ] { e.getMessage() }));
	} catch (ParserConfigurationException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG030, new Object[ ] { e.getMessage() }));
	} catch (SigningException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG030, new Object[ ] { e.getMessage() }));
	} catch (TransformersException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG030, new Object[ ] { e.getMessage() }));
	}
    }

    /**
     * Method that adds an implicit signature to a request message for coSign.
     * @param inputParameters Parameter that represents the request as a map of elements.
     * @param signature Parameter that represents the signature.
     */
    private static void incorporateSignatureImplicitCoCounterSign(Map<String, Object> inputParameters, byte[ ] signature, List<Map<String, Object>> documentList) {
	try {

	    Map<String, Object> docMap = new HashMap<String, Object>();
	    // si no es XML, se guarda en Base64Signature codificado en base 64
	    if (!SignatureFormatDetectorCommons.isXMLFormat(signature)) {
		inputParameters.put(DSSTagsRequest.INPUTDOC_SIGNATURE_BASE64SIGNATURE, new String(Base64CoderCommons.encodeBase64(signature)));
	    } else {
		// se comprueba si es enveloping, enveloped o detached
		DocumentBuilderFactory dBFactory = DocumentBuilderFactory.newInstance();
		dBFactory.setNamespaceAware(true);

		// Lectura y parseo de la firma xml.
		Document signDoc;
		signDoc = dBFactory.newDocumentBuilder().parse(new ByteArrayInputStream(signature));
		String typeOfESignature = getTypeOfESignature(signDoc);

		if (SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING.equals(typeOfESignature)) {
		    // si es enveloping, sin codificar en ds:Signature
		    inputParameters.put(DSSTagsRequest.INPUTDOC_SIGNATURE_SIGNATUREOBJECT, new String(signature));
		} else if (SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED.equals(typeOfESignature) || SignatureConstants.SIGN_FORMAT_XADES_DETACHED.equals(typeOfESignature)) {
		    // si es enveloped o detached, se incluye en ds:SignaturePtr
		    // referencia al elemento dss:BaseXML
		    String idSignaturePtr = String.valueOf(Math.random() * NumberConstants.INT_9999);
		    docMap.put(DSSTagsRequest.BASE64XML_LAST, new String(org.apache.axis2.util.XMLUtils.base64encode(signature)));
		    docMap.put(DSSTagsRequest.DOCUMENT_ATR_ID_LAST, idSignaturePtr);
		    inputParameters.put(DSSTagsRequest.INPUTDOC_SIGNATURE_SIGNATURE_PTR_ATR_WHICH, idSignaturePtr);

		    documentList.add(docMap);

		}

	    }

	} catch (SAXException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG030, new Object[ ] { e.getMessage() }));
	} catch (IOException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG030, new Object[ ] { e.getMessage() }));
	} catch (ParserConfigurationException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG030, new Object[ ] { e.getMessage() }));
	} catch (SigningException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG030, new Object[ ] { e.getMessage() }));
	} catch (TransformersException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG030, new Object[ ] { e.getMessage() }));
	}
    }

    /**
     * Method that obtains the XML signature mode.
     * @param eSignature xml signature.
     * @return four possible values:
     * <ul>
     * <li>{@link SignatureConstants#SIGN_FORMAT_XADES_ENVELOPING}</li>
     * <li>{@link SignatureConstants#SIGN_FORMAT_XADES_ENVELOPED}</li>
     * <li>{@link SignatureConstants#SIGN_FORMAT_XADES_DETACHED}</li>
     * <li>{@link SignatureConstants#SIGN_FORMAT_XADES_EXTERNALLY_DETACHED}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static String getTypeOfESignature(Document eSignature) throws SigningException {
	String rootName = eSignature.getDocumentElement().getNodeName();

	// Si el primer nodo (raíz) es <ds:Signature>, entonces es una firma
	// XAdES Enveloping
	if (rootName.equalsIgnoreCase(DS_SIGNATURE_NODE_NAME) || rootName.equals(ROOT_TAG)) {
	    return SIGN_FORMAT_XADES_ENVELOPING;
	} else {
	    // Si contiene un nodo <ds:Manifest> es una firma XAdES Externally
	    // Detached
	    NodeList signatureNodeLs = eSignature.getElementsByTagName(MANIFEST_TAG_NAME);
	    if (signatureNodeLs.getLength() > 0) {
		return SIGN_FORMAT_XADES_EXTERNALLY_DETACHED;
	    }

	    NodeList signsList = eSignature.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_SIGNATURE);
	    if (signsList.getLength() == 0) {
		throw new SigningException(Language.getResIntegra(ILogConstantKeys.XS_LOG003));
	    }
	    // Si contiene alguna referencia con la URI "" se trata de una firma
	    // XAdES Enveloped
	    Node signatureNode = signsList.item(0);
	    XMLSignature xmlSignature;
	    try {
		xmlSignature = new XMLSignatureElement((Element) signatureNode).getXMLSignature();
	    } catch (MarshalException e) {
		throw new SigningException(Language.getResIntegra(ILogConstantKeys.XS_LOG005), e);
	    }
	    // Tomamos las referencias de la firma
	    List<Reference> references = xmlSignature.getSignedInfo().getReferences();

	    // Buscamos la referencia con URI=""
	    for (int i = 0; i < references.size(); i++) {
		if ("".equals(references.get(i).getURI())) {
		    return SIGN_FORMAT_XADES_ENVELOPED;
		}
	    }
	    return SIGN_FORMAT_XADES_DETACHED;
	}
    }

    /**
     * Method that adds an implicit signature to a request message for verify a signature.
     * @param inputParameters Parameter that represents the request as a map of elements.
     * @param signature Parameter that represents the signature.
     */
    private static void incorporateSignatureImplicitVerifySign(Map<String, Object> inputParameters, byte[ ] signature, List<Map<String, Object>> documentList) {
	try {

	    Map<String, Object> docMap = new HashMap<String, Object>();
	    // si no es XML, se guarda en Base64Signature codificado en base 64
	    if (!SignatureFormatDetectorCommons.isXMLFormat(signature)) {
		inputParameters.put(DSSTagsRequest.SIGNATURE_BASE64, new String(Base64CoderCommons.encodeBase64(signature)));
	    } else {
		// se comprueba si es enveloping, enveloped o detached
		DocumentBuilderFactory dBFactory = DocumentBuilderFactory.newInstance();
		dBFactory.setNamespaceAware(true);

		// Lectura y parseo de la firma xml.
		Document signDoc;
		signDoc = dBFactory.newDocumentBuilder().parse(new ByteArrayInputStream(signature));
		String typeOfESignature = getTypeOfESignature(signDoc);

		if (SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING.equals(typeOfESignature)) {
		    // si es enveloping, sin codificar en ds:Signature
		    inputParameters.put(DSSTagsRequest.SIGNATURE_OBJECT, new String(signature));
		} else if (SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED.equals(typeOfESignature) || SignatureConstants.SIGN_FORMAT_XADES_DETACHED.equals(typeOfESignature)) {
		    // si es enveloped o detached, se incluye en ds:SignaturePtr
		    // referencia al elemento dss:BaseXML
		    String idSignaturePtr = String.valueOf(Math.random() * NumberConstants.INT_9999);
		    docMap.put(DSSTagsRequest.BASE64XML_LAST, new String(org.apache.axis2.util.XMLUtils.base64encode(signature)));
		    docMap.put(DSSTagsRequest.DOCUMENT_ATR_ID_LAST, idSignaturePtr);
		    inputParameters.put(DSSTagsRequest.SIGNATURE_PTR_ATR_WHICH, idSignaturePtr);

		    documentList.add(docMap);

		}

	    }

	} catch (SAXException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG030, new Object[ ] { e.getMessage() }));
	} catch (IOException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG030, new Object[ ] { e.getMessage() }));
	} catch (ParserConfigurationException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG030, new Object[ ] { e.getMessage() }));
	} catch (SigningException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG030, new Object[ ] { e.getMessage() }));
	} catch (TransformersException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG030, new Object[ ] { e.getMessage() }));
	}
    }

    /**
     * Method that adds optional parameters to a request for the verify signature service.
     * @param inputParameters Parameter that represents the request as a map of elements.
     * @param optParams Parameter that represents the optional elements to add.
     */
    private static void incorporateOptionalParameter(Map<String, Object> inputParameters, OptionalParameters optParams) {
	// returnReadableCertificateInfo
	if (optParams.isReturnReadableCertificateInfo()) {
	    inputParameters.put(DSSTagsRequest.RETURN_READABLE_CERT_INFO, "");
	}

	// additionalReportOption
	if (optParams.isAdditionalReportOption()) {
	    inputParameters.put(DSSTagsRequest.ADDICIONAL_REPORT_OPT_SIGNATURE_TIMESTAMP, GenerateMessageRequest.SIGNATURE_TIMESTAMP);
	}

	// returnProcessingDetails
	if (optParams.isReturnProcessingDetails()) {
	    inputParameters.put(DSSTagsRequest.RETURN_PROCESSING_DETAILS, "");
	}

	// returnSignPolicyDocument
	if (optParams.isReturnSignPolicyDocument()) {
	    // si se incluye, se incluye en la petición una URI que identifica
	    // el tipo de documento de la politica que se desea obtener.
	    inputParameters.put(DSSTagsRequest.RETURN_SIGN_POLICY_DOCUMENT, GenerateMessageRequest.FORMAL_DOCUMENT);
	}

	// returnSignedDataInfo
	if (optParams.isReturnSignedDataInfo()) {
	    inputParameters.put(DSSTagsRequest.RETURN_SIGNED_DATA_INFO, "");
	}
	
	// returnNextUpdate
	if(optParams.isReturnNextUpdate()){
	    inputParameters.put(DSSTagsRequest.RETURN_NEXT_UPDATE, "");
	}
	
	if(optParams.isProcessAsNotBaseline()){
	    inputParameters.put(DSSTagsRequest.PROCESS_AS_NOT_BASELINE, "");
	}

	// certificateValidationLevel
	if (optParams.getCertificateValidationLevel() != null) {
	    inputParameters.put(DSSTagsRequest.CERTIFICATE_VALIDATION_LEVEL, optParams.getCertificateValidationLevel());
	}
    }

    /**
     * Method that generates a XML request message to invoke the server timestamp service.
     * @param timestampReq Parameter that allows to generate the sign request.
     * @return a map with the parameters related to the server signature request.
     */
    public static Map<String, Object> generateTimestampRequest(TimestampRequest timestampReq) {
	// se crea el mensaje de petición a partir del párametro de entrada
	Map<String, Object> inputParameters = new HashMap<String, Object>();

	// documento a firmar.
	byte[ ] document = timestampReq.getDataToStamp();
	if (document != null) {
	    String docString = new String(document);
	    if (IXMLConstants.ELEMENT_INLINE_XML.equals(timestampReq.getDocumentType().getType())) {
		inputParameters.put(DSSTagsRequest.INLINEXML, docString);
	    } else if (IXMLConstants.ELEMENT_ESCAPED_XML.equals(timestampReq.getDocumentType().getType())) {
		inputParameters.put(DSSTagsRequest.ESCAPEDXML, docString);
	    } else if (IXMLConstants.ELEMENT_BASE64_DATA.equals(timestampReq.getDocumentType().getType()) || IXMLConstants.ELEMENT_BASE64_XML.equals(timestampReq.getDocumentType().getType())) {
		String encodedDocumentToSign = null;
		try {
		    encodedDocumentToSign = new String(Base64CoderCommons.encodeBase64(document));
		} catch (TransformersException e) {
		    LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG044), e);
		}

		if (XMLUtils.isXMLFormat(document)) {
		    // si es xml, se incluye en dss:Base64XML, codificado en
		    // base64
		    inputParameters.put(DSSTagsRequest.BASE64XML, encodedDocumentToSign);
		} else {
		    // si no es xml
		    inputParameters.put(DSSTagsRequest.BASE64DATA, encodedDocumentToSign);
		}
	    } else if (IXMLConstants.ELEMENT_TRANSFORMED_DATA.equals(timestampReq.getDocumentType().getType())) {
		try {
		    byte[ ] canonicalizedFile = document;
		    MessageDigest md = null;
		    for (String algorithm: timestampReq.getTransformData().getXPath()) {
			org.apache.xml.security.Init.init();
			canonicalizedFile = Canonicalizer.getInstance(algorithm).canonicalize(canonicalizedFile);
			md = MessageDigest.getInstance(timestampReq.getTransformData().getAlgorithm());
			md.update(canonicalizedFile);
			inputParameters.put(DSSTagsRequest.TRANSFORMED_DATA_TRANSFORM_ATR_ALGORITHM, algorithm);
		    }
		    if (md != null) {
			String inputDocumentProcessed = new String(Base64CoderCommons.encodeBase64(md.digest()));
			inputParameters.put(DSSTagsRequest.TRANSFORMED_DATA_BASE64DATA, inputDocumentProcessed);
		    }

		} catch (TransformersException e) {
		    LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG044), e);
		} catch (CanonicalizationException e) {
		    LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG053), e);
		} catch (InvalidCanonicalizerException e) {
		    LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG053), e);
		} catch (ParserConfigurationException e) {
		    LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG053), e);
		} catch (IOException e) {
		    LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG053), e);
		} catch (SAXException e) {
		    LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG053), e);
		} catch (NoSuchAlgorithmException e) {
		    LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG053), e);
		}
	    }

	} else if (timestampReq.getDocumentHash() != null) {
	    byte[ ] canonicalizedFile = timestampReq.getDocumentHash().getDigestValue();
	    MessageDigest md = null;
	    if (timestampReq.getDocumentHash().getTransform() != null) {
		try {
		    for (String algorithm: timestampReq.getDocumentHash().getTransform().getXPath()) {
			org.apache.xml.security.Init.init();
			canonicalizedFile = Canonicalizer.getInstance(algorithm).canonicalize(canonicalizedFile);
			md = MessageDigest.getInstance(timestampReq.getDocumentHash().getTransform().getAlgorithm());
			md.update(canonicalizedFile);
			inputParameters.put(DSSTagsRequest.DOCUMENT_HASH_TRANSFORM_ATR_ALGORITHM, algorithm);
		    }
		} catch (CanonicalizationException e) {
		    LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG053), e);
		} catch (InvalidCanonicalizerException e) {
		    LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG053), e);
		} catch (ParserConfigurationException e) {
		    LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG053), e);
		} catch (IOException e) {
		    LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG053), e);
		} catch (SAXException e) {
		    LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG053), e);
		} catch (NoSuchAlgorithmException e) {
		    LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG053), e);
		}
	    }
	    String digestMethod = timestampReq.getDocumentHash().getDigestMethod().getUri();
	    if (digestMethod == null) {
		digestMethod = DSSConstants.AlgorithmTypes.SHA1;
	    }
	    inputParameters.put(DSSTagsRequest.DIGEST_METHOD_ATR_ALGORITHM, digestMethod);

	    try {
		md = MessageDigest.getInstance(CryptoUtilXML.translateXmlDigestAlgorithm(digestMethod));
		md.update(canonicalizedFile);
		String inputDocumentProcessed = new String(Base64CoderCommons.encodeBase64(md.digest()));
		inputParameters.put(DSSTagsRequest.DIGEST_VALUE, inputDocumentProcessed);
	    } catch (TransformersException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG051), e);
	    } catch (NoSuchAlgorithmException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG053), e);
	    }
	}

	if (timestampReq.getTimestampTimestampToken() == null) {
	    inputParameters.put(DSSTagsRequest.SIGNATURE_TYPE, timestampReq.getTimestampType().getType());
	}
	inputParameters.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, timestampReq.getApplicationId());

	return inputParameters;
    }

}
