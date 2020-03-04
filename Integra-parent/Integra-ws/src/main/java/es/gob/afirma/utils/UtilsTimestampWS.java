// Copyright (C) 2012-13 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.utils.UtilsTimestampPdfBc.java.</p>
 * <b>Description:</b><p>Class that contains methods related to the manage of timestamps.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>05/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.2, 04/03/2020.
 */
package es.gob.afirma.utils;

import java.io.IOException;
import java.io.StringReader;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.log4j.Logger;
import org.apache.xml.security.c14n.Canonicalizer;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.signature.xades.IXMLConstants;
import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.transformers.TransformersFacade;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerException;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerFacade;
import es.gob.afirma.utils.DSSConstants.DSSTagsRequest;
import es.gob.afirma.utils.DSSConstants.ResultProcessIds;

/**
 * <p>Class that contains methods related to the manage of timestamps.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 04/03/2020.
 */
public final class UtilsTimestampWS {

	/**
	 * Attribute that represents the object that manages the log of the class.
	 */
	public static final Logger LOGGER = IntegraLogger.getInstance().getLogger(UtilsTimestampWS.class);

	/**
	 * Constructor method for the class TimestampUtils.java.
	 */
	private UtilsTimestampWS() {
	}

	/**
	 * Method that obtains a timestamp from TS@.
	 * @param dataToStamp Parameter that represents the data to stamp.
	 * @param applicationID Parameter that represents the identifier of the client application.
	 * @param signatureType Parameter that represents the timestamp type to generate. The allowed values are:
	 * <ul>
	 * <li>{@link DSSConstants.TimestampForm#RFC_3161} for ASN.1 timestamp.</li>
	 * <li>{@link DSSConstants.TimestampForm#XML} for XML timestamp.</li>
	 * </ul>
	 * @return an object that represents the timestamp. This object can be:
	 * <ul>
	 * <li>An instance of {@link TimeStampToken} when the timestamp is ASN.1 type.</li>
	 * <li>An instance of {@link org.w3c.dom.Element} when the timestamp is XML type.</li>
	 * </ul>
	 * @throws SigningException If the method fails.
	 */
	public static Object getTimestampFromDssService(byte[ ] dataToStamp, String applicationID, String signatureType) throws SigningException {
		return getTimestampFromDssService(dataToStamp, applicationID, signatureType, null);
	}

	/**
	 * Method that obtains a timestamp from TS@.
	 * @param dataToStamp Parameter that represents the data to stamp.
	 * @param applicationID Parameter that represents the identifier of the client application.
	 * @param signatureType Parameter that represents the timestamp type to generate. The allowed values are:
	 * <ul>
	 * <li>{@link DSSConstants.TimestampForm#RFC_3161} for ASN.1 timestamp.</li>
	 * <li>{@link DSSConstants.TimestampForm#XML} for XML timestamp.</li>
	 * </ul>
	 * @param idClient Parameter that represents client id.
	 * @return an object that represents the timestamp. This object can be:
	 * <ul>
	 * <li>An instance of {@link TimeStampToken} when the timestamp is ASN.1 type.</li>
	 * <li>An instance of {@link org.w3c.dom.Element} when the timestamp is XML type.</li>
	 * </ul>
	 * @throws SigningException If the method fails.
	 */
	public static Object getTimestampFromDssService(byte[ ] dataToStamp, String applicationID, String signatureType, String idClient) throws SigningException {
		LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG001));
		try {
			// Comprobamos que los parámetros de entrada no son nulos
			GenericUtilsCommons.checkInputParameterIsNotNull(dataToStamp, Language.getResIntegra(ILogConstantKeys.TSU_LOG032));
			GenericUtilsCommons.checkInputParameterIsNotNull(applicationID, Language.getResIntegra(ILogConstantKeys.TSU_LOG034));
			GenericUtilsCommons.checkInputParameterIsNotNull(signatureType, Language.getResIntegra(ILogConstantKeys.TSU_LOG035));

			Object result = null;
			String errorMsg = null;
			try {
				// Instanciamos el mapa con los parámetros que pasaremos al
				// servicio
				Map<String, Object> inParams = new HashMap<String, Object>();

				// Como parámetros de entrada especificamos InputDocument de
				// tipo
				// Base64Data, el identificador de aplicación y el formato del
				// sello
				// de tiempo
				errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG002);
				String base64Data = new String(Base64.encode(dataToStamp));
				inParams.put(DSSTagsRequest.BASE64DATA, base64Data);
				inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, applicationID);
				inParams.put(DSSTagsRequest.SIGNATURE_TYPE, signatureType);

				// Generamos el XML de petición
				errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG003);
				String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_SERVICE, TransformersConstants.VERSION_10);

				// Invocamos al servicio web de la TS@
				errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG004);
				String xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_SERVICE, applicationID, idClient);

				// Accedemos a la respuesta
				errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG005);
				Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_SERVICE, TransformersConstants.VERSION_10);

				// Si la respuesta ha sido correcta
				if (propertiesResult.get("dss:Result/dss:ResultMajor").equals(ResultProcessIds.SUCESS)) {

					// Accedemos al sello de tiempo
					result = getTimestampFromResponse(signatureType, propertiesResult);

				}
				// Si la respuesta no ha sido correcta
				else {
					// Accedemos al mensaje de error
					String resultMessage = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMessage"));

					// Lanzamos una excepción
					errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG006, new Object[ ] { resultMessage });
					LOGGER.error(errorMsg);
					throw new SigningException(errorMsg);
				}
			} catch (TransformersException e) {
				LOGGER.error(errorMsg);
				throw new SigningException(errorMsg, e);
			} catch (TSAServiceInvokerException e) {
				LOGGER.error(errorMsg);
				throw new SigningException(errorMsg, e);
			}
			return result;
		} finally {
			LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG033));
		}
	}

	/**
	 * Method that obtains the timestamp contained inside of a response from TS@.
	 * @param signatureType Parameter that represents the timestamp type to generate. The allowed values are:
	 * <ul>
	 * <li>{@link DSSConstants.TimestampForm#RFC_3161} for ASN.1 timestamp.</li>
	 * <li>{@link DSSConstants.TimestampForm#XML} for XML timestamp.</li>
	 * </ul>
	 * @param propertiesResult Parameter that represents a map with the elements of the response of TS@ web service.
	 * @return an object that represents the timestamp. This object can be:
	 * <ul>
	 * <li>An instance of {@link TimeStampToken} when the timestamp is ASN.1 type.</li>
	 * <li>An instance of {@link org.w3c.dom.Element} when the timestamp is XML type.</li>
	 * </ul>
	 * @throws SigningException If the method fails.
	 */
	private static Object getTimestampFromResponse(String signatureType, Map<String, Object> propertiesResult) throws SigningException {
		String errorMsg = null;
		try {
			// Si el sello de tiempo es ASN1
			if (signatureType.equals(DSSConstants.TimestampForm.RFC_3161)) {
				// Accedemos al sello de tiempo ASN1
				String asn1TimeStamp = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("RFC3161Timestamp"));

				// Comprobamos que el sello de tiempo está presente
				if (asn1TimeStamp == null) {
					errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG007);
					LOGGER.error(errorMsg);
					throw new SigningException(errorMsg);
				}

				// Si hemos obtenido sello de tiempo, lo decodificamos, lo
				// formateamos y
				// devolvemos
				errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG008);
				return new TimeStampToken(new CMSSignedData(Base64.decode(asn1TimeStamp)));
			}
			// Si el sello de tiempo es XML
			else {
				// Accedemos al sello de tiempo XML
				String xmlTimeStamp = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("XMLTimestamp"));

				// Comprobamos que el sello de tiempo está presente
				if (xmlTimeStamp == null) {
					errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG007);
					LOGGER.error(errorMsg);
					throw new SigningException(errorMsg);
				}

				// Si hemos obtenido sello de tiempo, lo transformamos a
				// objeto Node y lo devolvemos
				errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG008);

				DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
				dbf.setNamespaceAware(true);
				DocumentBuilder db = dbf.newDocumentBuilder();
				InputSource is = new InputSource();
				is.setCharacterStream(new StringReader(xmlTimeStamp));
				Document doc = db.parse(is);
				return doc.getDocumentElement();
			}
		} catch (IOException e) {
			LOGGER.error(errorMsg);
			throw new SigningException(errorMsg, e);
		} catch (TSPException e) {
			LOGGER.error(errorMsg);
			throw new SigningException(errorMsg, e);
		} catch (CMSException e) {
			LOGGER.error(errorMsg);
			throw new SigningException(errorMsg, e);
		} catch (ParserConfigurationException e) {
			LOGGER.error(errorMsg);
			throw new SigningException(errorMsg, e);
		} catch (SAXException e) {
			LOGGER.error(errorMsg);
			throw new SigningException(errorMsg, e);
		}
	}

	/**
	 * Method that checks if the input document of type Document, associated to a renovation of a XML time-stamp, is structurally correct.
	 * @param inputDocument Parameter that represents the <code>dss:Document</code> element of the time-stamp renovation request.
	 * @param referenceElement Parameter that represents the <code>ds:Reference</code> element which refers to the input document.
	 * @throws TSAServiceInvokerException If the validation fails.
	 */
	private static void checkDocumentTypeXMLTimestamp(Element inputDocument, Element referenceElement) throws TSAServiceInvokerException {
		// Si el Input Document es de tipo Document comprobamos que el
		// elemento hijo exista
		Element documentType = (Element) inputDocument.getFirstChild();
		if (documentType == null) {
			throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TSU_LOG062));
		}
		// Document de tipo Base64XML
		if (documentType.getLocalName().equals(IXMLConstants.ELEMENT_BASE64_XML)) {
			processBase64XMLXMLTimeStamp(documentType, referenceElement);
		}
		// Document de tipo InlineXML
		else if (documentType.getLocalName().equals(IXMLConstants.ELEMENT_INLINE_XML)) {
			processInlineXMLXMLTimeStamp(documentType, referenceElement);
		}
		// Document de tipo EscapedXML
		else if (documentType.getLocalName().equals(IXMLConstants.ELEMENT_ESCAPED_XML)) {
			processEscapedXMLXMLTimeStamp(documentType, referenceElement);
		}
		// Document de tipo Base64Data
		else if (documentType.getLocalName().equals(IXMLConstants.ELEMENT_BASE64_DATA)) {
			processBase64DataXMLTimeStamp(documentType, referenceElement);
		}
	}

	/**
	 * Method that obtains the only one reference without <code>Type</code> attribute of the list of references of a XML time-stamp.
	 * @param signature Parameter that represents the <code>ds:Signature</code> element of the XML time-stamp.
	 * @return an object that represents the <code>ds:Reference</code> element.
	 * @throws TSAServiceInvokerException If the method fails.
	 */
	private static Element getReferenceOfInputDocument(Element signature) throws TSAServiceInvokerException {
		// Accedemos a las referencias del sello de tiempo
		NodeList listReferences = signature.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_REFERENCE);
		// Buscamos la referencia que apunta al input document, esto es,
		// aquella referencia que no posee el atributo
		// Type="urn:oasis:names:tc:dss:1.0:core:schema:XMLTimeStampToken"
		Element referenceElement = null;
		int i = 0;
		while (i < listReferences.getLength() && referenceElement == null) {
			if (((Element) listReferences.item(i)).getAttribute(IXMLConstants.ATTRIBUTE_TYPE).isEmpty()) {
				referenceElement = (Element) listReferences.item(i);
			}
			i++;
		}
		// Si no hemos encontrado la referencia lanzamos una excepción
		if (referenceElement == null) {
			throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TSU_LOG073));
		}
		return referenceElement;
	}

	/**
	 * Method that checks if the input document associated to a renovation of a XML time-stamp is structurally correct.
	 * @param inputDocuments Parameter that represents the <code>dss:InputDocuments</code> element of the time-stamp renovation request.
	 * @param signature Parameter that represents the <code>ds:Signature</code> element of the time-stamp renovation request.
	 * @throws TSAServiceInvokerException If the validation fails.
	 */
	public static void checkInputDocumentXMLTimeStamp(Element inputDocuments, Element signature) throws TSAServiceInvokerException {
		LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG059));
		try {
			// Obtenemos la referencia del InputDocument
			Element referenceElement = getReferenceOfInputDocument(signature);
			// Determinamos de qué tipo es el Input Document
			Element inputDocument = (Element) inputDocuments.getFirstChild();
			if (inputDocument == null) {
				throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TSU_LOG061));
			}
			LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG049, new Object[ ] { inputDocument.getLocalName() }));
			// Comprobamos de qué tipo es el elemento dss:InputDocument
			if (inputDocument.getLocalName().equals(IXMLConstants.ELEMENT_DOCUMENT)) {
				checkDocumentTypeXMLTimestamp(inputDocument, referenceElement);
			} else if (inputDocument.getLocalName().equals(IXMLConstants.ELEMENT_DOCUMENT_HASH)) {
				// El Input Document es de tipo DocumentHash
				processDocumentHashXMLTimestamp(inputDocument, referenceElement);
			} else if (inputDocument.getLocalName().equals(IXMLConstants.ELEMENT_TRANSFORMED_DATA)) {
				// El Input Document es de tipo TransformedData
				processTransformedDataXMLTimestamp(inputDocument, referenceElement);
			} else if (inputDocument.getLocalName().equals(IXMLConstants.ELEMENT_ANY_TYPE)) {
				// El tipo AnyType no está soportado
				throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG077, new Object[ ] { inputDocument.getLocalName() }));
			}
			// El tipo es desconocido
			else {
				throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG077, new Object[ ] { inputDocument.getLocalName() }));
			}
		} finally {
			LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG060));
		}
	}

	/**
	 * Method that checks if an input document of type TransformedData matchs to the value calculated on the associated reference.
	 * @param transformedData Parameter that represents the <code>dss:TransformedData</code> element.
	 * @param reference Parameter that represents the associated reference.
	 * @throws TSAServiceInvokerException If the input document doesn't match to the value calculated on the associated reference.
	 */
	private static void processTransformedDataXMLTimestamp(Element transformedData, Element reference) throws TSAServiceInvokerException {
		LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG050, new Object[ ] { IXMLConstants.ELEMENT_TRANSFORMED_DATA, IUtilsTimestamp.TIMESTAMP_TYPE_XML }));
		try {
			// Comprobamos que el InputDocument tiene definida al menos una
			// transformada
			if (transformedData.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_TRANSFORM).getLength() > 0) {
				// Accedemos al elemento dss:Base64Data
				NodeList base64DataNodeList = transformedData.getElementsByTagNameNS(IXMLConstants.DSS_NAMESPACE, IXMLConstants.ELEMENT_BASE64_DATA);
				if (base64DataNodeList.getLength() > 0) {
					// Obtenemos el valor del elemento dss:Base64Data
					byte[ ] base64DataContent = Base64.decode(base64DataNodeList.item(0).getTextContent());

					// Comprobamos si el resumen del contenido del elemento
					// dss:Base64Data coincide con el resumen calculado en la
					// referencia
					// asociada
					checkDigestFromReference(reference, base64DataContent, IXMLConstants.ELEMENT_TRANSFORMED_DATA, null);
				} else {
					throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TSU_LOG076));
				}
			} else {
				throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TSU_LOG075));
			}
		} finally {
			LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG055, new Object[ ] { IXMLConstants.ELEMENT_TRANSFORMED_DATA, IUtilsTimestamp.TIMESTAMP_TYPE_XML }));
		}
	}

	/**
	 * Method that checks if an input document of type DocumentHash matchs to the value calculated on the associated reference.
	 * @param documentHash Parameter that represents the <code>dss:DocumentHash</code> element.
	 * @param reference Parameter that represents the associated reference.
	 * @throws TSAServiceInvokerException If the input document doesn't match to the value calculated on the associated reference.
	 */
	private static void processDocumentHashXMLTimestamp(Element documentHash, Element reference) throws TSAServiceInvokerException {
		LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG050, new Object[ ] { IXMLConstants.ELEMENT_DOCUMENT_HASH, IUtilsTimestamp.TIMESTAMP_TYPE_XML }));
		// Obtenemos el identificador de la referencia
		String idReference = reference.getAttribute(IXMLConstants.ATTRIBUTE_ID);
		try {
			// Accedemos al elemento ds:DigestMethod de la referencia
			Element referenceDigestMethod = null;
			if (reference.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_METHOD).getLength() > 0) {
				referenceDigestMethod = (Element) reference.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_METHOD).item(0);
				// Obtenemos el valor del algoritmo de hash
				String uriHashAlgorithm = referenceDigestMethod.getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM);
				if (uriHashAlgorithm.isEmpty()) {
					throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG067, new Object[ ] { idReference }));
				}
				// Comprobamos que el algoritmo de hash definido en la
				// referencia está soportado
				String hashAlgorithm = CryptoUtilXML.translateXmlDigestAlgorithm(uriHashAlgorithm);
				if (hashAlgorithm == null) {
					throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG070, new Object[ ] { uriHashAlgorithm, idReference }));
				}
			} else {
				throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG068, new Object[ ] { idReference }));
			}

			// Accedemos al elemento ds:DigestMethod del InputDocument
			Element inputDocumentDigestMethod = null;
			if (documentHash.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_METHOD).getLength() > 0) {
				inputDocumentDigestMethod = (Element) documentHash.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_METHOD).item(0);
				// Obtenemos el valor del algoritmo de hash
				String uriHashAlgorithm = inputDocumentDigestMethod.getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM);
				if (uriHashAlgorithm.isEmpty()) {
					throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG051, new Object[ ] { IXMLConstants.ELEMENT_DOCUMENT_HASH }));
				}
				// Comprobamos que el algoritmo de hash definido en el
				// InputDocument está soportado
				String hashAlgorithm = CryptoUtilXML.translateXmlDigestAlgorithm(uriHashAlgorithm);
				if (hashAlgorithm == null) {
					throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG074, new Object[ ] { uriHashAlgorithm }));
				}
			} else {
				throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TSU_LOG064));
			}

			// Accedemos al elemento ds:DigestValue de la referencia
			Element referenceDigestValue = null;
			byte[ ] referenceDigest = null;
			if (reference.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_VALUE).getLength() > 0) {
				referenceDigestValue = (Element) reference.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_VALUE).item(0);
				// Obtenemos el valor del digest contenido en la referencia
				referenceDigest = Base64.decode(referenceDigestValue.getTextContent());
			} else {
				throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG069, new Object[ ] { idReference }));
			}

			// Accedemos al elemento ds:DigestValue del InputDocument
			Element inputDocumentDigestValue = null;
			byte[ ] inputDocumentDigest = null;
			if (documentHash.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_VALUE).getLength() > 0) {
				inputDocumentDigestValue = (Element) documentHash.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_VALUE).item(0);
				// Obtenemos el valor del digest contenido en el InputDocument
				inputDocumentDigest = Base64.decode(inputDocumentDigestValue.getTextContent());
			} else {
				throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TSU_LOG063));
			}

			// Comparamos el digest indicado en la referencia con el digest
			// calculado
			if (!Arrays.equals(referenceDigest, inputDocumentDigest)) {
				throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG071, new Object[ ] { IXMLConstants.ELEMENT_DOCUMENT_HASH, idReference }));
			}
		} finally {
			LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG055, new Object[ ] { IXMLConstants.ELEMENT_DOCUMENT_HASH, IUtilsTimestamp.TIMESTAMP_TYPE_XML }));
		}
	}

	/**
	 * Method that obtains the hash algorithm defined inside of a <code>ds:Reference</code> element.
	 * @param reference Parameter that represents the <code>ds:Reference</code> element.
	 * @param idReference Parameter that represents the value of the attribute <code>Id</code> of the reference.
	 * @return the hash algorithm.
	 * @throws TSAServiceInvokerException If the hash algorithm cannot be retrieved.
	 */
	private static String getHashAlgorithmFromReference(Element reference, String idReference) throws TSAServiceInvokerException {
		String hashAlgorithm = null;
		Element digestMethod = null;
		if (reference.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_METHOD).getLength() > 0) {
			digestMethod = (Element) reference.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_METHOD).item(0);
			// Obtenemos el valor del algoritmo de hash
			String uriHashAlgorithm = digestMethod.getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM);
			if (uriHashAlgorithm.isEmpty()) {
				throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG067, new Object[ ] { idReference }));
			}
			hashAlgorithm = CryptoUtilXML.translateXmlDigestAlgorithm(uriHashAlgorithm);
			if (hashAlgorithm == null) {
				throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG070, new Object[ ] { uriHashAlgorithm, idReference }));
			}
		} else {
			throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG068, new Object[ ] { idReference }));
		}
		return hashAlgorithm;
	}

	/**
	 * ethod that obtains the digest value of an input document defined inside of a <code>ds:Reference</code> element.
	 * @param reference Parameter that represents the <code>ds:Reference</code> element.
	 * @param idReference Parameter that represents the value of the attribute <code>Id</code> of the reference.
	 * @return the digest value.
	 * @throws TSAServiceInvokerException If the digest value cannot be retrieved.
	 */
	private static byte[ ] getDigestFromReference(Element reference, String idReference) throws TSAServiceInvokerException {
		byte[ ] digest = null;
		// Accedemos al elemento ds:DigestValue
		Element digestValue = null;
		if (reference.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_VALUE).getLength() > 0) {
			digestValue = (Element) reference.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_VALUE).item(0);
			// Obtenemos el valor del digest contenido en la referencia
			digest = Base64.decode(digestValue.getTextContent());
		} else {
			throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG069, new Object[ ] { idReference }));
		}
		return digest;
	}

	/**
	 * Method that calculates the digest of an input document.
	 * @param inputDocumentContent Parameter that represents the content of the input document.
	 * @param elementType Parameter that represents the type of the input document.
	 * @param inputDocument Parameter that represents the input document.
	 * @param listTransforms Parameter that represents the list of transforms defined on the reference.
	 * @param hashAlgorithm Parameter that represents the hash algorithm defined on the reference.
	 * @param idReference Parameter that represents the value of <code>Id</code> attribute of the reference.
	 * @return the calculated digest.
	 * @throws TSAServiceInvokerException If the method fails.
	 */
	private static byte[ ] calculateDigestOfInputDocument(byte[ ] inputDocumentContent, String elementType, Element inputDocument, List<String> listTransforms, String hashAlgorithm, String idReference) throws TSAServiceInvokerException {
		try {
			// Calculamos el digest del input document
			byte[ ] inputDocumentDigest = null;
			if (inputDocument != null) {
				if (listTransforms != null) {
					for (int i = 0; i < listTransforms.size(); i++) {
						inputDocumentDigest = Canonicalizer.getInstance(listTransforms.get(i)).canonicalizeSubtree(inputDocument);
					}
				}
			} else {
				inputDocumentDigest = inputDocumentContent;
				if (listTransforms != null) {
					for (int i = 0; i < listTransforms.size(); i++) {
						inputDocumentDigest = Canonicalizer.getInstance(listTransforms.get(i)).canonicalize(inputDocumentDigest);
					}
				}
			}
			MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
			md.update(inputDocumentDigest);
			return md.digest();
		} catch (Exception e) {
			throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG072, new Object[ ] { elementType, idReference }), e);
		}
	}

	/**
	 * Method that checks if the digest value defined inside of a <code>ds:Reference</code> element matchs to the digest of the associated input document.
	 * @param reference Parameter that represents the <code>ds:Reference</code> element.
	 * @param inputDocumentContent Parameter that represents the content of the input document.
	 * @param elementType Parameter that represents the type of the input document.
	 * @param inputDocument Parameter that represents the input document.
	 * @throws TSAServiceInvokerException If the method fails.
	 */
	private static void checkDigestFromReference(Element reference, byte[ ] inputDocumentContent, String elementType, Element inputDocument) throws TSAServiceInvokerException {
		// Obtenemos el identificador de la referencia
		String idReference = reference.getAttribute(IXMLConstants.ATTRIBUTE_ID);

		LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG065, new Object[ ] { idReference }));
		try {
			// Obtenemos la lista de transformadas, en caso de haber
			List<String> listTransforms = null;
			NodeList transformsNodeList = reference.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_TRANSFORM);
			if (transformsNodeList.getLength() > 0) {
				listTransforms = new ArrayList<String>();
				for (int i = 0; i < transformsNodeList.getLength(); i++) {
					Element transform = (Element) transformsNodeList.item(i);
					listTransforms.add(transform.getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM));
				}
			}
			// Obtenemos el algoritmo de hash accediendo al elemento
			// ds:DigestMethod
			String hashAlgorithm = getHashAlgorithmFromReference(reference, idReference);

			// Obtenemos el valor del digest accediendo al elemento
			// ds:DigestValue
			byte[ ] referenceDigest = getDigestFromReference(reference, idReference);

			// Calculamos el digest del input document
			byte[ ] calculatedDigest = calculateDigestOfInputDocument(inputDocumentContent, elementType, inputDocument, listTransforms, hashAlgorithm, idReference);

			// Comparamos el digest indicado en la referencia con el digest
			// calculado
			if (!Arrays.equals(referenceDigest, calculatedDigest)) {
				throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG071, new Object[ ] { elementType, idReference }));
			}

		} finally {
			LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG066, new Object[ ] { idReference }));
		}

	}

	/**
	 * Method that checks if an input document of type Base64XML matchs to the value calculated on the associated reference.
	 * @param base64XML Parameter that represents the <code>dss:Base64XML</code> element.
	 * @param reference Parameter that represents the associated reference.
	 * @throws TSAServiceInvokerException If the input document doesn't match to the value calculated on the associated reference.
	 */
	private static void processBase64XMLXMLTimeStamp(Element base64XML, Element reference) throws TSAServiceInvokerException {
		LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG050, new Object[ ] { IXMLConstants.ELEMENT_BASE64_XML, IUtilsTimestamp.TIMESTAMP_TYPE_XML }));

		try {
			// Obtenemos el valor del elemento dss:Base64XML
			byte[ ] base64XMLContent = Base64.decode(base64XML.getTextContent());

			// Comprobamos si el resumen del contenido del elemento
			// dss:Base64XML coincide con el resumen calculado en la referencia
			// asociada
			checkDigestFromReference(reference, base64XMLContent, IXMLConstants.ELEMENT_BASE64_XML, null);
		} finally {
			LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG055, new Object[ ] { IXMLConstants.ELEMENT_BASE64_XML, IUtilsTimestamp.TIMESTAMP_TYPE_XML }));
		}
	}

	/**
	 * Method that checks if an input document of type Base64Data matchs to the value calculated on the associated reference.
	 * @param base64Data Parameter that represents the <code>dss:Base64Data</code> element.
	 * @param reference Parameter that represents the associated reference.
	 * @throws TSAServiceInvokerException If the input document doesn't match to the value calculated on the associated reference.
	 */
	private static void processBase64DataXMLTimeStamp(Element base64Data, Element reference) throws TSAServiceInvokerException {
		LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG050, new Object[ ] { IXMLConstants.ELEMENT_BASE64_DATA, IUtilsTimestamp.TIMESTAMP_TYPE_XML }));

		try {
			// Obtenemos el valor del elemento dss:Base64Data
			byte[ ] base64DataContent = Base64.decode(base64Data.getTextContent());

			// Comprobamos si el resumen del contenido del elemento
			// dss:Base64Data coincide con el resumen calculado en la referencia
			// asociada
			checkDigestFromReference(reference, base64DataContent, IXMLConstants.ELEMENT_BASE64_DATA, null);
		} finally {
			LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG055, new Object[ ] { IXMLConstants.ELEMENT_BASE64_DATA, IUtilsTimestamp.TIMESTAMP_TYPE_XML }));
		}
	}

	/**
	 * Method that checks if an input document of type InlineXML matchs to the value calculated on the associated reference.
	 * @param inlineXML Parameter that represents the <code>dss:InlineXML</code> element.
	 * @param reference Parameter that represents the associated reference.
	 * @throws TSAServiceInvokerException If the input document doesn't match to the value calculated on the associated reference.
	 */
	private static void processInlineXMLXMLTimeStamp(Element inlineXML, Element reference) throws TSAServiceInvokerException {
		LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG050, new Object[ ] { IXMLConstants.ELEMENT_INLINE_XML, IUtilsTimestamp.TIMESTAMP_TYPE_XML }));
		try {
			// Comprobamos si el resumen del contenido del elemento
			// dss:InlineXML coincide con el resumen calculado en la referencia
			// asociada
			checkDigestFromReference(reference, null, IXMLConstants.ELEMENT_INLINE_XML, (Element) inlineXML.getFirstChild());
		} catch (TransformerFactoryConfigurationError e) {
			throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TSU_LOG078), e);
		} finally {
			LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG055, new Object[ ] { IXMLConstants.ELEMENT_INLINE_XML, IUtilsTimestamp.TIMESTAMP_TYPE_XML }));
		}
	}

	/**
	 * Method that checks if an input document of type EscapedXML matchs to the value calculated on the associated reference.
	 * @param escapedXML Parameter that represents the <code>dss:EscapedXML</code> element.
	 * @param reference Parameter that represents the associated reference.
	 * @throws TSAServiceInvokerException If the input document doesn't match to the value calculated on the associated reference.
	 */
	private static void processEscapedXMLXMLTimeStamp(Element escapedXML, Element reference) throws TSAServiceInvokerException {
		LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG050, new Object[ ] { IXMLConstants.ELEMENT_ESCAPED_XML, IUtilsTimestamp.TIMESTAMP_TYPE_XML }));

		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			dbf.setIgnoringElementContentWhitespace(true);
			dbf.setExpandEntityReferences(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
			InputSource is = new InputSource();

			// Dado que el contenido del elemento EscapedXML está escapado,
			// debemos "desescaparlo"
			String unEscapedXML = StringEscapeUtils.unescapeXml(escapedXML.getTextContent());
			is.setCharacterStream(new StringReader(unEscapedXML));
			Document unescapedXML = db.parse(is);

			// Comprobamos si el resumen del contenido del elemento
			// dss:EscapedXML coincide con el resumen calculado en la referencia
			// asociada
			checkDigestFromReference(reference, null, IXMLConstants.ELEMENT_ESCAPED_XML, (Element) unescapedXML.getFirstChild());
		} catch (ParserConfigurationException e) {
			throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TSU_LOG078), e);
		} catch (SAXException e) {
			throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TSU_LOG078), e);
		} catch (IOException e) {
			throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TSU_LOG078), e);
		} finally {
			LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG055, new Object[ ] { IXMLConstants.ELEMENT_ESCAPED_XML, IUtilsTimestamp.TIMESTAMP_TYPE_XML }));
		}
	}

	/**
	 * Method that checks if the input document associated to a renovation of a RFC 3161 time-stamp is structurally correct.
	 * @param inputDocuments Parameter that represents the <code>dss:InputDocuments</code> element of the time-stamp renovation request.
	 * @param tst Parameter that represents thr RFC 3161 time-stamp.
	 * @throws TSAServiceInvokerException If the input document isn't valid.
	 */
	public static void checkInputDocumentRFC3161TimeStamp(Element inputDocuments, TimeStampToken tst) throws TSAServiceInvokerException {
		LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG047));
		try {
			MessageImprint messageImprint = null;
			// Accedemos al elemento dss:InputDocument
			Element inputDocument = (Element) inputDocuments.getFirstChild();
			if (inputDocument == null) {
				throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TSU_LOG061));
			}
			LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG049, new Object[ ] { inputDocument.getLocalName() }));
			// Comprobamos de qué tipo es el elemento dss:InputDocument
			if (inputDocument.getLocalName().equals(IXMLConstants.ELEMENT_DOCUMENT)) {
				// Si el Input Document es de tipo Document, sólo se admite el
				// tipo Base64Data
				Element documentType = (Element) inputDocument.getFirstChild();
				if (documentType == null) {
					throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TSU_LOG062));
				}
				if (!documentType.getLocalName().equals(IXMLConstants.ELEMENT_BASE64_DATA)) {
					throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG056, new Object[ ] { documentType.getLocalName() }));
				}
				messageImprint = processBase64DataRFC3161TimeStamp(documentType, tst);
			} else if (inputDocument.getLocalName().equals(IXMLConstants.ELEMENT_DOCUMENT_HASH)) {
				// Si el InputDocument es de tipo DocumentHash
				messageImprint = processDocumentHashRFC3161TimeStamp(inputDocument, tst);
			} else if (inputDocument.getLocalName().equals(IXMLConstants.ELEMENT_TRANSFORMED_DATA)) {
				// El tipo TransformedData no está soportado
				throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG056, new Object[ ] { inputDocument.getLocalName() }));
			} else if (inputDocument.getLocalName().equals(IXMLConstants.ELEMENT_ANY_TYPE)) {
				// El tipo AnyType no está soportado
				throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG056, new Object[ ] { inputDocument.getLocalName() }));
			}
			// El tipo es desconocido
			else {
				throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG056, new Object[ ] { inputDocument.getLocalName() }));
			}
			// Comprobamos que los resúmenes coinciden
			if (!Arrays.equals(tst.getTimeStampInfo().getMessageImprintDigest(), messageImprint.getHashedMessage())) {
				throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TSU_LOG057));
			}
			LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TSU_LOG058));
		} finally {
			LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG048));
		}
	}

	/**
	 * Method that obtains the {@link MessageImprint} associated to a RFC 3161 time-stamp from the content of an InputDocument of type Base64Data.
	 * @param base64Data Parameter that represents the InputDocument.
	 * @param tst Parameter that represents thr RFC 3161 time-stamp.
	 * @return the associated {@link MessageImprint}.
	 * @throws TSAServiceInvokerException If the time-stamp uses an unsupported hash algorithm.
	 */
	private static MessageImprint processBase64DataRFC3161TimeStamp(Element base64Data, TimeStampToken tst) throws TSAServiceInvokerException {
		LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG050, new Object[ ] { IXMLConstants.ELEMENT_BASE64_DATA, IUtilsTimestamp.TIMESTAMP_TYPE_RFC_3161 }));
		String hashAlgorithm = CryptoUtilXML.translateAlgorithmIdentifier(tst.getTimeStampInfo().getHashAlgorithm());
		try {
			if (hashAlgorithm == null) {
				throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG051, new Object[ ] { IXMLConstants.ELEMENT_BASE64_DATA }));
			}
			// Para DSS los algoritmos SHA-512 y RIPEMD-160 no están soportados
			if (hashAlgorithm.equals(ICryptoUtil.HASH_ALGORITHM_SHA512) || hashAlgorithm.equals(ICryptoUtil.HASH_ALGORITHM_RIPEMD160)) {
				throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG052, new Object[ ] { IXMLConstants.ELEMENT_BASE64_DATA, hashAlgorithm }));
			}
			MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
			md.update(Base64.decode(base64Data.getTextContent()));
			LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG054));
			return new MessageImprint(tst.getTimeStampInfo().getHashAlgorithm(), md.digest());
		} catch (NoSuchAlgorithmException e) {
			throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG052, new Object[ ] { IXMLConstants.ELEMENT_BASE64_DATA, hashAlgorithm }), e);
		} finally {
			LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG055, new Object[ ] { IXMLConstants.ELEMENT_BASE64_DATA, IUtilsTimestamp.TIMESTAMP_TYPE_RFC_3161 }));
		}
	}

	/**
	 * Method that obtains the {@link MessageImprint} associated to a RFC 3161 time-stamp from the content of an InputDocument of type DocumentHash.
	 * @param documentHash Parameter that represents the InputDocument.
	 * @param tst Parameter that represents thr RFC 3161 time-stamp.
	 * @return the associated {@link MessageImprint}.
	 * @throws TSAServiceInvokerException If the method fails.
	 */
	private static MessageImprint processDocumentHashRFC3161TimeStamp(Element documentHash, TimeStampToken tst) throws TSAServiceInvokerException {
		LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG050, new Object[ ] { IXMLConstants.ELEMENT_DOCUMENT_HASH, IUtilsTimestamp.TIMESTAMP_TYPE_RFC_3161 }));
		try {
			// Accedemos al elemento ds:DigestMethod
			Element digestMethod = null;
			if (documentHash.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_METHOD).getLength() > 0) {
				digestMethod = (Element) documentHash.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_METHOD).item(0);
				// Obtenemos el valor del algoritmo de hash
				String hashAlgorithm = digestMethod.getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM);
				if (hashAlgorithm.isEmpty()) {
					throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG051, new Object[ ] { IXMLConstants.ELEMENT_DOCUMENT_HASH }));
				}
				// Accedemos al elemento ds:DigestValue
				Element digestValue = null;
				if (documentHash.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_VALUE).getLength() > 0) {
					digestValue = (Element) documentHash.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_VALUE).item(0);
					MessageImprint messageImprint = CryptoUtilXML.generateMessageImprintFromXMLAlgorithm(hashAlgorithm, Base64.decode(digestValue.getTextContent()));
					if (messageImprint == null) {
						throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG052, new Object[ ] { IXMLConstants.ELEMENT_DOCUMENT_HASH, hashAlgorithm }));
					}
					// Comprobamos la relación entre el InputDocument de tipo
					// DocumentHash y
					// el sello de tiempo
					if (!tst.getTimeStampInfo().getHashAlgorithm().getAlgorithm().equals(messageImprint.getHashAlgorithm().getAlgorithm())) {
						throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG053, new Object[ ] { IXMLConstants.ELEMENT_DOCUMENT_HASH }));
					}
					LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG054));
					return messageImprint;
				}
				throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TSU_LOG063));
			}
			throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TSU_LOG064));
		} finally {
			LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG055, new Object[ ] { IXMLConstants.ELEMENT_DOCUMENT_HASH, IUtilsTimestamp.TIMESTAMP_TYPE_RFC_3161 }));
		}
	}
}
