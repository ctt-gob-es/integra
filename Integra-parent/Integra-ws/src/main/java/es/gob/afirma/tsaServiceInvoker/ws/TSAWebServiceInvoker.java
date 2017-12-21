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
 * <b>File:</b><p>es.gob.afirma.tsaServiceInvoker.ws.TSAWebServiceInvoker.java.</p>
 * <b>Description:</b><p>Class that manages the invoke of TS@ web services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>13/01/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 13/01/2014.
 */
package es.gob.afirma.tsaServiceInvoker.ws;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.ws.Dispatch;
import javax.xml.ws.Service;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.DOMException;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.sun.xml.wss.ProcessingContext;
import com.sun.xml.wss.XWSSProcessor;
import com.sun.xml.wss.XWSSProcessorFactory;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.signature.xades.IXMLConstants;
import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.transformers.TransformersFacade;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerConstants;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerException;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerFacade;
import es.gob.afirma.utils.DSSConstants.DSSTagsRequest;
import es.gob.afirma.utils.DSSConstants.ResultProcessIds;
import es.gob.afirma.utils.GeneralConstants;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.utils.UtilsCertificateCommons;
import es.gob.afirma.utils.UtilsKeystoreCommons;
import es.gob.afirma.utils.UtilsResourcesCommons;
import es.gob.afirma.utils.UtilsTimestampWS;

/**
 * <p>Class that manages the invoke of TS@ web services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 13/01/2014.
 */
public class TSAWebServiceInvoker {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(TSAWebServiceInvoker.class);

    /**
     * Attribute that represents the properties defined on the configuration file.
     */
    private Properties properties;

    /**
     * Attribute that represents the properties defined on the general configuration file.
     */
    private Properties generalProperties;

    /**
     * Attribute that indicates if to use a symmetric key to encode the SOAP requests (true) or not (false).
     */
    private boolean useSymmetricKey = false;

    /**
     * Attribute that represents the alias of the symmetric key use to encode the SOAP requests.
     */
    private String symmetricKeyAlias;

    /**
     * Attribute that represents the alias of the symmetric key use to encode the SOAP requests.
     */
    private String symmetricKeyValue;

    /**
     * Constant attribute that identifies the validation mode <i>NONE</i> of the time-stamp to send to renew time-stamp service of the TS@. In this mode,
     * the previous time-stamp will not be validated before to call to the renew time-stamp service of the TS@.
     */
    public static final int VALIDATION_MODE_RENEW_TIMESTAMP_NONE = 0;

    /**
     * Constant attribute that identifies the validation mode <i>SIMPLE</i> of the time-stamp to send to renew time-stamp service of the TS@. In this mode,
     * the integrity of the previous time-stamp will be validated before to call to the renew time-stamp service of the TS@.
     */
    public static final int VALIDATION_MODE_RENEW_TIMESTAMP_SIMPLE = 1;

    /**
     * Constant attribute that identifies the validation mode <i>SIMPLE</i> of the time-stamp to send to renew time-stamp service of the TS@. In this mode,
     * the previous time-stamp will be validated by the validation time-stamp service of the TS@ before to call to the renew time-stamp service of the TS@.
     */
    public static final int VALIDATION_MODE_RENEW_TIMESTAMP_COMPLETE = 2;

    /**
     * Constructor method for the class TSAWebServiceInvoker.java.
     * @param propertiesParam Parameter that represents the properties defined on the configuration file.
     */
    public TSAWebServiceInvoker(Properties propertiesParam, Properties generalPropertiesParam) {
	properties = propertiesParam;
	generalProperties = generalPropertiesParam;
    }

    /**
     * Method that performs the invocation to a method form TS@ web services.
     * @param serviceName Parameter that represents the name of the service to invoke.
     * @param params List of parameters related to the method to invoke.
     * @param idClient client identifier of ws invocation.
     * @return the response of TS@.
     * @throws TSAServiceInvokerException If the method fails.
     */
    public final Object performCall(String serviceName, Object[ ] params, String idClient) throws TSAServiceInvokerException {

	// Rescatamos la ruta al fichero descriptor de los servicios web de TS@
	String wsdlPath = generalProperties.getProperty(TSAServiceInvokerConstants.WS_WSDL_PATH);
	checkSvcInvokerParams(TSAServiceInvokerConstants.WS_WSDL_PATH, wsdlPath);
	URL wsdlURL = null;
	try {
	    wsdlURL = new URL(TSAWebServiceInvoker.class.getResource("."), wsdlPath);
	} catch (MalformedURLException e) {
	    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG001, new Object[ ] { wsdlPath }), e);
	}
	LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG002, new Object[ ] { wsdlPath }));

	// Comprobamos si el servicio solicitado es el de renovación de sello de
	// tiempo, en cuyo caso, llevamos a cabo la validación del sello de
	// tiempo previo
	// en función del parámetro indicado en el archivo de propiedades
	int validationMode = processValidationRenewTimestampService(serviceName);

	// Instanciamos el servicio
	Service service = Service.create(wsdlURL, new QName("http://www.map.es/TSA/V1/TSA.wsdl", serviceName));

	// Obtenemos el nombre del puerto para el servicio instanciado
	QName portName = null;
	Iterator<QName> it = service.getPorts();
	while (it.hasNext()) {
	    portName = it.next();
	}

	// Establecemos los datos relativos al almacén de claves para conexiones
	// seguras
	configureSSLTrustStore();

	// Rescatamos el tiempo de vida de las peticiones y respuestas
	Integer timeOut = getServiceTimeOut();
	LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG004, new Object[ ] { timeOut }));

	TSACallBackHandler callBackHandler = new TSACallBackHandler();

	// Establecemos los valores relativos a usar cifrado, o no, con clave
	// simétrica
	configureSymmetricKeyAttributes(callBackHandler);

	// Establecemos los valores relativos al certificado usado para
	// securizar, con X509 Certificate Token, las respuestas SOAP desde la
	// plataforma TS@
	configureSOAPResponseCertificate(callBackHandler);

	// Establecemos los valores relativos al certificado usado para
	// securizar, con SAML Token, las respuestas SOAP desde la plataforma
	// TS@
	configureSOAPResponseSAMLCertificate(callBackHandler);

	// Establecemos el valor de la clave simétrica usada para encriptar las
	// respuestas SOAP desde la plataforma TS@
	configureSOAPResponseSymmetricKey(callBackHandler);

	// Rescatamos el tipo de securización para la petición SOAP
	String securityOption = properties.getProperty(TSAServiceInvokerConstants.WS_AUTHORIZATION_METHOD_PROPERTY);
	checkSvcInvokerParams(TSAServiceInvokerConstants.WS_AUTHORIZATION_METHOD_PROPERTY, securityOption);
	LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG005, new Object[ ] { securityOption }));

	// Configuramos la securización de la petición SOAP
	InputStream clientConfig = configureSecureSOAPRequest(securityOption, callBackHandler);

	// Obtenemos los parámetros obtenidos procesando la plantilla XML
	String templateXML = params[0].toString();
	// Eliminamos de la plantilla XML la cabecera XML
	templateXML = templateXML.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "");
	// Definimos el mensaje SOAP
	String msgString = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"><SOAP-ENV:Body>";
	msgString = msgString + templateXML;
	msgString = msgString + "</SOAP-ENV:Body></SOAP-ENV:Envelope>";
	// Eliminamos los saltos de línea, retornos de carro y sangrado
	msgString = msgString.replaceAll("[\n\r\t]", "");

	SOAPMessage message = null;
	Dispatch<SOAPMessage> smDispatch = null;
	ProcessingContext context = null;
	SOAPMessage response = null;
	XWSSProcessorFactory xwssProcessorFactory = null;

	try {
	    // Construímos el mensaje de petición
	    MessageFactory factory = MessageFactory.newInstance();
	    message = factory.createMessage();
	    message.getSOAPPart().setContent((Source) new StreamSource(new StringReader(msgString)));
	    message.saveChanges();

	    // En caso de que nos encontremos en una petición de renovación de
	    // sello de tiempo y se haya indicado que se debe llevar a cabo una
	    // validación
	    // integral del sello de tiempo, comprobamos si el InputDocument
	    // indicado coincide con el sello de tiempo indicado como previo.
	    if (validationMode == VALIDATION_MODE_RENEW_TIMESTAMP_SIMPLE) {
		validatePreviousTimestampStructurally(message);
	    }
	    // En caso de que nos encontremos en una petición de renovación de
	    // sello de tiempo y se haya indicado que se debe llevar a cabo una
	    // validación
	    // completa, se lanza una petición de validación de sello de tiempo
	    // previo, y posteriormente, se lleva a cabo la petición
	    // de renovación de sello de tiempo, en caso de que la respuesta
	    // haya sido correcta
	    else if (validationMode == VALIDATION_MODE_RENEW_TIMESTAMP_COMPLETE) {
		validatePreviousTimestampViaTSA(message, idClient);

	    }
	} catch (SOAPException e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG006), e);
	} catch (DOMException e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG006), e);
	}

	try {
	    // Procesamos el mensaje de petición
	    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	    dbf.setNamespaceAware(true);
	    xwssProcessorFactory = XWSSProcessorFactory.newInstance();
	    XWSSProcessor cprocessor = xwssProcessorFactory.createProcessorForSecurityConfiguration(clientConfig, callBackHandler);
	    context = new ProcessingContext();
	    context.setSOAPMessage(message);
	    SOAPMessage secureMsg = cprocessor.secureOutboundMessage(context);

	    smDispatch = service.createDispatch(portName, SOAPMessage.class, Service.Mode.MESSAGE);
	    smDispatch.getRequestContext().put("com.sun.xml.ws.connect.timeout", timeOut);
	    smDispatch.getRequestContext().put("com.sun.xml.ws.request.timeout", timeOut);

	    response = smDispatch.invoke(secureMsg);

	} catch (Exception e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG006), e);
	}

	// Configuramos la securización de la respuesta SOAP
	InputStream serverConfig = configureSecureSOAPResponse();
	try {

	    XWSSProcessor sprocessor = xwssProcessorFactory.createProcessorForSecurityConfiguration(serverConfig, callBackHandler);

	    context = new ProcessingContext();
	    context.setSOAPMessage(response);

	    SOAPMessage verifiedMsg = sprocessor.verifyInboundMessage(context);
	    return traduceResponse(verifiedMsg);
	} catch (Exception e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG007), e);
	}
    }

    /**
     * Method that obtains the connection and request timeout for the TS@ web services defined on the properties file where to configure
     * the invoke of TS@ web services .
     * @return the connection and request timeout for the TS@ web services, in milliseconds.
     * @throws TSAServiceInvokerException If the value cannot be retrieved.
     */
    private Integer getServiceTimeOut() throws TSAServiceInvokerException {
	String serviceTimeOut = properties.getProperty(TSAServiceInvokerConstants.WS_CALL_TIMEOUT_PROPERTY);
	checkSvcInvokerParams(TSAServiceInvokerConstants.WS_CALL_TIMEOUT_PROPERTY, serviceTimeOut);
	Integer timeOut = null;
	try {
	    timeOut = Integer.valueOf(serviceTimeOut);
	} catch (NumberFormatException e) {
	    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG003, new Object[ ] { serviceTimeOut }), e);
	}
	return timeOut;
    }

    /**
     * Method that obtains the identifier of the client application from a time-stamp renovation request.
     * @param soapBody Parameter thtat represents the body of the time-stamp renovation request.
     * @return the identifier of the client application.
     * @throws TSAServiceInvokerException If the time-stamp renovation request doesn't contain the identifier of the client application.
     */
    private String getIdApplicationFromRequest(SOAPBody soapBody) throws TSAServiceInvokerException {
	NodeList idAplicacionNodeList = soapBody.getElementsByTagNameNS(IXMLConstants.DSS_NAMESPACE, IXMLConstants.ELEMENT_ID_APLICACION);
	if (idAplicacionNodeList.getLength() > 0) {
	    Element idAplicacionElement = (Element) idAplicacionNodeList.item(0);
	    return idAplicacionElement.getTextContent();
	} else {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG062));
	}
    }

    /**
     * Method that obtains the previous time-stamp from a time-stamp renovation request.
     * @param inParams Map with the input parameters related to the XML request of the web service to update with the value of the previous time-stamp.
     * @param soapBody Parameter thtat represents the body of the time-stamp renovation request.
     * @throws TSAServiceInvokerException If the previous time-stamp cannot be retrieved.
     */
    private void setPreviousTimestampFromRequest(Map<String, Object> inParams, SOAPBody soapBody) throws TSAServiceInvokerException {
	NodeList previousTimestampNodeList = soapBody.getElementsByTagNameNS(IXMLConstants.TIMESTAMP_NAMESPACE, IXMLConstants.ELEMENT_PREVIOUS_TIMESTAMP);
	if (previousTimestampNodeList.getLength() > 0) {
	    Element previousTimestampElement = (Element) previousTimestampNodeList.item(0);
	    NodeList timestampNodeList = previousTimestampElement.getElementsByTagNameNS(IXMLConstants.DSS_NAMESPACE, IXMLConstants.ELEMENT_TIMESTAMP);
	    if (timestampNodeList.getLength() > 0) {
		Element timestampElement = (Element) timestampNodeList.item(0);
		Element childTimestampElement = (Element) timestampElement.getFirstChild();
		String timestampTypeKey = null;
		if (childTimestampElement.getLocalName().equals(IXMLConstants.ELEMENT_RFC3161_TIMESTAMPTOKEN)) {
		    // Sello de tiempo previo RFC 3161
		    timestampTypeKey = DSSTagsRequest.TIMESTAMP_RFC3161_TIMESTAMPTOKEN;
		    inParams.put(timestampTypeKey, childTimestampElement.getTextContent());
		} else if (childTimestampElement.getLocalName().equals(IXMLConstants.ELEMENT_SIGNATURE)) {
		    // Sello de tiempo previo XML
		    timestampTypeKey = DSSTagsRequest.TIMESTAMP_XML_TIMESTAMPTOKEN;
		    try {
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer transformer = tf.newTransformer();
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			StringWriter writer = new StringWriter();
			transformer.transform(new DOMSource(childTimestampElement), new StreamResult(writer));
			inParams.put(timestampTypeKey, writer.getBuffer().toString());
		    } catch (Exception e) {
			throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG061), e);
		    }
		} else {
		    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG063));
		}
	    } else {
		throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG063));
	    }
	} else {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG063));
	}
    }

    /**
     * Method that obtains the input document of type Document from a time-stamp renovation request.
     * @param inParams Map with the input parameters related to the XML request of the web service to update with the value of the input document.
     * @param document Parameter that represents the input document of type Document.
     * @throws TSAServiceInvokerException If the input document cannot be retrieved.
     */
    private void setDocumentFromRequest(Map<String, Object> inParams, Element document) throws TSAServiceInvokerException {
	// Document de tipo Base64XML
	if (document.getLocalName().equals(IXMLConstants.ELEMENT_BASE64_XML)) {
	    inParams.put(DSSTagsRequest.BASE64XML, document.getTextContent());
	}
	// Document de tipo InlineXML
	else if (document.getLocalName().equals(IXMLConstants.ELEMENT_INLINE_XML)) {
	    try {
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		StringWriter writer = new StringWriter();
		transformer.transform(new DOMSource(document.getFirstChild()), new StreamResult(writer));
		inParams.put(DSSTagsRequest.INLINEXML, writer.getBuffer().toString());
	    } catch (Exception e) {
		throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG064), e);
	    }
	}
	// Document de tipo EscapedXML
	else if (document.getLocalName().equals(IXMLConstants.ELEMENT_ESCAPED_XML)) {
	    inParams.put(DSSTagsRequest.ESCAPEDXML, document.getTextContent());
	}
	// Document de tipo Base64Data
	else if (document.getLocalName().equals(IXMLConstants.ELEMENT_BASE64_DATA)) {
	    // Obtenemos el valor del elemento
	    inParams.put(DSSTagsRequest.BASE64DATA, document.getTextContent());
	} else {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG064));
	}
    }

    /**
     * Method that obtains the input document of type DocumentHash from a time-stamp renovation request.
     * @param inParams Map with the input parameters related to the XML request of the web service to update with the value of the input document.
     * @param inputDocument Parameter that represents the input document of type DocumentHash.
     * @throws TSAServiceInvokerException If the input document cannot be retrieved.
     */
    private void setDocumentHashFromRequest(Map<String, Object> inParams, Element inputDocument) throws TSAServiceInvokerException {
	// Obtenemos el algoritmo de hash
	NodeList digestMethodNodeList = inputDocument.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_METHOD);
	if (digestMethodNodeList.getLength() > 0) {
	    Element digestMethodElement = (Element) digestMethodNodeList.item(0);
	    inParams.put(DSSTagsRequest.DIGEST_METHOD_ATR_ALGORITHM, digestMethodElement.getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM));
	} else {
	    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG065, new Object[ ] { IXMLConstants.ELEMENT_DIGEST_METHOD }));
	}
	// Obtenemos el valor del digest
	NodeList digestValueNodeList = inputDocument.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_VALUE);
	if (digestValueNodeList.getLength() > 0) {
	    Element digestValueElement = (Element) digestValueNodeList.item(0);
	    inParams.put(DSSTagsRequest.DIGEST_VALUE, digestValueElement.getTextContent());
	} else {
	    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG065, new Object[ ] { IXMLConstants.ELEMENT_DIGEST_VALUE }));
	}
	// Obtenemos el valor de la transformada, en caso de existir
	NodeList transformsNodeList = inputDocument.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_TRANSFORMS);
	if (transformsNodeList.getLength() > 0) {
	    Element transformsElement = (Element) transformsNodeList.item(0);
	    NodeList transformNodeList = transformsElement.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_TRANSFORM);
	    if (transformNodeList.getLength() > 0) {
		Element transformElement = (Element) transformNodeList.item(0);
		inParams.put(DSSTagsRequest.DOCUMENT_HASH_TRANSFORM_ATR_ALGORITHM, transformElement.getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM));
	    }
	}
    }

    /**
     * Method that obtains the input document of type TransformedData from a time-stamp renovation request.
     * @param inParams Map with the input parameters related to the XML request of the web service to update with the value of the input document.
     * @param inputDocument Parameter that represents the input document of type TransformedData.
     * @throws TSAServiceInvokerException If the input document cannot be retrieved.
     */
    private void setTransformedDataFromRequest(Map<String, Object> inParams, Element inputDocument) throws TSAServiceInvokerException {
	// Obtenemos el valor de la transformada
	NodeList transformsNodeList = inputDocument.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_TRANSFORMS);
	if (transformsNodeList.getLength() > 0) {
	    Element transformsElement = (Element) transformsNodeList.item(0);
	    NodeList transformNodeList = transformsElement.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_TRANSFORM);
	    if (transformNodeList.getLength() > 0) {
		Element transformElement = (Element) transformNodeList.item(0);
		inParams.put(DSSTagsRequest.TRANSFORMED_DATA_TRANSFORM_ATR_ALGORITHM, transformElement.getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM));
	    } else {
		throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG065, new Object[ ] { IXMLConstants.ELEMENT_TRANSFORM }));
	    }
	} else {
	    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG065, new Object[ ] { IXMLConstants.ELEMENT_TRANSFORMS }));
	}
	// Obtenemos el valor codificado en Base64
	NodeList base64DataNodeList = inputDocument.getElementsByTagNameNS(IXMLConstants.DSS_NAMESPACE, IXMLConstants.ELEMENT_BASE64_DATA);
	if (base64DataNodeList.getLength() > 0) {
	    Element base64DataElement = (Element) base64DataNodeList.item(0);
	    inParams.put(DSSTagsRequest.TRANSFORMED_DATA_BASE64DATA, base64DataElement.getTextContent());
	} else {
	    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG065, new Object[ ] { IXMLConstants.ELEMENT_BASE64_DATA }));
	}
    }

    /**
     * ethod that obtains the input document from a time-stamp renovation request.
     * @param inParams Map with the input parameters related to the XML request of the web service to update with the value of the input document.
     * @param soapBody Parameter thtat represents the body of the time-stamp renovation request.
     * @throws TSAServiceInvokerException If the input document cannot be retrieved.
     */
    private void setInputDocumentFromRequest(Map<String, Object> inParams, SOAPBody soapBody) throws TSAServiceInvokerException {
	NodeList inputDocumentsNodeList = soapBody.getElementsByTagNameNS(IXMLConstants.DSS_NAMESPACE, IXMLConstants.ELEMENT_INPUT_DOCUMENTS);
	if (inputDocumentsNodeList.getLength() > 0) {
	    Element inputDocumentsElement = (Element) inputDocumentsNodeList.item(0);
	    Element inputDocument = (Element) inputDocumentsElement.getFirstChild();
	    // InputDocument de tipo Document
	    if (inputDocument.getLocalName().equals(IXMLConstants.ELEMENT_DOCUMENT)) {
		Element documentType = (Element) inputDocument.getFirstChild();
		setDocumentFromRequest(inParams, documentType);
	    }
	    // InputDocument de tipo DocumentHash
	    else if (inputDocument.getLocalName().equals(IXMLConstants.ELEMENT_DOCUMENT_HASH)) {
		setDocumentHashFromRequest(inParams, inputDocument);
	    }
	    // InputDocument de tipo TransformedData
	    else if (inputDocument.getLocalName().equals(IXMLConstants.ELEMENT_TRANSFORMED_DATA)) {
		setTransformedDataFromRequest(inParams, inputDocument);
	    } else {
		throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG064));
	    }
	} else {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG064));
	}
    }

    /**
     * Method that validates the previous time-stamp via TS@ DSS web service.
     * @param message Parameter that represents the time-stamp renovation request.
     * @param idClient client identifier of ws invocation.
     * @throws TSAServiceInvokerException If the validation fails.
     */
    private void validatePreviousTimestampViaTSA(SOAPMessage message, String idClient) throws TSAServiceInvokerException {
	try {
	    org.apache.xml.security.Init.init();
	    SOAPBody soapBody = message.getSOAPBody();
	    soapBody.addNamespaceDeclaration(IXMLConstants.DSS_PREFIX, IXMLConstants.DSS_NAMESPACE);
	    soapBody.addNamespaceDeclaration(IXMLConstants.DST_PREFIX, IXMLConstants.TIMESTAMP_NAMESPACE);

	    // Definimos el mapa con los parámetros de entrada para la petición
	    // de validación del sello de tiempo
	    Map<String, Object> inParams = new HashMap<String, Object>();

	    // Obtenemos el identificador de aplicación
	    String idApplication = getIdApplicationFromRequest(soapBody);
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, idApplication);

	    // Obtenemos el sello de tiempo previo
	    setPreviousTimestampFromRequest(inParams, soapBody);

	    // Obtenemos el InputDocument
	    setInputDocumentFromRequest(inParams, soapBody);

	    // Construímos el XML de petición para validar el sello de tiempo
	    String xmlInput = null;
	    try {
		xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    } catch (TransformersException e) {
		throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG066), e);
	    }

	    // Invocamos al servicio de validación de sello de tiempo de TS@
	    String xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, idApplication, idClient);

	    try {
		// Obtenemos el resultado de la inovación al servicio
		Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);

		// Si el resultado obtenido no es correcto, lanzamos una
		// excepción
		String resultMayor = (String) propertiesResult.get("dss:Result/dss:ResultMajor");
		if (!resultMayor.equals(ResultProcessIds.SUCESS)) {
		    // Accedemos al mensaje de error
		    String resultMessage = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMessage"));
		    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG068, new Object[ ] { resultMessage }));
		}
	    } catch (TransformersException e) {
		throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG067), e);
	    }

	} catch (SOAPException e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG060), e);
	}
    }

    /**
     * Method that checks if the input document indicated on the time-stamp renovation request is valid or not.
     * @param message Parameter that represents the time-stamp renovation request.
     * @throws TSAServiceInvokerException If the validation fails.
     */
    private void validatePreviousTimestampStructurally(SOAPMessage message) throws TSAServiceInvokerException {
	try {
	    org.apache.xml.security.Init.init();
	    SOAPBody soapBody = message.getSOAPBody();
	    soapBody.addNamespaceDeclaration(IXMLConstants.DSS_PREFIX, IXMLConstants.DSS_NAMESPACE);
	    soapBody.addNamespaceDeclaration(IXMLConstants.DST_PREFIX, IXMLConstants.TIMESTAMP_NAMESPACE);

	    // Accedemos al elemento dss:InputDocuments
	    Element inputDocuments = getInputDocumentsElement(soapBody);

	    // Accedemos al sello de tiempo previo
	    Element previousTimestamp = getPreviousTimestamp(soapBody);

	    // Si el sello de tiempo previo es de tipo RFC3161TimeStampToken
	    if (previousTimestamp.getLocalName().equals(IXMLConstants.ELEMENT_RFC3161_TIMESTAMPTOKEN)) {
		// Obtenemos el objeto java que representa el sello de
		// tiempo
		TimeStampToken tst = new TimeStampToken(new CMSSignedData(Base64.decode(previousTimestamp.getTextContent())));
		// Validamos la integridad del sello de tiempo
		UtilsTimestampWS.checkInputDocumentRFC3161TimeStamp(inputDocuments, tst);
	    }
	    // Si el sello de tiempo previo es de tipo XMLTimeStampToken
	    else if (previousTimestamp.getLocalName().equals(IXMLConstants.ELEMENT_SIGNATURE)) {
		// Validamos la integridad del sello de tiempo
		UtilsTimestampWS.checkInputDocumentXMLTimeStamp(inputDocuments, previousTimestamp);
	    }
	} catch (SOAPException e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG060), e);
	} catch (DOMException e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG061), e);
	} catch (TSPException e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG061), e);
	} catch (IOException e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG061), e);
	} catch (CMSException e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG061), e);
	}
    }

    /**
     * Method that obtains a XML element as the previous time-stamp from a time-stamp renovation request.
     * @param soapBody Parameter that represents the body of the time-stamp renovation request.
     * @return an object that represents the <code>dst:PreviousTimestamp</code> element.
     * @throws TSAServiceInvokerException If the method fails.
     */
    private Element getPreviousTimestamp(SOAPBody soapBody) throws TSAServiceInvokerException {
	Element previousTimestampElement = null;
	Element renewTimestampElement = null;
	if (soapBody.getElementsByTagNameNS(IXMLConstants.TIMESTAMP_NAMESPACE, IXMLConstants.ELEMENT_RENEW_TIMESTAMP).getLength() > 0) {
	    renewTimestampElement = (Element) soapBody.getElementsByTagNameNS(IXMLConstants.TIMESTAMP_NAMESPACE, IXMLConstants.ELEMENT_RENEW_TIMESTAMP).item(0);
	    previousTimestampElement = (Element) renewTimestampElement.getFirstChild();
	    if (previousTimestampElement == null) {
		throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG058));
	    }
	    Element timestampElement = (Element) previousTimestampElement.getFirstChild();
	    if (timestampElement == null) {
		throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG058));
	    }
	    Element timestamp = (Element) timestampElement.getFirstChild();
	    if (timestamp == null) {
		throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG058));
	    }
	    return timestamp;
	}
	throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG058));
    }

    /**
     * Method that obtains a XML element as the input document from a time-stamp renovation request.
     * @param soapBody Parameter that represents the body of the time-stamp renovation request.
     * @return an object that represents the <code>dss:InputDocuments</code> element.
     * @throws TSAServiceInvokerException If the method fails.
     */
    private Element getInputDocumentsElement(SOAPBody soapBody) throws TSAServiceInvokerException {
	Element inputDocumentsElement = null;
	if (soapBody.getElementsByTagNameNS(IXMLConstants.DSS_NAMESPACE, IXMLConstants.ELEMENT_INPUT_DOCUMENTS).getLength() > 0) {
	    inputDocumentsElement = (Element) soapBody.getElementsByTagNameNS(IXMLConstants.DSS_NAMESPACE, IXMLConstants.ELEMENT_INPUT_DOCUMENTS).item(0);
	}

	// Si la petición carece del elemento dss:InputDocument, error
	if (inputDocumentsElement == null) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG059));
	}
	return inputDocumentsElement;
    }

    /**
     * Method that obtains the validation mode of the time-stamp to send to renew time-stamp service of the TS@.
     * @param serviceName Parameter that represents the name of the TS@ called service.
     * @return the validation mode of the time-stamp to send to renew time-stamp service of the TS@.
     * @throws TSAServiceInvokerException If the method fails.
     */
    private int processValidationRenewTimestampService(String serviceName) throws TSAServiceInvokerException {
	int result = 0;
	// Comprobamos si el servicio solicitado es el de renovación de sello de
	// tiempo
	if (serviceName.equals(GeneralConstants.TSA_RETIMESTAMP_SERVICE)) {
	    // Rescatamos del archivo de propiedades la propiedad que indica el
	    // modo de validación que aplicar sobre el sello de tiempo previo a
	    // ser renovado
	    String renewTimestampValidationModeStr = properties.getProperty(TSAServiceInvokerConstants.WS_RENEW_TIMESTAMP_WS_VALIDATION_LEVEL_PROPERTY);
	    checkSvcInvokerParams(TSAServiceInvokerConstants.WS_RENEW_TIMESTAMP_WS_VALIDATION_LEVEL_PROPERTY, renewTimestampValidationModeStr);
	    // Comprobamos que dicha propiedad tiene un valor válido
	    Integer renewTimestampValidationMode = null;
	    try {
		renewTimestampValidationMode = Integer.valueOf(renewTimestampValidationModeStr);
	    } catch (NumberFormatException e) {
		throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG054, new Object[ ] { renewTimestampValidationModeStr }), e);
	    }
	    if (renewTimestampValidationMode == VALIDATION_MODE_RENEW_TIMESTAMP_NONE) {
		LOGGER.info(Language.getResIntegra(ILogConstantKeys.TWSI_LOG055));
		result = 0;
	    } else if (renewTimestampValidationMode == VALIDATION_MODE_RENEW_TIMESTAMP_SIMPLE) {
		LOGGER.info(Language.getResIntegra(ILogConstantKeys.TWSI_LOG056));
		result = 1;
	    } else if (renewTimestampValidationMode == VALIDATION_MODE_RENEW_TIMESTAMP_COMPLETE) {
		LOGGER.info(Language.getResIntegra(ILogConstantKeys.TWSI_LOG057));
		result = 2;
	    } else {
		throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG054, new Object[ ] { renewTimestampValidationModeStr }));
	    }
	}
	return result;
    }

    /**
     * Method that obtains the SOAP body from the SOAP response.
     * @param message Parameter that represents the SOAP response from TS@.
     * @return the SOAP body from the SOAP response.
     * @throws TransformerException If an unrecoverable error occurs during the course of the transformation.
     * @throws SOAPException If the SOAP body does not exist or cannot be retrieved.
     */
    private String traduceResponse(SOAPMessage message) throws TransformerException, SOAPException {
	TransformerFactory tf = TransformerFactory.newInstance();
	Transformer transformer = tf.newTransformer();
	transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
	StringWriter writer = new StringWriter();
	transformer.transform(new DOMSource(message.getSOAPBody().getFirstChild()), new StreamResult(writer));
	return writer.getBuffer().toString();
    }

    /**
     * Method that verifies if a value is not empty and not null.
     * @param parameterName Parameter that represents the name of the element to check.
     * @param parameterValue Parameter that represents the value to check.
     * @throws TSAServiceInvokerException If the value is empty or null.
     */
    private void checkSvcInvokerParams(String parameterName, String parameterValue) throws TSAServiceInvokerException {
	if (!GenericUtilsCommons.assertStringValue(parameterValue)) {
	    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG008, new Object[ ] { parameterName, properties.getProperty(TSAServiceInvokerConstants.APPLICATION_NAME) }));
	}
    }

    /**
     * Method that obtains the properties related to the trusted keystore from {@link #properties} and configure it.
     */
    private void configureSSLTrustStore() {
	// Rescatamos la ruta al almacén de confianza
	String trustsorePath = generalProperties.getProperty(TSAServiceInvokerConstants.TRUSTEDSTORE_PATH);
	if (trustsorePath == null && System.getProperty("javax.net.ssl.trustStore") == null) {
	    LOGGER.warn(Language.getResIntegra(ILogConstantKeys.TWSI_LOG009));
	} else if (trustsorePath != null) {
	    // Actualizamos la ruta al almacén de confianza
	    System.setProperty("javax.net.ssl.trustStore", trustsorePath);
	}
	LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG010, new Object[ ] { trustsorePath }));

	// Rescatamos la clave del almacén de confianza
	String truststorePassword = generalProperties.getProperty(TSAServiceInvokerConstants.TRUSTEDSTORE_PASSWORD);
	if (truststorePassword == null && System.getProperty("javax.net.ssl.trustStorePassword") == null) {
	    LOGGER.warn(Language.getResIntegra(ILogConstantKeys.TWSI_LOG011));
	} else if (truststorePassword != null) {
	    System.setProperty("javax.net.ssl.trustStorePassword", truststorePassword);
	}
    }

    /**
     * Method that obtains the properties related to the encryption of SOAP requests from {@link #properties}.
     * @param callBackHandler Parameter that represents the class used to proccess the SOAP messages.
     */
    private void configureSymmetricKeyAttributes(TSACallBackHandler callBackHandler) {
	// Rescatamos el indicador para cifrar, o no, la petición SOAP con clave
	// simétrica
	String encryptRequest = properties.getProperty(TSAServiceInvokerConstants.WS_REQUEST_SYMMETRICKEY_USE);

	if (encryptRequest != null) {
	    if (encryptRequest.equals(Boolean.toString(true))) {
		LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TWSI_LOG012));
		// Rescatamos el alias de la clave simétrica
		symmetricKeyAlias = properties.getProperty(TSAServiceInvokerConstants.WS_REQUEST_SYMMETRICKEY_ALIAS);
		if (symmetricKeyAlias == null) {
		    LOGGER.warn(Language.getResIntegra(ILogConstantKeys.TWSI_LOG013));
		} else {
		    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG014, new Object[ ] { symmetricKeyAlias }));
		    // Rescatamos el valor de la clave simétrica
		    symmetricKeyValue = properties.getProperty(TSAServiceInvokerConstants.WS_REQUEST_SYMMETRICKEY_VALUE);
		    if (symmetricKeyValue == null) {
			LOGGER.warn(Language.getResIntegra(ILogConstantKeys.TWSI_LOG015));
		    } else {
			useSymmetricKey = true;
			// Establecemos en el callbackhandler el valor de la
			// clave simétrica
			callBackHandler.setSymmetricKeyRequest(symmetricKeyValue);
		    }
		}
	    } else if (encryptRequest.equals(Boolean.toString(false))) {
		LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TWSI_LOG016));
	    } else {
		LOGGER.warn(Language.getResIntegra(ILogConstantKeys.TWSI_LOG017));
	    }
	} else {
	    LOGGER.warn(Language.getResIntegra(ILogConstantKeys.TWSI_LOG018));
	}
    }

    /**
     * Method tha obtains the InputStream as the representation of the SOAP header used to validate the SOAP responses.
     * @return the InputStream as the representation of the SOAP header used to validate the SOAP responses.
     */
    private InputStream configureSecureSOAPResponse() {
	return SOAPMessageSecurityProvider.generateInputStream(SOAPMessageSecurityProvider.XML_XWSS);
    }

    /**
     * Method that obtains the InputStream as the representation for the SOAP header used to generate the SOAP requests.
     * @param securityOption Parameter that represents the method used to secure the SOAP requests.
     * @param callBackHandler Parameter that represents the class used to proccess the SOAP messages.
     * @return the InputStream as the representation for the SOAP header used to generate the SOAP requests.
     * @throws TSAServiceInvokerException If the method fails.
     */
    private InputStream configureSecureSOAPRequest(String securityOption, TSACallBackHandler callBackHandler) throws TSAServiceInvokerException {
	InputStream is = null;
	// Autenticación por usuario y contraseña
	if (securityOption.equals(SOAPMessageSecurityProvider.AUTHENTICATION_USER_PASSWORD)) {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TWSI_LOG019));
	    // Rescatamos el nombre de usuario
	    String userName = properties.getProperty(TSAServiceInvokerConstants.WS_USERNAMETOKEN_USER_NAME_PROPERTY);
	    checkSvcInvokerParams(TSAServiceInvokerConstants.WS_USERNAMETOKEN_USER_NAME_PROPERTY, userName);
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG020, new Object[ ] { userName }));

	    // Rescatamos la contraseña del usuario
	    String userPassword = properties.getProperty(TSAServiceInvokerConstants.WS_USERNAMETOKEN_USER_PASSWORD_PROPERTY);
	    checkSvcInvokerParams(TSAServiceInvokerConstants.WS_USERNAMETOKEN_USER_PASSWORD_PROPERTY, userPassword);

	    // Obtenemos el InputStream que se refiere a la securización
	    // seleccionada
	    is = SOAPMessageSecurityProvider.generateXMLUserNameToken(userName, userPassword, useSymmetricKey, symmetricKeyAlias);

	}
	// Autenticación por certificado
	else if (securityOption.equals(SOAPMessageSecurityProvider.AUTHENTICATION_CERTIFICATE)) {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TWSI_LOG021));
	    // Rescatamos el método de inclusión del certificado en la petición
	    // SOAP
	    String certificateInclussionMethod = properties.getProperty(TSAServiceInvokerConstants.WS_X509CERTIFICATETOKEN_INCLUSION_METHOD);
	    checkSvcInvokerParams(TSAServiceInvokerConstants.WS_X509CERTIFICATETOKEN_INCLUSION_METHOD, certificateInclussionMethod);
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG022, new Object[ ] { certificateInclussionMethod }));

	    // Comprobamos que el tipo de método de inclusión es reconocido
	    checkCertificateInclussionMethod(certificateInclussionMethod);

	    // Rescatamos la ruta al almacén de claves donde se encuentra
	    // almacenada la clave privada a usar para firmar
	    // la petición SOAP
	    String keystorePath = properties.getProperty(TSAServiceInvokerConstants.WS_X509CERTIFICATETOKEN_KEYSTORE_PATH);
	    checkSvcInvokerParams(TSAServiceInvokerConstants.WS_X509CERTIFICATETOKEN_KEYSTORE_PATH, keystorePath);
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG023, new Object[ ] { keystorePath }));

	    // Rescatamos el tipo de almacén de claves donde se encuentra
	    // almacenada la clave privada a usar para firmar la petición SOAP
	    String keystoreType = properties.getProperty(TSAServiceInvokerConstants.WS_X509CERTIFICATETOKEN_KEYSTORE_TYPE);
	    checkSvcInvokerParams(TSAServiceInvokerConstants.WS_X509CERTIFICATETOKEN_KEYSTORE_TYPE, keystoreType);
	    // Comprobamos que el tipo de almacén de claves está soportado
	    checkKeystoreType(keystoreType, Language.getResIntegra(ILogConstantKeys.TWSI_LOG026));
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG024, new Object[ ] { keystoreType }));

	    // Rescatamos la contraseña del almacén de claves donde se encuentra
	    // almacenada la clave privada a usar para firmar la petición SOAP
	    String keystorePassword = properties.getProperty(TSAServiceInvokerConstants.WS_X509CERTIFICATETOKEN_KEYSTORE_PASSWORD);
	    checkSvcInvokerParams(TSAServiceInvokerConstants.WS_X509CERTIFICATETOKEN_KEYSTORE_PASSWORD, keystorePassword);

	    // Rescatamos el alias de la clave privada a usar para firmar la
	    // petición SOAP
	    String privateKeyAlias = properties.getProperty(TSAServiceInvokerConstants.WS_X509CERTIFICATETOKEN_PRIVATE_KEY_ALIAS);
	    checkSvcInvokerParams(TSAServiceInvokerConstants.WS_X509CERTIFICATETOKEN_PRIVATE_KEY_ALIAS, privateKeyAlias);
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG025, new Object[ ] { privateKeyAlias }));

	    // Rescatamos la contraseña de la clave privada a usar para firmar
	    // la petición SOAP
	    String privateKeyPassword = properties.getProperty(TSAServiceInvokerConstants.WS_X509CERTIFICATETOKEN_PRIVATE_KEY_PASSWORD);
	    checkSvcInvokerParams(TSAServiceInvokerConstants.WS_X509CERTIFICATETOKEN_PRIVATE_KEY_PASSWORD, privateKeyPassword);

	    // Accedemos al almacén de claves para rescatar la clave privada y
	    // el certificado usados para firmar la petición SOAP
	    byte[ ] keystoreBytes = getBytesFromFile(keystorePath);
	    try {
		PrivateKey privateKeySOAP = UtilsKeystoreCommons.getPrivateKeyEntry(keystoreBytes, keystorePassword, privateKeyAlias, keystoreType, privateKeyPassword);
		X509Certificate certificateSOAP = UtilsCertificateCommons.generateCertificate(UtilsKeystoreCommons.getCertificateEntry(keystoreBytes, keystorePassword, privateKeyAlias, keystoreType));
		// Asociamos los valores al CallBackHanlder
		callBackHandler.setPrivateKeySOAPRequest(privateKeySOAP);
		callBackHandler.setCertificateSOAPRequest(certificateSOAP);
	    } catch (Exception e) {
		throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG027, new Object[ ] { privateKeyAlias, keystorePath }), e);
	    }

	    // Obtenemos el InputStream que se refiere a la securización
	    // seleccionada
	    is = SOAPMessageSecurityProvider.generateXMLX509CertificateToken(certificateInclussionMethod, useSymmetricKey, symmetricKeyAlias);
	}
	// Autenticación por SAML
	else if (securityOption.equals(SOAPMessageSecurityProvider.AUTHENTICATION_SAML)) {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TWSI_LOG028));
	    // Rescatamos el método de confirmación del sujeto
	    String mandatorySubjectConfirmationMethod = properties.getProperty(TSAServiceInvokerConstants.WS_SAMLTOKEN_METHOD);
	    checkSvcInvokerParams(TSAServiceInvokerConstants.WS_SAMLTOKEN_METHOD, mandatorySubjectConfirmationMethod);
	    // Comprobamos que el método de confirmación del sujeto es
	    // reconocido
	    checkMandatorySubjectConfirmationMethod(mandatorySubjectConfirmationMethod);
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG029, new Object[ ] { mandatorySubjectConfirmationMethod }));

	    // Rescatamos la ruta al almacén de claves donde se encuentra
	    // almacenada la clave privada a usar para firmar
	    // la petición SOAP
	    String keystorePath = properties.getProperty(TSAServiceInvokerConstants.WS_SAMLTOKEN_KEYSTORE_PATH);
	    checkSvcInvokerParams(TSAServiceInvokerConstants.WS_SAMLTOKEN_KEYSTORE_PATH, keystorePath);
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG023, new Object[ ] { keystorePath }));

	    // Rescatamos el tipo de almacén de claves donde se encuentra
	    // almacenada la clave privada a usar para firmar la petición SOAP
	    String keystoreType = properties.getProperty(TSAServiceInvokerConstants.WS_SAMLTOKEN_KEYSTORE_TYPE);
	    checkSvcInvokerParams(TSAServiceInvokerConstants.WS_SAMLTOKEN_KEYSTORE_TYPE, keystoreType);
	    // Comprobamos que el tipo de almacén de claves está soportado
	    checkKeystoreType(keystoreType, Language.getResIntegra(ILogConstantKeys.TWSI_LOG026));
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG024, new Object[ ] { keystoreType }));

	    // Rescatamos la contraseña del almacén de claves donde se encuentra
	    // almacenada la clave privada a usar para firmar la petición SOAP
	    String keystorePassword = properties.getProperty(TSAServiceInvokerConstants.WS_SAMLTOKEN_KEYSTORE_PASSWORD);
	    checkSvcInvokerParams(TSAServiceInvokerConstants.WS_SAMLTOKEN_KEYSTORE_PASSWORD, keystorePassword);

	    // Rescatamos el alias de la clave privada a usar para firmar la
	    // petición SOAP
	    String privateKeyAlias = properties.getProperty(TSAServiceInvokerConstants.WS_SAMLTOKEN_PRIVATE_KEY_ALIAS);
	    checkSvcInvokerParams(TSAServiceInvokerConstants.WS_SAMLTOKEN_PRIVATE_KEY_ALIAS, privateKeyAlias);
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG025, new Object[ ] { privateKeyAlias }));

	    // Rescatamos la contraseña de la clave privada a usar para firmar
	    // la petición SOAP
	    String privateKeyPassword = properties.getProperty(TSAServiceInvokerConstants.WS_SAMLTOKEN_PRIVATE_KEY_PASSWORD);
	    checkSvcInvokerParams(TSAServiceInvokerConstants.WS_SAMLTOKEN_PRIVATE_KEY_PASSWORD, privateKeyPassword);

	    // Accedemos al almacén de claves para rescatar la clave privada y
	    // el certificado usados para firmar la petición SOAP
	    byte[ ] keystoreBytes = getBytesFromFile(keystorePath);
	    try {
		PrivateKey privateKeySOAP = UtilsKeystoreCommons.getPrivateKeyEntry(keystoreBytes, keystorePassword, privateKeyAlias, keystoreType, privateKeyPassword);
		X509Certificate certificateSOAP = UtilsCertificateCommons.generateCertificate(UtilsKeystoreCommons.getCertificateEntry(keystoreBytes, keystorePassword, privateKeyAlias, keystoreType));
		// Asociamos los valores al CallBackHanlder
		callBackHandler.setPrivateKeySOAPRequest(privateKeySOAP);
		callBackHandler.setCertificateSOAPRequest(certificateSOAP);
	    } catch (Exception e) {
		throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG027, new Object[ ] { privateKeyAlias, keystorePath }), e);
	    }

	    // Obtenemos el InputStream que se refiere a la securización
	    // seleccionada
	    is = SOAPMessageSecurityProvider.generateXMLSAMLToken(mandatorySubjectConfirmationMethod, useSymmetricKey, symmetricKeyAlias);
	}
	// Autenticación no reconocida
	else {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG030));
	}
	return is;
    }

    /**
     * Method that verifies if the inclussion method for the certificate used to secure the SOAP request has a correct value. The allowed
     * values are:
     * <ul>
     * <li>{@link SOAPMessageSecurityProvider#INCLUSION_METHOD_DIRECT}</li>
     * <li>{@link SOAPMessageSecurityProvider#INCLUSSION_METHOD_IDENTIFIER}</li>
     * <li>{@link SOAPMessageSecurityProvider#INCLUSSION_METHOD_ISSUERSERIALNUMBER}</li>
     * </ul>
     * @param certificateInclussionMethod Parameter that represents the inclussion method for the certificate used to secure the SOAP request.
     * @throws TSAServiceInvokerException If the inclussion method for the certificate used to secure the SOAP request has an incorrect value.
     */
    private void checkCertificateInclussionMethod(String certificateInclussionMethod) throws TSAServiceInvokerException {
	if (!certificateInclussionMethod.equals(SOAPMessageSecurityProvider.INCLUSION_METHOD_DIRECT) && !certificateInclussionMethod.equals(SOAPMessageSecurityProvider.INCLUSION_METHOD_IDENTIFIER) && !certificateInclussionMethod.equals(SOAPMessageSecurityProvider.INCLUSION_METHOD_ISSUERSERIALNUMBER)) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG031));
	}
    }

    /**
     * Method that verifies if the mandatory subject confirmation method used to secure the SOAP request with SAML has a correct value. The allowed
     * values are:
     * <ul>
     * <li>{@link SOAPMessageSecurityProvider#SAML_HOLDER_OF_KEY}</li>
     * <li>{@link SOAPMessageSecurityProvider#SAML_SENDER_VOUCHEZ}</li>
     * </ul>
     * @param mandatorySubjectConfirmationMethod Parameter that represents the mandatory subject confirmation method used to secure the SOAP request with SAML.
     * @throws TSAServiceInvokerException If the mandatory subject confirmation method used to secure the SOAP request with SAML has an incorrect value.
     */
    private void checkMandatorySubjectConfirmationMethod(String mandatorySubjectConfirmationMethod) throws TSAServiceInvokerException {
	if (!mandatorySubjectConfirmationMethod.equals(SOAPMessageSecurityProvider.SAML_HOLDER_OF_KEY) && !mandatorySubjectConfirmationMethod.equals(SOAPMessageSecurityProvider.SAML_SENDER_VOUCHEZ)) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG032));
	}
    }

    /**
     * Method that verifies if the type of a keystore has a correct value. The allowed
     * values are:
     * <ul>
     * <li>{@link UtilsKeystoreCommons#PKCS12}</li>
     * <li>{@link UtilsKeystoreCommons#JCEKS}</li>
     * <li>{@link UtilsKeystoreCommons#JKS}</li>
     * </ul>
     * @param keystoreType Parameter that represents the type of the keystore.
     * @param msg Parameter that represents the error message if the type of the keystore is incorrect.
     * @throws TSAServiceInvokerException If the type of the keystore is incorrect.
     */
    private void checkKeystoreType(String keystoreType, String msg) throws TSAServiceInvokerException {
	if (!keystoreType.equals(UtilsKeystoreCommons.PKCS12) && !keystoreType.equals(UtilsKeystoreCommons.JCEKS) && !keystoreType.equals(UtilsKeystoreCommons.JKS)) {
	    throw new TSAServiceInvokerException(msg);
	}
    }

    /**
     * Method that checks if a value isn't null and empty.
     * @param value Parameter that represents the value to check.
     * @param msg Parameter that represents the message used for the log if the value is null or empty.
     * @return a boolean that indicates if the value is null or empty (true), or not (false).
     */
    private boolean checkValue(String value, String msg) {
	if (value == null || value.isEmpty()) {
	    LOGGER.info(msg);
	    return false;
	}
	return true;
    }

    /**
     * Method that obtains the value of the symmetric key used to encrypt the SOAP responses from {@link #properties}.
     * @param callBackHandler Parameter that represents the class used to proccess the SOAP messages.
     */
    private void configureSOAPResponseSymmetricKey(TSACallBackHandler callBackHandler) {
	// Rescatamos el alias de la clave simétrica usada para encriptar las
	// respuestas SOAP por parte de TS@
	String responseSymmetricKeyAlias = properties.getProperty(TSAServiceInvokerConstants.WS_RESPONSE_SYMMETRICKEY_ALIAS);
	if (checkValue(responseSymmetricKeyAlias, Language.getResIntegra(ILogConstantKeys.TWSI_LOG033))) {
	    // Asociamos el valor al CallBackHanlder
	    callBackHandler.setAliasSymmetricKeyResponse(responseSymmetricKeyAlias);
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG034, new Object[ ] { responseSymmetricKeyAlias }));
	}
	// Rescatamos el valor de la clave simétrica usada para encriptar las
	// respuestas SOAP por parte de TS@
	String responseSymmetricKeyValue = properties.getProperty(TSAServiceInvokerConstants.WS_RESPONSE_SYMMETRICKEY_VALUE);
	if (checkValue(responseSymmetricKeyValue, Language.getResIntegra(ILogConstantKeys.TWSI_LOG035))) {
	    // Asociamos el valor al CallBackHanlder
	    callBackHandler.setSymmetricKeyResponse(responseSymmetricKeyValue);
	}
    }

    /**
     * Method that obtains the properties related to the certificate used to sign the SOAP responses from {@link #properties}.
     * @param callBackHandler Parameter that represents the class used to proccess the SOAP messages.
     * @throws TSAServiceInvokerException If any of the properties has an incorrect value.
     */
    private void configureSOAPResponseCertificate(TSACallBackHandler callBackHandler) throws TSAServiceInvokerException {
	// Rescatamos la ruta al almacén de claves donde se encuentra almacenado
	// el certificado usado por TS@ para firmar las respuestas SOAP
	String keystorePath = properties.getProperty(TSAServiceInvokerConstants.WS_RESPONSE_KEYSTORE_PATH);
	if (checkValue(keystorePath, Language.getResIntegra(ILogConstantKeys.TWSI_LOG036))) {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG037, new Object[ ] { keystorePath }));
	    // Rescatamos el tipo de almacén de claves donde se encuentra
	    // almacenado el certificado usado por TS@ para firmar las
	    // respuestas SOAP
	    String keystoreType = properties.getProperty(TSAServiceInvokerConstants.WS_RESPONSE_KEYSTORE_TYPE);
	    if (checkValue(keystoreType, Language.getResIntegra(ILogConstantKeys.TWSI_LOG038))) {
		LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG039, new Object[ ] { keystoreType }));
		// Comprobamos que el tipo de almacén de claves está soportado
		checkKeystoreType(keystoreType, Language.getResIntegra(ILogConstantKeys.TWSI_LOG040));
		// Rescatamos la contraseña del almacén de claves donde se
		// encuentra almacenado el certificado usado por TS@ para firmar
		// las respuestas SOAP
		String keystorePassword = properties.getProperty(TSAServiceInvokerConstants.WS_RESPONSE_KEYSTORE_PASSWORD);
		if (checkValue(keystorePassword, Language.getResIntegra(ILogConstantKeys.TWSI_LOG041))) {
		    // Rescatamos el alias del certificado usado por TS@ para
		    // firmar las respuestas SOAP
		    String certificateAlias = properties.getProperty(TSAServiceInvokerConstants.WS_RESPONSE_CERTIFICATE_ALIAS);
		    if (checkValue(certificateAlias, Language.getResIntegra(ILogConstantKeys.TWSI_LOG042))) {
			LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG043, new Object[ ] { certificateAlias }));
			// Accedemos al almacén de claves para rescatar el
			// certificado usado por TS@ para firmar las respuestas
			// SOAP
			byte[ ] keystoreBytes = getBytesFromFile(keystorePath);
			try {
			    X509Certificate certificateSOAP = UtilsCertificateCommons.generateCertificate(UtilsKeystoreCommons.getCertificateEntry(keystoreBytes, keystorePassword, certificateAlias, keystoreType));
			    // Asociamos el valor al CallBackHanlder
			    callBackHandler.setCertificateSOAPResponse(certificateSOAP);
			} catch (Exception e) {
			    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG044, new Object[ ] { certificateAlias, keystorePath }), e);
			}
		    }
		}
	    }
	}
    }

    /**
     * Method that obtains the properties related to the certificate used to sign the SOAP responses with SAML from {@link #properties}.
     * @param callBackHandler Parameter that represents the class used to proccess the SOAP messages.
     * @throws TSAServiceInvokerException If any of the properties has an incorrect value.
     */
    private void configureSOAPResponseSAMLCertificate(TSACallBackHandler callBackHandler) throws TSAServiceInvokerException {
	// Rescatamos la ruta al almacén de claves donde se encuentra almacenado
	// el certificado usado por TS@ para firmar las respuestas SOAP con SAML
	String keystorePath = properties.getProperty(TSAServiceInvokerConstants.WS_RESPONSE_SAML_KEYSTORE_PATH);
	if (checkValue(keystorePath, Language.getResIntegra(ILogConstantKeys.TWSI_LOG045))) {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG046, new Object[ ] { keystorePath }));
	    // Rescatamos el tipo de almacén de claves donde se encuentra
	    // almacenado el certificado usado por TS@ para firmar las
	    // respuestas SOAP con SAML
	    String keystoreType = properties.getProperty(TSAServiceInvokerConstants.WS_RESPONSE_SAML_KEYSTORE_TYPE);
	    if (checkValue(keystoreType, Language.getResIntegra(ILogConstantKeys.TWSI_LOG047))) {
		LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG048, new Object[ ] { keystoreType }));
		// Comprobamos que el tipo de almacén de claves está soportado
		checkKeystoreType(keystoreType, Language.getResIntegra(ILogConstantKeys.TWSI_LOG049));
		// Rescatamos la contraseña del almacén de claves donde se
		// encuentra almacenado el certificado usado por TS@ para firmar
		// las respuestas SOAP con SAML
		String keystorePassword = properties.getProperty(TSAServiceInvokerConstants.WS_RESPONSE_SAML_KEYSTORE_PASSWORD);
		if (checkValue(keystorePassword, Language.getResIntegra(ILogConstantKeys.TWSI_LOG050))) {
		    // Rescatamos el alias del certificado usado por TS@ para
		    // firmar las respuestas SOAP
		    String certificateAlias = properties.getProperty(TSAServiceInvokerConstants.WS_RESPONSE_SAML_CERTIFICATE_ALIAS);
		    if (checkValue(certificateAlias, Language.getResIntegra(ILogConstantKeys.TWSI_LOG051))) {
			LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG052, new Object[ ] { certificateAlias }));
			// Accedemos al almacén de claves para rescatar el
			// certificado usado por TS@ para firmar las respuestas
			// SOAP con SAML
			byte[ ] keystoreBytes = getBytesFromFile(keystorePath);
			try {
			    X509Certificate certificateSOAP = UtilsCertificateCommons.generateCertificate(UtilsKeystoreCommons.getCertificateEntry(keystoreBytes, keystorePassword, certificateAlias, keystoreType));
			    // Asociamos el valor al CallBackHanlder
			    callBackHandler.setCertificateSAMLResponse(certificateSOAP);
			} catch (Exception e) {
			    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG044, new Object[ ] { certificateAlias, keystorePath }), e);
			}
		    }
		}
	    }
	}
    }

    /**
     * Method that obtains a file as a bytes array.
     * @param filePath Parameter that represents the path of the file.
     * @return the bytes array of the file.
     * @throws TSAServiceInvokerException If the file does not exist, is a directory rather than a regular file, or for some other reason cannot be
     * opened for reading.
     */
    private byte[ ] getBytesFromFile(String filePath) throws TSAServiceInvokerException {
	InputStream fis = null;
	try {
	    fis = new FileInputStream(filePath);
	    return GenericUtilsCommons.getDataFromInputStream(fis);
	} catch (IOException e) {
	    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG053, new Object[ ] { filePath }), e);
	} finally {
	    UtilsResourcesCommons.safeCloseInputStream(fis);
	}
    }
}
