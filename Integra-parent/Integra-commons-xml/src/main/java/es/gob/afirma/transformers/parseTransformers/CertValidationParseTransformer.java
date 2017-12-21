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
 * <b>File:</b><p>es.gob.afirma.transformers.parseTransformers.AnyOutParameterParseTransformer.java.</p>
 * <b>Description:</b><p>Class that processes the responses of certificate validation from the web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>19/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 19/12/2011.
 */
package es.gob.afirma.transformers.parseTransformers;

import java.io.StringReader;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.transformers.TransformersProperties;
import es.gob.afirma.utils.UtilsXML;

/**
 * <p>Class that processes the responses of certificate validation from the web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 19/12/2011.
 */
public class CertValidationParseTransformer implements IParseTransformer {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static Logger logger = IntegraLogger.getInstance().getLogger(CertValidationParseTransformer.class);

    /**
     * Attribute that represents <code>InfoCertificate</code> element of the response.
     */
    private static final String INFO_CERTIFICATE_TAG = "InfoCertificate";

    /**
     * Attribute that represents <code>InfoCertificado</code> element of the response.
     */
    private static final String INFO_CERTIFICADO_TAG = "InfoCertificado";

    /**
     * Attribute that represents <code>ValidationResult</code> element of the response.
     */
    private static final String VALIDATION_RESULT_TAG = "ValidationResult";

    /**
     * Attribute that represents the request.
     */
    private String request = null;

    /**
     * Attribute that represents the version of the message.
     */
    private String messageVersion = null;

    /**
     * Attribute that represents method name.
     */
    private String method = null;

    /**
     * Constructor method for the class CertValidationParseTransformer.java.
     * @param req Parameter that represents the request.
     * @param methodParam Parameter that represents method name.
     * @param msgVersion Parameter that represents the version of the message.
     */
    public CertValidationParseTransformer(String req, String methodParam, String msgVersion) {
	request = req;
	method = methodParam;
	messageVersion = msgVersion;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.transformers.parseTransformers.IParseTransformer#getRequest()
     */
    public final String getRequest() {
	return request;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.transformers.parseTransformers.IParseTransformer#getMessageVersion()
     */
    public final String getMessageVersion() {
	return messageVersion;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.transformers.parseTransformers.IParseTransformer#transform(java.lang.String)
     */
    @SuppressWarnings("unchecked")
    public final Object transform(String xmlResponse) throws TransformersException {
	Map<String, Object> xmlData, res;
	String xpathRespElement;

	res = null;
	xpathRespElement = getXpathRespElement();
	logger.debug(Language.getFormatResIntegra(ILogConstantKeys.CVPT_LOG002, new Object[ ] { xpathRespElement }));
	if (xpathRespElement == null) {
	    throw new TransformersException(Language.getFormatResIntegra(ILogConstantKeys.CVPT_LOG001, new Object[ ] { TransformersConstants.RESP_ROOT_ELEMENT_CTE, request, messageVersion }));
	}

	xmlData = readResponse(xmlResponse, xpathRespElement);
	res = (Map<String, Object>) xmlData.get(ParseTransformerConstants.ERROR_KEY);

	if (res == null) {
	    res = (Map<String, Object>) xmlData.get(ParseTransformerConstants.OK_KEY);
	}

	return res;
    }

    /**
     * Method that obtains a map from the validation certificate response.
     * @param xmlResponse Parameter that represents the XML response message.
     * @param xpathRespElement Parameter that represents the name of the response element.
     * @return a map with the information of the generated error or the result of the service.
     * @throws TransformersException If there's an error reading the XML message.
     */
    private Map<String, Object> readResponse(String xmlResponse, String xpathRespElement) throws TransformersException {
	Document doc;
	Element rootElement;
	Map<String, Object> res, aux;

	res = null;

	try {
	    doc = UtilsXML.parseDocument(new StringReader(xmlResponse));
	} catch (Exception e) {
	    throw new TransformersException(Language.getResIntegra(ILogConstantKeys.CVPT_LOG003), e);
	}

	if (doc != null) {
	    // Leemos los datos de la respuesta
	    rootElement = doc.getDocumentElement();
	    if (!rootElement.getTagName().equals("mensajeSalida") && !rootElement.getTagName().equals("outputMessage")) {// el
		// elemento
		// raiz
		// es
		// "mensajeSalida"
		throw new TransformersException(Language.getResIntegra(ILogConstantKeys.CVPT_LOG004));
	    }

	    res = new Hashtable<String, Object>();
	    // Comprobamos si se ha producido algún error
	    aux = readErrorResponse(UtilsXML.getElement(rootElement, ParseTransformerConstants.RESPONSE_ELEMENT_SP + "/" + ParseTransformerConstants.EXCEPTION_ELEMENT_SP));
	    if (aux == null) {
		aux = readErrorResponse(UtilsXML.getElement(rootElement, ParseTransformerConstants.RESPONSE_ELEMENT + "/" + ParseTransformerConstants.EXCEPTION_ELEMENT));
	    }
	    if (aux == null) {
		// No se produjo ningún error, leemos el mensaje SOAP OK
		aux = readOKResponse(UtilsXML.getElement(rootElement, xpathRespElement));
		if (aux == null) {
		    throw new TransformersException(Language.getResIntegra(ILogConstantKeys.CVPT_LOG005));
		}
		res.put(ParseTransformerConstants.OK_KEY, aux);
	    } else {
		// Mensaje de error
		res.put(ParseTransformerConstants.ERROR_KEY, aux);
	    }
	}

	return res;
    }

    /**
     * Method that processes a response error from the XML validation certificate response.
     * @param exceptionElement Parameter that represents the element <code>Excepcion</code>.
     * @return a map with the values contained inside of the element <code>Excepcion</code>.
     */
    private Map<String, Object> readErrorResponse(Element exceptionElement) {
	List<?> exceptionData;
	Node aux;
	Map<String, Object> res = null;
	String nodeValue;

	if (exceptionElement != null) {
	    // Se ha producido una excepcion al validar el certificado que no
	    // ha permitido realizar la validación completamente.
	    res = new Hashtable<String, Object>();

	    exceptionData = UtilsXML.searchChildElements(exceptionElement);
	    for (int i = 0; i < exceptionData.size(); i++) {
		aux = (Node) exceptionData.get(i);
		if (aux.getNodeType() == Node.ELEMENT_NODE) {
		    // Los tags posibles son: codigoError, descripcion y
		    // excepcionAsociada
		    nodeValue = UtilsXML.getElementValue((Element) aux);
		    res.put(((Element) aux).getTagName(), nodeValue != null ? nodeValue : "");
		}
	    }
	}

	return res;
    }

    /**
     * Method that processes a correct response from the XML validation certificate response.
     * @param upperRespElement Parameter that represents the element <code>Respuesta</code>.
     * @return a map with the values contained inside of the element <code>Respuesta</code>.
     */
    private Map<String, Object> readOKResponse(Element upperRespElement) {
	Map<String, Object> mapResult;
	List<?> auxV;

	mapResult = null;
	if (upperRespElement != null) {
	    // Obtenemos la información de respuesta
	    auxV = UtilsXML.searchChildElements(upperRespElement);

	    if (request.equals("ValidarCertificado") || request.equals("ValidateCertificate")) {
		mapResult = new Hashtable<String, Object>();
		readValidateCertificate(mapResult, auxV);
	    } else if (auxV.size() == 1 && (request.equals("ObtenerInfoCertificado") || request.equals("GetInfoCertificate"))) {
		mapResult = readGetInfoCertResponse(auxV);
	    }
	}
	return mapResult;
    }

    /**
     * Method that reads the content of a certificate validation response.
     * @param mapResult Parameter that represents a map with result data.
     * @param auxV Parameter that represents a list of read fields and read values.
     */
    private void readValidateCertificate(Map<String, Object> mapResult, List<?> auxV) {
	Node auxN = (Node) auxV.get(0);
	if (auxN.getNodeType() == Node.ELEMENT_NODE) {
	    if (auxN.getNodeName().equals(INFO_CERTIFICADO_TAG)) {
		mapResult.put(INFO_CERTIFICADO_TAG, parseInfoCert((Element) auxN));
		if (auxV.size() == 2) {
		    mapResult.put("ResultadoValidacion", parseInfoVal((Element) auxV.get(1)));
		}
	    } else if (INFO_CERTIFICATE_TAG.equals(auxN.getNodeName())) {
		mapResult.put(INFO_CERTIFICATE_TAG, parseInfoCert((Element) auxN));
		if (auxV.size() == 2) {
		    mapResult.put(VALIDATION_RESULT_TAG, parseInfoVal((Element) auxV.get(1)));
		}
	    } else if (auxN.getNodeName().equals("ResultadoValidacion")) {
		mapResult.put("ResultadoValidacion", parseInfoVal((Element) auxN));
		if (auxV.size() == 2) {
		    mapResult.put(INFO_CERTIFICADO_TAG, parseInfoCert((Element) auxV.get(1)));
		}
	    } else if (VALIDATION_RESULT_TAG.equals(auxN.getNodeName())) {
		mapResult.put(VALIDATION_RESULT_TAG, parseInfoVal((Element) auxN));
		if (auxV.size() == 2) {
		    mapResult.put(INFO_CERTIFICATE_TAG, parseInfoCert((Element) auxV.get(1)));
		}
	    }
	}
    }

    /**
     * Method that reads the information about the validated certificate.
     * @param auxV Parameter that represents a list with the elements of the result message.
     * @return a map with the information about the validated certificate.
     */
    private Map<String, Object> readGetInfoCertResponse(List<?> auxV) {
	Map<String, Object> res = new Hashtable<String, Object>();
	Node auxN = (Node) auxV.get(0);
	if (auxN.getNodeType() == Node.ELEMENT_NODE && (INFO_CERTIFICATE_TAG.equals(auxN.getNodeName()) || auxN.getNodeName().equals(INFO_CERTIFICADO_TAG))) {
	    res.put(INFO_CERTIFICATE_TAG.equals(auxN.getNodeName()) ? INFO_CERTIFICATE_TAG : INFO_CERTIFICADO_TAG, parseInfoCert((Element) auxN));
	}
	return res;
    }

    /**
     * Method that reads the content of the element with the information about the certificate.
     * @param infoCertElement Parameter that represents the information about the certificate.
     * @return a map with the processed information.
     */
    private Map<String, Object> parseInfoCert(Element infoCertElement) {
	Map<String, Object> res;
	Node auxN;
	List<?> auxV, fieldV;

	res = new Hashtable<String, Object>();
	auxV = UtilsXML.searchChildElements(infoCertElement);

	for (int i = 0; i < auxV.size(); i++) {
	    // Nodo Campo
	    auxN = (Node) auxV.get(i);

	    if (auxN.getNodeType() == Node.ELEMENT_NODE && (auxN.getNodeName().equals("Campo") || "Field".equals(auxN.getNodeName()))) {
		fieldV = UtilsXML.searchChildElements((Element) auxN);
		putFieldsValues(fieldV, res);
	    }
	}

	return res;
    }

    /**
     * Method that updates a map with the values processed from a list.
     * @param fieldV Parameter that represents the list of values.
     * @param result Parameter that represents the map to update.
     */
    private void putFieldsValues(List<?> fieldV, Map<String, Object> result) {
	String fieldId, fieldValue;
	if (fieldV.size() == 2) {
	    Node field = (Node) fieldV.get(0);
	    if (field.getNodeType() == Node.ELEMENT_NODE && (field.getNodeName().equals("idCampo") || "idField".equals(field.getNodeName()))) {
		fieldId = UtilsXML.getElementValue((Element) field);
		field = (Node) fieldV.get(1);
		fieldValue = UtilsXML.getElementValue((Element) field);
		result.put(fieldId, fieldValue != null ? fieldValue : "");
	    } else if (field.getNodeType() == Node.ELEMENT_NODE && (field.getNodeName().equals("valorCampo") || "fieldValue".equals(field.getNodeName()))) {
		fieldValue = UtilsXML.getElementValue((Element) field);
		field = (Node) fieldV.get(1);
		fieldId = UtilsXML.getElementValue((Element) field);
		result.put(fieldId, fieldValue != null ? fieldValue : "");
	    }
	}
    }

    /**
     * Method that reads the element with the information of the certificate validation.
     * @param infoValElement Parameter that represents the element with the information of the certificate validation.
     * @return a map with the information processed.
     */
    private Map<String, Object> parseInfoVal(Element infoValElement) {
	Map<String, Object> res;
	List<?> auxV;

	res = null;

	if (infoValElement != null) {
	    // Obtenemos la información de respuesta
	    auxV = UtilsXML.searchChildElements(infoValElement);
	    res = parseInfoValRec(auxV, 0);
	}

	return res;
    }

    /**
     * Method that obtains a map with the values of a list of elements.
     * @param elementChilds Parameter that represents the list of elements.
     * @param index Parameter that represents the index of the list of elements where to start the process.
     * @return a map with each name and value of the elements.
     */
    private Map<String, Object> parseInfoValRec(List<?> elementChilds, int index) {
	Map<String, Object> res;
	List<?> auxV;
	Node auxN;
	String nodeValue;

	res = new Hashtable<String, Object>();

	if (elementChilds != null && index < elementChilds.size()) {
	    auxN = (Node) elementChilds.get(index);
	    // Obtenemos los elementos estado y descripcion
	    if (auxN.getNodeType() == Node.ELEMENT_NODE) {
		auxV = UtilsXML.searchChildElements((Element) auxN);

		if (auxV != null && auxV.size() > 0) {
		    res.put(auxN.getNodeName(), parseInfoValRec(auxV, 0));
		} else {
		    nodeValue = UtilsXML.getElementValue((Element) auxN);
		    res.put(((Element) auxN).getTagName(), nodeValue != null ? nodeValue : "");
		    for (int i = 1; i < elementChilds.size(); i++) {
			res.putAll(parseInfoValRec(elementChilds, index + i));
		    }
		}
	    }
	}
	return res;
    }

    /**
     * Method that obtains the XPath of certain element.
     * @return the XPath of certain element.
     */
    private String getXpathRespElement() {
	Properties properties;
	String res;

	properties = TransformersProperties.getMethodParseTransformersProperties(request, method, messageVersion);
	res = properties.getProperty(request + "." + method + "." + messageVersion + "." + TransformersConstants.PARSER_CTE + "." + TransformersConstants.RESP_ROOT_ELEMENT_CTE);

	return res;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.transformers.parseTransformers.IParseTransformer#getMethod()
     */
    public final String getMethod() {
	return method;
    }

}
