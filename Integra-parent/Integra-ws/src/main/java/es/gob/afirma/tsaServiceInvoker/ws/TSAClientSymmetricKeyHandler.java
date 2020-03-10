// Copyright (C) 2020 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.tsaServiceInvoker.ws.TSAClientSymmetricKeyHandler.java.</p>
 * <b>Description:</b><p>Class that secures SOAP messages of TS@ requests with symmetric key.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>04/03/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 10/03/2020.
 */
package es.gob.afirma.tsaServiceInvoker.ws;

import java.util.StringTokenizer;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.soap.SOAPBody;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPHeader;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.saaj.util.SAAJUtil;
import org.apache.log4j.Logger;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerConstants;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerException;
import es.gob.afirma.utils.UtilsAxis;

/**
 * <p>Class that secures SOAP messages of TS@ requests with symmetric key.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 10/03/2020.
 */
class TSAClientSymmetricKeyHandler extends AbstractTSAHandler {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(TSAClientSymmetricKeyHandler.class);
    
    /**
     * Constant attribute that represents the handler name. 
     */
    private static final String HANDLER_NAME = "tsaClientSymmetricKeyHandlerIntegra";
    
    /**
     * Attribute that represents the algorithm to use in the secret key generation. 
     */
    private static final String SECRET_KEY_ALGORITHM = "DESede";

    /**
     * Constructor method for the class TSAClientSymmetricKeyHandler.java. 
     */
    TSAClientSymmetricKeyHandler() {
	this.handlerDesc.setName(HANDLER_NAME);
	this.handlerDesc.getRules().setPhaseLast(true);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsaServiceInvoker.ws.AbstractTSAHandler#invoke(org.apache.axis2.context.MessageContext)
     */
    public InvocationResponse invoke(MessageContext msgContext) throws AxisFault {
	if (isEncryptMessage()) {
	    SOAPEnvelope secMsg;
	    secMsg = null;

	    try {
		// Generamos el nuevo mensaje SOAP con el contenido cifrado con
		// clave simétrica.
		secMsg = encryptMessage(msgContext);

		// Modificación de la petición SOAP.
		if (secMsg != null) {

		    // Insertamos el nuevo body generado.
		    msgContext.getEnvelope().addChild(secMsg.getBody());

		    // Añadimos la cabecera generada.
		    msgContext.getEnvelope().addChild(secMsg.getHeader());

		} else {
		    String errorMsg = Language.getResIntegra(ILogConstantKeys.TCSKH_LOG001);
		    LOGGER.error(errorMsg);
		    throw new TSAServiceInvokerException(errorMsg);
		}
	    } catch (Exception e) {
		throw AxisFault.makeFault(e);
	    }
	}
	return InvocationResponse.CONTINUE;
    }

    /**
     * Method that encrypts the SOAP request with a symmetric key.
     * @param msgContext Context where the SOAP request is.
     * @return a SOAPMessage that represents the new SOAP request generated or null if an error occurs.
     */
    private SOAPEnvelope encryptMessage(MessageContext msgContext) {
	SOAPEnvelope res = null;
	try {
	    // Creamos un SOAP envelope vacío (versión SOAP 1.1).
	    res = OMAbstractFactory.getSOAP11Factory().createSOAPEnvelope();

	    // Recuperamos el algoritmo de cifrado a utilizar.
	    String cipherAlg = getRequestSymmetricAlgorithm();
	    if (cipherAlg == null) {
		throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TCSKH_LOG002));
	    }

	    // Recuperamos el alias de la clave simétrica.
	    String symmetricKeyAlias = getRequestSymmetricKeyAlias();
	    if (symmetricKeyAlias == null) {
		throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TCSKH_LOG003));
	    }

	    // Obtenemos los datos a cifrar.
	    SOAPBody body = msgContext.getEnvelope().getBody();

	    // Ciframos los datos.
	    String base64EncryptedData = encrypt(SAAJUtil.toDOM(body), cipherAlg, getRequestSymmetricKeyValue());
	    if (base64EncryptedData == null) {
		throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TCSKH_LOG004));
	    }

	    // Generamos el identificador del elemento EncryptedData del body.
	    String id = UtilsAxis.generateNumbersUniqueId();
	    if (id == null) {
		throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TCSKH_LOG005));
	    }
	    String identifier = "#" + id;

	    // Generamos el elemento EncryptedData.
	    OMElement encryptedData = generateEncryptedDataElement(identifier, cipherAlg, symmetricKeyAlias, base64EncryptedData);
	    if (encryptedData == null) {
		throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TCSKH_LOG006));
	    }

	    // Incluimos la referencia al elemento en la cabecera SOAP.
	    SOAPHeader header = msgContext.getEnvelope().getHeader();
	    OMElement referenceList = UtilsAxis.findElementByTagName(header, TSAServiceInvokerConstants.SOAPElements.REFERENCE_LIST);
	    // Si ya existe el elemento referenceList, incluimos el
	    // DataReference, sino, lo creamos desde 0.
	    OMElement dataReference = generateDataReference(identifier);
	    if (referenceList == null) {
		referenceList = generateReferenceList();
	    }
	    referenceList.addChild(dataReference);

	    // Actualizamos la cabecera con los nuevos elementos.
	    OMElement securityElem = UtilsAxis.findElementByTagName(header, TSAServiceInvokerConstants.SOAPElements.SECURITY);
	    if (securityElem == null) {
		throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TCSKH_LOG007));
	    }
	    securityElem.addChild(referenceList);

	    // Añadimos todos los nuevos elementos al envelope generado.
	    res.addChild(header);
	    res.addChild(body);
	    res.getBody().getFirstElement().detach();
	    res.getBody().addChild(encryptedData);

	} catch (Exception e) {
	    LOGGER.error(Language.getResIntegra(ILogConstantKeys.TCSKH_LOG008));
	}
	return res;
    }

    /**
     * Method that encrypts a given element.
     * @param docToSign Element to encrypt.
     * @param cipherAlg Algorithm to use in the encryption process.
     * @param symmetricKey Key to use in the encryption process.
     * @return a String that represents the encrypted data or null if something fails in the process.
     */
    private String encrypt(Element docToSign, String cipherAlg, String symmetricKey) {
	String res = null;
	try {
	    // Instanciamos el cipher con el algoritmo seleccionado.
	    XMLCipher xmlCipher = XMLCipher.getInstance(cipherAlg);

	    // Transformamos la clave a utilizar para el cifrado en una
	    // SecretKey.
	    StringTokenizer key = new StringTokenizer(symmetricKey, ",");
	    byte[ ] keyBytes = new byte[key.countTokens()];
	    int j = 0;
	    while (key.hasMoreTokens()) {
		String ss = key.nextToken();
		keyBytes[j] = (byte) Integer.decode(ss).intValue();
		j++;
	    }
	    SecretKey secretKey = new SecretKeySpec(keyBytes, SECRET_KEY_ALGORITHM);

	    // Inicializamos el cipher.
	    xmlCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);

	    // Generamos los datos firmados
	    Document encryptedData = xmlCipher.doFinal(docToSign.getOwnerDocument(), docToSign, true);

	    if(encryptedData == null){
		throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TCSKH_LOG009));
	    }
	    
	    // Devolvemos los datos cifrados.
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TCSKH_LOG010));
	    res = encryptedData.getElementsByTagName("xenc:CipherValue").item(0).getFirstChild().getNodeValue();
	} catch (XMLEncryptionException e) {
	    LOGGER.error(Language.getResIntegra(ILogConstantKeys.TCSKH_LOG011));
	} catch (Exception e) {
	   LOGGER.error(Language.getResIntegra(ILogConstantKeys.TCSKH_LOG009));
	}
	return res;
    }

    /**
     * Method that generates an element of type EncryptedData.
     * @param identifier EncryptedData element Id.
     * @param cipherAlgoritm Algorithm URI used to generate the encryption.
     * @param symmetricKeyAlias Alias of the symmetric key used to generate the encryption.
     * @param base64EncryptedData Encrypted data in Base64.
     * @return an OMElement that represents the generated EncryptedData element.
     */
    private OMElement generateEncryptedDataElement(String identifier, String cipherAlgoritm, String symmetricKeyAlias, String base64EncryptedData) {
	// Creamos el elemento principal EncryptedData.
	OMFactory fac = OMAbstractFactory.getOMFactory();
	OMNamespace nsXenc = fac.createOMNamespace("http://www.w3.org/2001/04/xmlenc#", "xenc");
	OMElement res = fac.createOMElement(TSAServiceInvokerConstants.SOAPElements.ENCRYPTED_DATA, nsXenc);

	// Añadimos los atributos necesarios a EncryptedData.
	res.addAttribute(TSAServiceInvokerConstants.SOAPElements.ID, identifier.substring(1), null);
	res.addAttribute(TSAServiceInvokerConstants.SOAPElements.TYPE, "http://www.w3.org/2001/04/xmlenc#Content", null);

	// Creamos el elemento EncryptedMethod.
	OMElement encryptionMethodElem = fac.createOMElement(TSAServiceInvokerConstants.SOAPElements.ENCRYPTION_METHOD, nsXenc);
	encryptionMethodElem.addAttribute(TSAServiceInvokerConstants.SOAPElements.ALGORITHM, cipherAlgoritm, null);

	// Creamos el elemento KeyInfo.
	OMNamespace nsDs = fac.createOMNamespace("http://www.w3.org/2000/09/xmldsig#", "ds");
	OMElement keyInfoElem = fac.createOMElement(TSAServiceInvokerConstants.SOAPElements.KEY_INFO, nsDs);
	// Creamos el elemento KeyName y lo incluimos en KeyInfo.
	OMElement keyNameElem = fac.createOMElement(TSAServiceInvokerConstants.SOAPElements.KEY_NAME, nsDs);
	keyNameElem.setText(symmetricKeyAlias);
	keyInfoElem.addChild(keyNameElem);

	// Creamos el elemento CipherData.
	OMElement cipherDataElem = fac.createOMElement(TSAServiceInvokerConstants.SOAPElements.CIPHER_DATA, nsXenc);
	// Creamos el elemento CipherValue y lo incluimos en el CipherData.
	OMElement cipherValueElem = fac.createOMElement(TSAServiceInvokerConstants.SOAPElements.CIPHER_VALUE, nsXenc);
	cipherValueElem.setText(base64EncryptedData);
	cipherDataElem.addChild(cipherValueElem);

	// Incluimos los elementos generados en el EncryptedData.
	res.addChild(encryptionMethodElem);
	res.addChild(keyInfoElem);
	res.addChild(cipherDataElem);

	// Devolvemos el elemento generado.
	return res;
    }

    /**
     * Method that generates the DataReference element for the symmetric encryption header.
     * @param identifier EncryptedData element ID.
     * @return an OMelement that represents the DataReference element generated.
     */
    private OMElement generateDataReference(String identifier) {
	OMFactory fac = OMAbstractFactory.getOMFactory();
	OMNamespace nsXenc = fac.createOMNamespace("http://www.w3.org/2001/04/xmlenc#", "xenc");
	OMElement res = fac.createOMElement(TSAServiceInvokerConstants.SOAPElements.DATA_REFERENCE, nsXenc);
	res.addAttribute(TSAServiceInvokerConstants.SOAPElements.URI, identifier, null);
	return res;
    }

    /**
     * Method that generates the ReferenceList element for the symmetric encryption header.
     * @return an OMelement that represents the ReferenceList element generated.
     */
    private OMElement generateReferenceList() {
	OMFactory fac = OMAbstractFactory.getOMFactory();
	OMNamespace nsXenc = fac.createOMNamespace("http://www.w3.org/2001/04/xmlenc#", "xenc");
	OMElement res = fac.createOMElement(TSAServiceInvokerConstants.SOAPElements.REFERENCE_LIST, nsXenc);
	return res;
    }

}
