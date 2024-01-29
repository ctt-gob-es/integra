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
 * <b>File:</b><p>es.gob.afirma.tsaServiceInvoker.ws.TSAResponseSymmetricKeyHandler.java.</p>
 * <b>Description:</b><p>Class that checks and decrypts the SOAP messages of TS@ responses with symmetric key.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>04/03/2020.</p>
 * @author Gobierno de España.
 * @version 1.2, 18/04/2022.
 */
package es.gob.afirma.tsaServiceInvoker.ws;

import java.io.ByteArrayInputStream;
import java.util.StringTokenizer;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNode;
import org.apache.axiom.soap.SOAPBody;
import org.apache.axiom.soap.SOAPHeader;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.saaj.util.SAAJUtil;
import org.apache.axis2.util.XMLUtils;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.w3c.dom.Element;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.Logger;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerConstants;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerException;
import es.gob.afirma.utils.UtilsAxis;

/**
 * <p>Class that checks and decrypts the SOAP messages of TS@ responses with symmetric key.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 18/04/2022.
 */
public class TSAResponseSymmetricKeyHandler extends AbstractTSAHandler {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = Logger.getLogger(TSAResponseSymmetricKeyHandler.class);

    /**
     * Constant attribute that represents the handler name. 
     */
    private static final String HANDLER_NAME = "tsaResponseSymmetricKeyHandlerIntegra";

    /**
     * Attribute that represents the algorithm to use in the secret key generation. 
     */
    private static final String SECRET_KEY_ALGORITHM = "DESede";

    /**
     * Constructor method for the class TSAResponseSymmetricKeyHandler.java.
     */
    public TSAResponseSymmetricKeyHandler() {
	this.handlerDesc.setName(HANDLER_NAME);
	this.handlerDesc.getRules().setPhaseFirst(true);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public InvocationResponse invoke(MessageContext msgContext) throws AxisFault {
	if (isEncryptMessage()) {
	    // NOTA: Aunque el estandar dice que podría haber varios elementos
	    // DataReference y KeyReference dentro de ReferenceList, y que
	    // podrían existir claves cifradas en el body e incluso varios datos
	    // cifrados en distintos elementos, la implementación de
	    // comunicación simétrica a través de web services con TS@
	    // únicamente acepta esta estructura de petición, por lo que no es
	    // necesario implementar dicha lógica. Si en el futuro se cambia
	    // esta funcionalidad, habrá que adaptar este código para que cumpla
	    // con los nuevos requisitos.

	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TRSKH_LOG005));
	    try {
		// Recuperamos la cabecera SOAP.
		SOAPHeader header = msgContext.getEnvelope().getHeader();

		// Recuperamos el Body.
		SOAPBody body = msgContext.getEnvelope().getBody();

		// Recuperamos el identificador de los datos formados en la
		// cabecera.
		OMElement dataReference = UtilsAxis.findElementByTagName(header, TSAServiceInvokerConstants.SOAPElements.DATA_REFERENCE);
		if (dataReference == null) {
		    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TRSKH_LOG006, new Object[ ] { TSAServiceInvokerConstants.SOAPElements.DATA_REFERENCE }));
		}
		String identifier = UtilsAxis.findAttributeValue(dataReference, TSAServiceInvokerConstants.SOAPElements.URI).substring(1);

		// Recuperamos el elemento que contiene los datos cifrados.
		OMElement encryptedData = UtilsAxis.findElementByTagNameAndAttribute(body, TSAServiceInvokerConstants.SOAPElements.ENCRYPTED_DATA, TSAServiceInvokerConstants.SOAPElements.ID, identifier);
		if (encryptedData == null) {
		    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TRSKH_LOG006, new Object[ ] { TSAServiceInvokerConstants.SOAPElements.ENCRYPTED_DATA }));
		}

		// Recuperamos el nombre de la clave simétrica a usar para el
		// descifrado.
		OMElement keyName = UtilsAxis.findElementByTagName(encryptedData, TSAServiceInvokerConstants.SOAPElements.KEY_NAME);
		if (keyName == null) {
		    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TRSKH_LOG007, new Object[ ] { TSAServiceInvokerConstants.SOAPElements.KEY_NAME }));
		}
		String keyAlias = keyName.getText();

		// Recuperamos el algoritmo de cifrado utilizado en la
		// respuesta.
		OMElement encryptionMethod = UtilsAxis.findElementByTagName(encryptedData, TSAServiceInvokerConstants.SOAPElements.ENCRYPTION_METHOD);
		if (encryptionMethod == null) {
		    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TRSKH_LOG007, new Object[ ] { TSAServiceInvokerConstants.SOAPElements.ENCRYPTION_METHOD }));
		}
		String encryptAlgorithm = UtilsAxis.findAttributeValue(encryptionMethod, TSAServiceInvokerConstants.SOAPElements.ALGORITHM);

		// Desciframos...
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.TRSKH_LOG004, new Object[ ] { keyAlias, encryptAlgorithm }));
		OMElement decryptedBody = decrypt(keyAlias, encryptAlgorithm, encryptedData);

		// Si todo ha ido bien, generamos el nuevo body descifrado y lo
		// sustituimos por el anterior.
		if (decryptedBody != null) {
		    msgContext.getEnvelope().getBody().getFirstElement().detach();
		    msgContext.getEnvelope().getBody().addChild(decryptedBody);
		} else {
		    String errorMsg = Language.getResIntegra(ILogConstantKeys.TRSKH_LOG008);
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
     * Method that decrypts the SOAP message received from the TS@ platform when it is encrypted with symmetric key.
     * @param keyAlias Alias of the symmetric key to use in the process.
     * @param encryptAlgorithm Algorithm used to decrypt.
     * @param encryptedData Encrypted data element to decrypt.
     * @return an new XML element that represents the decrypted SOAP body of the response.
     */
    private OMElement decrypt(String keyAlias, String encryptAlgorithm, OMElement encryptedData) {
	OMElement res = null;
	try {
	    // Instanciamos el cipher con el algoritmo seleccionado.
	    XMLCipher xmlCipher = XMLCipher.getInstance(encryptAlgorithm);

	    // Comprobamos que el alias de la clave simétrica coincide con el
	    // definido en las propiedades de Integra.
	    String storedKeyAlias = getResponseSymmetricKeyAlias();
	    if (!storedKeyAlias.equals(keyAlias)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TRSKH_LOG001, new Object[ ] { keyAlias, storedKeyAlias });
		LOGGER.error(errorMsg);
		throw new TSAServiceInvokerException(errorMsg);
	    }

	    // Recuperamos la clave simétrica.
	    String symmetricKey = getResponseSymmetricKeyValue();

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
	    xmlCipher.init(XMLCipher.DECRYPT_MODE, secretKey);

	    // Desciframos el mensaje.
	    Element element = SAAJUtil.toDOM(encryptedData);
	    byte[ ] dencryptedDataBytes = xmlCipher.decryptToByteArray(element);

	    // Devolvemos el resultado obtenido.
	    OMNode resNode = XMLUtils.toOM(new ByteArrayInputStream(dencryptedDataBytes));
	    res = (OMElement) resNode;

	} catch (XMLEncryptionException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.TRSKH_LOG002);
	    LOGGER.error(errorMsg);
	} catch (Exception e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.TRSKH_LOG003);
	    LOGGER.error(errorMsg);
	}
	return res;

    }
}
