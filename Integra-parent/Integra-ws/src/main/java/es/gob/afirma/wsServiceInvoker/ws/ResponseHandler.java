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
 * <b>File:</b><p>es.gob.afirma.wsServiceInvoker.ws.ResponseHandler.java.</p>
 * <b>Description:</b><p>Class that represents handler used to verify the signature response.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>03/10/2011.</p>
 * @author Gobierno de España.
 * @version 1.3, 11/03/2020.
 */
package es.gob.afirma.wsServiceInvoker.ws;

import java.security.cert.X509Certificate;

import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.saaj.util.SAAJUtil;
import org.apache.log4j.Logger;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.components.crypto.CryptoType.TYPE;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.signature.xades.IXMLConstants;
import es.gob.afirma.signature.xades.IdRegister;
import org.apache.xml.crypto.dsig.XMLSignature;

/**
 * <p>Class that represents handler used to verify the signature response.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.3, 11/03/2020.
 */
public class ResponseHandler extends AbstractCommonHandler {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(ResponseHandler.class);

    /**
     * Constant attribute that represents the handler name. 
     */
    private static final String HANDLER_NAME = "responseHandlerIntegra";

    /**
     * Constructor method for the class CopyOfClientHandler.java.
     */
    public ResponseHandler() {
	this.handlerDesc.setName(HANDLER_NAME);
	this.handlerDesc.getRules().setPhaseLast(true);
    }

    /**
     * Constructor method for the class ResponseHandler.java.
     * @param keystorePath keystore path.
     * @param keystorePass keystore password.
     * @param keystoreType keystore type.
     * @param autUser alias of certificate stored in keystore.
     * @param autPassword password of certificate (private key).
     */
    public ResponseHandler(String keystorePath, String keystorePass, String keystoreType, String autUser, String autPassword) {
	this.handlerDesc.setName(HANDLER_NAME);
	this.handlerDesc.getRules().setPhaseLast(true);
	setUserKeystore(keystorePath);
	setUserKeystorePass(keystorePass);
	setUserKeystoreType(keystoreType);
	setUserAlias(autUser);
	setPassword(autPassword);
    }

    /**
     * {@inheritDoc}
     * @see org.apache.axis.Handler#invoke(org.apache.axis.MessageContext)
     */
    @Override
    public InvocationResponse invoke(MessageContext msgContext) throws AxisFault {
	Document doc = null;
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.RH_LOG001));
	try {
	    // Obtención del documento XML que representa la petición SOAP.
	    doc = SAAJUtil.getDocumentFromSOAPEnvelope(msgContext.getEnvelope());
	    // Obtenemos el objeto signature.
	    Element sigElement = null;
	    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_SIGNATURE);
	    if (nl.getLength() > 0) {
		sigElement = (Element) nl.item(0);
		// creamos un manejador de la firma (para validarlo) a partir
		// del xml de la firma.
		org.apache.xml.security.Init.init();
		org.apache.xml.security.signature.XMLSignature signature = new org.apache.xml.security.signature.XMLSignature(sigElement, "");

		IdRegister.registerElements(doc.getDocumentElement());
		// Obtenemos la clave pública usada en el servidor para las
		// respuestas a partir del almacén de certificados.
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.RH_LOG003, new Object[ ] { getUserAlias() }));
		CryptoType aliasCertificate = new CryptoType(TYPE.ALIAS);
		aliasCertificate.setAlias(getUserAlias());
		X509Certificate[ ] certificates = getCryptoInstance().getX509Certificates(aliasCertificate);
		if (certificates != null && certificates.length > 0) {
		    X509Certificate certificate = certificates[0];
		    if (signature.checkSignatureValue(certificate)) {
			LOGGER.debug(Language.getResIntegra(ILogConstantKeys.RH_LOG004));
		    } else {
			throw new AxisFault(Language.getFormatResIntegra(ILogConstantKeys.RH_LOG005, new Object[ ] { certificate.getSubjectDN(), certificate.getSerialNumber() }));
		    }
		} else {
		    throw new AxisFault(Language.getResIntegra(ILogConstantKeys.RH_LOG006));
		}
	    } else {
		throw new AxisFault(Language.getResIntegra(ILogConstantKeys.RH_LOG002));
	    }
	} catch (Exception e) {
	    throw AxisFault.makeFault(e);
	}
	return InvocationResponse.CONTINUE;
    }

}
