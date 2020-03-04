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
 * <b>File:</b><p>es.gob.afirma.afirma5ServiceInvoker.Afirma5ServiceInvokerFacade.java.</p>
 * <b>Description:</b><p>Class that represents the facade for the invocation of the web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>16/03/2011.</p>
 * @author Gobierno de España.
 * @version 1.2, 04/03/2020.
 */
package es.gob.afirma.wsServiceInvoker;

import java.io.StringReader;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Properties;
import java.util.StringTokenizer;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.log4j.Logger;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.properties.IntegraProperties;
import es.gob.afirma.utils.DSSConstants.DSSTagsRequest;
import es.gob.afirma.utils.GeneralConstants;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.utils.NativeTagsRequest;
import es.gob.afirma.utils.UtilsCertificateCommons;

/**
 * <p>Class that represents the facade for the invocation of the web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 04/03/2020.
 */
public final class Afirma5ServiceInvokerFacade {

    /**
     *  Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(Afirma5ServiceInvokerFacade.class);

    /**
     * Attribute that represents the instance of the class.
     */
    private static Afirma5ServiceInvokerFacade instance;

    /**
     * Gets a class instance.
     * @return  a class instance.
     */
    public static Afirma5ServiceInvokerFacade getInstance() {
	if (instance == null) {
	    instance = new Afirma5ServiceInvokerFacade();
	}
	return instance;
    }

    /**
     * Constructor method for the class Afirma5ServiceInvokerFacade.java.
     */
    private Afirma5ServiceInvokerFacade() {
    }

    /**
     * Invokes a @Firma service.
     * @param xmlInput input parameter of published @Firma services.
     * @param service service name to invoke.
     * @param method method name of invoked service.
     * @param applicationName customer application name.
     * @param idClient client identifier of ws invocation.
     * @return String with xml format with invocation service result.
     * @throws WSServiceInvokerException if an error happens (connection, not avalaible service, not valid input parameters)
     */
    public String invokeService(String xmlInput, String service, String method, String applicationName, String idClient) throws WSServiceInvokerException {

	if (!GenericUtilsCommons.assertStringValue(xmlInput) || !GenericUtilsCommons.assertStringValue(service) || !GenericUtilsCommons.assertStringValue(method) || !GenericUtilsCommons.assertStringValue(applicationName)) {
	    throw new WSServiceInvokerException(Language.getResIntegra(ILogConstantKeys.ASIF_LOG001));
	}
	return invoke(xmlInput, service, method, applicationName, null, idClient);
    }

    /**
     * Invokes a @Firma service.
     * @param xmlInput input parameter of published @Firma services.
     * @param service service name to invoke.
     * @param method method name of invoked service.
     * @param applicationName customer application name.
     * @return String with xml format with invocation service result.
     * @throws WSServiceInvokerException if an error happens (connection, not avalaible service, not valid input parameters)
     */
    public String invokeService(String xmlInput, String service, String method, String applicationName) throws WSServiceInvokerException {

	return invokeService(xmlInput, service, method, applicationName, null);
    }

    /**
     * Method that searchs in a XML document a node with the content of a certificate encoded with Base64.
     * @param doc Parameter that represents the XML document.
     * @param elementPath Parameter that represents the path to the node with the content of a certificate encoded with Base64.
     * @return an object that represents the certificate encoded with Base64.
     * @throws CertificateException If the method fails.
     * @throws Base64DecodingException If the method fails.
     */
    private X509Certificate getCertificateBase64Encoded(Document doc, String elementPath) throws CertificateException, Base64DecodingException {
	X509Certificate certificate = null;
	StringTokenizer st = new StringTokenizer(elementPath, "/");
	Element root = doc.getDocumentElement();
	while (st.hasMoreTokens()) {
	    NodeList nd = root.getElementsByTagName(st.nextToken());
	    if (nd != null && nd.getLength() == 1) {
		root = (Element) nd.item(0);
	    }
	}
	String encodedCertificate = root.getTextContent();
	if (encodedCertificate != null) {
	    // Decodificamos el certificado
	    byte[ ] decodedCertificate = Base64.decode(encodedCertificate);
	    // Obtenemos el elemento X509Certificate
	    certificate = UtilsCertificateCommons.generateCertificate(decodedCertificate);
	}
	return certificate;
    }

    /**
     * Invokes a @Firma service, it sets a collections of properties aren't in the configuration file of component.
     * @param xmlInput input parameter of published @Firma services.
     * @param service service name to invoke.
     * @param method method name of invoked service.
     * @param serviceProperties collection of configuration settings to invoke service.
     * @param idClient client identifier of ws invocation.
     * @return String with xml format with invocation service result.
     * @throws WSServiceInvokerException if an error happens (connection, not avalaible service, not valid input parameters)
     */
    public String invokeService(String xmlInput, String service, String method, Properties serviceProperties, String idClient) throws WSServiceInvokerException {

	if (!GenericUtilsCommons.assertStringValue(xmlInput) || !GenericUtilsCommons.assertStringValue(service) || !GenericUtilsCommons.assertStringValue(method) || serviceProperties.isEmpty()) {
	    throw new WSServiceInvokerException(Language.getResIntegra(ILogConstantKeys.ASIF_LOG001));
	}

	return invoke(xmlInput, service, method, null, serviceProperties, idClient);
    }

    /**
     * Invokes a @Firma service, it sets a collections of properties aren't in the configuration file of component.
     * @param xmlInput input parameter of published @Firma services.
     * @param service service name to invoke.
     * @param method method name of invoked service.
     * @param serviceProperties collection of configuration settings to invoke service.
     * @return String with xml format with invocation service result.
     * @throws WSServiceInvokerException if an error happens (connection, not avalaible service, not valid input parameters)
     */
    public String invokeService(String xmlInput, String service, String method, Properties serviceProperties) throws WSServiceInvokerException {
	return invokeService(xmlInput, service, method, serviceProperties, null);
    }

    /**
     * Method that invokes a @Firma service.
     * @param xmlInput Parameter that represents the input XML.
     * @param service Parameter that represents the name of the service to invoke.
     * @param method Parameter that represents the name of the method to invoke.
     * @param applicationName Parameter that represents the customer application name.
     * @param serviceProperties Parameter that represents the collection of configuration settings to invoke the service.
     * @param idClient Parameter that represents the client application identifier.
     * @return a XML with the invocation service result.
     * @throws WSServiceInvokerException If the method fails.
     */
    private String invoke(String xmlInput, String service, String method, String applicationName, Properties serviceProperties, String idClient) throws WSServiceInvokerException {
	AbstractWSServiceInvoker afirma5Invoker;
	Object[ ] serviceInParam;
	String res = null;
	boolean useCache = false;
	CertificateCacheKey cck = null;
	try {
	    serviceInParam = new Object[1];
	    serviceInParam[0] = xmlInput;

	    // Comprobamos si se está haciendo una llamada al servicio de
	    // validación de certificados (nativo o DSS)
	    if (service.equals(GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATE_REQUEST) || service.equals(GeneralConstants.CERTIFICATE_VALIDATION_REQUEST) || service.equals(GeneralConstants.VALIDACION_CERTIFICADO_REQUEST)) {
		// Accedemos al archivo de propiedades
		Properties prop = new IntegraProperties().getIntegraProperties(idClient);
		if (prop != null) {
		    // Obtenemos la propiedad que indica si se debe hacer uso de
		    // la caché de respuestas para validación de certificados o
		    // no
		    String useCacheStr = prop.getProperty(WSServiceInvokerConstants.WS_CERTIFICATES_CACHE_USE_PROP);
		    useCache = Boolean.parseBoolean(useCacheStr);
		    if (!useCache) {
			LOGGER.warn(Language.getResIntegra(ILogConstantKeys.ASIF_LOG003));
		    } else {
			// Si se ha indicado hacer uso de la caché de
			// certificados accedemos en los parámetros de
			// entrada a los datos del certificado
			// para extraer el emisor y el número de serie

			// Transformamos el XML de entrada a objeto DOM
			DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
			InputSource is = new InputSource();
			is.setCharacterStream(new StringReader(xmlInput));
			Document doc = db.parse(is);

			// Obtenemos el certificado
			X509Certificate certificate = getCertificate(service, doc);

			// Obtenemos el emisor
			String issuer = certificate.getIssuerDN().getName();

			// Obtenemos el número de serie
			BigInteger serialNumber = certificate.getSerialNumber();

			// Accedemos a la caché
			CertificatesCache cache = CertificatesCache.getInstance(idClient);

			// Instanciamos la clave a buscar
			cck = new CertificateCacheKey(issuer, serialNumber, service);

			// Buscamos el elemento en la caché
			res = cache.get(cck);
		    }
		}
	    }

	    // Si no hemos obtenido el elemento de la caché lo invocamos
	    if (res == null) {
		afirma5Invoker = getAfirma5InvokerInstance(service, applicationName, serviceProperties, idClient);
		res = afirma5Invoker.invokeService(method, serviceInParam);
	    }
	    // Si se debe almacenar la respuesta en la caché se lleva a cabo
	    addElementToCache(useCache, cck, res, idClient);
	} catch (Exception e) {
	    LOGGER.error(e);
	    throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.ASIF_LOG002, new Object[ ] { service }), e);
	}
	return res;
    }

    /**
     * Method that obtains an instance of {@link AbstractWSServiceInvoker}.
     * @param service Parameter that represents the name of the service to invoke.
     * @param applicationName Parameter that represents the customer application name.
     * @param serviceProperties Parameter that represents the collection of configuration settings to invoke the service.
     * @return an instance of {@link AbstractWSServiceInvoker}.
     * @param idClient Parameter that represents the client application identifier.
     * @throws WSServiceInvokerException If the method fails.
     */
    private AbstractWSServiceInvoker getAfirma5InvokerInstance(String service, String applicationName, Properties serviceProperties, String idClient) throws WSServiceInvokerException {
	if (serviceProperties == null) {
	    return Afirma5ServiceInvokerFactory.getAfirma5ServiceInvoker(applicationName, service, idClient);
	} else {
	    return Afirma5ServiceInvokerFactory.getAfirma5ServiceInvoker(service, serviceProperties);
	}
    }

    /**
     * Method that checks if it's necessary to add an entry to the certificates validation responses cache.
     * @param useCache Parameter that indicates if to use the certificates validation responses cache (true) or not (false).
     * @param cck Parameter that represents the key to add to the certificates validation responses cache.
     * @param res Parameter that represents the value to add to the certificates validation responses cache.
     * @param idClient Parameter that represents the client application identifier.
     * @throws WSServiceInvokerException If the method fails.
     */
    private void addElementToCache(boolean useCache, CertificateCacheKey cck, String res, String idClient) throws WSServiceInvokerException {
	if (useCache && cck != null) {
	    // Accedemos a la caché
	    CertificatesCache cache = CertificatesCache.getInstance(idClient);
	    // Añadimos la respuesta a la misma
	    cache.put(cck, res);
	}
    }

    /**
     * Method that obtains a certificate from an XML.
     * @param service Parameter that represents the service to invoke using the XML.
     * @param doc Parameter that represents the XML.
     * @return the certificate.
     * @throws Base64DecodingException If the method fails.
     * @throws CertificateException If the method fails.
     */
    private X509Certificate getCertificate(String service, Document doc) throws CertificateException, Base64DecodingException {
	X509Certificate certificate = null;
	// Si la llamada es al servicio DSS buscamos en el
	// nodo
	// dss:SignatureObject/dss:Other/ds:X509Data/ds:X509Certificate
	// el valor del certificado codificado en Base64
	if (service.equals(GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATE_REQUEST)) {
	    certificate = getCertificateBase64Encoded(doc, DSSTagsRequest.X509_CERTIFICATE);
	}
	// Si la llamada es al servicio nativo en inglés buscamos en
	// el nodo parameters/certificate
	// el valor del certificado codificado en Base64
	else if (service.equals(GeneralConstants.CERTIFICATE_VALIDATION_REQUEST)) {
	    certificate = getCertificateBase64Encoded(doc, NativeTagsRequest.CERTIFICATE);
	}
	// Si la llamada es al servicio nativo en inglés buscamos en
	// el nodo parametros/certificado
	// el valor del certificado codificado en Base64
	else {
	    certificate = getCertificateBase64Encoded(doc, NativeTagsRequest.CERTIFICADO);
	}
	return certificate;
    }
}
