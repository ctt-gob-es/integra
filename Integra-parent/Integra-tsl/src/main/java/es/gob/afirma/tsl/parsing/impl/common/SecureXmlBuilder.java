package es.gob.afirma.tsl.parsing.impl.common;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.logger.Logger;

/**
 * Constructor de objetos para la carga de docuemntos XML.
 */
public class SecureXmlBuilder {


    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = Logger.getLogger(SecureXmlBuilder.class);
    
	private static DocumentBuilderFactory SECURE_BUILDER_FACTORY = null;

	/**
	 * Obtiene un generador de &aacute;boles DOM con el que crear o cargar un XML.
	 * @return Generador de &aacute;rboles DOM.
	 * @throws ParserConfigurationException Cuando ocurre un error durante la creaci&oacute;n.
	 */
	public static DocumentBuilder getSecureDocumentBuilder() throws ParserConfigurationException {
		if (SECURE_BUILDER_FACTORY == null) {
			SECURE_BUILDER_FACTORY = DocumentBuilderFactory.newInstance();
			try {
				SECURE_BUILDER_FACTORY.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, Boolean.TRUE.booleanValue());
			}
			catch (final Exception e) {
				LOGGER.warn(ILogTslConstant.SXB_LOG001);
			}

			// Los siguientes atributos deberia establececerlos automaticamente la implementacion de
			// la biblioteca al habilitar la caracteristica anterior. Por si acaso, los establecemos
			// expresamente
			final String[] securityProperties = new String[] {
					javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD,
					javax.xml.XMLConstants.ACCESS_EXTERNAL_SCHEMA,
					javax.xml.XMLConstants.ACCESS_EXTERNAL_STYLESHEET
			};
			for (final String securityProperty : securityProperties) {
				try {
					SECURE_BUILDER_FACTORY.setAttribute(securityProperty, ""); //$NON-NLS-1$
				}
				catch (final Exception e) {
					// Podemos las trazas en debug ya que estas propiedades son adicionales
					// a la activacion de el procesado seguro
					LOGGER.debug(Language.getFormatResIntegraTsl(ILogTslConstant.SXB_LOG002, new String[] { securityProperty }));
				}
			}

			SECURE_BUILDER_FACTORY.setValidating(false);
			SECURE_BUILDER_FACTORY.setNamespaceAware(true);
		}
		return SECURE_BUILDER_FACTORY.newDocumentBuilder();
	}
}
