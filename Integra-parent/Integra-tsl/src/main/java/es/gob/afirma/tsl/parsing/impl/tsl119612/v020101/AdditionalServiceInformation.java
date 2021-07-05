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
// http://joinup.ec.europa.eu/software/page/eupl/licence-eupl

/** 
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.tsl119612.v020101.AdditionalServiceInformation.java.</p>
 * <b>Description:</b><p>Class that represents a TSL extension that provide additional information on a service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 15/06/2021.
 */
package es.gob.afirma.tsl.parsing.impl.tsl119612.v020101;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

import org.apache.log4j.Logger;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.exceptions.TSLMalformedException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.parsing.ifaces.IAnyTypeExtension;
import es.gob.afirma.tsl.parsing.ifaces.ITSLCommonURIs;
import es.gob.afirma.tsl.parsing.ifaces.ITSLElementsAndAttributes;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;
import es.gob.afirma.tsl.parsing.impl.common.extensions.Extension;
import es.gob.afirma.tsl.utils.UtilsStringChar;


/** 
 * <p>Class that represents a TSL extension that provide additional information on a service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 15/06/2021.
 */
public class AdditionalServiceInformation extends Extension {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = 3974521361488087185L;


	/**
	 * Attribute that represents the object that manages the log of the class.
	 */
	private static final Logger LOGGER = Logger.getLogger(AdditionalServiceInformation.class);

	/**
	 * Attribute that represents an URI identifying the additional information.
	 */
	private URI uri = null;

	/**
	 * Attribute that represents a string containing the serviceInformation value.
	 */
	private String informationValue = null;

	/**
	 * Constructor method for the class AdditionalServiceInformation.java.
	 * @param isCritical Flag to indicate if this extension is critical (<code>true</code>) or not (<code>false</code>).
	 * @param extensionType Extension type. Refer to its location inside the XML. It could be one of the following:
	 * <ul>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SCHEME}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_TSP_INFORMATION}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SERVICE_INFORMATION}</li>
	 * </ul>
	 */
	private AdditionalServiceInformation(boolean isCritical, int extensionType) {
		super(isCritical, extensionType, IAnyTypeExtension.IMPL_ADDITIONAL_SERVICE_INFORMATION);
	}

	/**
	 * Constructor method for the class AdditionalServiceInformation.java.
	 * @param uriServInf URI identifying the additional information.
	 * @param isCritical Flag to indicate if this extension is critical (<code>true</code>) or not (<code>false</code>).
	 * @param extensionType Extension type. Refer to its location inside the XML. It could be one of the following:
	 * <ul>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SCHEME}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_TSP_INFORMATION}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SERVICE_INFORMATION}</li>
	 * </ul>
	 */
	public AdditionalServiceInformation(URI uriServInf, boolean isCritical, int extensionType) {
		this(isCritical, extensionType);
		setUri(uriServInf);
	}

	/**
	 * Gets the value of the attribute {@link #uri}.
	 * @return the value of the attribute {@link #uri}.
	 */
	public final URI getUri() {
		return uri;
	}

	/**
	 * Sets the value of the attribute {@link #uri}.
	 * @param uriServInf The value for the attribute {@link #uri}.
	 */
	public final void setUri(URI uriServInf) {
		if (uriServInf != null) {
			String auxUriString = uriServInf.toString();
			if (auxUriString != null && auxUriString.endsWith(UtilsStringChar.SYMBOL_SLASH_STRING)) {
				try {
					this.uri = new URI(auxUriString.substring(0, auxUriString.length() - 1));
				} catch (URISyntaxException e) {
					this.uri = null;
				}
			} else {
				this.uri = uriServInf;
			}
		}
	}

	/**
	 * Gets the value of the attribute {@link #informationValue}.
	 * @return the value of the attribute {@link #informationValue}.
	 */
	public final String getInformationValue() {
		return informationValue;
	}

	/**
	 * Sets the value of the attribute {@link #informationValue}.
	 * @param informValue The value for the attribute {@link #informationValue}.
	 */
	public final void setInformationValue(String informValue) {
		this.informationValue = informValue;
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.extensions.Extension#checkExtensionTypeSpec119612Vers020101()
	 */
	@Override
	protected final void checkExtensionTypeSpec119612Vers020101() throws TSLMalformedException {

		// Esta extensión tan solo puede ser del tipo
		// 'ServiceInformationExtension'.
		if (getExtensionType() != IAnyTypeExtension.TYPE_SERVICE_INFORMATION) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ASI_LOG001, new Object[ ] { extensionTypeToString(IAnyTypeExtension.TYPE_SERVICE_INFORMATION), extensionTypeToString(getExtensionType()) }));
		}

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.mtsl.parsing.impl.common.extensions.Extension#checkExtensionValueSpec119612Vers020101(es.gob.afirma.mtsl.parsing.interfaces.ITSLObject, es.gob.afirma.mtsl.parsing.impl.common.ServiceHistoryInstance, boolean)
	 */
	@Override
	protected final void checkExtensionValueSpec119612Vers020101(ITSLObject tsl, ServiceHistoryInstance shi, boolean isCritical) throws TSLMalformedException {

		// El atributo uri es obligatorio.
		if (uri == null) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ASI_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_ADDITIONALSERVICEINFORMATION, ITSLElementsAndAttributes.ELEMENT_EXTENSION_ADDITIONALSERVICEINFORMATION_URI }));
		}

		// Pasamos a cadena la URI para poder compararla.
		String uriString = uri.toString();

		// La URI debe ser una de las permitidas.
		boolean isValid = uriString.equals(ITSLCommonURIs.TSL_SERVINFEXT_ADDSERVINFEXT_ROOTCAQC) || uriString.equals(ITSLCommonURIs.TSL_SERVINFEXT_ADDSERVINFEXT_FORESIGNATURES) || uriString.equals(ITSLCommonURIs.TSL_SERVINFEXT_ADDSERVINFEXT_FORESEALS);
		isValid = isValid || uriString.equals(ITSLCommonURIs.TSL_SERVINFEXT_ADDSERVINFEXT_FORWEBSITEAUTHENTICATION);

		if (!isValid) {
			if (isCritical) {
				throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ASI_LOG003, new Object[ ] { uriString }));
			} else {
				LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.ASI_LOG005, new Object[ ] { shi.getServiceNameInLanguage(Locale.UK.getLanguage()), uriString }));
			}
		}

		// Pasamos a cadena el tipo del servicio.
		String serviceType = shi.getServiceTypeIdentifier().toString();

		// Comprobamos las restricciones respecto a la URI y el tipo de servicio
		// asociado.
		if (ITSLCommonURIs.TSL_SERVINFEXT_ADDSERVINFEXT_ROOTCAQC.equals(uriString) && !ITSLCommonURIs.TSL_SERVICETYPE_CA_QC.equals(serviceType)) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.ASI_LOG004, new Object[ ] { ITSLCommonURIs.TSL_SERVINFEXT_ADDSERVINFEXT_ROOTCAQC, ITSLCommonURIs.TSL_SERVICETYPE_CA_QC }));
		}

	}

}
