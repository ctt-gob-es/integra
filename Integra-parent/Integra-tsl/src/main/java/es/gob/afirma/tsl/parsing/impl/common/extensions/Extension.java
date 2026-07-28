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
// https://eupl.eu/1.1/es/

/** 
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.extensions.Extension.java.</p>
 * <b>Description:</b><p>Abstract class that represents a TSL Extension with could contains differents elements
 * regardless it implementation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 11/11/2020.
 */
package es.gob.afirma.tsl.parsing.impl.common.extensions;

import es.gob.afirma.tsl.exceptions.TSLMalformedException;
import es.gob.afirma.tsl.parsing.ifaces.IAnyTypeExtension;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;


/** 
 * <p>Abstract class that represents a TSL Extension with could contains differents elements
 * regardless it implementation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 11/11/2020.
 */
public abstract class Extension implements IAnyTypeExtension {

	/**
     * Attribute that represents the serial version UID. 
     */
    private static final long serialVersionUID = -8901066099998538703L;

	/**
	 * Attribute that represents if this extension is marked how critical (<code>true</code>) or not (<code>false</code>).
	 */
	private boolean critical = false;

	/**
	 * Attribute that represents the extension type, refers to its location inside the XML.
	 * It could be one of the following:<br>
	 * <ul>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SCHEME}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_TSP_INFORMATION}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SERVICE_INFORMATION}</li>
	 * </ul>
	 */
	private int type = -1;

	/**
	 * Attribute that represents the implementation of the extension.
	 * It must be one of the following:<br>
	 * <ul>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#IMPL_ADDITIONAL_SERVICE_INFORMATION}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#IMPL_EXPIRED_CERTS_REVOCATION_INFO}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#IMPL_QUALIFICATIONS}</li>
	 *  <li>Scheme Extension: {@link IAnyTypeExtension#IMPL_TAKENOVERBY}</li>
	 *  <li>Scheme Extension: {@link IAnyTypeExtension#IMPL_UNKNOWN_EXTENSION}</li>
	 * </ul>
	 */
	private int implementation = -1;

	/**
	 * Constructor method for the class Extension.java.
	 */
	private Extension() {
		super();
	}

	/**
	 * Constructor method for the class Extension.java.
	 * @param isCritical Flag to indicate if this extension is critical (<code>true</code>) or not (<code>false</code>).
	 * @param extensionType Extension type. Refer to its location inside the XML. It could be one of the following:<br>
	 * <ul>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SCHEME}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_TSP_INFORMATION}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SERVICE_INFORMATION}</li>
	 * </ul>
	 * @param implementationExtension Implementation Extension. It must be one of the following:<br>
	 * <ul>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#IMPL_ADDITIONAL_SERVICE_INFORMATION}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#IMPL_EXPIRED_CERTS_REVOCATION_INFO}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#IMPL_QUALIFICATIONS}</li>
	 *  <li>Scheme Extension: {@link IAnyTypeExtension#IMPL_TAKENOVERBY}</li>
	 *  <li>Scheme Extension: {@link IAnyTypeExtension#IMPL_UNKNOWN_EXTENSION}</li>
	 * </ul>
	 */
	protected Extension(boolean isCritical, int extensionType, int implementationExtension) {
		this();
		critical = isCritical;
		type = extensionType;
		implementation = implementationExtension;
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.ifaces.IAnyTypeExtension#isCritical()
	 */
	public final boolean isCritical() {
		return critical;
	}

	/**
	 * Gets the value of the attribute {@link #type}.
	 * @return the value of the attribute {@link #type}.
	 */
	public final int getExtensionType() {
		return type;
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.ifaces.IAnyTypeExtension#getImplementationExtension()
	 */
	@Override
	public final int getImplementationExtension() {
		return implementation;
	}

	/**
	 * Gets a string name representation of the specified extension type.
	 * @param extensionType Extension type. Refer to its location inside the XML. It could be one of the following:
	 * <ul>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SCHEME}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_TSP_INFORMATION}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SERVICE_INFORMATION}</li>
	 * </ul>
	 * @return string name representation of the specified extension type.
	 */
	public final String extensionTypeToString(int extensionType) {

		String result = null;
		switch (extensionType) {
			case IAnyTypeExtension.TYPE_SCHEME:
				result = "Scheme Extension";
				break;

			case IAnyTypeExtension.TYPE_TSP_INFORMATION:
				result = "TSP Information Extension";
				break;

			case IAnyTypeExtension.TYPE_SERVICE_INFORMATION:
				result = "Service Information Extension";
				break;

			default:
				result = "Unknown Extension";
				break;
		}

		return result;

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.ifaces.IAnyTypeExtension#checkExtensionValue(es.gob.afirma.tsl.parsing.ifaces.ITSLObject, es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance)
	 */
	@Override
	public final void checkExtensionValue(ITSLObject tsl, ServiceHistoryInstance shi) throws TSLMalformedException {
	    	checkExtensionTypeSpec119612Vers020101();
		checkExtensionValueSpec119612Vers020101(tsl, shi, isCritical());
	    
//		// En función de la especificación y versión de esta, se actúa de una
//		// manera u otra.
//		String tslSpecification = tsl.getSpecification();
//		String tslSpecificationVersion = tsl.getSpecificationVersion();
//
//		switch (tslSpecification) {
//			case ITSLSpecificationsVersions.SPECIFICATION_119612:
//
//				switch (tslSpecificationVersion) {
//					case ITSLSpecificationsVersions.VERSION_020101:
//						checkExtensionTypeSpec119612Vers020101();
//						checkExtensionValueSpec119612Vers020101(tsl, shi, isCritical());
//						break;
//
//					default:
//						break;
//				}
//
//				break;
//
//			default:
//				break;
//		}

	}

	/**
	 * Checks if the extension type is the appropriate for this extension for the specification ETSI 119612
	 * and version 2.1.1.
	 * @throws TSLMalformedException Incase of the extension type is not the appropriate.
	 */
	protected abstract void checkExtensionTypeSpec119612Vers020101() throws TSLMalformedException;

	/**
	 * Checks if the extension has an appropiate value in the TSL for the specification ETSI 119612
	 * and version 2.1.1.
	 * @param tsl TSL Object representation that contains the service and the extension.
	 * @param shi Service Information (or service history information) in which is declared the extension.
	 * @param isCritical Indicates if the extension is critical (<code>true</code>) or not (<code>false</code>).
	 * @throws TSLMalformedException In case of the extension has not a correct value.
	 */
	protected abstract void checkExtensionValueSpec119612Vers020101(ITSLObject tsl, ServiceHistoryInstance shi, boolean isCritical) throws TSLMalformedException;


}
