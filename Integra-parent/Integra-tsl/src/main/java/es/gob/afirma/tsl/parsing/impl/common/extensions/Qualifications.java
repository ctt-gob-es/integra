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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.extensions.Qualifications.java.</p>
 * <b>Description:</b><p>Class that represents a qualification criteria extension. The qualification criteria
 * is specified by a set of Qualification Elements, each one expressed as a list of assertions to be verified
 * and a list of qualifiers that apply to the examined certificate when all the assertions are verified.
 * The certificate is qualified with all the qualifiers obtained with the application of all the qualification
 * elements.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 15/06/2021.
 */
package es.gob.afirma.tsl.parsing.impl.common.extensions;

import java.util.ArrayList;
import java.util.List;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.exceptions.TSLMalformedException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.parsing.ifaces.IAnyTypeExtension;
import es.gob.afirma.tsl.parsing.ifaces.ITSLCommonURIs;
import es.gob.afirma.tsl.parsing.ifaces.ITSLElementsAndAttributes;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;


/** 
 * <p>Class that represents a qualification criteria extension. The qualification criteria
 * is specified by a set of Qualification Elements, each one expressed as a list of assertions to be verified
 * and a list of qualifiers that apply to the examined certificate when all the assertions are verified.
 * The certificate is qualified with all the qualifiers obtained with the application of all the qualification
 * elements.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 15/06/2021.
 */
public class Qualifications extends Extension {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = -871789508404312128L;

    /**
	 * Attribute that represents the qualifications extension list.
	 */
	private List<QualificationElement> qualificationsList = null;

	/**
	 * Constructor method for the class Qualifications.java.
	 * @param isCritical Flag to indicate if this extension is critical (<code>true</code>) or not (<code>false</code>).
	 * @param extensionType Extension type. Refer to its location inside the XML. It could be one of the following:
	 * <ul>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SCHEME}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_TSP_INFORMATION}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SERVICE_INFORMATION}</li>
	 * </ul>
	 */
	public Qualifications(boolean isCritical, int extensionType) {
		super(isCritical, extensionType, IAnyTypeExtension.IMPL_QUALIFICATIONS);
		qualificationsList = new ArrayList<QualificationElement>();
	}

	/**
	 * Gets the value of the attribute {@link #qualificationsList}.
	 * @return the value of the attribute {@link #qualificationsList}.
	 */
	public final List<QualificationElement> getQualificationsList() {
		return qualificationsList;
	}

	/**
	 * Adds new Qualification Element to the list if it is not <code>null</code>.
	 * @param qe Qualification Element to add.
	 */
	public final void addNewQualificationElement(QualificationElement qe) {
		if (qe != null) {
			qualificationsList.add(qe);
		}
	}

	/**
	 * Checks if there is at least one qualification element.
	 * @return <code>true</code> if there is at least one qualification element. otherwise <code>false</code>.
	 */
	public final boolean isThereSomeQualificationElement() {
		return !qualificationsList.isEmpty();
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
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.EXT_LOG008, new Object[ ] { extensionTypeToString(IAnyTypeExtension.TYPE_SERVICE_INFORMATION), extensionTypeToString(getExtensionType()) }));
		}

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.extensions.Extension#checkExtensionValueSpec119612Vers020101(es.gob.afirma.tsl.parsing.ifaces.ITSLObject, es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance, boolean)
	 */
	@Override
	protected final void checkExtensionValueSpec119612Vers020101(ITSLObject tsl, ServiceHistoryInstance shi, boolean isCritical) throws TSLMalformedException {

		// El tipo de servicio debe ser "CA/QC".
		String serviceType = shi.getServiceTypeIdentifier().toString();
		if (!serviceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_CA_QC)) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.EXT_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_QUALIFICATIONS, serviceType }));
		}

		// La lista de "Qualifications" no puede ser vacía.
		if (qualificationsList.isEmpty()) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.EXT_LOG004, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_QUALIFICATIONS }));
		} else {
			for (QualificationElement qualificationElement: qualificationsList) {
				qualificationElement.checkExtensionValueSpec119612Vers020101(tsl, shi, isCritical);
			}
		}

	}

}
