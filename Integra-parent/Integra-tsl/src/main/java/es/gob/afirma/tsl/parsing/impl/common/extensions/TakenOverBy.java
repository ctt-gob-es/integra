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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.extensions.TakenOverBy.java.</p>
 * <b>Description:</b><p>Class that represents a TakenOverBy TSL extension.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 15/06/2021.
 */
package es.gob.afirma.tsl.parsing.impl.common.extensions;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.exceptions.TSLMalformedException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.parsing.ifaces.IAnyTypeExtension;
import es.gob.afirma.tsl.parsing.ifaces.ITSLElementsAndAttributes;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;
import es.gob.afirma.tsl.utils.UtilsCountryLanguage;
import es.gob.afirma.tsl.utils.UtilsStringChar;


/** 
 * <p>Class that represents a TakenOverBy TSL extension.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 15/06/2021.
 */
public class TakenOverBy extends Extension {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = 6275736212553679787L;

    /**
	 * Attribute that represents the URI element.
	 */
	private URI uri = null;

	/**
	 * Attribute that represents the name of the legal entity responsible for the TSP
	 * in all the presented languages:
	 * Map&lt;Language, List&lt;Names&gt;&gt;.
	 */
	private Map<String, List<String>> tspNames = null;

	/**
	 * Attribute that represents the formal name under which the scheme operator
	 * does business or is given its mandate in all presented languages.
	 */
	private Map<String, String> schemeOperatorNames = null;

	/**
	 * Attribute that represents he country or territory in which the
	 * scheme is established.
	 */
	private String schemeTerritory = null;

	/**
	 * Constructor method for the class TakenOverBy.java.
	 * @param isCritical Flag to indicate if this extension is critical (<code>true</code>) or not (<code>false</code>).
	 * @param extensionType Extension type. Refer to its location inside the XML. It could be one of the following:
	 * <ul>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SCHEME}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_TSP_INFORMATION}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SERVICE_INFORMATION}</li>
	 * </ul>
	 */
	public TakenOverBy(boolean isCritical, int extensionType) {
		super(isCritical, extensionType, IAnyTypeExtension.IMPL_TAKENOVERBY);
		tspNames = new HashMap<String, List<String>>();
		schemeOperatorNames = new HashMap<String, String>();
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
	 * @param uriParam The value for the attribute {@link #uri}.
	 */
	public final void setUri(URI uriParam) {
		this.uri = uriParam;
	}

	/**
	 * Gets all the TSP names in all the presented languages.
	 * @return Map with all the names in differents languages for this TSP.
	 * <code>null</code> if there is not.
	 */
	public final Map<String, List<String>> getAllTSPNames() {

		if (tspNames.isEmpty()) {
			return null;
		} else {
			return tspNames;
		}

	}

	/**
	 * Gets the TSP name for the specified language.
	 * @param language language from which gets the names (ISO 639).
	 * @return List of string with the names for the input language. If there is not, then <code>null</code>.
	 */
	public final List<String> getTSPNamesForLanguage(String language) {
		return tspNames.get(language);
	}

	/**
	 * Adds a new TSP name in a specified language.
	 * @param language language to which add the name (ISO 639).
	 * @param name String that represents the name to add.
	 */
	public final void addNewTSPName(String language, String name) {

		List<String> namesList = tspNames.get(language);
		if (namesList == null) {
			namesList = new ArrayList<String>();
		}
		namesList.add(name);
		tspNames.put(language, namesList);

	}

	/**
	 * Checks if there is at least one TSP name.
	 * @return <code>true</code> if there is, otherwise false.
	 */
	public final boolean isThereSomeTSPName() {
		return !tspNames.isEmpty();
	}

	/**
	 * Gets the value of the attribute {@link #schemeOperatorNames}.
	 * @return the value of the attribute {@link #schemeOperatorNames}.
	 */
	public final Map<String, String> getAllSchemeOperatorNames() {
		return schemeOperatorNames;
	}

	/**
	 * Gets the scheme operator name for the specified language.
	 * @param language Language from which gets the scheme operator name.
	 * @return the scheme operator name for the specified language, or <code>null</code>
	 * if not exists for that language.
	 */
	public final String getSchemeOperatorNameInLanguage(String language) {
		return schemeOperatorNames.get(language);
	}

	/**
	 * Adds a new scheme operator name for the specified language.
	 * @param language language to which associate the new scheme operator name. If
	 * it is <code>null</code>, then this method do nothing.
	 * @param schemeOperatorName Scheme operator name.
	 */
	public final void addNewSchemeOperatorName(String language, String schemeOperatorName) {
		if (language != null) {
			schemeOperatorNames.put(language, schemeOperatorName);
		}
	}

	/**
	 * Checks if there is at least one scheme operator name.
	 * @return <code>true</code> if there is, otherwise false.
	 */
	public final boolean isThereSomeSchemeOperatorName() {
		return !schemeOperatorNames.isEmpty();
	}

	/**
	 * Gets the value of the attribute {@link #schemeTerritory}.
	 * @return the value of the attribute {@link #schemeTerritory}.
	 */
	public final String getSchemeTerritory() {
		return schemeTerritory;
	}

	/**
	 * Sets the value of the attribute {@link #schemeTerritory}.
	 * @param schemeTerritoryParam The value for the attribute {@link #schemeTerritory}.
	 */
	public final void setSchemeTerritory(String schemeTerritoryParam) {
		this.schemeTerritory = schemeTerritoryParam;
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
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.EXT_LOG001, new Object[ ] { extensionTypeToString(IAnyTypeExtension.TYPE_SERVICE_INFORMATION), extensionTypeToString(getExtensionType()) }));
		}

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.extensions.Extension#checkExtensionValueSpec119612Vers020101(es.gob.afirma.tsl.parsing.ifaces.ITSLObject, es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance, boolean)
	 */
	@Override
	protected final void checkExtensionValueSpec119612Vers020101(ITSLObject tsl, ServiceHistoryInstance shi, boolean isCritical) throws TSLMalformedException {

		// Todos los atributos de esta extensión deben tener un valor asignado.
		if (uri == null) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.EXT_LOG006, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_TAKENOVERBY_LOCALNAME, ITSLElementsAndAttributes.ELEMENT_EXTENSION_TAKENOVERBY_URI }));
		}
		if (tspNames.isEmpty()) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.EXT_LOG006, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_TAKENOVERBY_LOCALNAME, ITSLElementsAndAttributes.ELEMENT_EXTENSION_TAKENOVERBY_TSPNAME }));
		}
		if (schemeOperatorNames.isEmpty()) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.EXT_LOG006, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_TAKENOVERBY_LOCALNAME, ITSLElementsAndAttributes.ELEMENT_EXTENSION_TAKENOVERBY_SCHEMEOPERATORNAME }));
		}
		if (UtilsStringChar.isNullOrEmptyTrim(schemeTerritory) || !UtilsCountryLanguage.checkCountryCode(schemeTerritory)) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.EXT_LOG006, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_TAKENOVERBY_LOCALNAME, ITSLElementsAndAttributes.ELEMENT_EXTENSION_TAKENOVERBY_SCHEMETERRITORY }));
		}

	}

}
