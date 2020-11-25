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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.TSPInformation.java.</p>
 * <b>Description:</b><p>Class that defines a TSP Information with all its information not dependent
 * of the specification or TSL version.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/11/2020.
 */
package es.gob.afirma.tsl.parsing.impl.common;

import java.io.Serializable;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import es.gob.afirma.tsl.parsing.ifaces.IAnyTypeExtension;


/** 
 * <p>Class that defines a TSP Information with all its information not dependent
 * of the specification or TSL version.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2020.
 */
public class TSPInformation implements Serializable {

    /**
     * Attribute that represents . 
     */
    private static final long serialVersionUID = -3834421959705633792L;

    /**
	 * Attribute that represents the name of the legal entity responsible for the TSP
	 * in all the presented languages:
	 * Map<Language, List<Names>>.
	 */
	private Map<String, List<String>> tspNames = null;

	/**
	 * Attribute that represents the trade name of the legal entity responsible for the TSP
	 * in all the presented languages:
	 * Map<Language, List<TradeNames>>.
	 */
	private Map<String, List<String>> tspTradeNames = null;

	/**
	 * Attribute that represents the the address of the legal entity responsible for the TSP
	 * in all presented languages.
	 */
	private Address tspAddress = null;

	/**
	 * Attribute that represents the URI(s) where users (subscribers, relying parties)
	 * can obtain TSP-specific information in all presented languages.
	 */
	private Map<String, List<URI>> tspURIs = null;

	/**
	 * Attribute that represents a list with all the extensions associated to this TSP Information.
	 */
	private List<IAnyTypeExtension> tspInformationExtensions = null;

	/**
	 * Constructor method for the class TSPInformation.java.
	 */
	public TSPInformation() {
		super();
		tspNames = new HashMap<String, List<String>>();
		tspTradeNames = new HashMap<String, List<String>>();
		tspAddress = new Address();
		tspURIs = new HashMap<String, List<URI>>();
		tspInformationExtensions = new ArrayList<IAnyTypeExtension>();
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
	 * Gets the name for the specified language for this TSP.
	 * @param language language from which gets the names (ISO 639).
	 * @return List of string with the names for the input language. If there is not, then <code>null</code>.
	 */
	public final List<String> getTSPNamesForLanguage(String language) {

		return tspNames.get(language);

	}

	/**
	 * Adds a new name in a specified language for this TSP.
	 * @param language language to which add the name (ISO 639).
	 * @param name String that represents the name to add.
	 */
	public final void addNewName(String language, String name) {

		List<String> namesList = tspNames.get(language);
		if (namesList == null) {
			namesList = new ArrayList<String>();
		}
		namesList.add(name);
		tspNames.put(language, namesList);

	}

	/**
	 * Checks if there is at least one name for this TSP.
	 * @return <code>true</code> if there is, otherwise false.
	 */
	public final boolean isThereSomeName() {
		return !tspNames.isEmpty();
	}

	/**
	 * Gets all the TSP trade names in all the presented languages.
	 * @return Map with all the trade names in differents languages for this TSP.
	 * <code>null</code> if there is not.
	 */
	public final Map<String, List<String>> getAllTSPTradeNames() {

		if (tspTradeNames.isEmpty()) {
			return null;
		} else {
			return tspTradeNames;
		}

	}

	/**
	 * Gets the trade name for the specified language for this TSP.
	 * @param language language from which gets the trade names (ISO 639).
	 * @return List of string with the trade names for the input language.
	 * If there is not, then <code>null</code>.
	 */
	public final List<String> getTSPTradeNamesForLanguage(String language) {

		return tspTradeNames.get(language);

	}

	/**
	 * Adds a new trade name in a specified language for this TSP.
	 * @param language language to which add the trade name (ISO 639).
	 * @param name String that represents the trade name to add.
	 */
	public final void addNewTradeName(String language, String name) {

		List<String> tradeNamesList = tspTradeNames.get(language);
		if (tradeNamesList == null) {
			tradeNamesList = new ArrayList<String>();
		}
		tradeNamesList.add(name);
		tspTradeNames.put(language, tradeNamesList);

	}

	/**
	 * Checks if there is at least one trade name for this TSP.
	 * @return <code>true</code> if there is, otherwise false.
	 */
	public final boolean isThereSomeTradeName() {
		return !tspTradeNames.isEmpty();
	}

	/**
	 * Gets the value of the attribute {@link #tspAddress}.
	 * @return the value of the attribute {@link #tspAddress}.
	 */
	public final Address getTspAddress() {
		return tspAddress;
	}

	/**
	 * Sets the value of the attribute {@link #tspAddress}.
	 * @param tspAddressParam The value for the attribute {@link #tspAddress}.
	 */
	public final void setTspAddress(Address tspAddressParam) {
		this.tspAddress = tspAddressParam;
	}

	/**
	 * Gets all the URI in all the presented languages.
	 * @return Map with all the URI in differents languages for this TSP.
	 * <code>null</code> if there is not.
	 */
	public final Map<String, List<URI>> getAllURI() {

		if (tspURIs.isEmpty()) {
			return null;
		} else {
			return tspURIs;
		}

	}

	/**
	 * Gets the URI for the specified language for this TSP.
	 * @param language language from which gets the URI (ISO 639).
	 * @return List of URI for the input language.
	 * If there is not, then <code>null</code>.
	 */
	public final List<URI> getURIForLanguage(String language) {

		return tspURIs.get(language);

	}

	/**
	 * Adds a new URI in a specified language for this TSP.
	 * @param language language to which add the URI (ISO 639).
	 * @param uri String that represents the URI to add.
	 */
	public final void addNewURI(String language, URI uri) {

		List<URI> uriList = tspURIs.get(language);
		if (uriList == null) {
			uriList = new ArrayList<URI>();
		}
		uriList.add(uri);
		tspURIs.put(language, uriList);

	}

	/**
	 * Checks if there is at least one URI for this TSP.
	 * @return <code>true</code> if there is, otherwise false.
	 */
	public final boolean isThereSomeURI() {
		return !tspURIs.isEmpty();
	}

	/**
	 * Gets the value of the attribute {@link #tspInformationExtensions}.
	 * @return the value of the attribute {@link #tspInformationExtensions}.
	 */
	public final List<IAnyTypeExtension> getTspInformationExtensions() {
		return tspInformationExtensions;
	}

	/**
	 * Adds a new extension if it is not <code>null</code>.
	 * @param extension extension to add.
	 */
	public final void addNewTSPInformationExtension(IAnyTypeExtension extension) {
		if (extension != null) {
			tspInformationExtensions.add(extension);
		}
	}

	/**
	 * Checks if there is at least one TSP information extension.
	 * @return <code>true</code> if there is at least one TSP information extension, otherwise <code>false</code>.
	 */
	public final boolean isThereSomeTSPInformationExtension() {
		return tspInformationExtensions.isEmpty();
	}

}
