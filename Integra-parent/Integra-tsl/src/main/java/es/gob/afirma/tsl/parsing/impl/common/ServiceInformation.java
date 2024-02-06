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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.ServiceInformation.java.</p>
 * <b>Description:</b><p>Class that defines a TSP Service Information with all its information
 * not dependent of the specification or TSL version.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/11/2020.
 */
package es.gob.afirma.tsl.parsing.impl.common;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** 
 * <p>Class that defines a TSP Service Information with all its information
 * not dependent of the specification or TSL version.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2020.
 */
public class ServiceInformation extends ServiceHistoryInstance {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = -7372148867536900402L;
    /**
	 * Attribute that represents the URI(s) where users (subscribers, relying parties)
	 * can obtain service-specific information provided by the scheme operator in all presented
	 * languages.
	 */
	private Map<String, List<URI>> schemeServiceDefinitionURIs = null;

	/**
	 * Attribute that represents one or more URIs where users (subscribers, relying parties)
	 * can access the service.
	 */
	private List<URI> serviceSupplyPointsTSL = null;

	/**
	 * Attribute that represents the URI(s) where users (subscribers, relying parties)
	 * can obtain service-specific information provided by the TSP in all presented
	 * languages.
	 */
	private Map<String, List<URI>> serviceDefinitionURIs = null;

	/**
	 * Constructor method for the class ServiceInformation.java.
	 */
	public ServiceInformation() {
		super();
		schemeServiceDefinitionURIs = new HashMap<String, List<URI>>();
		serviceSupplyPointsTSL = new ArrayList<URI>();
		serviceDefinitionURIs = new HashMap<String, List<URI>>();
	}

	/**
	 * Gets the URI(s) where users (subscribers, relying parties)
	 * can obtain service-specific information provided by the scheme operator
	 * in all presented languages.
	 * @return Map by language with the URI. <code>null</code> if there is not URI.
	 */
	public final Map<String, List<URI>> getSchemeServiceDefinitionURIs() {

		if (schemeServiceDefinitionURIs.isEmpty()) {
			return null;
		} else {
			return schemeServiceDefinitionURIs;
		}

	}

	/**
	 * Adds a new URI with the specified language to the scheme service definitions.
	 * @param language Language representation (ISO 639) for the URI.
	 * @param ssdUri URI to add.
	 */
	public final void addNewSchemeServiceDefinitionURI(String language, URI ssdUri) {

		List<URI> uriList = schemeServiceDefinitionURIs.get(language);
		if (uriList == null) {
			uriList = new ArrayList<URI>();
		}
		uriList.add(ssdUri);
		schemeServiceDefinitionURIs.put(language, uriList);

	}

	/**
	 * Checks if exists at least one scheme service definition URI.
	 * @return <code>true</code> if there is, otherwise <code>false</code>.
	 */
	public final boolean isThereSomeSchemeServiceDefinitionURI() {
		return !schemeServiceDefinitionURIs.isEmpty();
	}

	/**
	 * Gets an array with the Service Supply Points URI.
	 * @return list with the Service Supply Points URI.
	 * <code>null</code> if there is not.
	 */
	public final List<URI> getServiceSupplyPoints() {

		if (serviceSupplyPointsTSL.isEmpty()) {
			return null;
		} else {
			return serviceSupplyPointsTSL;
		}

	}

	/**
	 * Add new service supply point URI.
	 * @param sspUri URI with the new service supply point to add.
	 */
	public final void addNewServiceSupplyPointURI(URI sspUri) {
		serviceSupplyPointsTSL.add(sspUri);
	}

	/**
	 * Checks if there is at least one service supply point.
	 * @return <code>true</code> if there is, otherwise <code>false</code>.
	 */
	public final boolean isThereSomeServiceSupplyPointURI() {
		return !serviceSupplyPointsTSL.isEmpty();
	}

	/**
	 * Gets the URI(s) where users (subscribers, relying parties)
	 * can obtain service-specific information provided by the TSP
	 * in all presented languages.
	 * @return Map by language with the URI. <code>null</code> if there is not URI.
	 */
	public final Map<String, List<URI>> getServiceDefinitionURIs() {

		if (serviceDefinitionURIs.isEmpty()) {
			return null;
		} else {
			return serviceDefinitionURIs;
		}

	}

	/**
	 * Adds a new URI with the specified language to the TSP definitions.
	 * @param language Language representation (ISO 639) for the URI.
	 * @param sdUri URI to add.
	 */
	public final void addNewServiceDefinitionURI(String language, URI sdUri) {

		List<URI> uriList = serviceDefinitionURIs.get(language);
		if (uriList == null) {
			uriList = new ArrayList<URI>();
		}
		uriList.add(sdUri);
		serviceDefinitionURIs.put(language, uriList);

	}

	/**
	 * Checks if exists at least one TSP definition URI.
	 * @return <code>true</code> if there is, otherwise <code>false</code>.
	 */
	public final boolean isThereSomeServiceDefinitionURI() {
		return !serviceDefinitionURIs.isEmpty();
	}

}
