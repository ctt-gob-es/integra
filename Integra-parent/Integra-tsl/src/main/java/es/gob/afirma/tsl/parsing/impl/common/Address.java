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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.Address.java.</p>
 * <b>Description:</b><p>Class that represents an Address with all its information
 * not dependent of the specification or TSL version.</p>
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

/** 
 * <p>Class that represents an Address with all its information
 * not dependent of the specification or TSL version.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2020.
 */
public class Address implements Serializable {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = -1686647392745605405L;
    /**
	 * Attribute that represents the postal addresses in all the presented languages.
	 */
	private Map<String, List<PostalAddress>> postalAddresses = null;

	/**
	 * Attribute that represents the electronic addresses in all the presented languages.
	 */
	private Map<String, List<URI>> electronicAddresses = null;

	/**
	 * Constructor method for the class Address.java.
	 */
	public Address() {
		super();
		postalAddresses = new HashMap<String, List<PostalAddress>>();
		electronicAddresses = new HashMap<String, List<URI>>();
	}

	/**
	 * Gets the value of the attribute {@link #postalAddresses}.
	 * @return the value of the attribute {@link #postalAddresses}.
	 */
	public final Map<String, List<PostalAddress>> getPostalAddresses() {
		return postalAddresses;
	}

	/**
	 * Adds a new Postal Addres for the specified language.
	 * @param language language to which add a new postal address.
	 * @param pa Postal Address to add.
	 */
	public final void addNewPostalAddress(String language, PostalAddress pa) {

		if (language != null && pa != null) {

			List<PostalAddress> paList = postalAddresses.get(language);
			if (paList == null) {
				paList = new ArrayList<PostalAddress>();
			}
			paList.add(pa);
			postalAddresses.put(language, paList);

		}

	}

	/**
	 * Sets the value of the attribute {@link #postalAddresses}.
	 * @param paList The value for the attribute {@link #postalAddresses}.
	 */
	public final void setPostalAddresses(Map<String, List<PostalAddress>> paList) {
		this.postalAddresses = paList;
	}

	/**
	 * Checks if there is some postal address added to this address.
	 * @return <code>true</code> if there is, otherwise <code>false</code>.
	 */
	public final boolean isThereSomePostalAddress() {
		return !postalAddresses.isEmpty();
	}

	/**
	 * Gets the value of the attribute {@link #electronicAddresses}.
	 * @return the value of the attribute {@link #electronicAddresses}.
	 */
	public final Map<String, List<URI>> getElectronicAddresses() {
		return electronicAddresses;
	}

	/**
	 * Adds a new Electronic Addres for the specified language.
	 * @param language language to which add a new electronic address.
	 * @param ea Electronic address to add.
	 */
	public final void addNewElectronicAddress(String language, URI ea) {

		if (language != null && ea != null) {

			List<URI> eaList = electronicAddresses.get(language);
			if (eaList == null) {
				eaList = new ArrayList<URI>();
			}
			eaList.add(ea);
			electronicAddresses.put(language, eaList);
		}

	}

	/**
	 * Sets the value of the attribute {@link #electronicAddresses}.
	 * @param eaList The value for the attribute {@link #electronicAddresses}.
	 */
	public final void setElectronicAddresses(Map<String, List<URI>> eaList) {
		this.electronicAddresses = eaList;
	}

	/**
	 * Checks if there is some electronic address added to this address.
	 * @return <code>true</code> if there is, otherwise <code>false</code>.
	 */
	public final boolean isThereSomeElectronicAddress() {
		return !electronicAddresses.isEmpty();
	}

}
