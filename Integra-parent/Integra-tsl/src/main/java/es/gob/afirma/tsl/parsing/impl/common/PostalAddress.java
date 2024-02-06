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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.PostalAddress.java.</p>
 * <b>Description:</b><p>Class that represents a Postal Address with all its information
 * not dependent of the specification or TSL version.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/11/2020.
 */
package es.gob.afirma.tsl.parsing.impl.common;

import java.io.Serializable;


/** 
 * <p>Class that represents a Postal Address with all its information
 * not dependent of the specification or TSL version.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2020.
 */
public class PostalAddress implements Serializable {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = 649319566847944187L;

    /**
	 * Attribute that represents the street address.
	 */
	private String street = null;

	/**
	 * Attribute that represents the locality.
	 */
	private String locality = null;

	/**
	 * Attribute that represents the state or province.
	 */
	private String stateOrProvince = null;

	/**
	 * Attribute that represents the postal code.
	 */
	private String postalCode = null;

	/**
	 * Attribute that represents the country name.
	 */
	private String countryName = null;

	/**
	 * Constructor method for the class PostalAddress.java.
	 */
	public PostalAddress() {
		super();
	}

	/**
	 * Constructor method for the class PostalAddress.java.
	 * @param streetAddress String with the street address of the Postal Address.
	 * @param localityAddress String with the locality of the Postal Address.
	 * @param stateOrProvinceAddress String with the state or province of the Postal Address.
	 * @param postalCodeAddress String with the postal code of the Postal Address.
	 * @param countryNameAddress String with the country name of the Postal Address.
	 */
	public PostalAddress(String streetAddress, String localityAddress, String stateOrProvinceAddress, String postalCodeAddress, String countryNameAddress) {

		this();
		street = streetAddress;
		locality = localityAddress;
		stateOrProvince = stateOrProvinceAddress;
		postalCode = postalCodeAddress;
		countryName = countryNameAddress;

	}

	/**
	 * Gets the value of the attribute {@link #street}.
	 * @return the value of the attribute {@link #street}.
	 */
	public final String getStreet() {
		return street;
	}

	/**
	 * Sets the value of the attribute {@link #street}.
	 * @param streetParam The value for the attribute {@link #street}.
	 */
	public final void setStreet(String streetParam) {
		this.street = streetParam;
	}

	/**
	 * Gets the value of the attribute {@link #locality}.
	 * @return the value of the attribute {@link #locality}.
	 */
	public final String getLocality() {
		return locality;
	}

	/**
	 * Sets the value of the attribute {@link #locality}.
	 * @param localityParam The value for the attribute {@link #locality}.
	 */
	public final void setLocality(String localityParam) {
		this.locality = localityParam;
	}

	/**
	 * Gets the value of the attribute {@link #stateOrProvince}.
	 * @return the value of the attribute {@link #stateOrProvince}.
	 */
	public final String getStateOrProvince() {
		return stateOrProvince;
	}

	/**
	 * Sets the value of the attribute {@link #stateOrProvince}.
	 * @param stateOrProvinceParam The value for the attribute {@link #stateOrProvince}.
	 */
	public final void setStateOrProvince(String stateOrProvinceParam) {
		this.stateOrProvince = stateOrProvinceParam;
	}

	/**
	 * Gets the value of the attribute {@link #postalCode}.
	 * @return the value of the attribute {@link #postalCode}.
	 */
	public final String getPostalCode() {
		return postalCode;
	}

	/**
	 * Sets the value of the attribute {@link #postalCode}.
	 * @param postalCodeParam The value for the attribute {@link #postalCode}.
	 */
	public final void setPostalCode(String postalCodeParam) {
		this.postalCode = postalCodeParam;
	}

	/**
	 * Gets the value of the attribute {@link #countryName}.
	 * @return the value of the attribute {@link #countryName}.
	 */
	public final String getCountryName() {
		return countryName;
	}

	/**
	 * Sets the value of the attribute {@link #countryName}.
	 * @param countryNameParam The value for the attribute {@link #countryName}.
	 */
	public final void setCountryName(String countryNameParam) {
		this.countryName = countryNameParam;
	}
}
