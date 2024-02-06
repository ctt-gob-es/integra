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
 * <b>File:</b><p>es.gob.afirma.tsl.elements.TslCountryRegion.java.</p>
 * <b>Description:</b><p> .</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 11/11/2020.
 */
package es.gob.afirma.tsl.elements;

import java.io.Serializable;


/** 
 * <p>Class the maps the <i>TSL_COUNTRY_REGION</i> database table as a Plain Old Java Object.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 11/11/2020.
 */
public class TslCountryRegion implements Serializable {

    /**
     * Attribute that represents . 
     */
    private static final long serialVersionUID = 5600491759534736186L;

    /**
	 * Attribute that represents the object ID.
	 */
	private Long idTslCountryRegion;

	/**
	 * Attribute that represents the country/region code for a TSL (ISO 3166).
	 */
	private String countryRegionCode;

	/**
	 * Attribute that represents the country/region name.
	 */
	private String countryRegionName;

	
	/**
	 * Gets the value of the attribute {@link #idTslCountryRegion}.
	 * @return the value of the attribute {@link #idTslCountryRegion}.
	 */
	public Long getIdTslCountryRegion() {
	    return idTslCountryRegion;
	}

	
	/**
	 * Sets the value of the attribute {@link #idTslCountryRegion}.
	 * @param idTslCountryRegion The value for the attribute {@link #idTslCountryRegion}.
	 */
	public void setIdTslCountryRegion(Long idTslCountryRegion) {
	    this.idTslCountryRegion = idTslCountryRegion;
	}

	
	/**
	 * Gets the value of the attribute {@link #countryRegionCode}.
	 * @return the value of the attribute {@link #countryRegionCode}.
	 */
	public String getCountryRegionCode() {
	    return countryRegionCode;
	}

	
	/**
	 * Sets the value of the attribute {@link #countryRegionCode}.
	 * @param countryRegionCode The value for the attribute {@link #countryRegionCode}.
	 */
	public void setCountryRegionCode(String countryRegionCode) {
	    this.countryRegionCode = countryRegionCode;
	}

	
	/**
	 * Gets the value of the attribute {@link #countryRegionName}.
	 * @return the value of the attribute {@link #countryRegionName}.
	 */
	public String getCountryRegionName() {
	    return countryRegionName;
	}

	
	/**
	 * Sets the value of the attribute {@link #countryRegionName}.
	 * @param countryRegionName The value for the attribute {@link #countryRegionName}.
	 */
	public void setCountryRegionName(String countryRegionName) {
	    this.countryRegionName = countryRegionName;
	}

	/**
	 * Attribute that represents the list of mappings associated to this TSL Country/Region.
	 */
	//private List<TslCountryRegionMapping> listTslCountryRegionMappings;

	/**
	 * Attribute that represents the TSL data associated to this country/region (if it is defined).
	 */
	//private TslData tslData;

}
