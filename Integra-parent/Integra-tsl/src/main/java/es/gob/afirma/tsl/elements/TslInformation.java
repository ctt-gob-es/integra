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
 * <b>File:</b><p>es.gob.afirma.tsl.elements.TslInformation.java.</p>
 * <b>Description:</b><p>Class that represents structure of a TSL information request.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/10/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/10/2020.
 */
package es.gob.afirma.tsl.elements;

import java.io.Serializable;

import es.gob.afirma.tsl.elements.json.ByteArrayB64;
import es.gob.afirma.tsl.elements.json.DateString;


/** 
 * <p>Class that represents structure of a TSL information request.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/10/2020.
 */
public class TslInformation implements Serializable {

    /**
     * Constant attribute that represents the serial version UID. 
     */
    private static final long serialVersionUID = 3486950117377324414L;
    /**
	 * Attribute that represents the ETSI specification and its version that implements the TSL.
	 */
	private String etsiSpecificationAndVersion;

	/**
	 * Attribute that represents the country region in TSL information.
	 */
	private String countryRegion;

	/**
	 * Attribute that represents the sequence number in TSL information.
	 */
	private Integer sequenceNumber;

	/**
	 * Attribute that represents the location in TSL information.
	 */
	private String tslLocation;

	/**
	 * Attribute that represents the issued date in TSL information.
	 */
	private DateString issued;

	/**
	 * Attribute that represents the next update date in TSL information.
	 */
	private DateString nextUpdate;

	/**
	 * Attribute that represents the xml data in TSL information.
	 */
	private ByteArrayB64 tslXmlData;

	/**
	 * Gets the value of the attribute {@link #etsiSpecificationAndVersion}.
	 * @return the value of the attribute {@link #etsiSpecificationAndVersion}.
	 */
	public final String getEtsiSpecificationAndVersion() {
		return etsiSpecificationAndVersion;
	}

	/**
	 * Sets the value of the attribute {@link #etsiSpecificationAndVersion}.
	 * @param etsiSpecificationAndVersionParam The value for the attribute {@link #etsiSpecificationAndVersion}.
	 */
	public final void setEtsiSpecificationAndVersion(String etsiSpecificationAndVersionParam) {
		this.etsiSpecificationAndVersion = etsiSpecificationAndVersionParam;
	}

	/**
	 * Gets the value of the attribute {@link #countryRegion}.
	 * @return the value of the attribute {@link #countryRegion}.
	 */
	public String getCountryRegion() {
		return countryRegion;
	}

	/**
	 * Sets the value of the attribute {@link #countryRegion}.
	 * @param countryRegionParam The value for the attribute {@link #countryRegion}.
	 */
	public void setCountryRegion(final String countryRegionParam) {
		this.countryRegion = countryRegionParam;
	}

	/**
	 * Gets the value of the attribute {@link #sequenceNumber}.
	 * @return the value of the attribute {@link #sequenceNumber}.
	 */
	public Integer getSequenceNumber() {
		return sequenceNumber;
	}

	/**
	 * Sets the value of the attribute {@link #sequenceNumber}.
	 * @param sequenceNumberParam The value for the attribute {@link #sequenceNumber}.
	 */
	public void setSequenceNumber(final Integer sequenceNumberParam) {
		this.sequenceNumber = sequenceNumberParam;
	}

	/**
	 * Gets the value of the attribute {@link #tslLocation}.
	 * @return the value of the attribute {@link #tslLocation}.
	 */
	public String getTslLocation() {
		return tslLocation;
	}

	/**
	 * Sets the value of the attribute {@link #tslLocation}.
	 * @param tslLocationParam The value for the attribute {@link #tslLocation}.
	 */
	public void setTslLocation(final String tslLocationParam) {
		this.tslLocation = tslLocationParam;
	}

	/**
	 * Gets the value of the attribute {@link #issued}.
	 * @return the value of the attribute {@link #issued}.
	 */
	public DateString getIssued() {
		return issued;
	}

	/**
	 * Sets the value of the attribute {@link #issued}.
	 * @param issuedParam The value for the attribute {@link #issued}.
	 */
	public void setIssued(final DateString issuedParam) {
		this.issued = issuedParam;
	}

	/**
	 * Gets the value of the attribute {@link #nextUpdate}.
	 * @return the value of the attribute {@link #nextUpdate}.
	 */
	public DateString getNextUpdate() {
		return nextUpdate;
	}

	/**
	 * Sets the value of the attribute {@link #nextUpdate}.
	 * @param nextUpdateParam The value for the attribute {@link #nextUpdate}.
	 */
	public void setNextUpdate(final DateString nextUpdateParam) {
		this.nextUpdate = nextUpdateParam;
	}

	/**
	 * Gets the value of the attribute {@link #tslXmlData}.
	 * @return the value of the attribute {@link #tslXmlData}.
	 */
	public ByteArrayB64 getTslXmlData() {
		return tslXmlData;
	}

	/**
	 * Sets the value of the attribute {@link #tslXmlData}.
	 * @param tslXmlDataParam The value for the attribute {@link #tslXmlData}.
	 */
	public void setTslXmlData(final ByteArrayB64 tslXmlDataParam) {
		this.tslXmlData = tslXmlDataParam;
	}


}
