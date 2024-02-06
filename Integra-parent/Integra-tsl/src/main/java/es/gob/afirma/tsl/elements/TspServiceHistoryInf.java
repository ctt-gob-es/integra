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
 * <b>File:</b><p>es.gob.afirma.tsl.elements.TspServiceHistoryInf.java.</p>
 * <b>Description:</b><p>Class that represents the structure of a TSP Service History Information.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/10/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/10/2020.
 */
package es.gob.afirma.tsl.elements;

import java.io.Serializable;

import es.gob.afirma.tsl.elements.json.DateString;


/** 
 * <p>Class that represents the structure of a TSP Service History Information.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/10/2020.
 */
public class TspServiceHistoryInf implements Serializable {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = 922260636458076595L;
	/**
	 * Attribute that represents the TSP service name.
	 */
	private String tspServiceName;

	/**
	 * Attribute that represents the TSP service type.
	 */
	private String tspServiceType;

	/**
	 * Attribute that represents the TSP service status.
	 */
	private String tspServiceStatus;

	/**
	 * Attribute that represents the TSP service status starting date.
	 */
	private DateString tspServiceStatusStartingDate;

	/**
	 * Gets the value of the attribute {@link #tspServiceName}.
	 * @return the value of the attribute {@link #tspServiceName}.
	 */
	public final String getTspServiceName() {
		return tspServiceName;
	}

	/**
	 * Sets the value of the attribute {@link #tspServiceName}.
	 * @param tspServiceNameParam The value for the attribute {@link #tspServiceName}.
	 */
	public final void setTspServiceName(String tspServiceNameParam) {
		this.tspServiceName = tspServiceNameParam;
	}

	/**
	 * Gets the value of the attribute {@link #tspServiceType}.
	 * @return the value of the attribute {@link #tspServiceType}.
	 */
	public final String getTspServiceType() {
		return tspServiceType;
	}

	/**
	 * Sets the value of the attribute {@link #tspServiceType}.
	 * @param tspServiceTypeParam The value for the attribute {@link #tspServiceType}.
	 */
	public final void setTspServiceType(String tspServiceTypeParam) {
		this.tspServiceType = tspServiceTypeParam;
	}

	/**
	 * Gets the value of the attribute {@link #tspServiceStatus}.
	 * @return the value of the attribute {@link #tspServiceStatus}.
	 */
	public final String getTspServiceStatus() {
		return tspServiceStatus;
	}

	/**
	 * Sets the value of the attribute {@link #tspServiceStatus}.
	 * @param tspServiceStatusParam The value for the attribute {@link #tspServiceStatus}.
	 */
	public final void setTspServiceStatus(String tspServiceStatusParam) {
		this.tspServiceStatus = tspServiceStatusParam;
	}

	/**
	 * Gets the value of the attribute {@link #tspServiceStatusStartingDate}.
	 * @return the value of the attribute {@link #tspServiceStatusStartingDate}.
	 */
	public final DateString getTspServiceStatusStartingDate() {
		return tspServiceStatusStartingDate;
	}

	/**
	 * Sets the value of the attribute {@link #tspServiceStatusStartingDate}.
	 * @param tspServiceStatusStartingDateParam The value for the attribute {@link #tspServiceStatusStartingDate}.
	 */
	public final void setTspServiceStatusStartingDate(DateString tspServiceStatusStartingDateParam) {
		this.tspServiceStatusStartingDate = tspServiceStatusStartingDateParam;
	}

}
