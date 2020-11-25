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
 * <b>File:</b><p>es.gob.afirma.tsl.elements.TspServiceInformation.java.</p>
 * <b>Description:</b><p>Class that represents the structure of a TSP Service Information.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/10/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/10/2020
 */
package es.gob.afirma.tsl.elements;

import java.io.Serializable;


/** 
 * <p>Class that represents the structure of a TSP Service Information.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/10/2020.
 */
public class TspServiceInformation extends TspServiceHistoryInf implements Serializable {

    /**
     * Attribute that represents . 
     */
    private static final long serialVersionUID = 5422960314974310981L;
    /**
	 * Attribute that represents the TSP service history information (if it is used).
	 */
	private TspServiceHistoryInf tspServiceHistoryInf;

	/**
	 * Gets the value of the attribute {@link #tspServiceHistoryInf}.
	 * @return the value of the attribute {@link #tspServiceHistoryInf}.
	 */
	public TspServiceHistoryInf getTspServiceHistoryInf() {
		return tspServiceHistoryInf;
	}

	/**
	 * Sets the value of the attribute {@link #tspServiceHistoryInf}.
	 * @param tspServiceHistoryInfParam The value for the attribute {@link #tspServiceHistoryInf}.
	 */
	public void setTspServiceHistoryInf(TspServiceHistoryInf tspServiceHistoryInfParam) {
		this.tspServiceHistoryInf = tspServiceHistoryInfParam;
	}

	/**
	 * Checks if the service history information has been used and it is defined.
	 * @return <code>true</code> if there is service history information, otherwise <code>false</code>.
	 */
	public boolean checkIfThereIsServiceHistoryInf() {
		return tspServiceHistoryInf != null;
	}

}
