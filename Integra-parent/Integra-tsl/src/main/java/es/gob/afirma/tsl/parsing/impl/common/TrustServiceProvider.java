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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.TrustServiceProvider.java.</p>
 * <b>Description:</b><p>Class that defines a Trust Service Provider with all its information not dependent
 * of the specification or TSL version.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/11/2020.
 */
package es.gob.afirma.tsl.parsing.impl.common;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;


/** 
 * <p>Class that defines a Trust Service Provider with all its information not dependent
 * of the specification or TSL version.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2020.
 */
public class TrustServiceProvider implements Serializable {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = -566864003820866814L;
    /**
	 * Attribute that represents the information about the TSP.
	 */
	private TSPInformation tspInformation = null;

	/**
	 * Attribute that represents the list of services associated to this TSP.
	 */
	private List<TSPService> tspServicesList = null;

	/**
	 * Constructor method for the class TrustServiceProvider.java.
	 */
	public TrustServiceProvider() {

		super();
		tspInformation = new TSPInformation();
		tspServicesList = new ArrayList<TSPService>();

	}

	/**
	 * Gets the value of the attribute {@link #tspInformation}.
	 * @return the value of the attribute {@link #tspInformation}.
	 */
	public final TSPInformation getTspInformation() {
		return tspInformation;
	}

	/**
	 * Sets the value of the attribute {@link #tspInformation}.
	 * @param tspInf The value for the attribute {@link #tspInformation}.
	 */
	public final void setTspInformation(TSPInformation tspInf) {
		this.tspInformation = tspInf;
	}

	/**
	 * Gets an array with the services associated to this TSP.
	 * @return list with the services associated to this TSP.
	 * <code>null</code> if there is not.
	 */
	public final List<TSPService> getAllTSPServices() {

		if (tspServicesList.isEmpty()) {
			return null;
		} else {
			return tspServicesList;
		}

	}

	/**
	 * Adds a new service to this TSP.
	 * @param tspService Service to add.
	 */
	public final void addNewTSPService(TSPService tspService) {
		if (tspService != null) {
			tspServicesList.add(tspService);
		}
	}

	/**
	 * Checks if there is some service associated to this TSP.
	 * @return <code>true</code> if there is, otherwise <code>false</code>.
	 */
	public final boolean isThereSomeTSPService() {
		return !tspServicesList.isEmpty();
	}
}
