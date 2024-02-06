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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.TSPService.java.</p>
 * <b>Description:</b><p>Class that defines a TSP Service with all its information not dependent
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
 * <p>Class that defines a TSP Service with all its information not dependent
 * of the specification or TSL version.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2020.
 */
public class TSPService implements Serializable {

    /**
     * Attribute that represents the serial version UID. 
     */
    private static final long serialVersionUID = 6168142981286473476L;
    /**
     * Attribute that represents all the service information associated to the TSP.
     */
    private ServiceInformation serviceInformation = null;

    /**
     * Attribute that represents all the service history information about this TSP.
     */
    private List<ServiceHistoryInstance> shiList = null;

    /**
     * Constructor method for the class TSPService.java.
     */
    public TSPService() {
	super();
	serviceInformation = new ServiceInformation();
	shiList = new ArrayList<ServiceHistoryInstance>();
    }

    /**
     * Gets the value of the attribute {@link #serviceInformation}.
     * @return the value of the attribute {@link #serviceInformation}.
     */
    public final ServiceInformation getServiceInformation() {
	return serviceInformation;
    }

    /**
     * Sets the value of the attribute {@link #serviceInformation}.
     * @param serviceInformationParam The value for the attribute {@link #serviceInformation}.
     */
    public final void setServiceInformation(ServiceInformation serviceInformationParam) {
	this.serviceInformation = serviceInformationParam;
    }

    /**
     * Gets a list of service information about the history of the TSP
     * ordered by service status starting time, from news to older.
     * @return List of service information about the history of the TSP.
     * <code>null</code> if there is not.
     */
    public final List<ServiceHistoryInstance> getAllServiceHistory() {

	if (shiList.isEmpty()) {
	    return null;
	} else {
	    return shiList;
	}

    }

    /**
     * Adds a new service history information for this TSP.
     * @param shi Service History information to add.
     */
    public final void addNewServiceHistory(ServiceHistoryInstance shi) {

	if (shi != null) {

	    // Nos aseguramos que se añade de forma ordenada por fecha
	    // de más reciente a más antigua.
	    // Si es el primero, lo añadimos simplemente.
	    if (shiList.isEmpty()) {
		shiList.add(shi);
	    }
	    // Si no, vamos recorriendo los existentes hasta encontrar
	    // uno cuya fecha sea anterior, y se coloca en esa posición.
	    else {
		boolean alreadyAdded = false;
		for (int index = 0; !alreadyAdded && index < shiList.size(); index++) {
		    if (shiList.get(index).getServiceStatusStartingTime().before(shi.getServiceStatusStartingTime())) {
			shiList.add(index, shi);
			alreadyAdded = true;
		    }
		}
		// Si aún no lo hemos añadido es que hay que hacerlo
		// al final.
		if (!alreadyAdded) {
		    shiList.add(shi);
		}
	    }

	}

    }

    /**
     * Checks if there is some service history information for this TSP.
     * @return <code>true</code> if there is, otherwise <code>false</code>.
     */
    public final boolean isThereSomeServiceHistory() {
	return !shiList.isEmpty();
    }

}
