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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.ServiceDigitalIdentity.java.</p>
 * <b>Description:</b><p>Class that defines a Service Digital Identity with all its information not dependent
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
 * <p>Class that defines a Service Digital Identity with all its information not dependent
 * of the specification or TSL version.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2020.
 */
public class ServiceDigitalIdentity implements Serializable {

    /**
     * Attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = 4588088813455518905L;


	/**
	 * Attribute that represents the list of digital identities associated to this
	 * service digital identity.
	 */
	private List<DigitalID> digitalIdentities = null;

	/**
	 * Constructor method for the class ServiceDigitalIdentity.java.
	 */
	public ServiceDigitalIdentity() {
		super();
		digitalIdentities = new ArrayList<DigitalID>();
	}

	/**
	 * Checks if there is some digital identity associated to this Service Digital Identity.
	 * @return <code>true</code> if there is some digital identity associated to this Service
	 * Digital Identity, otherwise <code>false</code>.
	 */
	public final boolean isThereSomeIdentity() {
		return !digitalIdentities.isEmpty();
	}

	/**
	 * Adds a new digital identity to this service digital identity.
	 * @param digitalIdentity Digital identity to add.
	 */
	public final void addNewDigitalIdentity(DigitalID digitalIdentity) {

		if (digitalIdentity != null) {
			digitalIdentities.add(digitalIdentity);
		}

	}

	/**
	 * Gets all the digital identities associated to this service digital identity.
	 * @return List with all the digital identities associated to this service digital identity.
	 */
	public final List<DigitalID> getAllDigitalIdentities() {
		return digitalIdentities;
	}
}
