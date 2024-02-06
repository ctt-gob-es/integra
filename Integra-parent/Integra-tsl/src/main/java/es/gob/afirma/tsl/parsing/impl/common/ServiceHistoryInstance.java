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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance.java.</p>
 * <b>Description:</b><p>Class that defines a TSP Service History Information with all its information
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
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import es.gob.afirma.tsl.parsing.ifaces.IAnyTypeExtension;

/** 
 * <p>Class that defines a TSP Service History Information with all its information
 * not dependent of the specification or TSL version.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2020.
 */
public class ServiceHistoryInstance implements Serializable {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = 5734089141353055592L;

	/**
	 * Attribute that represents the identifier of the service type, according to the
	 * type of TSL being presented.
	 */
	private URI serviceTypeIdentifier = null;

	/**
	 * Attribute that represents the name under which the TSP provides the service in all
	 * presented languages.
	 */
	private Map<String, String> serviceNames = null;

	/**
	 * Attribute that represents the kind/type/identity of the service digital.
	 */
	private ServiceDigitalIdentity serviceDigitalIdentity = null;

	/**
	 * Attribute that represents the identifier of the service status.
	 */
	private URI serviceStatus = null;

	/**
	 * Attribute that represents the date and time on which the service status in
	 * question became effective.
	 */
	private Date serviceStatusStartingTime = null;

	/**
	 * Attribute that represents a list with all the extensions associated to this Service Information.
	 */
	private List<IAnyTypeExtension> serviceInformationExtensions = null;

	/**
	 * Attribute that represents a flag to indicate if this service instance is valid and usable.
	 */
	private boolean serviceValidAndUsable = true;

	/**
	 * Constructor method for the class ServiceHistoryInstance.java.
	 */
	public ServiceHistoryInstance() {
		super();
		serviceNames = new HashMap<String, String>();
		serviceDigitalIdentity = new ServiceDigitalIdentity();
		serviceInformationExtensions = new ArrayList<IAnyTypeExtension>();
	}

	/**
	 * Gets the value of the attribute {@link #serviceNames}.
	 * @return the value of the attribute {@link #serviceNames}.
	 */
	public final Map<String, String> getServiceNames() {
		return serviceNames;
	}

	/**
	 * Gets the service name in the specified language.
	 * @param language Language from which search the service name.
	 * @return Service name in the language specified, or <code>null</code> if not is defined.
	 */
	public final String getServiceNameInLanguage(String language) {
		return serviceNames.get(language);
	}

	/**
	 * Add a new service name.
	 * @param language language (ISO 639) in which is writed the name.
	 * @param name Service name.
	 */
	public final void addNewServiceName(String language, String name) {
		serviceNames.put(language, name);
	}

	/**
	 * Checks if there is at least one service name.
	 * @return <code>true</code> if there is, otherwise <code>false</code>.
	 */
	public final boolean isThereSomeServiceName() {
		return !serviceNames.isEmpty();
	}

	/**
	 * Gets the value of the attribute {@link #serviceTypeIdentifier}.
	 * @return the value of the attribute {@link #serviceTypeIdentifier}.
	 */
	public final URI getServiceTypeIdentifier() {
		return serviceTypeIdentifier;
	}

	/**
	 * Sets the value of the attribute {@link #serviceTypeIdentifier}.
	 * @param serviceTypeIdentifierParam The value for the attribute {@link #serviceTypeIdentifier}.
	 */
	public final void setServiceTypeIdentifier(URI serviceTypeIdentifierParam) {
		this.serviceTypeIdentifier = serviceTypeIdentifierParam;
	}

	/**
	 * Gets the value of the attribute {@link #serviceStatus}.
	 * @return the value of the attribute {@link #serviceStatus}.
	 */
	public final URI getServiceStatus() {
		return serviceStatus;
	}

	/**
	 * Sets the value of the attribute {@link #serviceStatus}.
	 * @param serviceStatusParam The value for the attribute {@link #serviceStatus}.
	 */
	public final void setServiceStatus(URI serviceStatusParam) {
		this.serviceStatus = serviceStatusParam;
	}

	/**
	 * Gets the value of the attribute {@link #serviceStatusStartingTime}.
	 * @return the value of the attribute {@link #serviceStatusStartingTime}.
	 */
	public final Date getServiceStatusStartingTime() {
		return serviceStatusStartingTime;
	}

	/**
	 * Sets the value of the attribute {@link #serviceStatusStartingTime}.
	 * @param serviceStatusStartingTimeParam The value for the attribute {@link #serviceStatusStartingTime}.
	 */
	public final void setServiceStatusStartingTime(Date serviceStatusStartingTimeParam) {
		this.serviceStatusStartingTime = serviceStatusStartingTimeParam;
	}

	/**
	 * Checks if there is some digital identity associated to this Service Information.
	 * @return <code>true</code> if there is some digital identity associated to this Service
	 * Information, otherwise <code>false</code>.
	 */
	public final boolean isThereSomeIdentity() {
		return serviceDigitalIdentity.isThereSomeIdentity();
	}

	/**
	 * Adds a new digital identity to this service information.
	 * @param digitalIdentity Digital identity to add.
	 */
	public final void addNewDigitalIdentity(DigitalID digitalIdentity) {
		serviceDigitalIdentity.addNewDigitalIdentity(digitalIdentity);
	}

	/**
	 * Gets all the digital identities associated to this service information.
	 * @return List with all the digital identities associated to this service information.
	 */
	public final List<DigitalID> getAllDigitalIdentities() {
		return serviceDigitalIdentity.getAllDigitalIdentities();
	}

	/**
	 * Gets the value of the attribute {@link #serviceInformationExtensions}.
	 * @return the value of the attribute {@link #serviceInformationExtensions}.
	 */
	public final List<IAnyTypeExtension> getServiceInformationExtensions() {
		return serviceInformationExtensions;
	}

	/**
	 * Adds a new extension if it is not <code>null</code>.
	 * @param extension extension to add.
	 */
	public final void addNewServiceInformationExtension(IAnyTypeExtension extension) {
		if (extension != null) {
			serviceInformationExtensions.add(extension);
		}
	}

	/**
	 * Checks if there is at least one service information extension.
	 * @return <code>true</code> if there is at least one service information extension, otherwise <code>false</code>.
	 */
	public final boolean isThereSomeServiceInformationExtension() {
		return !serviceInformationExtensions.isEmpty();
	}

	/**
	 * Gets the value of the attribute {@link #serviceValidAndUsable}.
	 * @return the value of the attribute {@link #serviceValidAndUsable}.
	 */
	public final boolean isServiceValidAndUsable() {
		return serviceValidAndUsable;
	}

	/**
	 * Sets the value of the attribute {@link #serviceValidAndUsable}.
	 * @param serviceValidAndUsableParam The value for the attribute {@link #serviceValidAndUsable}.
	 */
	public final void setServiceValidAndUsable(boolean serviceValidAndUsableParam) {
		this.serviceValidAndUsable = serviceValidAndUsableParam;
	}

}
