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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.TSLPointer.java.</p>
 * <b>Description:</b><p>Class that defines a TSL pointer with all its information not dependent
 * of the specification or version.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 15/06/2021.
 */
package es.gob.afirma.tsl.parsing.impl.common;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.exceptions.TSLParsingException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;


/** 
 * <p>Class that defines a TSL pointer with all its information not dependent
 * of the specification or version.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 15/06/2021.
 */
public class TSLPointer implements Serializable {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = -3110390214407977981L;
    /**
	 * Attribute that represents the URI location for this TSL Pointer.
	 */
	private URI tslLocation = null;

	/**
	 * Attribute that represents the list of service digital identities associted to this TSL pointer.
	 */
	private List<ServiceDigitalIdentity> serviceDigitalIdentities = null;

	/**
	 * Constructor method for the class TSLPointer.java.
	 */
	private TSLPointer() {
		super();
		serviceDigitalIdentities = new ArrayList<ServiceDigitalIdentity>();
	}

	/**
	 * Constructor method for the class TSLPointer.java.
	 * @param uriTSLLocation URI string for the TSL location.
	 * @throws TSLParsingException In case of some error parsing the URI of the TSL location.
	 */
	public TSLPointer(String uriTSLLocation) throws TSLParsingException {
		this();
		try {
			tslLocation = new URI(uriTSLLocation);
		} catch (URISyntaxException e) {
			throw new TSLParsingException(Language.getFormatResIntegraTsl(ILogTslConstant.TSLP_LOG001, new Object[ ] { uriTSLLocation }), e);
		}
	}

	/**
	 * Gets the location URI of this TSL pointer.
	 * @return location URI of this TSL pointer.
	 */
	public final URI getTSLLocation() {
		return tslLocation;
	}

	/**
	 * Checks if there is some service digital identity associated to this TSL pointer.
	 * @return <code>true</code> if there is some service digital identity associated to
	 * this TSL pointer, otherwise <code>false</code>.
	 */
	public final boolean isThereSomeServiceDigitalIdentity() {
		return !serviceDigitalIdentities.isEmpty();
	}

	/**
	 * Gets the list of service digital identities associates to this TSL pointer.
	 * @return the list of service digital identities associates to this TSL pointer.
	 */
	public final List<ServiceDigitalIdentity> getServiceDigitalIdentities() {
		return serviceDigitalIdentities;
	}

	/**
	 * Add a service digital identity to the list associated to this TLS pointer.
	 * Not is added if the input parameter is null.
	 * @param sdi Service digital identity to add.
	 */
	public final void addNewServiceDigitalIdentity(ServiceDigitalIdentity sdi) {
		if (sdi != null) {
			serviceDigitalIdentities.add(sdi);
		}
	}

}
