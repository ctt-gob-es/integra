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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.ifaces.IAnyTypeExtension.java.</p>
 * <b>Description:</b><p>Interface that defines the common method for any type extensions in a TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/11/2020.
 */
package es.gob.afirma.tsl.parsing.ifaces;

import java.io.Serializable;

import es.gob.afirma.tsl.exceptions.TSLMalformedException;
import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;


/** 
 * <p>Interface that defines the common method for any type extensions in a TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2020.
 */
public interface IAnyTypeExtension extends Serializable {
    /**
	 * Constant attribute that identifies a extension how 'Schemne Extension'.
	 */
	int TYPE_SCHEME = 0;

	/**
	 * Constant attribute that identifies a extension how 'TSP Information Extension'.
	 */
	int TYPE_TSP_INFORMATION = 1;

	/**
	 * Constant attribute that identifies a extension how 'Service Information Extension'.
	 */
	int TYPE_SERVICE_INFORMATION = 2;

	/**
	 * Constant attribute that represents the implementation extension: AdditionalServiceInformation.
	 */
	int IMPL_ADDITIONAL_SERVICE_INFORMATION = 0;

	/**
	 * Constant attribute that represents the implementation extension: ExpiredCertsRevocationInfo.
	 */
	int IMPL_EXPIRED_CERTS_REVOCATION_INFO = 1;

	/**
	 * Constant attribute that represents the implementation extension: Qualifications.
	 */
	int IMPL_QUALIFICATIONS = 2;

	/**
	 * Constant attribute that represents the implementation extension: TakenOverBy.
	 */
	int IMPL_TAKENOVERBY = 3;

	/**
	 * Constant attribute that represents the implementation extension: UnknownExtension.
	 */
	int IMPL_UNKNOWN_EXTENSION = 4;

	/**
	 * Checks if the extension is critical or not.
	 * @return <code>true</code> if the extension is critical, otherwise <code>false</code>.
	 */
	boolean isCritical();

	/**
	 * Gets the implementation for the extension.
	 * @return Implementation for the extension.
	 */
	int getImplementationExtension();

	/**
	 * Checks if the extension has an appropiate value in the TSL.
	 * @param tsl TSL Object representation that contains the service and the extension.
	 * @param shi Service Information (or service history information) in which is declared the extension.
	 * @throws TSLMalformedException In case of the extension has not a correct value.
	 */
	void checkExtensionValue(ITSLObject tsl, ServiceHistoryInstance shi) throws TSLMalformedException;
}
