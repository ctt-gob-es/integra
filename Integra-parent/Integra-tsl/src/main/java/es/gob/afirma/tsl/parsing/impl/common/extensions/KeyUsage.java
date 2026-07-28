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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.extensions.KeyUsage.java.</p>
 * <b>Description:</b><p>Class that provides a list of key usage bit-values to match with the
 * correspondent bits present in the keyUsage certificate Extension. The assertion is verified if the
 * KeyUsage Extension is present in the certificate and all key usage bits provided are matched with
 * the corresponding bit in the certificate KeyUsage Extension.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 15/06/2021.
 */
package es.gob.afirma.tsl.parsing.impl.common.extensions;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.exceptions.TSLMalformedException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.parsing.ifaces.ITSLElementsAndAttributes;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;
import es.gob.afirma.tsl.utils.NumberConstants;



/** 
 * <p>Class that provides a list of key usage bit-values to match with the
 * correspondent bits present in the keyUsage certificate Extension. The assertion is verified if the
 * KeyUsage Extension is present in the certificate and all key usage bits provided are matched with
 * the corresponding bit in the certificate KeyUsage Extension.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 15/06/2021.
 */
public class KeyUsage implements Serializable {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = -2014984562980814038L;

    /**
	 * Attribute that represents the list with the differente key usages.
	 * The maximum elements is {@link NumberConstants#INT_9}.
	 */
	private List<KeyUsageBit> keyUsageBitList = null;

	/**
	 * Constructor method for the class KeyUsage.java.
	 */
	public KeyUsage() {
		super();
		keyUsageBitList = new ArrayList<KeyUsageBit>();
	}

	/**
	 * Gets the key usage bit list.
	 * @return Key Usage Bit List.
	 */
	public final List<KeyUsageBit> getKeyUsageBitList() {
		return keyUsageBitList;
	}

	/**
	 * Checks if there is at least one key usage bit.
	 * @return <code>true</code> if there is at least one key usage bit, otherwise <code>false</code>.
	 */
	public final boolean isThereSomeKeyUsageBit() {
		return !keyUsageBitList.isEmpty();
	}

	/**
	 * Adds a new Key Usage Bit to the list if there is free space.
	 * @param kub Key Usage Bit to add.
	 * @return <code>true</code> if the input parameter not is <code>null</code> and there is
	 * free space in the list, otherwise false.
	 */
	public final boolean addNewKeyUsageBit(KeyUsageBit kub) {

		boolean result = false;

		if (kub != null && keyUsageBitList.size() < NumberConstants.INT_9) {
			keyUsageBitList.add(kub);
			result = true;
		}

		return result;

	}

	/**
	 * Checks if the key usage has an appropiate value in the TSL for the specification ETSI 119612
	 * and version 2.1.1.
	 * @param tsl TSL Object representation that contains the service and the extension.
	 * @param shi Service Information (or service history information) in which is declared the extension.
	 * @param isCritical Indicates if the extension is critical (<code>true</code>) or not (<code>false</code>).
	 * @throws TSLMalformedException In case of the key usage has not a correct value.
	 */
	protected final void checkExtensionValueSpec119612Vers020101(ITSLObject tsl, ServiceHistoryInstance shi, boolean isCritical) throws TSLMalformedException {

		// La lista debe tener entre 1 y 9 elementos.
		if (keyUsageBitList.isEmpty() || keyUsageBitList.size() > NumberConstants.INT_9) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.EXT_LOG004, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_QUALIFICATION_CRITERIALIST_KEYUSAGE }));
		}

		// Comprobamos cada uno de los KeyUsageBit.
		for (KeyUsageBit kub: keyUsageBitList) {
			kub.checkExtensionValueSpec119612Vers020101(tsl, shi, isCritical);
		}

	}

	/**
	 * Checks if the input certificate has the same key usage set that this object.
	 * @param cert Certificate to check.
	 * @return <code>true</code> if the input certificate has the same key usage set that this object,
	 * otherwise <code>false</code>.
	 */
	public final boolean checkCertificate(X509Certificate cert) {

		boolean result = false;

		// Si el certificado de entrada no es nulo y hay KeyUsage que
		// comprobar...
		if (cert != null && isThereSomeKeyUsageBit()) {

			// Consideramos inicialmente que el certificado lo cumple...
			result = true;
			for (int index = 0; index < keyUsageBitList.size() && result; index++) {

				result = keyUsageBitList.get(index).checkCertificate(cert);

			}

		}

		return result;

	}

}
