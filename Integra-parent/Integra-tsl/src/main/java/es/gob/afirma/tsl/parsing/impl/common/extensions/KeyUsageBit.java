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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.extensions.KeyUsageBit.java.</p>
 * <b>Description:</b><p>Class that represents a Key Usage Bit Identifier.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 11/11/2020.
 */
package es.gob.afirma.tsl.parsing.impl.common.extensions;

import java.io.Serializable;
import java.security.cert.X509Certificate;

import es.gob.afirma.i18n.Language;
import es.gob.afirma.tsl.exceptions.TSLMalformedException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.parsing.ifaces.ITSLElementsAndAttributes;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;
import es.gob.afirma.tsl.utils.UtilsStringChar;
import es.gob.afirma.utils.NumberConstants;

/** 
 * <p>Class that represents a Key Usage Bit Identifier.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 11/11/2020.
 */
public class KeyUsageBit implements Serializable {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = 4555686006215165907L;

    /**
	 * Constant attribute that represents the key usage name 'digitalSignature'.
	 */
	public static final String NAME_DIGITALSIGNATURE = "digitalSignature";

	/**
	 * Constant attribute that represents the key usage name 'nonRepudiation'.
	 */
	public static final String NAME_NONREPUDATION = "nonRepudiation";

	/**
	 * Constant attribute that represents the key usage name 'keyEncipherment'.
	 */
	public static final String NAME_KEYENCIPHERMENT = "keyEncipherment";

	/**
	 * Constant attribute that represents the key usage name 'dataEncipherment'.
	 */
	public static final String NAME_DATAENCIPHERMENT = "dataEncipherment";

	/**
	 * Constant attribute that represents the key usage name 'keyAgreement'.
	 */
	public static final String NAME_KEYAGREEMENT = "keyAgreement";

	/**
	 * Constant attribute that represents the key usage name 'keyCertSign'.
	 */
	public static final String NAME_KEYCERTSIGN = "keyCertSign";

	/**
	 * Constant attribute that represents the key usage name 'crlSign'.
	 */
	public static final String NAME_CRLSIGN = "crlSign";

	/**
	 * Constant attribute that represents the key usage name 'encipherOnly'.
	 */
	public static final String NAME_ENCIPHERONLY = "encipherOnly";

	/**
	 * Constant attribute that represents the key usage name 'decipherOnly'.
	 */
	public static final String NAME_DECIPHERONLY = "decipherOnly";

	/**
	 * Attribute that represents the Key Usage Name.
	 */
	private String name = null;

	/**
	 * Attribute that represents the value assigned to the Key Usage.
	 */
	private boolean value = false;

	/**
	 * Attribute that represents the position of the KeyUsage represented in a certificate KeyUsage extension array.
	 */
	private int namePosition = -1;

	/**
	 * Constructor method for the class KeyUsageBit.java.
	 */
	private KeyUsageBit() {
		super();
	}

	/**
	 * Constructor method for the class KeyUsageBit.java.
	 * @param keyUsageName Key Usage name to assign.
	 * @param keyUsageValue Key usage value to assign.
	 */
	public KeyUsageBit(String keyUsageName, boolean keyUsageValue) {
		this();
		name = keyUsageName;
		value = keyUsageValue;
		namePosition = translateKeyUsageNameToPosition();
	}

	/**
	 * Gets the value of the attribute {@link #name}.
	 * @return the value of the attribute {@link #name}.
	 */
	public final String getName() {
		return name;
	}

	/**
	 * Gets the value of the attribute {@link #value}.
	 * @return the value of the attribute {@link #value}.
	 */
	public final boolean getValue() {
		return value;
	}

	/**
	 * Sets the Key Usage.
	 * @param keyUsageName Key Usage name to assign.
	 * @param keyUsageValue Key usage value to assign.
	 */
	public final void setKeyUsage(String keyUsageName, boolean keyUsageValue) {
		name = keyUsageName;
		value = keyUsageValue;
		namePosition = translateKeyUsageNameToPosition();
	}

	/**
	 * Checks if the key usage bit has an appropiate value in the TSL for the specification ETSI 119612
	 * and version 2.1.1.
	 * @param tsl TSL Object representation that contains the service and the extension.
	 * @param shi Service Information (or service history information) in which is declared the extension.
	 * @param isCritical Indicates if the extension is critical (<code>true</code>) or not (<code>false</code>).
	 * @throws TSLMalformedException In case of the key usage bit has not a correct value.
	 */
	protected final void checkExtensionValueSpec119612Vers020101(ITSLObject tsl, ServiceHistoryInstance shi, boolean isCritical) throws TSLMalformedException {

		// Comprobamos que el nombre del KeyUsage se encuentre entre los
		// permitidos.
		if (!UtilsStringChar.isNullOrEmptyTrim(name)) {

			boolean isValid = name.equals(NAME_DIGITALSIGNATURE) || name.equals(NAME_NONREPUDATION) || name.equals(NAME_KEYENCIPHERMENT);
			isValid = isValid || name.equals(NAME_DATAENCIPHERMENT) || name.equals(NAME_KEYAGREEMENT);
			isValid = isValid || name.equals(NAME_KEYCERTSIGN) || name.equals(NAME_CRLSIGN);
			isValid = isValid || name.equals(NAME_ENCIPHERONLY) || name.equals(NAME_DECIPHERONLY);

			if (!isValid) {
				throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.EXT_LOG005, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_QUALIFICATION_CRITERIALIST_KEYUSAGE, name }));
			}

		} else {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.EXT_LOG006, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_QUALIFICATION_CRITERIALIST_KEYUSAGE, ITSLElementsAndAttributes.ELEMENT_EXTENSION_QUALIFICATION_CRITERIALIST_KEYUSAGE_NAME }));
		}

	}

	/**
	 * Translates the key usage name to its position in the KeyUsage array of a certificate.
	 * @return position number of the key usage in the array.
	 */
	private int translateKeyUsageNameToPosition() {

		int result = -1;

		result = name.equals(NAME_DIGITALSIGNATURE) ? 0 : result;
		result = name.equals(NAME_NONREPUDATION) ? 1 : result;
		result = name.equals(NAME_KEYENCIPHERMENT) ? 2 : result;
		result = name.equals(NAME_DATAENCIPHERMENT) ? NumberConstants.INT_3 : result;
		result = name.equals(NAME_KEYAGREEMENT) ? NumberConstants.INT_4 : result;
		result = name.equals(NAME_KEYCERTSIGN) ? NumberConstants.INT_5 : result;
		result = name.equals(NAME_CRLSIGN) ? NumberConstants.INT_6 : result;
		result = name.equals(NAME_ENCIPHERONLY) ? NumberConstants.INT_7 : result;
		result = name.equals(NAME_DECIPHERONLY) ? NumberConstants.INT_8 : result;

		return result;

	}

	/**
	 * Checks if the input certificate has the KeyUsage set to the same value how this object.
	 * @param cert Certificate X509v3 to check.
	 * @return <code>true</code> if the certificate has the KeyUsage set to the same value how this object,
	 * otherwise <code>false</code>.
	 */
	public final boolean checkCertificate(X509Certificate cert) {

		return value == cert.getKeyUsage()[namePosition];

	}

}
