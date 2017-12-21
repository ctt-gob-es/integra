// Copyright (C) 2012-13 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.signature.SignersFactory.java.</p>
 * <b>Description:</b><p>Class that represents a factory used to provide implementations for {@link Signer}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>28/06/2011.</p>
 * @author Gobierno de España.
 * @version 1.0, 28/06/2011.
 */
package es.gob.afirma.signature;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;

/**
 * <p>Class that represents a factory used to provide implementations for {@link Signer}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 28/06/2011.
 */
public final class SignersFactory {

    /**
     *  Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(SignersFactory.class);

    /**
     * Attribute that represents the unique instance of the class.
     */
    private static SignersFactory signersFactory = null;

    /**
     * Attribute that represents list of signers supported with their handler associated.
     */
    private static Map<String, String> signers;

    /**
     * Constructor method for the class SignersFactory.java.
     */
    private SignersFactory() {
    }

    /**
     * Method that obtains the unique instance of the class.
     * @return the unique instance of the class.
     */
    public static SignersFactory getInstance() {
	if (signersFactory != null) {
	    return signersFactory;
	} else {

	    // Cargamos
	    signersFactory = new SignersFactory();
	    signers = new HashMap<String, String>();

	    String xadesInstanceName = "es.gob.afirma.signature.xades.XadesSigner";
	    signers.put(SignatureConstants.SIGN_FORMAT_CADES, "es.gob.afirma.signature.cades.CadesSigner");
	    signers.put(SignatureConstants.SIGN_FORMAT_PADES, "es.gob.afirma.signature.pades.PadesSigner");
	    signers.put(SignatureConstants.SIGN_FORMAT_XADES_DETACHED, xadesInstanceName);
	    signers.put(SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED, xadesInstanceName);
	    signers.put(SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING, xadesInstanceName);
	    signers.put(SignatureConstants.SIGN_FORMAT_XADES_EXTERNALLY_DETACHED, xadesInstanceName);
	    if (LOGGER.isDebugEnabled()) {
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.SF_LOG002, new Object[ ] { signersFactory.toString() }));
	    }
	    return signersFactory;
	}
    }

    /**
     * Method that obtains the appropriate implementation of {@link Signer} by the signature format.
     * @param signatureFormat Parameter that represents the signature format related to the element to obtain.
     * @return the appropriate implementation of {@link Signer} by the signature format.
     * @throws SigningException If the method fails.
     */
    public Signer getSigner(String signatureFormat) throws SigningException {
	if (signers.containsKey(signatureFormat)) {
	    try {
		return (Signer) Class.forName(signers.get(signatureFormat)).newInstance();
	    } catch (InstantiationException e) {
		throw new SigningException(Language.getFormatResIntegra(ILogConstantKeys.SF_LOG001, new Object[ ] { signers.get(signatureFormat) }), e);
	    } catch (IllegalAccessException e) {
		throw new SigningException(Language.getFormatResIntegra(ILogConstantKeys.SF_LOG001, new Object[ ] { signers.get(signatureFormat) }), e);
	    } catch (ClassNotFoundException e) {
		throw new SigningException(Language.getFormatResIntegra(ILogConstantKeys.SF_LOG001, new Object[ ] { signers.get(signatureFormat) }), e);
	    }
	} else {
	    throw new SigningException(Language.getFormatResIntegra(ILogConstantKeys.SF_LOG003, new Object[ ] { signatureFormat }));
	}
    }

    /**
     * Method that obtains a list with the supported signature formats.
     * @return a list with the supported signature formats.
     */
    public String toString() {
	StringBuilder exstr = new StringBuilder(Language.getResIntegra(ILogConstantKeys.SF_LOG004));
	for (String signer: signers.keySet()) {
	    exstr.append("\n\t\t").append(signer);
	}
	return exstr.toString();
    }

}
