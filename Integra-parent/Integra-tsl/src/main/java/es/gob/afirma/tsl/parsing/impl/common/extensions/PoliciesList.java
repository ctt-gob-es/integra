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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.extensions.PoliciesList.java.</p>
 * <b>Description:</b><p>Class that represents Policy Lists.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 11/11/2020.
 */
package es.gob.afirma.tsl.parsing.impl.common.extensions;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;

import es.gob.afirma.i18n.Language;
import es.gob.afirma.tsl.exceptions.TSLMalformedException;
import es.gob.afirma.tsl.exceptions.TSLQualificationEvalProcessException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.parsing.ifaces.ITSLElementsAndAttributes;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;
import es.gob.afirma.tsl.utils.UtilsCertificateTsl;
import es.gob.afirma.tsl.utils.UtilsStringChar;


/** 
 * <p>Class that represents Policy Lists.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 11/11/2020.
 */
public class PoliciesList implements Serializable {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = -3698032406753729175L;
	/**
	 * Constant attribute that represents that the identifier is defined as URN.
	 */
	public static final int IDENTIFIER_OID_AS_URN = 0;

	/**
	 * Constant attribute that represents that the identifier is defined as URI.
	 */
	public static final int IDENTIFIER_OID_AS_URI = 1;

	/**
	 * Constant attribute that represents that the identifier type is undefined.
	 */
	public static final int IDENTIFIER_OID_AS_UNSPECIFIED = 2;

	/**
	 * Constant attribute that represents the token 'urn:oid:'.
	 */
	private static final String URN_OID_TOKEN = "urn:oid:";

	/**
	 * Attribute that represents the policy identifiers list.
	 */
	private List<String> policyIdentifiersList = null;

	/**
	 * Constructor method for the class PoliciesList.java.
	 */
	public PoliciesList() {
		super();
		policyIdentifiersList = new ArrayList<String>();
	}

	/**
	 * Gets the policy identifiers list.
	 * @return the policy identifiers list
	 */
	public final List<String> getPolicyIdentifiersList() {
		return policyIdentifiersList;
	}

	/**
	 * Checks if there is at least one policy identifier in the list.
	 * @return <code>true</code> if there is at least one policy identifier in the list,
	 * otherwise <code>false</code>.
	 */
	public final boolean isThereSomePolicyIdentifier() {
		return !policyIdentifiersList.isEmpty();
	}

	/**
	 * Adds a new policy identifier if not is <code>null</code>.
	 * @param policyIdentifier policy identifier to add.
	 * @param type Identifier type. It must be one of the following: {@link #IDENTIFIER_OID_AS_URN},
	 * {@link #IDENTIFIER_OID_AS_URI} or {@link #IDENTIFIER_OID_AS_UNSPECIFIED}.
	 */
	public final void addNewPolicyIdentifier(String policyIdentifier, int type) {

		// Comprobamos que identificador no es nulo ni vacío...
		if (!UtilsStringChar.isNullOrEmptyTrim(policyIdentifier)) {

			String policyIdentifierMod = policyIdentifier;

			// En función del tipo...
			switch (type) {

				case IDENTIFIER_OID_AS_URN:
					// En caso de tratarse de un identificador tipo URN, le
					// quitamos
					// la cabecera y nos quedamos solo con el OID.
					policyIdentifierMod = removeUrnPrefix(policyIdentifier);
					break;

				// Si viene como URI, sin especificar u otro, lo dejamos igual.
				case IDENTIFIER_OID_AS_URI:
				case IDENTIFIER_OID_AS_UNSPECIFIED:
				default:
					policyIdentifierMod = policyIdentifier;
					break;
			}

			policyIdentifiersList.add(policyIdentifierMod);

		}
	}

	/**
	 * Removes the URN prefix from the input policy identifier.
	 * @param policyIdentifier String to analyze.
	 * @return The same input stream but removing the urn prefix.
	 */
	private String removeUrnPrefix(String policyIdentifier) {

		// Inicializamos la cadena resultante.
		String result = null;

		// La longitud de la cadena de entrada debe ser mayor a la del token a
		// eliminar.
		if (URN_OID_TOKEN.length() < policyIdentifier.length()) {

			// Obtenemos los caracteres correspondientes al prefijo.
			String prefix = policyIdentifier.substring(0, URN_OID_TOKEN.length());

			// Lo comparamos con el token (ignorando mayúsculas y minúsculas)...
			if (URN_OID_TOKEN.equalsIgnoreCase(prefix)) {

				// Si son iguales, nos quedamos con el resto.
				result = policyIdentifier.substring(URN_OID_TOKEN.length());

			} else {

				// Si no, lo devolvemos tal cual.
				result = policyIdentifier;

			}

		}
		// Si no es así, la devolvemos tal cual.
		else {

			result = policyIdentifier;

		}

		return result;

	}

	/**
	 * Checks if the policies list has an appropiate value in the TSL for the specification ETSI 119612
	 * and version 2.1.1.
	 * @param tsl TSL Object representation that contains the service and the extension.
	 * @param shi Service Information (or service history information) in which is declared the extension.
	 * @param isCritical Indicates if the extension is critical (<code>true</code>) or not (<code>false</code>).
	 * @throws TSLMalformedException In case of the policies list has not a correct value.
	 */
	protected final void checkExtensionValueSpec119612Vers020101(ITSLObject tsl, ServiceHistoryInstance shi, boolean isCritical) throws TSLMalformedException {

		// Debe tener al menos un elemento.
		if (policyIdentifiersList.isEmpty()) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.EXT_LOG004, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_QUALIFICATION_CRITERIALIST_POLICYSET }));
		}

	}

	/**
	 * Checks if the input certificate has the CertificatePolicies extension and it includes all the
	 * OIDs declared in this object.
	 * @param cert Certificate X509v3 to check.
	 * @return <code>true</code> if the input certificate has the CertificatePolicies extension and it includes all the
	 * OIDs declared in this object, otherwise <code>false</code>.
	 * @throws TSLQualificationEvalProcessException In case of some error evaluating the input certificate
	 * with all defined criteria.
	 */
	public final boolean checkCertificate(X509Certificate cert) throws TSLQualificationEvalProcessException {

		boolean result = false;

		if (isThereSomePolicyIdentifier()) {

			try {

				// Obtenemos la extensión que representa los
				// CertificatePolicies.
				CertificatePolicies certPoliciesExtension = CertificatePolicies.fromExtensions(UtilsCertificateTsl.getBouncyCastleCertificate(cert).getTBSCertificate().getExtensions());

				// Si la extensión no es nula...
				if (certPoliciesExtension != null && certPoliciesExtension.getPolicyInformation() != null && certPoliciesExtension.getPolicyInformation().length > 0) {

					// Recorremos y almacenamos los identifiers en un conjunto
					// (sin repeticiones).
					Set<String> certIdentifiers = new HashSet<String>();
					PolicyInformation[ ] polInformationArray = certPoliciesExtension.getPolicyInformation();
					for (PolicyInformation policyInformation: polInformationArray) {
						certIdentifiers.add(policyInformation.getPolicyIdentifier().getId());
					}
					// Ahora, si el conjunto obtenido no es nulo ni vacío,
					// comprobamos que los
					// identificadores establecidos en este objeto se
					// encuentran todos definidos en
					// el certificado.
					if (!certIdentifiers.isEmpty()) {
						result = certIdentifiers.containsAll(policyIdentifiersList);
					}

				}
			} catch (Exception e) {
				throw new TSLQualificationEvalProcessException(Language.getResIntegraTsl(ILogTslConstant.EXT_LOG010), e);
			}

		}

		return result;

	}
}
