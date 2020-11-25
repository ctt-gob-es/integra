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
 * <b>File:</b><p>es.gob.afirma.tsl.utils.UtilsCRL.java.</p>
 * <b>Description:</b><p>Utilities class that provides functionality to manage and work with X.509 CRL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 18/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 18/11/2020.
 */
package es.gob.afirma.tsl.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.asn1.x509.TBSCertList.CRLEntry;
import org.bouncycastle.jce.provider.X509CRLEntryObject;

import es.gob.afirma.i18n.Language;
import es.gob.afirma.tsl.exceptions.CommonUtilsException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.utils.UtilsResourcesCommons;
/** 
 * <p>Utilities class that provides functionality to manage and work with X.509 CRL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 18/11/2020.
 */
public final class UtilsCRL {
	/**
	 * Attribute that represents the object that manages the log of the class.
	 */
	private static final Logger LOGGER = Logger.getLogger(UtilsCRL.class);

	/**
	 * Constructor method for the class UtilsCRL.java.
	 */
	private UtilsCRL() {
		super();
	}

	/**
	 * Builds a X.509 CRL from the input byte array.
	 * @param crlByteArray Byte array that represents a X.509 CRL.
	 * @return a X.509 CRL builded from the input byte array, or <code>null</code>
	 * if the input array is <code>null</code> or empty.
	 * @throws CommonUtilsException In case of some error building the X.509 CRL.
	 */
	public static X509CRL buildX509CRLfromByteArray(byte[ ] crlByteArray) throws CommonUtilsException {

		X509CRL result = null;

		// Si el array de bytes no es nulo ni vacío...
		if (crlByteArray != null && crlByteArray.length > 0) {

			// Creamos un input stream.
			ByteArrayInputStream bais = new ByteArrayInputStream(crlByteArray);
			// Intentamos parsear la CRL...
			try {
				result = buildX509CRLfromByteArray(bais);
			} finally {
				UtilsResourcesCommons.safeCloseInputStream(bais);
			}

		}

		// Devolvemos el resultado obtenido.
		return result;

	}

	/**
	 * Builds a X.509 CRL from the input stream.
	 * This method does not close the input stream.
	 * @param isCRL Input stream that represents a X.509 CRL.
	 * @return a X.509 CRL builded from the input stream, or <code>null</code>
	 * if the input stream is <code>null</code>.
	 * @throws CommonUtilsException In case of some error building the X.509 CRL.
	 */
	public static X509CRL buildX509CRLfromByteArray(InputStream isCRL) throws CommonUtilsException {

		X509CRL result = null;

		// Si el input stream no es nulo...
		if (isCRL != null) {

			// Intentamos construir el X.509 CRL...
			try {
				CertificateFactory cf = CertificateFactory.getInstance(UtilsCertificateTsl.X509_TYPE);
				result = (X509CRL) cf.generateCRL(isCRL);
			} catch (CertificateException e) {
				throw new CommonUtilsException(Language.getResIntegraTsl(ILogTslConstant.UTILS_CRL_000), e);
			} catch (CRLException e) {
				throw new CommonUtilsException(Language.getResIntegraTsl(ILogTslConstant.UTILS_CRL_001), e);
			}

		}

		// Devolvemos el resultado obtenido.
		return result;

	}

	/**
	 * Search a {@link X509CRLEntry} in the input CRL for the input certificate. Also checks if the CRL is indirect (or not) and
	 * test if it is compatible with the certificate or any of the issuers allowed.
	 * @param cert X.509 certificate to chek if has a entry in the CRL.
	 * @param crl X.509 CRL to analyze.
	 * @param possibleCrlEntryIssuers Array of X.509 certificates that maybe could be the issuers of the CRL.
	 * @return <code>null</code> if the input certificate or CRL are <code>null</code>, or if the certificate has not an
	 * entry in the CRL. Returns a X.509 CRL entry if the CRL has the same issuer than the certificate or any of
	 * the input possible issuers (considering also that the CRL could be indirect), and exists this entry in the CRL
	 * for the input certificate.
	 * @throws CommonUtilsException In case of some error analyzing the input CRL.
	 */
	public static X509CRLEntry searchCrlEntryForCertificate(X509Certificate cert, X509CRL crl, X509Certificate[ ] possibleCrlEntryIssuers) throws CommonUtilsException {

		X509CRLEntry result = null;

		if (crl != null && cert != null) {

			try {

				// Obtenemos la información de certificados revocados en la CRL.
				TBSCertList tbsCertList = TBSCertList.getInstance(crl.getTBSCertList());
				// Guardamos en una variable si la CRL es indirecta.
				boolean isIndirect = isIndirectCRL(crl);
				// Obtenemos el nombre del emisor de la CRL.
				X500Name caName = tbsCertList.getIssuer();

				// Obtenemos el nombre del emisor del certificado.
				X500Name certIssuer = X500Name.getInstance(((X509Certificate) cert).getIssuerX500Principal().getEncoded());

				// Creamos un conjunto de X500Name que puedan representar al
				// emisor
				// de la entrada CRL. Estos se forman con el emisor del
				// certificado
				// a buscar, y cualquiera de los indicados específicamente.
				Set<X500Name> possibleCrlEntryIssuersSet = new HashSet<X500Name>();
				possibleCrlEntryIssuersSet.add(certIssuer);
				if (possibleCrlEntryIssuers != null) {
					for (X509Certificate possibleCrlIssuer: possibleCrlEntryIssuers) {
						possibleCrlEntryIssuersSet.add(X500Name.getInstance(possibleCrlIssuer.getIssuerX500Principal().getEncoded()));
					}
				}

				// Bandera que indica si el emisor actual está entre los
				// reconocidos.
				boolean isCaNameRecognized = possibleCrlEntryIssuersSet.contains(caName);

				// Si el emisor de la CRL se encuentra entre los reconocidos
				// o se trata de una CRL indirecta, continuamos.
				if (isIndirect || isCaNameRecognized) {

					// Contianuamos el proceso de búsqueda en un método auxiliar
					// para evitar la complejidad ciclomática.
					result = searchCrlEntryForCertificateAux(cert, tbsCertList, isIndirect, caName, possibleCrlEntryIssuersSet, isCaNameRecognized);

				} else {

					// Mensaje indicando que la CRL no es indirecta y su emisor
					// no se encuentra entre los admitidos.
					if (possibleCrlEntryIssuers == null || possibleCrlEntryIssuers.length == 0) {
						LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.UTILS_CRL_002, new Object[ ] { caName.toString(), certIssuer.toString() }));
					} else {
						LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.UTILS_CRL_003, new Object[ ] { caName.toString(), certIssuer.toString() }));
					}

				}

			} catch (CRLException e) {

				throw new CommonUtilsException(Language.getResIntegraTsl(ILogTslConstant.UTILS_CRL_004), e);

			}

		}

		return result;

	}

	/**
	 * Auxiliar method to avoid de cyclomatic complexity.
	 * Search a {@link X509CRLEntry} in the input CRL for the input certificate. Also checks if the CRL is indirect (or not) and
	 * test if it is compatible with the certificate or any of the issuers allowed.
	 * @param cert X.509 certificate to chek if has a entry in the CRL.
	 * @param tbsCertList Entries certificate list on the CRL.
	 * @param isIndirect Flag that indicates if the CRL is indirect.
	 * @param issuerCrlName a {@link X500Name} taht represents the CRL issuer.
	 * @param possibleCrlEntryIssuersSet {@link Set} of {@link X500Name} taht represents valid issuers for the CRL.
	 * @param issuerCrlRecognized Flag that indicates if at the moment is recognized the CRL issuer.
	 * @return Returns a X.509 CRL entry if the CRL has the same issuer than the certificate or any of
	 * the input possible issuers (considering also that the CRL could be indirect), and exists this entry in the CRL
	 * for the input certificate.
	 */
	private static X509CRLEntry searchCrlEntryForCertificateAux(X509Certificate cert, TBSCertList tbsCertList, boolean isIndirect, X500Name issuerCrlName, Set<X500Name> possibleCrlEntryIssuersSet, boolean issuerCrlRecognized) {

		// Se inicializa el resultado.
		X509CRLEntry result = null;

		X500Name caName = issuerCrlName;
		boolean isCaNameRecognized = issuerCrlRecognized;

		// Para no parsear todas las entradas, recorremos los objetos ASN.1.
		@SuppressWarnings("rawtypes")
		Enumeration revokedCerts = tbsCertList.getRevokedCertificateEnumeration();

		// Si se han encontrado entradas de certificados revocados...
		if (revokedCerts != null) {

			// Obtenemos el número de serie del certificado.
			BigInteger certSerialNumber = cert.getSerialNumber();

			// Mientras no hayamos encontrado la entrada CRL, y
			// haya entradas de certificados que recorrer...
			while (result == null && revokedCerts.hasMoreElements()) {

				// Parseamos el siguiente elemento.
				CRLEntry crlEntry = CRLEntry.getInstance(revokedCerts.nextElement());

				// Si la CRL es indirecta y esta entrada tiene extensiones,
				// si tiene la extensión que determina el emisor de los
				// certificados
				// revocados listados, lo sobrescribimos.
				if (isIndirect && crlEntry.hasExtensions()) {
					// Extraemos la extensión con el nombre del emisor.
					Extension currentCaName = crlEntry.getExtensions().getExtension(Extension.certificateIssuer);
					// Si no es nulo, lo extraemos.
					if (currentCaName != null) {
						caName = X500Name.getInstance(GeneralNames.getInstance(currentCaName.getParsedValue()).getNames()[0].getName());
						isCaNameRecognized = possibleCrlEntryIssuersSet.contains(caName);
					}
				}

				// Si reconocemos el emisor actual y el número de serie coincide
				// con el
				// del certificado.
				if (isCaNameRecognized && crlEntry.getUserCertificate().getValue().equals(certSerialNumber)) {

					// Esta es la entrada buscada.
					result = new X509CRLEntryObject(crlEntry);

				}

			}

		}

		// Devolvemos el resultado.
		return result;

	}

	/**
	 * Checks if the input CRL is indirect or not.
	 * @param crl X.509 CRL to analyze.
	 * @return <code>true</code> if the input CRL is indirect, otherwise <code>false</code>.
	 */
	public static boolean isIndirectCRL(X509CRL crl) {

		boolean result = false;

		if (crl != null) {

			byte[ ] idp = crl.getExtensionValue(Extension.issuingDistributionPoint.getId());
			result = idp != null && IssuingDistributionPoint.getInstance(ASN1OctetString.getInstance(idp).getOctets()).isIndirectCRL();

		}

		return result;

	}

	/**
	 * Method that obtains the CRL with the same issuer of a certificate (or one of the chain)
	 * that cover the input date or is posterior.
	 * @param cert Parameter that represents the certificate.
	 * @param crls Parameter that represents the list of CRLs to process.
	 * @param date Parameter that represents the date used to compare the the date on which the CRL has been issued.
	 * @return an object that represents the CRL that matches with the input certificate. <code>null</code>
	 *  if a compatible CRL has not been founded.
	 */
	public static X509CRL getCRLforCertificate(X509Certificate cert, X509CRL[ ] crls, Date date) {

		return getCRL(cert, null, crls, date);

	}

	/**
	 * Method that obtains the CRL with the same issuer of a certificate (or one of the chain)
	 * that cover the input date or is posterior.
	 * @param cert Parameter that represents the certificate.
	 * @param certChain Parameter that represents the certification chain to process. From starting certificate to root.
	 * @param crls Parameter that represents the list of CRLs to process.
	 * @param date Parameter that represents the date used to compare the the date on which the CRL has been issued.
	 * @return an object that represents the CRL that matches with the input certificate. <code>null</code>
	 *  if a compatible CRL has not been founded.
	 */
	public static X509CRL getCRL(X509Certificate cert, List<? extends X509Certificate> certChain, X509CRL[ ] crls, Date date) {

		X509CRL crl = null;

		// Si la lista de CRLs recibidas no es nula...
		if (crls != null) {

			// Primero tratamos de buscar aquellas CRL cuyo issuer coincida
			// perfectamente con el del certificado.
			List<X509CRL> crlsWithSameIssuerThanCert = getCRLsWithSameIssuerThanCert(cert, crls);

			// Si hemos encontrado alguna...
			if (crlsWithSameIssuerThanCert != null && !crlsWithSameIssuerThanCert.isEmpty()) {

				// Obtenemos la CRL que cubra la fecha de validación y tenga el
				// mayor
				// CRLNumber, o en su defecto, que sea posterior a la fecha de
				// validación y tenga el mayor CRLNumber.
				crl = getCRLwithRangedOrPosteriorDateAndHighestCrlNumber(crlsWithSameIssuerThanCert, date);

			}

		}

		return crl;

	}

	/**
	 * Method that obtains a sublist of CRL from the input list with the same issuer than the input certificate.
	 * @param cert Parameter that represents the certificate.
	 * @param crls Parameter that represents the list of CRLs to process.
	 * @return a sublist of CRL from the input list with the same issuer than the input certificate.
	 */
	private static List<X509CRL> getCRLsWithSameIssuerThanCert(X509Certificate cert, X509CRL[ ] crls) {

		List<X509CRL> result = null;

		if (cert != null && crls != null && crls.length > 0) {

			X500Principal certIssuerX500Principal = cert.getIssuerX500Principal();

			for (X509CRL crl: crls) {

				if (crl.getIssuerX500Principal().equals(certIssuerX500Principal)) {
					if (result == null) {
						result = new ArrayList<X509CRL>();
					}
					result.add(crl);
				}

			}

		}

		return result;

	}

	/**
	 * Gets the CRL from the input list that cover the input date or is posterior to this.
	 * If there are more than one that rules this, then is returned the one with the highest CRLNumber.
	 * @param crls List of CRLs from the same issuer to check.
	 * @param date Date to take how reference.
	 * @return the CRL from the input list that cover the input date or is postoreior to this.
	 * If there are more than one that rules this, then is returned the one with the highest CRLNumber.
	 * If no CRL is found, then return <code>null</code>.
	 */
	private static X509CRL getCRLwithRangedOrPosteriorDateAndHighestCrlNumber(List<X509CRL> crls, Date date) {

		X509CRL result = null;

		// Si la lista de CRLs no es nula ni vacía...
		if (crls != null && !crls.isEmpty()) {

			// Seleccionamos aquellas que cubran la fecha de validación.
			List<X509CRL> crlsDate = getCRLsAccordingDate(crls, date);

			// Si hemos obtenido alguna...
			if (crlsDate != null && !crlsDate.isEmpty()) {

				// Nos quedamos con aquella que tenga el número de serie más
				// alto, ya que todas pertenecen
				// al mismo emisor.
				result = getCRLWithHighestCRLNumber(crlsDate);

			} else {

				// Si no, cogemos aquellas que son posteriores a la fecha de
				// validación...
				crlsDate = getCRLsAfterSpecificDate(crls, date);

				// Si hemos obtenido alguna...
				if (crlsDate != null && !crlsDate.isEmpty()) {

					// Nos quedamos con aquella que tenga el número de serie más
					// alto, ya que todas pertenecen
					// al mismo emisor.
					result = getCRLWithHighestCRLNumber(crlsDate);

				}

			}

		}

		return result;

	}

	/**
	 * Gets the CRLs (from the input list) that are according to the input date.
	 * @param crls List of CRL to analyze.
	 * @param date Date from which take reference.
	 * @return List with the selected CRLs. <code>null</code> if there is not.
	 */
	private static List<X509CRL> getCRLsAccordingDate(List<X509CRL> crls, Date date) {

		List<X509CRL> result = null;

		if (crls != null && !crls.isEmpty() && date != null) {

			// Nos quedamos primero con aquellas CRLs que cubren con su periodo
			// de validez
			// la fecha de entrada.
			for (X509CRL crl: crls) {
				if (date.before(crl.getNextUpdate()) && date.after(crl.getThisUpdate())) {
					if (result == null) {
						result = new ArrayList<X509CRL>();
					}
					result.add(crl);
				}
			}

		}

		return result;

	}

	/**
	 * Gets the CRL from the input list with the highest CRLNumber.
	 * @param crls List of CRL to check.
	 * @return the CRL from the input list with the highest CRLNumber.
	 */
	private static X509CRL getCRLWithHighestCRLNumber(List<X509CRL> crls) {

		X509CRL result = null;

		// Si se ha recibido al menos una CRL...
		if (crls != null && !crls.isEmpty()) {

			long maxCrlNumber = -1;

			// Las recorremos...
			for (X509CRL crl: crls) {

				// Si no es nula...
				if (crl != null) {

					try {

						// Obtenemos el CRL Number.
						CRLNumber crlNumber = getCRLNumber(crl);

						// Si aún no hemos encontrado ninguna, cogemos esta
						// mismo.
						if (result == null) {

							result = crl;
							maxCrlNumber = crlNumber.getCRLNumber().longValue();

						} else {

							// Comparamos su CRLNumber con el que ya teníamos, y
							// si es mayor,
							// nos la quedamos.
							long crlNumberValue = crlNumber.getCRLNumber().longValue();
							if (crlNumberValue > maxCrlNumber) {

								result = crl;
								maxCrlNumber = crlNumberValue;

							}

						}

					} catch (Exception e) {
						LOGGER.error(e.getMessage());
					}

				}

			}

		}

		return result;

	}

	/**
	 * Gets the CRLNumber from a X.509 CRL.
	 * @param crl X.509 CRL to analyze.
	 * @return CRLNumber from the input X.509 CRL. <code>null</code> if the input parameter is <code>null</code>.
	 * @throws IOException In case of some error extracting the information from the X.509 CRL.
	 */
	public static CRLNumber getCRLNumber(X509CRL crl) throws IOException {

		CRLNumber result = null;

		if (crl != null) {

			byte[ ] crlNumberExtValByteArray = crl.getExtensionValue(Extension.cRLNumber.getId());
			ASN1InputStream ais = new ASN1InputStream(crlNumberExtValByteArray);
			try {
				DEROctetString dos = (DEROctetString) ais.readObject();
				result = new CRLNumber(ASN1Integer.getInstance(dos.getOctets()).getPositiveValue());
			} catch (IOException e) {
				throw e;
			} finally {
				UtilsResourcesCommons.safeCloseInputStream(ais);
			}

		}

		return result;

	}

	/**
	 * Gets the CRLs (from the input list) that are posterior to the input date.
	 * @param crls List of CRL to analyze.
	 * @param date Date from which take reference.
	 * @return List with the selected CRLs. <code>null</code> if there is not.
	 */
	private static List<X509CRL> getCRLsAfterSpecificDate(List<X509CRL> crls, Date date) {

		List<X509CRL> result = null;

		if (crls != null && !crls.isEmpty() && date != null) {

			// Nos quedamos con aquellas que sean posteriores a la fecha.
			for (X509CRL crl: crls) {
				if (date.before(crl.getThisUpdate())) {
					if (result == null) {
						result = new ArrayList<X509CRL>();
					}
					result.add(crl);
				}
			}

		}

		return result;

	}


}
