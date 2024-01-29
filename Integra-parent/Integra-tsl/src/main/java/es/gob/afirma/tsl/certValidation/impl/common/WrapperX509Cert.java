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
 * <b>File:</b><p>es.gob.afirma.tsl.certValidation.impl.common.WrapperX509Cert.java.</p>
 * <b>Description:</b><p>Wrapper class for a X.509v3 Certificate. This class provides methods to
 * calculate/extract some information of the certificate.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 29/09/2023.</p>
 * @author Gobierno de España.
 * @version 1.0, 29/09/2023.
 */
package es.gob.afirma.tsl.certValidation.impl.common;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import es.gob.afirma.tsl.exceptions.CommonUtilsException;
import es.gob.afirma.tsl.exceptions.TSLCertificateValidationException;
import es.gob.afirma.tsl.parsing.impl.common.TSLCertificateExtensionAnalyzer;
import es.gob.afirma.tsl.utils.UtilsCertificateTsl;

/** 
 * <p>Wrapper class for a X.509v3 Certificate. This class provides methods to
 * calculate/extract some information of the certificate.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 29/09/2023.
 */
public class WrapperX509Cert {

	/**
	 * Attribute that represents the X.509 Certificate (Java).
	 */
	private X509Certificate x509Cert = null;

	/**
	 * Attribute that represents the X.509 Certificate (Bouncy Castle Provider).
	 */
	private Certificate x509CertBC = null;

	/**
	 * Attribute that represents an extension analyzer for the certificate.
	 */
	private TSLCertificateExtensionAnalyzer certExtAnalyzer = null;

	/**
	 * Constructor method for the class WrapperX509Cert.java.
	 */
	private WrapperX509Cert() {
		super();
	}

	/**
	 * Constructor method for the class WrapperX509Cert.java.
	 * @param cert X.509 certificate to wrap.
	 * @throws TSLCertificateValidationException In case of some error parsing
	 * the input certificate with Bouncy Castle provider.
	 */
	public WrapperX509Cert(X509Certificate cert) throws TSLCertificateValidationException {
		this();
		x509Cert = cert;
		try {
			x509CertBC = UtilsCertificateTsl.getBouncyCastleCertificate(cert);
		} catch (CommonUtilsException e) {
			throw new TSLCertificateValidationException (e.getMessage(), e);
		}
		certExtAnalyzer = new TSLCertificateExtensionAnalyzer(x509CertBC);
	}
	
	

	
	/**
	 * Gets the organization name of the certificate.
	 * @return Organization name.
	 */
	public String getOrganizationNameCertificate() {
		String result = null;
		if (x509CertBC != null) {
			X500Name x500name = x509CertBC.getTBSCertificate().getIssuer();
			RDN[ ] rndArray = x500name.getRDNs(BCStyle.O);
			if (rndArray != null && rndArray.length > 0) {
				if (rndArray[0].getFirst() != null) {
					result = IETFUtils.valueToString(rndArray[0].getFirst().getValue());
				}
			}
		}
		return result;
	}
	
	/**
	 * Gets the common name of the issuer certificate
	 * @return Issuer name.
	 */
	public String getCommonNameIssuer(){
		String result = null;
		if (x509CertBC != null) {
			X500Name x500name = x509CertBC.getTBSCertificate().getIssuer();
			RDN[ ] rndArray = x500name.getRDNs(BCStyle.CN);
			if (rndArray != null && rndArray.length > 0) {
				if (rndArray[0].getFirst() != null) {
					result = IETFUtils.valueToString(rndArray[0].getFirst().getValue());
				}
			}
		}
		return result;
	}
	
	/**
	 * Get the issuer alternative name.
	 * @return Issuer alternative name.
	 */
	public String getIssuerAlternativeName() {
		String result = null;
		if (x509CertBC.getTBSCertificate().getExtensions() != null) {
			AuthorityInformationAccess aia = AuthorityInformationAccess.fromExtensions(x509CertBC.getTBSCertificate().getExtensions());
			if (aia != null) {
				AccessDescription[ ] descriptions = aia.getAccessDescriptions();
				for (AccessDescription ad: descriptions) {
					if (ad.getAccessMethod().getId().equals(X509ObjectIdentifiers.id_ad_caIssuers.getId())){
						result = ad.getAccessLocation().getName().toString();
					}
				}
			}
		}

		return result;
	}
}
