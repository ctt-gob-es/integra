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
 * <b>File:</b><p>es.gob.afirma.tsl.certValidation.InfoCertificateIssuer.java.</p>
 * <b>Description:</b><p>Class that represents the information of the issuer certificate obtained from the TSL of the certificate to be validated.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 25/09/2023.</p>
 * @author Gobierno de España.
 * @version 1.0, 25/09/2023.
 */
package es.gob.afirma.tsl.certValidation;

import java.io.Serializable;
import java.security.PublicKey;
import java.security.cert.X509Certificate;


/** 
 * <p>Class that represents the information of the issuer certificate obtained from the TSL of the certificate to be validated.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 25/09/2023.
 */
public class InfoCertificateIssuer implements Serializable {

    /**
     * Attribute that represents . 
     */
    private static final long serialVersionUID = 4020241336711526757L;
    /**
	 * Attribute that represents the issuer X509 certificate of the certificate to validate.
	 */
	private X509Certificate issuerCert = null;

	/**
	 * Attribute that represents the issuer name of the certificate to validate.
	 */
	private String issuerSubjectName = null;

	/**
	 * Attribute that represents the issuer Public Key of the certificate to validate.
	 */
	private PublicKey issuerPublicKey = null;

	/**
	 * Attribute that represents the issuer Subject Key Identifier of the certificate to validate in bytes.
	 */
	private byte[ ] issuerSKIbytes = null;
	/**
	 * Constructor method for the class InfoCertificateIssuer.java. 
	 */
	public InfoCertificateIssuer() {
	}
	/**
	 * Gets the value of the attribute {@link #issuerCert}.
	 * @return the value of the attribute {@link #issuerCert}.
	 */
	public X509Certificate getIssuerCert() {
		return issuerCert;
	}
	/**
	 * Sets the value of the attribute {@link #issuerCert}.
	 * @param issuerCert The value for the attribute {@link #issuerCert}.
	 */
	public void setIssuerCert(X509Certificate issuerCert) {
		this.issuerCert = issuerCert;
	}
	/**
	 * Gets the value of the attribute {@link #issuerSubjectName}.
	 * @return the value of the attribute {@link #issuerSubjectName}.
	 */
	public String getIssuerSubjectName() {
		return issuerSubjectName;
	}
	/**
	 * Sets the value of the attribute {@link #issuerSubjectName}.
	 * @param issuerSubjectName The value for the attribute {@link #issuerSubjectName}.
	 */
	public void setIssuerSubjectName(String issuerSubjectName) {
		this.issuerSubjectName = issuerSubjectName;
	}
	/**
	 * Gets the value of the attribute {@link #issuerPublicKey}.
	 * @return the value of the attribute {@link #issuerPublicKey}.
	 */
	public PublicKey getIssuerPublicKey() {
		return issuerPublicKey;
	}
	/**
	 * Sets the value of the attribute {@link #issuerPublicKey}.
	 * @param issuerPublicKey The value for the attribute {@link #issuerPublicKey}.
	 */
	public void setIssuerPublicKey(PublicKey issuerPublicKey) {
		this.issuerPublicKey = issuerPublicKey;
	}
	/**
	 * Gets the value of the attribute {@link #issuerSKIbytes}.
	 * @return the value of the attribute {@link #issuerSKIbytes}.
	 */
	public byte[] getIssuerSKIbytes() {
		return issuerSKIbytes;
	}
	/**
	 * Sets the value of the attribute {@link #issuerSKIbytes}.
	 * @param issuerSKIbytes The value for the attribute {@link #issuerSKIbytes}.
	 */
	public void setIssuerSKIbytes(byte[] issuerSKIbytes) {
		this.issuerSKIbytes = issuerSKIbytes;
	}
	

}
