/* 
* Este fichero forma parte de la plataforma de @firma. 
* La plataforma de @firma es de libre distribución cuyo código fuente puede ser consultado
* y descargado desde http://administracionelectronica.gob.es
*
* Copyright 2005-2019 Gobierno de España
* Este fichero se distribuye bajo las licencias EUPL versión 1.1 según las
* condiciones que figuran en el fichero 'LICENSE.txt' que se acompaña.  Si se   distribuyera este 
* fichero individualmente, deben incluirse aquí las condiciones expresadas allí.
*/

/** 
 * <b>File:</b><p>es.gob.afirma.tsl.elements.InfoCertificateIssuer.java.</p>
 * <b>Description:</b><p>Class that represents the information of the issuer certificate obtained from the TSL of the certificate to be validated. .</p>
 * <b>Project:</b><p>Horizontal platform of validation services of multiPKI certificates and electronic signature.</p>
 * <b>Date:</b><p> 24/02/2023.</p>
 * @author Gobierno de España.
 * @version 1.0, 24/02/2023.
 */
package es.gob.afirma.tsl.elements;

import java.io.Serializable;
import java.security.PublicKey;
import java.security.cert.X509Certificate;


/** 
 * <p>Class that represents the information of the issuer certificate obtained from the TSL of the certificate to be validated. .</p>
 * <b>Project:</b><p>Horizontal platform of validation services of multiPKI certificates and electronic signature.</p>
 * @version 1.0,  24/02/2023.
 */
public class InfoCertificateIssuer implements Serializable {

	/**
	 * Attribute that represents the serial version UID. 
	 */
	private static final long serialVersionUID = -7810515956041240322L;
	
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
