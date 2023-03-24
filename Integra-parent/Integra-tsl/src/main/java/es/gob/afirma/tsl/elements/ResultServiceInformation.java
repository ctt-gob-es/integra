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
 * <b>File:</b><p>es.gob.afirma.tsl.elements.ResultServiceInformation.java.</p>
 * <b>Description:</b><p> Class that represents the result obtained when executing the procedure
 * 4.3.Obtaining listed services matching a certificate of ETSI TS 119 615
 * v.1.1.1.</p>
 * <b>Project:</b><p>Horizontal platform of validation services of multiPKI certificates and electronic signature.</p>
 * <b>Date:</b><p> 24/02/2023.</p>
 * @author Gobierno de España.
 * @version 1.0, 24/02/2023.
 */
package es.gob.afirma.tsl.elements;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/** 
 * <p> Class that represents the result obtained when executing the procedure
 * 4.3.Obtaining listed services matching a certificate of ETSI TS 119 615
 * v.1.1.1.</p>
 * <b>Project:</b><p>Horizontal platform of validation services of multiPKI certificates and electronic signature.</p>
 * @version 1.0,  24/02/2023.
 */
public class ResultServiceInformation implements Serializable {

	/**
	 * Attribute that represents the serial version UID. 
	 */
	private static final long serialVersionUID = -5928966259025672264L;
	/**
	 * Class that represents information about the TSPServices that identify the
	 * certificate.
	 *
	 */
	private List<SIResult> siResults;

	/**
	 * Attribute that represents the status indication of the process consisting
	 * in obtaining for a certificate, for a specific type of 'Service type
	 * identifier' URI value, a matching listed service and its associated
	 * service information.
	 */
	private String siStatus;
	/**
	 * Attribute that represents the list of indications supplementing SI-Status indication of the process.
	 */
	private List<String> siSubStatus;
	
	/**
	 * Attribute that represents the information obtained in the procedure
	 * 4.3.Obtaining listed services matching a certificate of ETSI TS 119 615 v.1.1.1.
	 */
	private InfoSIResult infoSIResult;
	
	/**
	 * Attribute that represents the information obtained about the certificate issuer of the certificate to be validated during PROC 3.
	 */
	InfoCertificateIssuer infoCertificateIssuer;

	/**
	 * Constructor method for the class ResultServiceInformation.java.
	 */
	public ResultServiceInformation() {
		siSubStatus = new ArrayList<String>();
		siResults = new ArrayList<SIResult>();
		infoSIResult =  new InfoSIResult();
		infoCertificateIssuer = new InfoCertificateIssuer();

	}

	/**
	 * Gets the value of the attribute {@link #siResults}.
	 * @return the value of the attribute {@link #siResults}.
	 */
	public List<SIResult> getSiResults() {
		return siResults;
	}

	/**
	 * Sets the value of the attribute {@link #siResults}.
	 * @param siResults The value for the attribute {@link #siResults}.
	 */
	public void setSiResults(List<SIResult> siResults) {
		this.siResults = siResults;
	}

	/**
	 * Gets the value of the attribute {@link #siStatus}.
	 * @return the value of the attribute {@link #siStatus}.
	 */
	public String getSiStatus() {
		return siStatus;
	}

	/**
	 * Sets the value of the attribute {@link #siStatus}.
	 * @param siStatus The value for the attribute {@link #siStatus}.
	 */
	public void setSiStatus(String siStatus) {
		this.siStatus = siStatus;
	}

	/**
	 * Gets the value of the attribute {@link #siSubStatus}.
	 * @return the value of the attribute {@link #siSubStatus}.
	 */
	public List<String> getSiSubStatus() {
		return siSubStatus;
	}

	/**
	 * Sets the value of the attribute {@link #siSubStatus}.
	 * @param siSubStatus The value for the attribute {@link #siSubStatus}.
	 */
	public void setSiSubStatus(List<String> siSubStatus) {
		this.siSubStatus = siSubStatus;
	}

	/**
	 * Gets the value of the attribute {@link #infoSIResult}.
	 * @return the value of the attribute {@link #infoSIResult}.
	 */
	public InfoSIResult getInfoSIResult() {
		return infoSIResult;
	}
	

	/**
	 * Sets the value of the attribute {@link #infoSIResult}.
	 * @param infoSIResult The value for the attribute {@link #infoSIResult}.
	 */
	public void setInfoSIResult(InfoSIResult infoSIResult) {
		this.infoSIResult = infoSIResult;
	}


	/**
	 * Gets the value of the attribute {@link #infoCertificateIssuer}.
	 * @return the value of the attribute {@link #infoCertificateIssuer}.
	 */
	public InfoCertificateIssuer getInfoCertificateIssuer() {
		return infoCertificateIssuer;
	}

	/**
	 * Sets the value of the attribute {@link #infoCertificateIssuer}.
	 * @param infoCertificateIssuer The value for the attribute {@link #infoCertificateIssuer}.
	 */
	public void setInfoCertificateIssuer(InfoCertificateIssuer infoCertificateIssuer) {
		this.infoCertificateIssuer = infoCertificateIssuer;
	}

	public void removeAllData(){
		infoSIResult = new InfoSIResult();
		siResults = new ArrayList<SIResult>();
		siSubStatus = new ArrayList<String>();
		siStatus = null;
		infoCertificateIssuer = new InfoCertificateIssuer();
	}
}
