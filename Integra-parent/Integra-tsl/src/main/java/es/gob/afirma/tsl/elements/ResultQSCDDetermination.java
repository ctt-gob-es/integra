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
 * <b>File:</b><p>es.gob.afirma.tsl.elements.ResultQSCDDetermination.java.</p>
 * <b>Description:</b><p>Class that represents the result obtained when executing the procedure
 * 4.5.QSCD determination of ETSI TS 119 615 v.1.1.1.</p>
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
 * <p>Class that represents the result obtained when executing the procedure
 * 4.5.QSCD determination of ETSI TS 119 615 v.1.1.1.</p>
 * <b>Project:</b><p>Horizontal platform of validation services of multiPKI certificates and electronic signature.</p>
 * @version 1.0,  24/02/2023.
 */
public class ResultQSCDDetermination implements Serializable {

	/**
	 * Attribute that represents the serial version UID. 
	 */
	private static final long serialVersionUID = -2020122981806625454L;
	/**
	 * Attribute that indicates whether CERT had its private key residing in a
	 * QSCD in accordance with the trusted lists, through one of the following
	 * values: a) "QSCD_YES" to indicate that CERT had its private key residing
	 * in a QSCD at Date-time according to the EUMS trusted lists; b) "QSCD_NO"
	 * to indicate that CERT did not have its private key residing in a QSCD at
	 * Date-time according to the EUMS trusted lists; c) "QSCD_INDETERMINATE" to
	 * indicate that the EUMS trusted lists cannot be used to confirm whether
	 * CERT had its private key residing in a QSCD at Date-time; d) Void.
	 * QSCD-Status The status
	 */
	private String qscdResult;

	/**
	 * Attribute that represents the status indication of the process.
	 */
	private String qscdStatus;

	/**
	 * Attribute that represents a list of indications supplementing qscdStaus indication.
	 */
	private List<String> qscdSubStatus;

	/**
	 * Constructor method for the class ResultQSCDDetermination.java.
	 */
	public ResultQSCDDetermination() {
		qscdSubStatus = new ArrayList<String>();
	}

	/**
	 * Gets the value of the attribute {@link #qscdResult}.
	 * @return the value of the attribute {@link #qscdResult}.
	 */
	public String getQscdResult() {
		return qscdResult;
	}

	/**
	 * Sets the value of the attribute {@link #qscdResult}.
	 * @param qscdResult The value for the attribute {@link #qscdResult}.
	 */
	public void setQscdResult(String qscdResult) {
		this.qscdResult = qscdResult;
	}

	/**
	 * Gets the value of the attribute {@link #qscdStatus}.
	 * @return the value of the attribute {@link #qscdStatus}.
	 */
	public String getQscdStatus() {
		return qscdStatus;
	}

	/**
	 * Sets the value of the attribute {@link #qscdStatus}.
	 * @param qscdStatus The value for the attribute {@link #qscdStatus}.
	 */
	public void setQscdStatus(String qscdStatus) {
		this.qscdStatus = qscdStatus;
	}

	/**
	 * Gets the value of the attribute {@link #qscdSubStatus}.
	 * @return the value of the attribute {@link #qscdSubStatus}.
	 */
	public List<String> getQscdSubStatus() {
		return qscdSubStatus;
	}

	/**
	 * Sets the value of the attribute {@link #qscdSubStatus}.
	 * @param qscdSubStatus The value for the attribute {@link #qscdSubStatus}.
	 */
	public void setQscdSubStatus(List<String> qscdSubStatus) {
		this.qscdSubStatus = qscdSubStatus;
	}


}
