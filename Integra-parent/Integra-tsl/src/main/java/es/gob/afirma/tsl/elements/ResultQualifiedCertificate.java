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
 * <b>File:</b><p>es.gob.afirma.tsl.elements.ResultQualifiedCertificate.java.</p>
 * <b>Description:</b><p>Class that represents the result obtained when executing the procedure 4.4.EU
 * qualified certificate determination of ETSI TS 119 615 v.1.1.1.</p>
 * <b>Project:</b><p>Horizontal platform of validation services of multiPKI certificates and electronic signature.</p>
 * <b>Date:</b><p> 23/02/2023.</p>
 * @author Gobierno de España.
 * @version 1.0, 23/02/2023.
 */
package es.gob.afirma.tsl.elements;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import es.gob.afirma.tsl.exceptions.TSLCertificateValidationException;
import es.gob.afirma.tsl.exceptions.TSLValidationException;
import es.gob.afirma.tsl.parsing.impl.common.TSLCertificateExtensionAnalyzer;
import es.gob.afirma.tsl.parsing.impl.common.extensions.QualificationElement;

/** 
 * <p>Class that represents the result obtained when executing the procedure 4.4.EU
 * qualified certificate determination of ETSI TS 119 615 v.1.1.1.</p>
 * <b>Project:</b><p>Horizontal platform of validation services of multiPKI certificates and electronic signature.</p>
 * @version 1.0,  23/02/2023.
 */
public class ResultQualifiedCertificate implements Serializable {

	/**
	 * Attribute that represents the serial version UID. 
	 */
	private static final long serialVersionUID = -6761256209499564860L;
	/**
	 * Attribute that represents a set of indications of the EU qualified status
	 * of CERT.
	 */
	private List<QCResult> qcResults;
	/**
	 * Attribute that represents the status indication of the process.
	 */
	private String qcStatus;
	/**
	 * Attribute that represents a list of indications supplementing QC-Status
	 * indication.
	 */
	private List<String> qcSubStatus;
	/**
	 * Attribute that represents . 
	 */
	private List<QualificationElement> check1ListOfQE;
	/**
	 * Attribute that represents . 
	 */
	private List<QualificationElement> check2ListOfQE;
	/**
	 * Attribute that represents . 
	 */
	private List<QualificationElement> check3ListOfQE;

	/**
	 * Attribute that represents the information obtained in the procedure
	 * 4.4.EU qualified certificate determination of ETSI TS 119 615 v.1.1.1.
	 */
	private InfoQCResult infoQcResult;
	
	/**
	 * Attribute indicating whether the procedure has terminated.
	 */
	private boolean endProcedure;
	
	
	
	/**
	 * Attribute that represents an extension analyzer for the certificate to validate.
	 */
	private TSLCertificateExtensionAnalyzer tslCertExtAnalyzer = null;

	/**
	 * Constructor method for the class ResultQualifiedCertificate.java.
	 */
	public ResultQualifiedCertificate() {
		qcSubStatus = new ArrayList<String>();
		qcResults  = new ArrayList<QCResult>();
		check1ListOfQE = new ArrayList<QualificationElement>();
		check2ListOfQE  = new ArrayList<QualificationElement>();
		check3ListOfQE  = new ArrayList<QualificationElement>();
		infoQcResult = new InfoQCResult();
		endProcedure = Boolean.FALSE;

	}
	
	/**
	 * Constructor method for the class ResultQualifiedCertificate.java.
	 * @param cert
	 * @throws TSLValidationException 
	 */
	public ResultQualifiedCertificate(X509Certificate cert) throws TSLValidationException{
		this();
		try {
			tslCertExtAnalyzer = new TSLCertificateExtensionAnalyzer(cert);
			qcSubStatus = new ArrayList<String>();
			qcResults  = new ArrayList<QCResult>();
			check1ListOfQE = new ArrayList<QualificationElement>();
			check2ListOfQE  = new ArrayList<QualificationElement>();
			check3ListOfQE  = new ArrayList<QualificationElement>();
			infoQcResult = new InfoQCResult();
			endProcedure = Boolean.FALSE;
			
		} catch (TSLCertificateValidationException e) {
			throw new TSLValidationException(e.getMessage(), e);
		}
	}

	/**
	 * Gets the value of the attribute {@link #qcResults}.
	 * 
	 * @return the value of the attribute {@link #qcResults}.
	 */
	public List<QCResult> getQcResults() {
		return qcResults;
	}

	/**
	 * Sets the value of the attribute {@link #qcResults}.
	 * 
	 * @param qcResults
	 *            The value for the attribute {@link #qcResults}.
	 */
	public void setQcResults(List<QCResult> qcResults) {
		this.qcResults = qcResults;
	}

	/**
	 * Gets the value of the attribute {@link #qcStatus}.
	 * 
	 * @return the value of the attribute {@link #qcStatus}.
	 */
	public String getQcStatus() {
		return qcStatus;
	}

	/**
	 * Sets the value of the attribute {@link #qcStatus}.
	 * 
	 * @param qcStatus
	 *            The value for the attribute {@link #qcStatus}.
	 */
	public void setQcStatus(String qcStatus) {
		this.qcStatus = qcStatus;
	}

	/**
	 * Gets the value of the attribute {@link #qcSubStatus}.
	 * 
	 * @return the value of the attribute {@link #qcSubStatus}.
	 */
	public List<String> getQcSubStatus() {
		return qcSubStatus;
	}

	/**
	 * Sets the value of the attribute {@link #qcSubStatus}.
	 * 
	 * @param qcSubStatus
	 *            The value for the attribute {@link #qcSubStatus}.
	 */
	public void setQcSubStatus(List<String> qcSubStatus) {
		this.qcSubStatus = qcSubStatus;
	}

	/**
	 * Gets the value of the attribute {@link #infoQcResult}.
	 * @return the value of the attribute {@link #infoQcResult}.
	 */
	public InfoQCResult getInfoQcResult() {
		return infoQcResult;
	}

	/**
	 * Sets the value of the attribute {@link #infoQcResult}.
	 * @param infoQcResult The value for the attribute {@link #infoQcResult}.
	 */
	public void setInfoQcResult(InfoQCResult infoQcResult) {
		this.infoQcResult = infoQcResult;
	}

	/**
	 * Gets the value of the attribute {@link #tslCertExtAnalyzer}.
	 * @return the value of the attribute {@link #tslCertExtAnalyzer}.
	 */
	public TSLCertificateExtensionAnalyzer getTslCertExtAnalyzer() {
		return tslCertExtAnalyzer;
	}

	/**
	 * Gets the value of the attribute {@link #check1ListOfQE}.
	 * @return the value of the attribute {@link #check1ListOfQE}.
	 */
	public List<QualificationElement> getCheck1ListOfQE() {
		return check1ListOfQE;
	}

	/**
	 * Gets the value of the attribute {@link #check2ListOfQE}.
	 * @return the value of the attribute {@link #check2ListOfQE}.
	 */
	public List<QualificationElement> getCheck2ListOfQE() {
		return check2ListOfQE;
	}

	/**
	 * Gets the value of the attribute {@link #check3ListOfQE}.
	 * @return the value of the attribute {@link #check3ListOfQE}.
	 */
	public List<QualificationElement> getCheck3ListOfQE() {
		return check3ListOfQE;
	}

	/**
	 * Gets the value of the attribute {@link #endProcedure}.
	 * @return the value of the attribute {@link #endProcedure}.
	 */
	public boolean isEndProcedure() {
		return endProcedure;
	}

	/**
	 * Sets the value of the attribute {@link #endProcedure}.
	 * @param endProcedure The value for the attribute {@link #endProcedure}.
	 */
	public void setEndProcedure(boolean endProcedure) {
		this.endProcedure = endProcedure;
	}

}
