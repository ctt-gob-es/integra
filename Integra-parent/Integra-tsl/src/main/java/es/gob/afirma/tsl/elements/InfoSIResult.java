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
 * <b>File:</b><p>es.gob.afirma.tsl.elements.InfoSIResult.java.</p>
 * <b>Description:</b><p>Class representing information obtained in the procedure 4.3.Obtaining listed
 * services matching a certificate of ETSI TS 119 615 v.1.1.1.</p>
 * <b>Project:</b><p>Horizontal platform of validation services of multiPKI certificates and electronic signature.</p>
 * <b>Date:</b><p> 24/02/2023.</p>
 * @author Gobierno de España.
 * @version 1.1, 24/07/2023.
 */
package es.gob.afirma.tsl.elements;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;


/** 
 * <p>Class representing information obtained in the procedure 4.3.Obtaining listed
 * services matching a certificate of ETSI TS 119 615 v.1.1.1.</p>
 * <b>Project:</b><p>Horizontal platform of validation services of multiPKI certificates and electronic signature.</p>
 * @version 1.1,  24/07/2023.
 */
public class InfoSIResult implements Serializable {

	/**
	 * Attribute that represents the serial version UID. 
	 */
	private static final long serialVersionUID = -121235106994058576L;
	/**
	 * Attribute that represents the 'TSPName' list of the TSPServices that the
	 * certificate identifies.
	 */
	private List<String> listTSPNames;
	/**
	 * Attribute that represents the 'TSPTradeName' list of the TSPServices that
	 * the certificate identifies.
	 */
	private List<String> listTSPTradeNames;
	
	/**
	 * Attribute that represents the 'TSPNames' list of the TSPServices of the country of the certificate.
	 */
	private List<String> listTSPNamesCountry;
	/**
	 * Attribute that represents the 'TSPTradeName' list of the TSPServices of the country of the certificate.
	 */
	private List<String> listTSPTradeNamesCountry;

	/**
	 * Attribute that represents the list of the ServiceHistoryInstance.
	 */
	private List<ServiceHistoryInstance> listSiAtDateTime;
	/**
	 * Attribute that stores information from the TSPService that has identified
	 * the timestamp certificate.
	 */
	private SIResult siResultTSA;
	
	/**
	 * Constructor method for the class InfoSIResult.java.
	 */
	public InfoSIResult() {
		listTSPNames = new ArrayList<String>();
		listTSPTradeNames = new ArrayList<String>();
		listSiAtDateTime = new ArrayList<ServiceHistoryInstance>();
		listTSPNamesCountry = new ArrayList<String>();
		listTSPTradeNamesCountry = new ArrayList<String>();
	}

	/**
	 * Gets the value of the attribute {@link #listTSPNames}.
	 * 
	 * @return the value of the attribute {@link #listTSPNames}.
	 */
	public List<String> getListTSPNames() {
		return listTSPNames;
	}

	/**
	 * Sets the value of the attribute {@link #listTSPNames}.
	 * 
	 * @param listTSPNames
	 *            The value for the attribute {@link #listTSPNames}.
	 */
	public void setListTSPNames(List<String> listTSPNames) {
		this.listTSPNames = listTSPNames;
	}

	/**
	 * Gets the value of the attribute {@link #listTSPTradeNames}.
	 * 
	 * @return the value of the attribute {@link #listTSPTradeNames}.
	 */
	public List<String> getListTSPTradeNames() {
		return listTSPTradeNames;
	}

	/**
	 * Sets the value of the attribute {@link #listTSPTradeNames}.
	 * 
	 * @param listTSPTradeNames
	 *            The value for the attribute {@link #listTSPTradeNames}.
	 */
	public void setListTSPTradeNames(List<String> listTSPTradeNames) {
		this.listTSPTradeNames = listTSPTradeNames;
	}

	/**
	 * Gets the value of the attribute {@link #listSiAtDateTime}.
	 * 
	 * @return the value of the attribute {@link #listSiAtDateTime}.
	 */
	public List<ServiceHistoryInstance> getListSiAtDateTime() {
		return listSiAtDateTime;
	}

	/**
	 * Sets the value of the attribute {@link #listSiAtDateTime}.
	 * 
	 * @param listSiAtDateTime
	 *            The value for the attribute {@link #listSiAtDateTime}.
	 */
	public void setListSiAtDateTime(List<ServiceHistoryInstance> listSiAtDateTime) {
		this.listSiAtDateTime = listSiAtDateTime;
	}

	/**
	 * Gets the value of the attribute {@link #siResultTSA}.
	 * 
	 * @return the value of the attribute {@link #siResultTSA}.
	 */
	public SIResult getSiResultTSA() {
		return siResultTSA;
	}

	/**
	 * Sets the value of the attribute {@link #siResultTSA}.
	 * 
	 * @param siResultTSA
	 *            The value for the attribute {@link #siResultTSA}.
	 */
	public void setSiResultTSA(SIResult siResultTSA) {
		this.siResultTSA = siResultTSA;
	}

	
	/**
	 * Gets the value of the attribute {@link #listTSPNamesCountry}.
	 * @return the value of the attribute {@link #listTSPNamesCountry}.
	 */
	public List<String> getListTSPNamesCountry() {
	    return listTSPNamesCountry;
	}

	
	/**
	 * Sets the value of the attribute {@link #listTSPNamesCountry}.
	 * @param listTSPNamesCountry The value for the attribute {@link #listTSPNamesCountry}.
	 */
	public void setListTSPNamesCountry(List<String> listTSPNamesCountry) {
	    this.listTSPNamesCountry = listTSPNamesCountry;
	}

	
	/**
	 * Gets the value of the attribute {@link #listTSPTradeNamesCountry}.
	 * @return the value of the attribute {@link #listTSPTradeNamesCountry}.
	 */
	public List<String> getListTSPTradeNamesCountry() {
	    return listTSPTradeNamesCountry;
	}

	
	/**
	 * Sets the value of the attribute {@link #listTSPTradeNamesCountry}.
	 * @param listTSPTradeNamesCountry The value for the attribute {@link #listTSPTradeNamesCountry}.
	 */
	public void setListTSPTradeNamesCountry(List<String> listTSPTradeNamesCountry) {
	    this.listTSPTradeNamesCountry = listTSPTradeNamesCountry;
	}

}
