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
 * <b>File:</b><p>es.gob.afirma.tsl.elements.SIResult.java.</p>
 * <b>Description:</b><p>Class that represents information obtained from each TSPService that
 * identifies the certificate.</p>
 * <b>Project:</b><p>Horizontal platform of validation services of multiPKI certificates and electronic signature.</p>
 * <b>Date:</b><p> 24/02/2023.</p>
 * @author Gobierno de España.
 * @version 1.1, 24/07/2023.
 */
package es.gob.afirma.tsl.elements;

import java.io.Serializable;

import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;
import es.gob.afirma.tsl.parsing.impl.common.TSPService;
import es.gob.afirma.tsl.parsing.impl.common.TrustServiceProvider;
import java.util.ArrayList;
import java.util.List;

/** 
 * <p> Class that represents information obtained from each TSPService that
 * identifies the certificate.</p>
 * <b>Project:</b><p>Horizontal platform of validation services of multiPKI certificates and electronic signature.</p>
 * @version 1.1,  24/07/2023.
 */
public class SIResult implements Serializable {

    /**
     * Attribute that represents the serial version UID. 
     */
    private static final long serialVersionUID = 5436267013549631510L;

    /**
     * Attribute that represents the XML section corresponding to a 'Service
     * information'element.
     */
    private ServiceHistoryInstance siFull;
    /**
     * Attribute that represents the XML section corresponding either to the Date-time related 'Service
     * (current) information' element or to the Date-time related
     * 'Service history instance' element.
     */
    private ServiceHistoryInstance siAtDateTime;

    /**
     * Attribute representing the TSPService associated with the SIResult.
     */
    private TSPService tspService;
    /**
     * Attribute that represents the identifier of the service status.
     */
    private String serviceStatus;

    /**
     * Attribute that represents a 'TSP name' element.
     */
    private String tspName;
    /**
     * Attribute that represents a 'TSP name' element of the country of the certificate..
     */
    private String tspNameCountry;
    /**
     * Attribute that represents list of 'TSP trade name' elements.
     */
    private List<String> listTspTradeName;

    /**
     * Attribute that stores information from the TrustServiceProvider that has identified the certificate.
     */
    private TrustServiceProvider tspDetected;

    /**
     * Attribute that indicate that "Service type identifier" for electronic signatures (ForeSignatures).
     */
    boolean asiForESIG = false;
    /**
     * Attribute that indicate that "Service type identifier" for time stamp (ForeSeals).
     */
    boolean asiForESeal = false;
    /**
     * Attribute that indicate that "Service Type Identifier" for website authentication (ForWebSiteAuthentication).
     */
    boolean asiForWSA = false;

    /**
     * Attribute that indicates if the input Service Information is from an Historic Service (<code>true</code>)
     */
    private boolean isHistoricServiceInf = Boolean.FALSE;

    /**
     * Attribute indicating whether the TSP's service type is 'http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST'.
     */
    private boolean serviceTypeIsTSAQualified = Boolean.FALSE;
    /**
     * Attribute that represents whether the process is successful or has failed.
     */
    private boolean error = Boolean.FALSE;

    /**
     * Constructor method for the class SIResult.java.
     */
    public SIResult() {
	listTspTradeName = new ArrayList<String>();
    }

    /**
     * Gets the value of the attribute {@link #siFull}.
     * @return the value of the attribute {@link #siFull}.
     */
    public ServiceHistoryInstance getSiFull() {
	return siFull;
    }

    /**
     * Sets the value of the attribute {@link #siFull}.
     * @param siFull The value for the attribute {@link #siFull}.
     */
    public void setSiFull(ServiceHistoryInstance siFull) {
	this.siFull = siFull;
    }

    /**
     * Gets the value of the attribute {@link #siAtDateTime}.
     * @return the value of the attribute {@link #siAtDateTime}.
     */
    public ServiceHistoryInstance getSiAtDateTime() {
	return siAtDateTime;
    }

    /**
     * Sets the value of the attribute {@link #siAtDateTime}.
     * @param siAtDateTime The value for the attribute {@link #siAtDateTime}.
     */
    public void setSiAtDateTime(ServiceHistoryInstance siAtDateTime) {
	this.siAtDateTime = siAtDateTime;
    }

    /**
     * Gets the value of the attribute {@link #serviceStatus}.
     * @return the value of the attribute {@link #serviceStatus}.
     */
    public String getServiceStatus() {
	return serviceStatus;
    }

    /**
     * Sets the value of the attribute {@link #serviceStatus}.
     * @param serviceStatus The value for the attribute {@link #serviceStatus}.
     */
    public void setServiceStatus(String serviceStatus) {
	this.serviceStatus = serviceStatus;
    }

    /**
     * Gets the value of the attribute {@link #tspName}.
     * @return the value of the attribute {@link #tspName}.
     */
    public String getTspName() {
	return tspName;
    }

    /**
     * Sets the value of the attribute {@link #tspName}.
     * @param tspName The value for the attribute {@link #tspName}.
     */
    public void setTspName(String tspName) {
	this.tspName = tspName;
    }

    /**
     * Gets the value of the attribute {@link #asiForESIG}.
     * @return the value of the attribute {@link #asiForESIG}.
     */
    public boolean isAsiForESIG() {
	return asiForESIG;
    }

    /**
     * Sets the value of the attribute {@link #asiForESIG}.
     * @param asiForESIG The value for the attribute {@link #asiForESIG}.
     */
    public void setAsiForESIG(boolean asiForESIG) {
	this.asiForESIG = asiForESIG;
    }

    /**
     * Gets the value of the attribute {@link #asiForESeal}.
     * @return the value of the attribute {@link #asiForESeal}.
     */
    public boolean isAsiForESeal() {
	return asiForESeal;
    }

    /**
     * Sets the value of the attribute {@link #asiForESeal}.
     * @param asiForESeal The value for the attribute {@link #asiForESeal}.
     */
    public void setAsiForESeal(boolean asiForESeal) {
	this.asiForESeal = asiForESeal;
    }

    /**
     * Gets the value of the attribute {@link #asiForWSA}.
     * @return the value of the attribute {@link #asiForWSA}.
     */
    public boolean isAsiForWSA() {
	return asiForWSA;
    }

    /**
     * Sets the value of the attribute {@link #asiForWSA}.
     * @param asiForWSA The value for the attribute {@link #asiForWSA}.
     */
    public void setAsiForWSA(boolean asiForWSA) {
	this.asiForWSA = asiForWSA;
    }

    /**
     * Gets the value of the attribute {@link #isHistoricServiceInf}.
     * @return the value of the attribute {@link #isHistoricServiceInf}.
     */
    public boolean isHistoricServiceInf() {
	return isHistoricServiceInf;
    }

    /**
     * Sets the value of the attribute {@link #isHistoricServiceInf}.
     * @param isHistoricServiceInf The value for the attribute {@link #isHistoricServiceInf}.
     */
    public void setHistoricServiceInf(boolean isHistoricServiceInf) {
	this.isHistoricServiceInf = isHistoricServiceInf;
    }

    /**
     * Gets the value of the attribute {@link #serviceTypeIsTSAQualified}.
     * @return the value of the attribute {@link #serviceTypeIsTSAQualified}.
     */
    public boolean isServiceTypeIsTSAQualified() {
	return serviceTypeIsTSAQualified;
    }

    /**
     * Sets the value of the attribute {@link #serviceTypeIsTSAQualified}.
     * @param serviceTypeIsTSAQualified The value for the attribute {@link #serviceTypeIsTSAQualified}.
     */
    public void setServiceTypeIsTSAQualified(boolean serviceTypeIsTSAQualified) {
	this.serviceTypeIsTSAQualified = serviceTypeIsTSAQualified;
    }

    /**
     * Gets the value of the attribute {@link #tspService}.
     * @return the value of the attribute {@link #tspService}.
     */
    public TSPService getTspService() {
	return tspService;
    }

    /**
     * Sets the value of the attribute {@link #tspService}.
     * @param tspService The value for the attribute {@link #tspService}.
     */
    public void setTspService(TSPService tspService) {
	this.tspService = tspService;
    }

    /**
     * Gets the value of the attribute {@link #tspDetected}.
     * @return the value of the attribute {@link #tspDetected}.
     */
    public TrustServiceProvider getTspDetected() {
	return tspDetected;
    }

    /**
     * Sets the value of the attribute {@link #tspDetected}.
     * @param tspDetected The value for the attribute {@link #tspDetected}.
     */
    public void setTspDetected(TrustServiceProvider tspDetected) {
	this.tspDetected = tspDetected;
    }

    /**
     * Gets the value of the attribute {@link #listTspTradeName}.
     * @return the value of the attribute {@link #listTspTradeName}.
     */
    public List<String> getListTspTradeName() {
	return listTspTradeName;
    }

    /**
     * Sets the value of the attribute {@link #listTspTradeName}.
     * @param tspTradeName The value for the attribute {@link #listTspTradeName}.
     */
    public void setListTspTradeName(List<String> listTspTradeName) {
	this.listTspTradeName = listTspTradeName;
    }

    /**
     * Gets the value of the attribute {@link #tspNameCountry}.
     * @return the value of the attribute {@link #tspNameCountry}.
     */
    public String getTspNameCountry() {
	return tspNameCountry;
    }

    /**
     * Sets the value of the attribute {@link #tspNameCountry}.
     * @param tspNameCountry The value for the attribute {@link #tspNameCountry}.
     */
    public void setTspNameCountry(String tspNameCountry) {
	this.tspNameCountry = tspNameCountry;
    }

    
    /**
     * Gets the value of the attribute {@link #error}.
     * @return the value of the attribute {@link #error}.
     */
    public boolean isError() {
        return error;
    }

    
    /**
     * Sets the value of the attribute {@link #error}.
     * @param error The value for the attribute {@link #error}.
     */
    public void setError(boolean error) {
        this.error = error;
    }

    /**
     * Resets all the data;
     */
    public final void resetAllData() {
	setAsiForESeal(Boolean.FALSE);
	setAsiForESIG(Boolean.FALSE);
	setAsiForWSA(Boolean.FALSE);
	setHistoricServiceInf(Boolean.FALSE);
	setServiceStatus(null);
	setServiceTypeIsTSAQualified(Boolean.FALSE);
	setSiAtDateTime(null);
	setSiFull(null);
	setTspName(null);
	setListTspTradeName(new ArrayList<String>());
	setTspDetected(null);
	setTspNameCountry(null);
	setError(Boolean.FALSE);
    }

}
