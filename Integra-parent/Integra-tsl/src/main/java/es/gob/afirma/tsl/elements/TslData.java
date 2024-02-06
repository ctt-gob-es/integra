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
 * <b>File:</b><p>es.gob.afirma.tsl.elements.TSLData.java.</p>
 * <b>Description:</b><p>Class that represents a TSL Data Object.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/11/2020.
 */
package es.gob.afirma.tsl.elements;

import java.io.Serializable;
import java.util.Date;

/** 
 * <p>Class that represents a TSL Data Object.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2020.
 */
public class TslData implements Serializable {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = -2704705462855243130L;
    
    /**
	 * Attribute that represents the country/region for this TSL.
	 */
	private Long idTslData;

	/**
	 * Attribute that represents the sequence number of this TSL.
	 */
	private Integer sequenceNumber;

	/**
	 * Attribute that represents a TSL responsible.
	 */
	private String responsible;

	/**
	 * Attribute that represents the issue date of this TSL.
	 */
	private Date issueDate;

	/**
	 * Attribute that represents the expiration Date for this TSL.
	 */
	private Date expirationDate;

	/**
	 * Attribute that represents the URI where this TSL is officially located.
	 */
	private String uriTslLocation;

	/**
	 * Attribute that represents the XML document of this TSL.
	 */
	private byte[ ] xmlDocument;

	/**
	 * Attribute that represents the legible document of this TSL.
	 */
	private byte[ ] legibleDocument;

	/**
	 * Attribute that represents the ETSI TS specification and version of this TSL.
	 */
	private CTslImpl tslImpl;

	/**
	 * Attribute that represents the country/region for this TSL.
	 */
	private TslCountryRegion tslCountryRegion;

	
	/**
	 * Gets the value of the attribute {@link #idTslData}.
	 * @return the value of the attribute {@link #idTslData}.
	 */
	public Long getIdTslData() {
	    return idTslData;
	}

	
	/**
	 * Sets the value of the attribute {@link #idTslData}.
	 * @param idTslData The value for the attribute {@link #idTslData}.
	 */
	public void setIdTslData(Long idTslData) {
	    this.idTslData = idTslData;
	}

	
	/**
	 * Gets the value of the attribute {@link #sequenceNumber}.
	 * @return the value of the attribute {@link #sequenceNumber}.
	 */
	public Integer getSequenceNumber() {
	    return sequenceNumber;
	}

	
	/**
	 * Sets the value of the attribute {@link #sequenceNumber}.
	 * @param sequenceNumber The value for the attribute {@link #sequenceNumber}.
	 */
	public void setSequenceNumber(Integer sequenceNumber) {
	    this.sequenceNumber = sequenceNumber;
	}

	
	/**
	 * Gets the value of the attribute {@link #responsible}.
	 * @return the value of the attribute {@link #responsible}.
	 */
	public String getResponsible() {
	    return responsible;
	}

	
	/**
	 * Sets the value of the attribute {@link #responsible}.
	 * @param responsible The value for the attribute {@link #responsible}.
	 */
	public void setResponsible(String responsible) {
	    this.responsible = responsible;
	}

	
	/**
	 * Gets the value of the attribute {@link #issueDate}.
	 * @return the value of the attribute {@link #issueDate}.
	 */
	public Date getIssueDate() {
	    return issueDate;
	}

	
	/**
	 * Sets the value of the attribute {@link #issueDate}.
	 * @param issueDate The value for the attribute {@link #issueDate}.
	 */
	public void setIssueDate(Date issueDate) {
	    this.issueDate = issueDate;
	}

	
	/**
	 * Gets the value of the attribute {@link #expirationDate}.
	 * @return the value of the attribute {@link #expirationDate}.
	 */
	public Date getExpirationDate() {
	    return expirationDate;
	}

	
	/**
	 * Sets the value of the attribute {@link #expirationDate}.
	 * @param expirationDate The value for the attribute {@link #expirationDate}.
	 */
	public void setExpirationDate(Date expirationDate) {
	    this.expirationDate = expirationDate;
	}

	
	/**
	 * Gets the value of the attribute {@link #uriTslLocation}.
	 * @return the value of the attribute {@link #uriTslLocation}.
	 */
	public String getUriTslLocation() {
	    return uriTslLocation;
	}

	
	/**
	 * Sets the value of the attribute {@link #uriTslLocation}.
	 * @param uriTslLocation The value for the attribute {@link #uriTslLocation}.
	 */
	public void setUriTslLocation(String uriTslLocation) {
	    this.uriTslLocation = uriTslLocation;
	}

	
	/**
	 * Gets the value of the attribute {@link #xmlDocument}.
	 * @return the value of the attribute {@link #xmlDocument}.
	 */
	public byte[ ] getXmlDocument() {
	    return xmlDocument;
	}

	
	/**
	 * Sets the value of the attribute {@link #xmlDocument}.
	 * @param xmlDocument The value for the attribute {@link #xmlDocument}.
	 */
	public void setXmlDocument(byte[ ] xmlDocument) {
	    this.xmlDocument = xmlDocument;
	}

	
	/**
	 * Gets the value of the attribute {@link #legibleDocument}.
	 * @return the value of the attribute {@link #legibleDocument}.
	 */
	public byte[ ] getLegibleDocument() {
	    return legibleDocument;
	}

	
	/**
	 * Sets the value of the attribute {@link #legibleDocument}.
	 * @param legibleDocument The value for the attribute {@link #legibleDocument}.
	 */
	public void setLegibleDocument(byte[ ] legibleDocument) {
	    this.legibleDocument = legibleDocument;
	}

	
	/**
	 * Gets the value of the attribute {@link #tslImpl}.
	 * @return the value of the attribute {@link #tslImpl}.
	 */
	public CTslImpl getTslImpl() {
	    return tslImpl;
	}

	
	/**
	 * Sets the value of the attribute {@link #tslImpl}.
	 * @param tslImpl The value for the attribute {@link #tslImpl}.
	 */
	public void setTslImpl(CTslImpl tslImpl) {
	    this.tslImpl = tslImpl;
	}

	
	/**
	 * Gets the value of the attribute {@link #tslCountryRegion}.
	 * @return the value of the attribute {@link #tslCountryRegion}.
	 */
	public TslCountryRegion getTslCountryRegion() {
	    return tslCountryRegion;
	}

	
	/**
	 * Sets the value of the attribute {@link #tslCountryRegion}.
	 * @param tslCountryRegion The value for the attribute {@link #tslCountryRegion}.
	 */
	public void setTslCountryRegion(TslCountryRegion tslCountryRegion) {
	    this.tslCountryRegion = tslCountryRegion;
	}

	
	/**
	 * Gets the value of the attribute {@link #newTSLAvailable}.
	 * @return the value of the attribute {@link #newTSLAvailable}.
	 */
	public String getNewTSLAvailable() {
	    return newTSLAvailable;
	}

	
	/**
	 * Sets the value of the attribute {@link #newTSLAvailable}.
	 * @param newTSLAvailable The value for the attribute {@link #newTSLAvailable}.
	 */
	public void setNewTSLAvailable(String newTSLAvailable) {
	    this.newTSLAvailable = newTSLAvailable;
	}

	
	/**
	 * Gets the value of the attribute {@link #lastNewTSLAvailableFind}.
	 * @return the value of the attribute {@link #lastNewTSLAvailableFind}.
	 */
	public Date getLastNewTSLAvailableFind() {
	    return lastNewTSLAvailableFind;
	}

	
	/**
	 * Sets the value of the attribute {@link #lastNewTSLAvailableFind}.
	 * @param lastNewTSLAvailableFind The value for the attribute {@link #lastNewTSLAvailableFind}.
	 */
	public void setLastNewTSLAvailableFind(Date lastNewTSLAvailableFind) {
	    this.lastNewTSLAvailableFind = lastNewTSLAvailableFind;
	}

	
	/**
	 * Gets the value of the attribute {@link #serialVersionUID}.
	 * @return the value of the attribute {@link #serialVersionUID}.
	 */
	public static long getSerialversionuid() {
	    return serialVersionUID;
	}

	/**
	 * Attribute that represents if a new TSL are available.
	 */
	private String newTSLAvailable;

	/**
	 * Attribute that represents the last new TSL available are find.
	 */
	private Date lastNewTSLAvailableFind;
    

}
