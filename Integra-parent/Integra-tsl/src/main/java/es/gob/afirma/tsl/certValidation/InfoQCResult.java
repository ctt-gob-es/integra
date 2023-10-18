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
 * <b>File:</b><p>es.gob.afirma.tsl.certValidation.InfoQCResult.java.</p>
 * <b>Description:</b><p>Class representing information obtained in the procedure 4.4.EU
 * qualified certificate determination of ETSI TS 119 615 v.1.1.1.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 25/09/2023.</p>
 * @author Gobierno de España.
 * @version 1.0, 25/09/2023.
 */
package es.gob.afirma.tsl.certValidation;

import java.io.Serializable;

import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;
import es.gob.afirma.tsl.parsing.impl.common.TSPService;
import es.gob.afirma.tsl.parsing.impl.common.TrustServiceProvider;


/** 
 * <p>Class representing information obtained in the procedure 4.4.EU
 * qualified certificate determination of ETSI TS 119 615 v.1.1.1.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 25/09/2023.
 */
public class InfoQCResult implements Serializable {

    /**
     * Attribute that represents that represents the serial version UID.
     */
    private static final long serialVersionUID = -3353019569258292740L;
    /**
	 * Attribute indicating whether the certificate has been detected in the TSL.
	 */
	private boolean certificateDetected;
	
	/**
	 * Attribute that represents a 'TSP name' element.
	 */
	private String tspName;
	/**
	 * Attribute that represents a 'TSP trade name' element.
	 */
	private String tspTradeName;


	/**
	 * Attribute indicating which qualifiers the TSPService contains.
	 */
	private TspServiceQualifier tspSerQualifier;
	
	/**
	 * Attribute indicating the extensions obtained from the certificate.
	 */
	private CertificateExtension certExtension = null;
	
	/**
	 * Attribute that indicates the value obtained in CHECK1.
	 */
	private String check1;
	/**
	 * Attribute that indicates the value obtained in CHECK1.
	 */
	private String check2;
	/**
	 * Attribute that indicates the value obtained in CHECK1.
	 */
	private String check3;
	
	/**
	 * Attribute that stores information from the TSPService that has identified the timestamp certificate.
	 */
	private TSPService tspServiceTSA;
	
	/**
	 * Attribute that indicates that the certificate has been detected in a time-stamping service.
	 */
	private boolean tspServiceTSADetected;
	/**
	 * Attribute that represents the row to be selected in the table Table 1: QC-For-eSig determination, Table 2: QC-For-eSeal determination y Table 3: QC-For-WebSiteAuthentication determination. 
	 */
	private String selectRow;
	
	/**
	 * Attribute that represents . 
	 */
	private TspServiceQualifier qualifierCheck1;
	/**
	 * Attribute that represents . 
	 */
	private TspServiceQualifier qualifierCheck2;
	/**
	 * Attribute that represents . 
	 */
	private TspServiceQualifier qualifierCheck3;
	/**
	 * Attribute that stores information from the TSPService that has identified the certificate.
	 */
	private TSPService tspServiceDetected;
	
	/**
	 * Attribute that stores information from the TrustServiceProvider that has identified the certificate.
	 */
	private TrustServiceProvider tspDetected;
	
	/**
	 * Attribute that represents the information obtained about the certificate issuer of the certificate to be validated during PROC 3.
	 */
	private InfoCertificateIssuer infoCertificateIssuer;
	
	
	/**
	 * TSL - TSP Service History Information from which extract the information to validate the certificate.
	 */
	private ServiceHistoryInstance shiSelected;
	
	/**
	 * Attribute that indicates if the input Service Information is from an Historic Service (<code>true</code>)
	 */
	private boolean isHistoricServiceInf = Boolean.FALSE;
	

	/**
	 * Constructor method for the class InfoQCResult.java.
	 */
	public InfoQCResult() {
		qualifierCheck1 = new TspServiceQualifier();
		qualifierCheck2 =new TspServiceQualifier();
		qualifierCheck3 = new TspServiceQualifier();
		infoCertificateIssuer = new InfoCertificateIssuer();
		tspServiceTSADetected = Boolean.FALSE;
		
	
		
	}

	/**
	 * Gets the value of the attribute {@link #certificateDetected}.
	 * @return the value of the attribute {@link #certificateDetected}.
	 */
	public boolean isCertificateDetected() {
		return certificateDetected;
	}

	/**
	 * Sets the value of the attribute {@link #certificateDetected}.
	 * @param certificateDetected The value for the attribute {@link #certificateDetected}.
	 */
	public void setCertificateDetected(boolean certificateDetected) {
		this.certificateDetected = certificateDetected;
	}

	/**
	 * Gets the value of the attribute {@link #tspSerQualifier}.
	 * @return the value of the attribute {@link #tspSerQualifier}.
	 */
	public TspServiceQualifier getTspSerQualifier() {
		return tspSerQualifier;
	}

	/**
	 * Sets the value of the attribute {@link #tspSerQualifier}.
	 * @param tspSerQualifier The value for the attribute {@link #tspSerQualifier}.
	 */
	public void setTspSerQualifier(TspServiceQualifier tspSerQualifier) {
		this.tspSerQualifier = tspSerQualifier;
	}

	/**
	 * Gets the value of the attribute {@link #certExtension}.
	 * @return the value of the attribute {@link #certExtension}.
	 */
	public CertificateExtension getCertExtension() {
		return certExtension;
	}

	/**
	 * Sets the value of the attribute {@link #certExtension}.
	 * @param certExtension The value for the attribute {@link #certExtension}.
	 */
	public void setCertExtension(CertificateExtension certExtension) {
		this.certExtension = certExtension;
	}

	/**
	 * Gets the value of the attribute {@link #check1}.
	 * @return the value of the attribute {@link #check1}.
	 */
	public String getCheck1() {
		return check1;
	}

	/**
	 * Sets the value of the attribute {@link #check1}.
	 * @param check1 The value for the attribute {@link #check1}.
	 */
	public void setCheck1(String check1) {
		this.check1 = check1;
	}

	/**
	 * Gets the value of the attribute {@link #check2}.
	 * @return the value of the attribute {@link #check2}.
	 */
	public String getCheck2() {
		return check2;
	}

	/**
	 * Sets the value of the attribute {@link #check2}.
	 * @param check2 The value for the attribute {@link #check2}.
	 */
	public void setCheck2(String check2) {
		this.check2 = check2;
	}

	/**
	 * Gets the value of the attribute {@link #check3}.
	 * @return the value of the attribute {@link #check3}.
	 */
	public String getCheck3() {
		return check3;
	}

	/**
	 * Sets the value of the attribute {@link #check3}.
	 * @param check3 The value for the attribute {@link #check3}.
	 */
	public void setCheck3(String check3) {
		this.check3 = check3;
	}

	/**
	 * Gets the value of the attribute {@link #tspServiceTSA}.
	 * @return the value of the attribute {@link #tspServiceTSA}.
	 */
	public TSPService getTspServiceTSA() {
		return tspServiceTSA;
	}

	/**
	 * Sets the value of the attribute {@link #tspServiceTSA}.
	 * @param tspServiceTSA The value for the attribute {@link #tspServiceTSA}.
	 */
	public void setTspServiceTSA(TSPService tspServiceTSA) {
		this.tspServiceTSA = tspServiceTSA;
	}

	/**
	 * Gets the value of the attribute {@link #qualifierCheck1}.
	 * @return the value of the attribute {@link #qualifierCheck1}.
	 */
	public TspServiceQualifier getQualifierCheck1() {
		return qualifierCheck1;
	}

	/**
	 * Sets the value of the attribute {@link #qualifierCheck1}.
	 * @param qualifierCheck1 The value for the attribute {@link #qualifierCheck1}.
	 */
	public void setQualifierCheck1(TspServiceQualifier qualifierCheck1) {
		this.qualifierCheck1 = qualifierCheck1;
	}

	/**
	 * Gets the value of the attribute {@link #qualifierCheck2}.
	 * @return the value of the attribute {@link #qualifierCheck2}.
	 */
	public TspServiceQualifier getQualifierCheck2() {
		return qualifierCheck2;
	}

	/**
	 * Sets the value of the attribute {@link #qualifierCheck2}.
	 * @param qualifierCheck2 The value for the attribute {@link #qualifierCheck2}.
	 */
	public void setQualifierCheck2(TspServiceQualifier qualifierCheck2) {
		this.qualifierCheck2 = qualifierCheck2;
	}

	/**
	 * Gets the value of the attribute {@link #qualifierCheck3}.
	 * @return the value of the attribute {@link #qualifierCheck3}.
	 */
	public TspServiceQualifier getQualifierCheck3() {
		return qualifierCheck3;
	}

	/**
	 * Sets the value of the attribute {@link #qualifierCheck3}.
	 * @param qualifierCheck3 The value for the attribute {@link #qualifierCheck3}.
	 */
	public void setQualifierCheck3(TspServiceQualifier qualifierCheck3) {
		this.qualifierCheck3 = qualifierCheck3;
	}

	/**
	 * Gets the value of the attribute {@link #selectRow}.
	 * @return the value of the attribute {@link #selectRow}.
	 */
	public String getSelectRow() {
		return selectRow;
	}

	/**
	 * Sets the value of the attribute {@link #selectRow}.
	 * @param selectRow The value for the attribute {@link #selectRow}.
	 */
	public void setSelectRow(String selectRow) {
		this.selectRow = selectRow;
	}

	/**
	 * Gets the value of the attribute {@link #tspServiceDetected}.
	 * @return the value of the attribute {@link #tspServiceDetected}.
	 */
	public TSPService getTspServiceDetected() {
		return tspServiceDetected;
	}

	/**
	 * Sets the value of the attribute {@link #tspServiceDetected}.
	 * @param tspServiceDetected The value for the attribute {@link #tspServiceDetected}.
	 */
	public void setTspServiceDetected(TSPService tspServiceDetected) {
		this.tspServiceDetected = tspServiceDetected;
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
	 * Gets the value of the attribute {@link #tspTradeName}.
	 * @return the value of the attribute {@link #tspTradeName}.
	 */
	public String getTspTradeName() {
		return tspTradeName;
	}

	/**
	 * Sets the value of the attribute {@link #tspTradeName}.
	 * @param tspTradeName The value for the attribute {@link #tspTradeName}.
	 */
	public void setTspTradeName(String tspTradeName) {
		this.tspTradeName = tspTradeName;
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
	 * Gets the value of the attribute {@link #infoCertificateIssuer}.
	 * @return the value of the attribute {@link #infoCertificateIssuer}.
	 */
	public InfoCertificateIssuer getInfoCertificateIssuer() {
		return infoCertificateIssuer;
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
	 * Sets the value of the attribute {@link #infoCertificateIssuer}.
	 * @param infoCertificateIssuer The value for the attribute {@link #infoCertificateIssuer}.
	 */
	public void setInfoCertificateIssuer(InfoCertificateIssuer infoCertificateIssuer) {
		this.infoCertificateIssuer = infoCertificateIssuer;
	}

	/**
	 * Gets the value of the attribute {@link #shiSelected}.
	 * @return the value of the attribute {@link #shiSelected}.
	 */
	public ServiceHistoryInstance getShiSelected() {
		return shiSelected;
	}

	/**
	 * Sets the value of the attribute {@link #shiSelected}.
	 * @param shiSelected The value for the attribute {@link #shiSelected}.
	 */
	public void setShiSelected(ServiceHistoryInstance shiSelected) {
		this.shiSelected = shiSelected;
	}


	/**
	 * Gets the value of the attribute {@link #tspServiceTSADetected}.
	 * @return the value of the attribute {@link #tspServiceTSADetected}.
	 */
	public boolean isTspServiceTSADetected() {
		return tspServiceTSADetected;
	}

	/**
	 * Sets the value of the attribute {@link #tspServiceTSADetected}.
	 * @param tspServiceTSADetected The value for the attribute {@link #tspServiceTSADetected}.
	 */
	public void setTspServiceTSADetected(boolean tspServiceTSADetected) {
		this.tspServiceTSADetected = tspServiceTSADetected;
	}
}
