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
 * <b>File:</b><p>es.gob.afirma.tsl.elements.CertificateExtension.java.</p>
 * <b>Description:</b><p> .</p>
 * <b>Project:</b><p>Horizontal platform of validation services of multiPKI certificates and electronic signature.</p>
 * <b>Date:</b><p> 23/02/2023.</p>
 * @author Gobierno de España.
 * @version 1.2,  13/02/2024.
 */
package es.gob.afirma.tsl.elements;

import java.io.Serializable;


/** 
 * <p>Class representing the extensions contained in the certificate.</p>
 * <b>Project:</b><p>Horizontal platform of validation services of multiPKI certificates and electronic signature.</p>
 * @version 1.2,  13/02/2024.
 */
public class CertificateExtension implements Serializable {

	/**
	 * Attribute that represents the serial version UID. 
	 */
	private static final long serialVersionUID = 1183055320896780558L;
	/**
	 * Attribute that indicates if the certificate contains the extension
	 * 'id_etsi_qcs_QcCompliance'.
	 */
	private boolean qcCompliance;
	/**
	 * Attribute that indicates if the certificate contains the extension
	 * 'id_etsi_qct_esign'.
	 */
	private boolean qcType1;
	/**
	 * Attribute that indicates if the certificate contains the extension
	 * 'id_etsi_qct_eseal'.
	 */
	private boolean qcType2;
	/**
	 * Attribute that indicates if the certificate contains the extension
	 * 'id_etsi_qct_web'.
	 */
	private boolean qcType3;
	/**
	 * Attribute that indicates if the certificate contains the extension
	 * 'qcp-public'.
	 */
	private boolean policyIdQCP;
	/**
	 * Attribute that indicates if the certificate contains the extension
	 * 'qcp-public-with-sscd'.
	 */
	private boolean policyIdQCP_SSCD;
	/**
	 * Attribute that indicates if the certificate contains the extension
	 * 'id_etsi_qcs_QcSSCD'.
	 */
	private boolean qcSSCD;

	/**
	 * Constructor method for the class CertificateExtension.java.
	 */
	public CertificateExtension() {
	}

	/**
	 * Method that obtains the row to be selected in the Table 1: QC-For-eSig
	 * determination, Table 2: QC-For-eSeal determination y Table 3:
	 * QC-For-WebSiteAuthentication determination.
	 * 
	 * @return Selected row.
	 */
	public String getRowCheck() {
	    String row = null;
		if ((qcCompliance && !qcType1 && !qcType2 && !qcType3)|| (qcCompliance && qcType1 && !qcType2 && !qcType3)) {
			return row = IQCCertificateConstants.QC_ROW1;
		}
		if (qcCompliance && !qcType1 && qcType2 && !qcType3) {
			return row = IQCCertificateConstants.QC_ROW2;
		}
		if (qcCompliance && !qcType1 && !qcType2 && qcType3) {
			return row = IQCCertificateConstants.QC_ROW3;
		}
		if (qcCompliance && qcType1 && qcType2 && !qcType3) {
			return row = IQCCertificateConstants.QC_ROW4;
		}
		if (qcCompliance && qcType1 && !qcType2 && qcType3) {
			return row = IQCCertificateConstants.QC_ROW5;
		}
		if (qcCompliance && !qcType1 && qcType2 && qcType3) {
			return row = IQCCertificateConstants.QC_ROW6;
		}
		if (qcCompliance && qcType1 && qcType2 && qcType3) {
			return row = IQCCertificateConstants.QC_ROW7;
		}
		if (!qcCompliance && !qcType1 && !qcType2 && !qcType3) {
			return row = IQCCertificateConstants.QC_ROW8;
		}
		if (!qcCompliance && qcType1 && !qcType2 && !qcType3) {
			return row = IQCCertificateConstants.QC_ROW9;
		}
		if (!qcCompliance && !qcType1 && qcType2 && !qcType3) {
			return row = IQCCertificateConstants.QC_ROW10;
		}
		if (!qcCompliance && !qcType1 && !qcType2 && qcType3) {
			return row = IQCCertificateConstants.QC_ROW11;
		}
		if (!qcCompliance && qcType1 && qcType2 && !qcType3) {
			return row = IQCCertificateConstants.QC_ROW12;
		}
		if (!qcCompliance && qcType1 && !qcType2 && qcType3) {
			return row = IQCCertificateConstants.QC_ROW13;
		}
		if (!qcCompliance && !qcType1 && qcType2 && qcType3) {
			return row = IQCCertificateConstants.QC_ROW14;
		}
		if (!qcCompliance && qcType1 && qcType2 && qcType3) {
			return row = IQCCertificateConstants.QC_ROW15;
		}
		return row;
	}

	/**
	 * Method that obtains the row to be selected in the Table 5: QC-For-eSig
	 * determination under Directive 1999/93/EC [i.7]
	 * 
	 * @return Selected row.
	 */
	public String getRowCheck1Dir1999_93_EC() {
		String row = null;
		if (qcCompliance && !policyIdQCP && !policyIdQCP_SSCD) {
			return row = IQCCertificateConstants.QC_ROW1;
		}
		if (!qcCompliance && policyIdQCP && !policyIdQCP_SSCD) {
			return row = IQCCertificateConstants.QC_ROW2;
		}
		if (!qcCompliance && !policyIdQCP && policyIdQCP_SSCD) {
			return row = IQCCertificateConstants.QC_ROW3;
		}
		if (qcCompliance || policyIdQCP || policyIdQCP_SSCD) {
			return row = IQCCertificateConstants.QC_ROW4;
		}
		if (!qcCompliance && !policyIdQCP && !policyIdQCP_SSCD) {
			return row = IQCCertificateConstants.QC_ROW5;
		}

		return row;
	}

	/**
	 * Gets the value of the attribute {@link #qcCompliance}.
	 * 
	 * @return the value of the attribute {@link #qcCompliance}.
	 */
	public boolean isQcCompliance() {
		return qcCompliance;
	}

	/**
	 * Sets the value of the attribute {@link #qcCompliance}.
	 * 
	 * @param qcCompliance
	 *            The value for the attribute {@link #qcCompliance}.
	 */
	public void setQcCompliance(boolean qcCompliance) {
		this.qcCompliance = qcCompliance;
	}

	/**
	 * Gets the value of the attribute {@link #qcType1}.
	 * 
	 * @return the value of the attribute {@link #qcType1}.
	 */
	public boolean isQcType1() {
		return qcType1;
	}

	/**
	 * Sets the value of the attribute {@link #qcType1}.
	 * 
	 * @param qcType1
	 *            The value for the attribute {@link #qcType1}.
	 */
	public void setQcType1(boolean qcType1) {
		this.qcType1 = qcType1;
	}

	/**
	 * Gets the value of the attribute {@link #qcType2}.
	 * 
	 * @return the value of the attribute {@link #qcType2}.
	 */
	public boolean isQcType2() {
		return qcType2;
	}

	/**
	 * Sets the value of the attribute {@link #qcType2}.
	 * 
	 * @param qcType2
	 *            The value for the attribute {@link #qcType2}.
	 */
	public void setQcType2(boolean qcType2) {
		this.qcType2 = qcType2;
	}

	/**
	 * Gets the value of the attribute {@link #qcType3}.
	 * 
	 * @return the value of the attribute {@link #qcType3}.
	 */
	public boolean isQcType3() {
		return qcType3;
	}

	/**
	 * Sets the value of the attribute {@link #qcType3}.
	 * 
	 * @param qcType3
	 *            The value for the attribute {@link #qcType3}.
	 */
	public void setQcType3(boolean qcType3) {
		this.qcType3 = qcType3;
	}

	/**
	 * Gets the value of the attribute {@link #policyIdQCP}.
	 * 
	 * @return the value of the attribute {@link #policyIdQCP}.
	 */
	public boolean isPolicyIdQCP() {
		return policyIdQCP;
	}

	/**
	 * Sets the value of the attribute {@link #policyIdQCP}.
	 * 
	 * @param policyIdQCP
	 *            The value for the attribute {@link #policyIdQCP}.
	 */
	public void setPolicyIdQCP(boolean policyIdQCP) {
		this.policyIdQCP = policyIdQCP;
	}

	/**
	 * Gets the value of the attribute {@link #policyIdQCP_SSCD}.
	 * 
	 * @return the value of the attribute {@link #policyIdQCP_SSCD}.
	 */
	public boolean isPolicyIdQCP_SSCD() {
		return policyIdQCP_SSCD;
	}

	/**
	 * Sets the value of the attribute {@link #policyIdQCP_SSCD}.
	 * 
	 * @param policyIdQCP_SSCD
	 *            The value for the attribute {@link #policyIdQCP_SSCD}.
	 */
	public void setPolicyIdQCP_SSCD(boolean policyIdQCP_SSCD) {
		this.policyIdQCP_SSCD = policyIdQCP_SSCD;
	}

	/**
	 * Gets the value of the attribute {@link #qcSSCD}.
	 * 
	 * @return the value of the attribute {@link #qcSSCD}.
	 */
	public boolean isQcSSCD() {
		return qcSSCD;
	}

	/**
	 * Sets the value of the attribute {@link #qcSSCD}.
	 * 
	 * @param qcSSCD
	 *            The value for the attribute {@link #qcSSCD}.
	 */
	public void setQcSSCD(boolean qcSSCD) {
		this.qcSSCD = qcSSCD;
	}

	/**
	 * Method to obtain the row of Table 6: QSCD status check
	 * (Directive regime).
	 * @return selected row.
	 */
	public String getRowQSCDDirectiveRegime() {
		String row = null;
		if (qcSSCD || policyIdQCP_SSCD) {
			row = IQCCertificateConstants.QC_ROW1;
		}
		if (!qcSSCD && !policyIdQCP_SSCD) {
			row = IQCCertificateConstants.QC_ROW2;
		}
		return row;
	}

	/**
	 * Method to obtain the row of Table 7: QSCD status check (Regulation regime)
	 * 
	 * @return selected row.
	 */
	public String getRowQSCDRegulationRegime() {
		String row = null;
		if (qcSSCD) {
			row = IQCCertificateConstants.QC_ROW1;
		} else {
			row = IQCCertificateConstants.QC_ROW2;
		}
		return row;
	}

}
