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
 * <b>File:</b><p>es.gob.afirma.tsl.elements.TspServiceQualifier.java.</p>
 * <b>Description:</b><p>Class representing the qualifiers contained in a TSPservice that identifies a
 * certificate.</p>
 * <b>Project:</b><p>Horizontal platform of validation services of multiPKI certificates and electronic signature.</p>
 * <b>Date:</b><p> 24/02/2023.</p>
 * @author Gobierno de España.
 * @version 1.1, 05/03/2024.
 */
package es.gob.afirma.tsl.elements;

import java.io.Serializable;


/** 
 * <p>Class representing the qualifiers contained in a TSPservice that identifies a
 * certificate.</p>
 * <b>Project:</b><p>Horizontal platform of validation services of multiPKI certificates and electronic signature.</p>
 * @version 1.1,  05/03/2024.
 */
public class TspServiceQualifier implements Serializable {

	/**
	 * Attribute that represents the serial version UID. 
	 */
	private static final long serialVersionUID = 7497353511695373659L;

	/**
	 * Attribute indicating whether the TSPService contains the "notQualified"
	 * qualifier.
	 */
	private boolean notQualified;
	/**
	 * Attribute indicating whether the TSPService contains the "qcStatement"
	 * qualifier.
	 */
	private boolean qcStatement;
	/**
	 * Attribute indicating whether the TSPService contains the "qcForESig"
	 * qualifier.
	 */
	private boolean qcForESig;
	/**
	 * Attribute indicating whether the TSPService contains the "qcForESeal"
	 * qualifier.
	 */
	private boolean qcForESeal;
	/**
	 * Attribute indicating whether the TSPService contains the "qcForWSA"
	 * qualifier.
	 */
	private boolean qcForWSA;
	/**
	 * Attribute indicating whether the TSPService contains the
	 * "qcForLegalPerson" qualifier.
	 */
	private boolean qcForLegalPerson;
	/**
	 * Attribute indicating whether the TSPService contains the "qcWithSSCD"
	 * qualifier.
	 */
	private boolean qcWithSSCD;
	/**
	 * Attribute indicating whether the TSPService contains the "qcNoSSCD"
	 * qualifier.
	 */
	private boolean qcNoSSCD;
	/**
	 * Attribute indicating whether the TSPService contains the
	 * "qcSSCDStatusAsInCert" qualifier.
	 */
	private boolean qcSSCDStatusAsInCert;
	/**
	 * Attribute indicating whether the TSPService contains the "qcWithQSCD"
	 * qualifier.
	 */
	private boolean qcWithQSCD;
	/**
	 * Attribute indicating whether the TSPService contains the "qcNoQSCD"
	 * qualifier.
	 */
	private boolean qcNoQSCD;
	/**
	 * Attribute indicating whether the TSPService contains the
	 * "qcQSCDStatusAsInCert" qualifier.
	 */
	private boolean qcQSCDStatusAsInCert;
	/**
	 * Attribute indicating whether the TSPService contains the
	 * "qcQSCDManagedOnBehalf" qualifier.
	 */
	private boolean qcQSCDManagedOnBehalf;

	/**
	 * Constructor method for the class TSLQualifier.java.
	 */
	public TspServiceQualifier() {
	}

	/**
	 * Method that check whether the following qualifiers are present among
	 * them: 'QCForESig'
	 * ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig"),
	 * 'NotQualified'
	 * ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/NotQualified") and
	 * 'QCStatement'
	 * ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement")
	 * 
	 * @return
	 */
	public boolean checkQcForEsigAndNotQualifiedAndQCStatementCompliance() {
		return qcForESig || notQualified || qcStatement;
	}
	
	/**
	 * Method that check whether the following qualifiers are present among
	 * them: 'QCForESig'
	 * ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForEseal"),
	 * 'NotQualified'
	 * ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/NotQualified") and
	 * 'QCStatement'
	 * ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement")
	 * 
	 * @return
	 */
	public boolean checkQcForEsealgAndNotQualifiedAndQCStatementCompliance() {
		return qcForESeal || notQualified || qcStatement;
	}
	
	/**
	 * 	/**
	 * Method that check whether the following qualifiers are present among
	 * them: 'QCForESig'
	 * ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForWSA"),
	 * 'NotQualified'
	 * ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/NotQualified") and
	 * 'QCStatement'
	 * ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement")
	 * 
	 * @return
	 */
	public boolean checkQcForWSAAndNotQualifiedAndQCStatementCompliance() {
		return qcForWSA || notQualified || qcStatement;
	}

	
	/**
	 * Method that obtains the column to be selected in the table Table 1: QC-For-eSig determination.
	 * @return Selected column.
	 */
	public String getColumnCheck1() {
		String column = null;
		if (!notQualified && !qcStatement && !qcForESig) {
			return column = IQCCertificateConstants.QC_CHECK_COLUMN1;
		}
		if (notQualified) {
			return column = IQCCertificateConstants.QC_CHECK_COLUMN2;
		}
		if (!notQualified && qcStatement && !qcForESig) {
			return column = IQCCertificateConstants.QC_CHECK_COLUMN3;
		}
		if (!notQualified && !qcStatement && qcForESig) {
			return column = IQCCertificateConstants.QC_CHECK_COLUMN4;
		}
		if (!notQualified && qcStatement && qcForESig) {
			return column = IQCCertificateConstants.QC_CHECK_COLUMN5;
		}

		return column;
	}



	/**
	 * Method that obtains the column to be selected in the table Table 2: QC-For-eSeal determination
	 * @return Selected column.
	 */
	public String getColumnCheck2() {
		String column = null;
		if (!notQualified && !qcStatement && !qcForESeal) {
			return column = IQCCertificateConstants.QC_CHECK_COLUMN1;
		}
		if (notQualified) {
			return column = IQCCertificateConstants.QC_CHECK_COLUMN2;
		}
		if (!notQualified && qcStatement && !qcForESeal) {
			return column = IQCCertificateConstants.QC_CHECK_COLUMN3;
		}
		if (!notQualified && !qcStatement && qcForESeal) {
			return column = IQCCertificateConstants.QC_CHECK_COLUMN4;
		}
		if (!notQualified && qcStatement && qcForESeal) {
			return column = IQCCertificateConstants.QC_CHECK_COLUMN5;
		}

		return column;
	}
	

	/**
	 * Method that obtains the column to be selected in the table Table 3: QC-For-WebSiteAuthentication determination
	 * @return Selected column.
	 */
	public String getColumnCheck3() {
		String column = null;
		if (!notQualified && !qcStatement && !qcForWSA) {
			return column = IQCCertificateConstants.QC_CHECK_COLUMN1;
		}
		if (notQualified) {
			return column = IQCCertificateConstants.QC_CHECK_COLUMN2;
		}
		if (!notQualified && qcStatement && !qcForWSA) {
			return column = IQCCertificateConstants.QC_CHECK_COLUMN3;
		}
		if (!notQualified && !qcStatement && qcForWSA) {
			return column = IQCCertificateConstants.QC_CHECK_COLUMN4;
		}
		if (!notQualified && qcStatement && qcForWSA) {
			return column = IQCCertificateConstants.QC_CHECK_COLUMN5;
		}

		return column;
	
	}
	
	/**
	 * Gets the value of the attribute {@link #notQualified}.
	 * 
	 * @return the value of the attribute {@link #notQualified}.
	 */
	public boolean isNotQualified() {
		return notQualified;
	}

	/**
	 * Sets the value of the attribute {@link #notQualified}.
	 * 
	 * @param notQualified
	 *            The value for the attribute {@link #notQualified}.
	 */
	public void setNotQualified(boolean notQualified) {
		this.notQualified = notQualified;
	}

	/**
	 * Gets the value of the attribute {@link #qcStatement}.
	 * 
	 * @return the value of the attribute {@link #qcStatement}.
	 */
	public boolean isQcStatement() {
		return qcStatement;
	}

	/**
	 * Sets the value of the attribute {@link #qcStatement}.
	 * 
	 * @param qcStatement
	 *            The value for the attribute {@link #qcStatement}.
	 */
	public void setQcStatement(boolean qcStatement) {
		this.qcStatement = qcStatement;
	}

	/**
	 * Gets the value of the attribute {@link #qcForESig}.
	 * 
	 * @return the value of the attribute {@link #qcForESig}.
	 */
	public boolean isQcForESig() {
		return qcForESig;
	}

	/**
	 * Sets the value of the attribute {@link #qcForESig}.
	 * 
	 * @param qcForESig
	 *            The value for the attribute {@link #qcForESig}.
	 */
	public void setQcForESig(boolean qcForESig) {
		this.qcForESig = qcForESig;
	}

	/**
	 * Gets the value of the attribute {@link #qcForESeal}.
	 * 
	 * @return the value of the attribute {@link #qcForESeal}.
	 */
	public boolean isQcForESeal() {
		return qcForESeal;
	}

	/**
	 * Sets the value of the attribute {@link #qcForESeal}.
	 * 
	 * @param qcForESeal
	 *            The value for the attribute {@link #qcForESeal}.
	 */
	public void setQcForESeal(boolean qcForESeal) {
		this.qcForESeal = qcForESeal;
	}

	/**
	 * Gets the value of the attribute {@link #qcForWSA}.
	 * 
	 * @return the value of the attribute {@link #qcForWSA}.
	 */
	public boolean isQcForWSA() {
		return qcForWSA;
	}

	/**
	 * Sets the value of the attribute {@link #qcForWSA}.
	 * 
	 * @param qcForWSA
	 *            The value for the attribute {@link #qcForWSA}.
	 */
	public void setQcForWSA(boolean qcForWSA) {
		this.qcForWSA = qcForWSA;
	}

	/**
	 * Gets the value of the attribute {@link #qcForLegalPerson}.
	 * 
	 * @return the value of the attribute {@link #qcForLegalPerson}.
	 */
	public boolean isQcForLegalPerson() {
		return qcForLegalPerson;
	}

	/**
	 * Sets the value of the attribute {@link #qcForLegalPerson}.
	 * 
	 * @param qcForLegalPerson
	 *            The value for the attribute {@link #qcForLegalPerson}.
	 */
	public void setQcForLegalPerson(boolean qcForLegalPerson) {
		this.qcForLegalPerson = qcForLegalPerson;
	}

	/**
	 * Gets the value of the attribute {@link #qcWithSSCD}.
	 * 
	 * @return the value of the attribute {@link #qcWithSSCD}.
	 */
	public boolean isQcWithSSCD() {
		return qcWithSSCD;
	}

	/**
	 * Sets the value of the attribute {@link #qcWithSSCD}.
	 * 
	 * @param qcWithSSCD
	 *            The value for the attribute {@link #qcWithSSCD}.
	 */
	public void setQcWithSSCD(boolean qcWithSSCD) {
		this.qcWithSSCD = qcWithSSCD;
	}

	/**
	 * Gets the value of the attribute {@link #qcNoSSCD}.
	 * 
	 * @return the value of the attribute {@link #qcNoSSCD}.
	 */
	public boolean isQcNoSSCD() {
		return qcNoSSCD;
	}

	/**
	 * Sets the value of the attribute {@link #qcNoSSCD}.
	 * 
	 * @param qcNoSSCD
	 *            The value for the attribute {@link #qcNoSSCD}.
	 */
	public void setQcNoSSCD(boolean qcNoSSCD) {
		this.qcNoSSCD = qcNoSSCD;
	}

	/**
	 * Gets the value of the attribute {@link #qcSSCDStatusAsInCert}.
	 * 
	 * @return the value of the attribute {@link #qcSSCDStatusAsInCert}.
	 */
	public boolean isQcSSCDStatusAsInCert() {
		return qcSSCDStatusAsInCert;
	}

	/**
	 * Sets the value of the attribute {@link #qcSSCDStatusAsInCert}.
	 * 
	 * @param qcSSCDStatusAsInCert
	 *            The value for the attribute {@link #qcSSCDStatusAsInCert}.
	 */
	public void setQcSSCDStatusAsInCert(boolean qcSSCDStatusAsInCert) {
		this.qcSSCDStatusAsInCert = qcSSCDStatusAsInCert;
	}

	/**
	 * Gets the value of the attribute {@link #qcWithQSCD}.
	 * 
	 * @return the value of the attribute {@link #qcWithQSCD}.
	 */
	public boolean isQcWithQSCD() {
		return qcWithQSCD;
	}

	/**
	 * Sets the value of the attribute {@link #qcWithQSCD}.
	 * 
	 * @param qcWithQSCD
	 *            The value for the attribute {@link #qcWithQSCD}.
	 */
	public void setQcWithQSCD(boolean qcWithQSCD) {
		this.qcWithQSCD = qcWithQSCD;
	}

	/**
	 * Gets the value of the attribute {@link #qcNoQSCD}.
	 * 
	 * @return the value of the attribute {@link #qcNoQSCD}.
	 */
	public boolean isQcNoQSCD() {
		return qcNoQSCD;
	}

	/**
	 * Sets the value of the attribute {@link #qcNoQSCD}.
	 * 
	 * @param qcNoQSCD
	 *            The value for the attribute {@link #qcNoQSCD}.
	 */
	public void setQcNoQSCD(boolean qcNoQSCD) {
		this.qcNoQSCD = qcNoQSCD;
	}

	/**
	 * Gets the value of the attribute {@link #qcQSCDStatusAsInCert}.
	 * 
	 * @return the value of the attribute {@link #qcQSCDStatusAsInCert}.
	 */
	public boolean isQcQSCDStatusAsInCert() {
		return qcQSCDStatusAsInCert;
	}

	/**
	 * Sets the value of the attribute {@link #qcQSCDStatusAsInCert}.
	 * 
	 * @param qcQSCDStatusAsInCert
	 *            The value for the attribute {@link #qcQSCDStatusAsInCert}.
	 */
	public void setQcQSCDStatusAsInCert(boolean qcQSCDStatusAsInCert) {
		this.qcQSCDStatusAsInCert = qcQSCDStatusAsInCert;
	}

	/**
	 * Gets the value of the attribute {@link #qcQSCDManagedOnBehalf}.
	 * 
	 * @return the value of the attribute {@link #qcQSCDManagedOnBehalf}.
	 */
	public boolean isQcQSCDManagedOnBehalf() {
		return qcQSCDManagedOnBehalf;
	}

	/**
	 * Sets the value of the attribute {@link #qcQSCDManagedOnBehalf}.
	 * 
	 * @param qcQSCDManagedOnBehalf
	 *            The value for the attribute {@link #qcQSCDManagedOnBehalf}.
	 */
	public void setQcQSCDManagedOnBehalf(boolean qcQSCDManagedOnBehalf) {
		this.qcQSCDManagedOnBehalf = qcQSCDManagedOnBehalf;
	}

	/**
	 * Method that obtains the column to be selected in the Table 5: QC-For-eSig determination under Directive 1999/93/EC [i.7]
	 * @return Selected column.
	 */
	public String getColumnCheck1Dir1999_93_EC() {
		String column = null;
		if (!notQualified && !qcStatement) {
			return column = IQCCertificateConstants.QC_CHECK_COLUMN1;
		}
		if (notQualified && !qcStatement) {
			return column = IQCCertificateConstants.QC_CHECK_COLUMN2;
		}
		if (!notQualified && qcStatement) {
			return column = IQCCertificateConstants.QC_CHECK_COLUMN3;
		}

		return column;
	}

}
