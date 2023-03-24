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
 * <b>File:</b><p>es.gob.afirma.tsl.elements.QCResults.java.</p>
 * <b>Description:</b><p>Class representing the possible qualification values returned by procedure 4..4.EU qualified certificate determination of ETSI TS 119 615 v.1.1.1.</p>
 * <b>Project:</b><p>Horizontal platform of validation services of multiPKI certificates and electronic signature.</p>
 * <b>Date:</b><p> 23/02/2023.</p>
 * @author Gobierno de España.
 * @version 1.0, 23/02/2023.
 */
package es.gob.afirma.tsl.elements;



/** 
 * <p>Class representing the possible qualification values returned by procedure 4..4.EU qualified certificate determination of ETSI TS 119 615 v.1.1.1.</p>
 * <b>Project:</b><p>Horizontal platform of validation services of multiPKI certificates and electronic signature.</p>
 * @version 1.0,  23/02/2023.
 */
public enum QCResult {
	/**Attribute representing the qualification value 'NOT_QUALIFIED'.*/
	NOT_QUALIFIED("NOT_QUALIFIED"),
	/**Attribute representing the qualification value'NOT_QUALIFIED_FOR_ESIG'.*/
	NOT_QUALIFIED_FOR_ESIG("NOT_QUALIFIED_FOR_ESIG"),
	/**Attribute representing the qualification value'NOT_QUALIFIED_FOR_ESEAL'.*/
	NOT_QUALIFIED_FOR_ESEAL("NOT_QUALIFIED_FOR_ESEAL"),
	/**Attribute representing the qualification value'NOT_QWAC'.*/
	NOT_QWAC("NOT_QWAC"),
	/**Attribute representing the qualification value'QC_FOR_ESIG'.*/
	QC_FOR_ESIG("QC_FOR_ESIG"),
	/**Attribute representing the qualification value'QC_FOR_ESEAL'.*/
	QC_FOR_ESEAL("QC_FOR_ESEAL"),
	/**Attribute representing the qualification value'QWAC'.*/
	QWAC("QWAC"),
	/**Attribute representing the qualification value'INDET_QC_FOR_ESIG'.*/
	INDET_QC_FOR_ESIG("INDET_QC_FOR_ESIG"),
	/**Attribute representing the qualification value'INDET_QC_FOR_ESEAL'.*/
	INDET_QC_FOR_ESEAL("INDET_QC_FOR_ESEAL"),
	/**Attribute representing the qualification value'INDET_QWAC'.*/
	INDET_QWAC("INDET_QWAC"),
	/**Attribute representing the qualification value'INDETERMINATE'.*/
	INDETERMINATE("INDETERMINATE");

	/**
	 * Attribute that represents the qualification of a certificate.
	 */
	private String qualifiedCertificate;

	/**
	 * Constructor method for the class QCResult.java.
	 * @param qualifiedCertificateParam Qualification of a certificate.
	 */
	private QCResult(String qualifiedCertificateParam) {
		this.qualifiedCertificate = qualifiedCertificateParam;
	}

	/**
	 * Gets the value of the attribute {@link #qualifiedCertificate}.
	 * @return the value of the attribute {@link #qualifiedCertificate}.
	 */
	public String getQualifiedCertificate() {
		return qualifiedCertificate;
	}

	/**
	 * Obtains a SignatureFormat instance by a format name.
	 * @param formatName name of signature format.
	 * @return a SignatureFormat instance
	 */
	public static final QCResult getQCResult(String qc) {
		for (QCResult qCert: QCResult.values()) {
			if (qCert.getQualifiedCertificate().equals(qc)) {
				return qCert;
			}
		}
		return null;
	}
}
