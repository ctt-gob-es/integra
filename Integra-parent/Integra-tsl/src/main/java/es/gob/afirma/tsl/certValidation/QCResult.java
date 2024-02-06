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
 * <b>File:</b><p>es.gob.afirma.tsl.certValidation.QCResult.java.</p>
 * <b>Description:</b><p>lass representing the possible qualification values returned by procedure 4..4.EU qualified certificate determination of ETSI TS 119 615 v.1.1.1.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 25/09/2023.</p>
 * @author Gobierno de España.
 * @version 1.0, 25/09/2023.
 */
package es.gob.afirma.tsl.certValidation;


/** 
 * <p>lass representing the possible qualification values returned by procedure 4..4.EU qualified certificate determination of ETSI TS 119 615 v.1.1.1.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 25/09/2023.
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
	 * @param qc name of signature format.
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
