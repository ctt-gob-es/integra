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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.TSLCertificateExtensionAnalyzer.java.</p>
 * <b>Description:</b><p>Utilities wrapper for analyze the extensions defined in a specific X509v3 certificate.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 13/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.2, 19/09/2022.
 */
package es.gob.afirma.tsl.parsing.impl.common;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.qualified.QCStatement;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.exceptions.CommonUtilsException;
import es.gob.afirma.tsl.exceptions.TSLCertificateValidationException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.parsing.ifaces.ITSLOIDs;
import es.gob.afirma.tsl.utils.UtilsCertificateTsl;

/** 
 * <p>Utilities wrapper for analyze the extensions defined in a specific X509v3 certificate.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 19/09/2022.
 */
public class TSLCertificateExtensionAnalyzer {

    /**
     * Attribute that represents the certificate to analyze.
     */
    private Certificate certBc = null;
    /**
     * Attribute that represents the list of QcStatements OIDs extracted from the certificate.
     */
    private List<String> qcStatementsOids = null;

    /**
     * Attribute that represents the list of QcStatements Ext EU Types OIDs extracted from the certificate.
     */
    private List<String> qcStatementExtEuTypeOids = null;

    /**
     * Attribute that represents the list of Certification Policies - Policy Information OIDs extracted from the certificate.
     */
    private List<String> policyInformationsOids = null;

    /**
     * Constructor method for the class TSLCertificateExtensionAnalyzer.java.
     */
    private TSLCertificateExtensionAnalyzer() {
	super();
    }

    /**
     * Constructor method for the class TSLCertificateExtensionAnalyzer.java.
     * @param cert X509v3 certificate to analyze.
     * @throws TSLCertificateValidationException If the input certificate is <code>null</code>, or there is
     * some error extracting its information.
     */
    public TSLCertificateExtensionAnalyzer(X509Certificate cert) throws TSLCertificateValidationException {

	this();

	// Si la entrada es nula lanzamos excepción.
	if (cert == null) {
	    throw new TSLCertificateValidationException(Language.getResIntegraTsl(ILogTslConstant.TCEA_LOG001));
	}

	// Calculamos ahora la representación del certificado.
	try {
	    certBc = UtilsCertificateTsl.getBouncyCastleCertificate(cert);
	} catch (CommonUtilsException e) {
	    throw new TSLCertificateValidationException(Language.getResIntegraTsl(ILogTslConstant.TCEA_LOG002), e);
	}

	// Extraemos y analizamos las extensiones que pueda tener.
	analyzeCertificateExtensions();

    }

    /**
     * Auxiliar method that analyzes and extracts all the certificate
     * extension information.
     * @throws TSLCertificateValidationException In case of some error working with the QcStatements
     * extension or the CertificatePolicies extension.
     */
    private void analyzeCertificateExtensions() throws TSLCertificateValidationException {

	// Obtenemos la extensión QCStatements - 1.3.6.1.5.5.7.1.3,
	// la cual es opcional.
	ASN1Sequence qcStatements = null;
	try {
	    qcStatements = (ASN1Sequence) certBc.getTBSCertificate().getExtensions().getExtensionParsedValue(Extension.qCStatements);
	} catch (Exception e) {
	    throw new TSLCertificateValidationException(Language.getResIntegraTsl(ILogTslConstant.TCEA_LOG003), e);
	}

	// Si la hemos obtenido, la analizamos.
	if (qcStatements != null) {

	    // Inicializamos la lista donde los almacenaremos.
	    qcStatementsOids = new ArrayList<String>(qcStatements.size());
	    // Los recorremos y vamos guardando...
	    for (int index = 0; index < qcStatements.size(); index++) {
		QCStatement qcStatement = QCStatement.getInstance(qcStatements.getObjectAt(index));
		String qcStatementOid = qcStatement.getStatementId().getId();
		qcStatementsOids.add(qcStatementOid);
		// Analizamos si se trata del EuType, en cuyo caso obtenemos
		// la información que contenga.
		if (ITSLOIDs.OID_QCSTATEMENT_EXT_EUTYPE.getId().equals(qcStatementOid)) {
		    extractQcStatementExtEuTypeInformation(qcStatement);
		}
	    }
	}

	// Recuperamos el Certification Policies.
	CertificatePolicies certificatePolicies = null;
	try {
	    certificatePolicies = CertificatePolicies.fromExtensions(certBc.getTBSCertificate().getExtensions());
	} catch (Exception e) {
	    throw new TSLCertificateValidationException(Language.getResIntegraTsl(ILogTslConstant.TCEA_LOG004), e);
	}

	// Si hemos recuperado las políticas de certificación...
	if (certificatePolicies != null) {

	    // Recuperamos los PolicyInformation asociados.
	    PolicyInformation[ ] piArray = certificatePolicies.getPolicyInformation();

	    // Si hay...
	    if (piArray != null && piArray.length > 0) {

		// Inicializamos la lista donde los almacenaremos...
		policyInformationsOids = new ArrayList<String>(piArray.length);

		// Los recorremos y vamos almacenando...
		for (PolicyInformation policyInformation: piArray) {
		    policyInformationsOids.add(policyInformation.getPolicyIdentifier().getId());
		}

	    }

	}

    }

    /**
     * Auxiliar method that get a QcStatement QcType extension and check it for analyze
     * its type.
     * @param qcStatementQcType QcType QcStatement Extension to analyze.
     * @throws TSLCertificateValidationException In case of some error working with tht QcStatement QcType Extension.
     */
    private void extractQcStatementExtEuTypeInformation(QCStatement qcStatementQcType) throws TSLCertificateValidationException {

	ASN1Encodable qcStatementInfoAsn1Encodable = qcStatementQcType.getStatementInfo();

	// Para este caso debe tratarse de una secuencia de
	// OIDs.
	ASN1Sequence seqOids = null;
	try {
	    seqOids = ASN1Sequence.getInstance(qcStatementInfoAsn1Encodable);
	} catch (IllegalArgumentException e) {
	    seqOids = null;
	}

	// Si es una secuencia no vacía...
	if (seqOids != null && seqOids.size() > 0) {

	    // Inicializamos la lista que contendrá
	    // los EuType que tenga el certificado.
	    qcStatementExtEuTypeOids = new ArrayList<String>(seqOids.size());

	    // Los recorremos y vamos añadiendo a la lista...
	    for (int index = 0; index < seqOids.size(); index++) {

		ASN1ObjectIdentifier objectId = ASN1ObjectIdentifier.getInstance(seqOids.getObjectAt(index));
		qcStatementExtEuTypeOids.add(objectId.getId());

	    }

	}

    }

    /**
     * Gets the certificate associated to this analyzer.
     * @return X509v3 certificate used in this analyzer.
     */
    public final Certificate getCertificate() {
	return certBc;
    }

    /**
     * Gets the value of the attribute {@link #qcStatementsOids}.
     * @return the value of the attribute {@link #qcStatementsOids}.
     */
    public final List<String> getQcStatementsOids() {
	return qcStatementsOids;
    }

    /**
     * Checks if the certificate has some QcStatement extension.
     * @return <code>true</code> if the certificate has some QcStatement extension,
     * otherwise <code>false</code>.
     */
    public final boolean isThereSomeQcStatementExtension() {
	return qcStatementsOids != null && !qcStatementsOids.isEmpty();
    }

    /**
     * Checks if the certificate has the input QcStatement Extension OID.
     * @param qcStatementOid QcStatement Extension OID in {@link String} representation.
     * @return <code>true</code> if the certificate has the QcStatement Extension OID,
     * otherwise <code>false</code>.
     */
    public final boolean hasQcStatementExtensionOid(String qcStatementOid) {
	return isThereSomeQcStatementExtension() ? qcStatementsOids.contains(qcStatementOid) : false;
    }

    /**
     * Checks if the certificate has the input QcStatement Extension OID.
     * @param qcStatementOidsList QcStatement Extension OIDs List to check.
     * @return <code>true</code> if the certificate has some of the input QcStatement Extension OID,
     * otherwise <code>false</code>.
     */
    public final boolean hasSomeQcStatementExtensionOid(List<String> qcStatementOidsList) {

	boolean result = false;

	if (isThereSomeQcStatementExtension() && qcStatementOidsList != null && !qcStatementOidsList.isEmpty()) {

	    for (String qcStatementOid: qcStatementOidsList) {
		if (hasQcStatementExtensionOid(qcStatementOid)) {
		    result = true;
		    break;
		}
	    }

	}

	return result;

    }

    /**
     * Gets the value of the attribute {@link #qcStatementExtEuTypeOids}.
     * @return the value of the attribute {@link #qcStatementExtEuTypeOids}.
     */
    public final List<String> getQcStatementExtEuTypeOids() {
	return qcStatementExtEuTypeOids;
    }

    /**
     * Checks if the certificate has the QcStatement EuType extension.
     * @return <code>true</code> if the certificate has the QcStatement EuType extension,
     * otherwise <code>false</code>.
     */
    public final boolean isThereSomeQcStatementEuTypeExtension() {
	return qcStatementExtEuTypeOids != null && !qcStatementExtEuTypeOids.isEmpty();
    }

    /**
     * Checks if the certificate has the input QcStatement EuType Extension OID.
     * @param qcStatementEuTypeOid QcStatement EuType Extension OID in {@link String} representation.
     * @return <code>true</code> if the certificate has the QcStatement EuType Extension OID,
     * otherwise <code>false</code>.
     */
    public final boolean hasQcStatementEuTypeExtensionOid(String qcStatementEuTypeOid) {
	return isThereSomeQcStatementEuTypeExtension() ? qcStatementExtEuTypeOids.contains(qcStatementEuTypeOid) : false;
    }

    /**
     * Gets the value of the attribute {@link #policyInformationsOids}.
     * @return the value of the attribute {@link #policyInformationsOids}.
     */
    public final List<String> getPolicyInformationsOids() {
	return policyInformationsOids;
    }

    /**
     * Checks if the certificate has some Certification Policies - Policy Information extension.
     * @return <code>true</code> if the certificate has some Certification Policies - Policy
     * Information extension, otherwise <code>false</code>.
     */
    public final boolean isThereSomeCertPolPolInfExtension() {
	return policyInformationsOids != null && !policyInformationsOids.isEmpty();
    }

    /**
     * Checks if the certificate has the Certification Policies - Policy Information Extension OID.
     * @param certPolPolInfOid Certification Policies - Policy Information Extension OID in
     * {@link String} representation.
     * @return <code>true</code> if the certificate has the Certification Policies - Policy
     * Information Extension OID, otherwise <code>false</code>.
     */
    public final boolean hasCertPolPolInfExtensionOid(String certPolPolInfOid) {
	return isThereSomeCertPolPolInfExtension() ? policyInformationsOids.contains(certPolPolInfOid) : false;
    }

    /**
     * Checks if the certificate has some of the input Certification Policies - Policy Information Extension OIDs.
     * @param certPolPolInfOidsList Certification Policies - Policy Information Extension OIDs List to check.
     * @return <code>true</code> if the certificate has some of the input Certification Policies - Policy
     * Information Extension OIDs, otherwise <code>false</code>.
     */
    public final boolean hasSomeCertPolPolInfExtensionOid(List<String> certPolPolInfOidsList) {

	boolean result = false;

	if (isThereSomeCertPolPolInfExtension() && certPolPolInfOidsList != null && !certPolPolInfOidsList.isEmpty()) {

	    for (String certPolPolInfOid: certPolPolInfOidsList) {
		if (hasCertPolPolInfExtensionOid(certPolPolInfOid)) {
		    result = true;
		    break;
		}
	    }

	}

	return result;

    }

}
