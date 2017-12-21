// Copyright (C) 2012-13 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.signature.AbstractSignatureTest.java.</p>
 * <b>Description:</b><p>Class that defines common methods used by tests defined for classes stored into <code>es.gob.afirma.signature</code> package.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/04/2015.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/04/2015.
 */
package es.gob.afirma.signature;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import junit.framework.TestCase;

import org.junit.Ignore;

import es.gob.afirma.utils.UtilsFileSystemCommons;

/** 
 * <p>Class that defines common methods used by tests defined for classes stored into <code>es.gob.afirma.signature</code> package.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 13/04/2015.
 */
@Ignore
public class AbstractSignatureTest extends TestCase {

    /**
     * Constant attribute that represents the message which identifies an exception isn't thrown. 
     */
    protected static final String ERROR_EXCEPTION_NOT_THROWED = "No se ha lanzado la excepción esperada";

    /**
     * Constant attribute that represents the XML file name defined for tests. 
     */
    private static final String XML_DOCUMENT_PATH = "ficheroAfirmar.xml";

    /**
     * Constant attribute that represents the text file name defined for tests. 
     */
    private static final String TEXT_DOCUMENT_PATH = "ficheroAfirmar.txt";

    /**
     * Constant attribute that represents the PDF file name defined for tests. 
     */
    private static final String PDF_DOCUMENT_PATH = "pdfToSign.pdf";

    /**
     * Constant attribute that represents the path for a CAdES signature generated with SHA-512 for tests. 
     */
    private static final String CADES_SIGN_PATH = "signatures/CAdES.p7s";

    /**
     * Constant attribute that represents the PDF file name defined for tests. 
     */
    private static final String PDF_DOCUMENT_SIGNED_PATH = "signatures/PDF/PAdES-Basic.pdf";

    /**
     * Constant attribute that represents the PDF file name defined for tests.
     */
    private static final String PDF_DOCUMENT_PATH_TO_SIGN_RUBRIC = "signatures/PDF/pdfToSignRubric.pdf";

    /**
     * Constant attribute that represents the PDF file name defined for tests. 
     */
    private static final String PDF_DOCUMENT_PATH_TO_COSIGN_RUBRIC = "signatures/PDF/pdfToCoSignRubric.pdf";

    /**
     * Attribute that represents the private key used for tests. 
     */
    private static PrivateKeyEntry certificatePrivateKey;

    /**
     * Attribute that represents the certificate used for tests. 
     */
    private static X509Certificate certificate;

    /**
     * Constant attribute that represents the XML file defined for tests. 
     */
    private static byte[ ] xmlDocument;

    /**
     * Constant attribute that represents the text file defined for tests. 
     */
    private static byte[ ] textDocument;

    /**
     * Constant attribute that represents the PDF file defined for tests. 
     */
    private static byte[ ] pdfDocument;

    /**
     * Constant attribute that represents the PDF file defined for tests. 
     */
    private static byte[ ] pdfDocumentCosign;

    /**
     * Constant attribute that represents the CAdES signature generated with SHA-512 for tests. 
     */
    private static byte[ ] cadesSignature;

    /**
     * Constant attribute that represents the PDF file defined for tests. 
     */
    private static byte[ ] pdfDocumentToSignRubric;
    

    /**
     * Constant attribute that represents the PDF file defined for tests. 
     */
    private static byte[ ] pdfDocumentToCoSignRubric;
    
    /**
     * Constant attribute that represents the PDF file with rubric.
     */
    private static byte[] pdfDocumentWithRubric;

    /**
     * Method that obtains the private key used for tests.
     * @return an object that represents the private key.
     */
    protected PrivateKeyEntry getCertificatePrivateKey() {
	if (certificatePrivateKey == null) {
	    KeyStore.Entry key = null;
	    try {
		InputStream is = new FileInputStream(ClassLoader.getSystemResource("keyStoreJCEKS.jks").getFile());
		KeyStore ks = KeyStore.getInstance("JCEKS");
		char[ ] password = "12345".toCharArray();
		ks.load(is, password);
		key = ks.getEntry("raul conde", new KeyStore.PasswordProtection(password));
	    } catch (NoSuchAlgorithmException e) {
		e.printStackTrace();
	    } catch (CertificateException e) {
		e.printStackTrace();
	    } catch (IOException e) {
		e.printStackTrace();
	    } catch (KeyStoreException e) {
		e.printStackTrace();
	    } catch (UnrecoverableEntryException e) {
		e.printStackTrace();
	    }
	    certificatePrivateKey = (KeyStore.PrivateKeyEntry) key;
	}
	return certificatePrivateKey;
    }

    /**
     * Method that obtains the certificate used for tests.
     * @return an object that represents the certificate.
     */
    protected X509Certificate getCertificate() {
	if (certificate == null) {
	    try {
		InputStream is = new FileInputStream(ClassLoader.getSystemResource("keyStoreJCEKS.jks").getFile());
		KeyStore ks = KeyStore.getInstance("JCEKS");
		char[ ] password = "12345".toCharArray();
		ks.load(is, password);
		certificate = (X509Certificate) ks.getCertificate("raul conde");
	    } catch (NoSuchAlgorithmException e) {
		e.printStackTrace();
	    } catch (CertificateException e) {
		e.printStackTrace();
	    } catch (IOException e) {
		e.printStackTrace();
	    } catch (KeyStoreException e) {
		e.printStackTrace();
	    }
	}
	return certificate;
    }

    /**
     * Method that obtains the text file defined for tests.
     * @return the text file defined for tests.
     */
    protected byte[ ] getTextDocument() {
	if (textDocument == null) {
	    textDocument = UtilsFileSystemCommons.readFile(TEXT_DOCUMENT_PATH, true);
	}
	return textDocument;
    }

    /**
     * Method that obtains the XML file defined for tests.
     * @return the XML file defined for tests.
     */
    protected byte[ ] getXmlDocument() {
	if (xmlDocument == null) {
	    xmlDocument = UtilsFileSystemCommons.readFile(XML_DOCUMENT_PATH, true);
	}
	return xmlDocument;
    }

    /**
     * Method that obtains the PDF file defined for tests.
     * @return the PDF file defined for tests.
     */
    protected byte[ ] getPdfDocument() {
	if (pdfDocument == null) {
	    pdfDocument = UtilsFileSystemCommons.readFile(PDF_DOCUMENT_PATH, true);
	}
	return pdfDocument;
    }

    /**
     * Method that obtains the CAdES signature generated with SHA-512 for tests.
     * @return CAdES signature generated with SHA-512 for tests.
     */
    protected byte[ ] getCadesSignature() {
	if (cadesSignature == null) {
	    cadesSignature = UtilsFileSystemCommons.readFile(CADES_SIGN_PATH, true);
	}
	return cadesSignature;
    }

    protected byte[ ] getPdfDocumentCosign() {
	if (pdfDocumentCosign == null) {
	    pdfDocumentCosign = UtilsFileSystemCommons.readFile(PDF_DOCUMENT_SIGNED_PATH, true);
	}
	return pdfDocumentCosign;
    }

    /**
     * Method that obtains the PDF file defined for tests.
     * @return the PDF file defined for tests.
     */
    protected byte[ ] getPdfDocumentToSignRubric() {
	if (pdfDocumentToSignRubric == null) {
	    pdfDocumentToSignRubric = UtilsFileSystemCommons.readFile(PDF_DOCUMENT_PATH_TO_SIGN_RUBRIC, true);
	}
	return pdfDocumentToSignRubric;
    }
    
    /**
     * Method that obtains the PDF file defined for tests.
     * @return the PDF file defined for tests.
     */
    protected byte[ ] getPdfDocumentToCosignRubric() {
	if (pdfDocumentToCoSignRubric == null) {
	    pdfDocumentToCoSignRubric = UtilsFileSystemCommons.readFile(PDF_DOCUMENT_PATH_TO_COSIGN_RUBRIC, true);
	}
	return pdfDocumentToCoSignRubric;
    }
}
