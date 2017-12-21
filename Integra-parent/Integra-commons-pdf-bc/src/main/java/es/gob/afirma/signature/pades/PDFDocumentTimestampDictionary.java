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
 * <b>File:</b><p>es.gob.afirma.signature.pades.PDFDocumentTimestampDictionary.java.</p>
 * <b>Description:</b><p>Class that contains information related to a Document Time-stamp dictionary of a PDF document.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>13/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 13/11/2014.
 */
package es.gob.afirma.signature.pades;

import java.io.Serializable;
import java.security.cert.X509Certificate;

import org.bouncycastle.tsp.TimeStampToken;

import com.lowagie.text.pdf.PdfDictionary;

/** 
 * <p>Class that contains information related to a Document Time-stamp dictionary of a PDF document.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 13/11/2014.
 */
public class PDFDocumentTimestampDictionary implements Serializable, Comparable<PDFDocumentTimestampDictionary> {

	/**
	 * Class serial version.
	 */
	private static final long serialVersionUID = -3135481642658466653L;

	/**
	 * Attribute that represents the Document Time-stamp dictionary. 
	 */
	private PdfDictionary dictionary;

	/**
	 * Attribute that represents the name of the Document Time-stamp dictionary. 
	 */
	private String name;

	/**
	 * Attribute that represents the number of the revision on the PDF document when the Document Time-stamp dictionary was added. 
	 */
	private Integer revision;

	/**
	 * Attribute that represents the time-stamp contained inside of the Document Time-stamp dictionary. 
	 */
	private TimeStampToken timestamp;

	/**
	 * Attribute that represents the signing certificate of the time-stamp contained inside of the Document Time-stamp dictionary. 
	 */
	private X509Certificate certificate;

	/**
	 * Constructor method for the class PDFDocumentTimestampDictionary.java.
	 * @param dictionaryParam Parameter that represents the signature dictionary. 
	 * @param nameParam Parameter that represents the name of the signature dictionary. 
	 * @param revisionParam Parameter that represents the number of the revision on the PDF document when the Time-stamp dictionary was added.
	 * @param timestampParam Parameter that represents the time-stamp contained inside of the Document Time-stamp dictionary.
	 * @param  certificateParam Parameter that represents the signing certificate of the time-stamp contained inside of the Document Time-stamp dictionary.
	 */
	public PDFDocumentTimestampDictionary(PdfDictionary dictionaryParam, String nameParam, Integer revisionParam, TimeStampToken timestampParam, X509Certificate certificateParam) {
		this.dictionary = dictionaryParam;
		this.name = nameParam;
		this.revision = revisionParam;
		this.timestamp = timestampParam;
		this.certificate = certificateParam;
	}

	/**
	 * Gets the value of the attribute {@link #dictionary}.
	 * @return the value of the attribute {@link #dictionary}.
	 */
	public final PdfDictionary getDictionary() {
		return dictionary;
	}

	/**
	 * Sets the value of the attribute {@link #dictionary}.
	 * @param dictionaryParam The value for the attribute {@link #dictionary}.
	 */
	public final void setDictionary(PdfDictionary dictionaryParam) {
		this.dictionary = dictionaryParam;
	}

	/**
	 * Gets the value of the attribute {@link #name}.
	 * @return the value of the attribute {@link #name}.
	 */
	public final String getName() {
		return name;
	}

	/**
	 * Sets the value of the attribute {@link #name}.
	 * @param nameParam The value for the attribute {@link #name}.
	 */
	public final void setName(String nameParam) {
		this.name = nameParam;
	}

	/**
	 * Gets the value of the attribute {@link #revision}.
	 * @return the value of the attribute {@link #revision}.
	 */
	public final Integer getRevision() {
		return revision;
	}

	/**
	 * Sets the value of the attribute {@link #revision}.
	 * @param revisionParam The value for the attribute {@link #revision}.
	 */
	public final void setRevision(Integer revisionParam) {
		this.revision = revisionParam;
	}

	/**
	 * {@inheritDoc}
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public final int compareTo(PDFDocumentTimestampDictionary o) {
		return revision.compareTo(o.getRevision());
	}

	/**
	 * Gets the value of the attribute {@link #timestamp}.
	 * @return the value of the attribute {@link #timestamp}.
	 */
	public final TimeStampToken getTimestamp() {
		return timestamp;
	}

	/**
	 * Sets the value of the attribute {@link #timestamp}.
	 * @param timestampParam The value for the attribute {@link #timestamp}.
	 */
	public final void setTimestamp(TimeStampToken timestampParam) {
		this.timestamp = timestampParam;
	}

	/**
	 * Gets the value of the attribute {@link #certificate}.
	 * @return the value of the attribute {@link #certificate}.
	 */
	public final X509Certificate getCertificate() {
		return certificate;
	}

	/**
	 * Sets the value of the attribute {@link #certificate}.
	 * @param certificateParam The value for the attribute {@link #certificate}.
	 */
	public final void setCertificate(X509Certificate certificateParam) {
		this.certificate = certificateParam;
	}

}
