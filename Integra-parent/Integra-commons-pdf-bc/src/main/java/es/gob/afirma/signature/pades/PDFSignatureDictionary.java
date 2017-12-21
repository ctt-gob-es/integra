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
 * <b>File:</b><p>es.gob.afirma.signature.pades.PDFSignatureDictionary.java.</p>
 * <b>Description:</b><p>Class that contains information related to a signature dictionary of a PDF document.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>13/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 13/11/2014.
 */
package es.gob.afirma.signature.pades;

import java.io.Serializable;

import com.lowagie.text.pdf.PdfDictionary;

/** 
 * <p>Class that contains information related to a signature dictionary of a PDF document.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 13/11/2014.
 */
public class PDFSignatureDictionary implements Serializable, Comparable<PDFSignatureDictionary> {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = -1252456113292585014L;

    /**
     * Attribute that represents the number of the revision on the PDF document when the signature dictionary was added. 
     */
    private Integer revision;

    /**
     * Attribute that represents the signature dictionary. 
     */
    private PdfDictionary dictionary;

    /**
     * Attribute that represents the name of the signature dictionary. 
     */
    private String name;

    /**
     * Constructor method for the class PDFSignatureDictionary.java.
     * @param revisionParam Parameter that represents the number of the revision on the PDF document when the signature dictionary was added.
     * @param dictionaryParam Parameter that represents the signature dictionary.
     * @param nameParam Parameter that represents the name of the signature dictionary.
     */
    public PDFSignatureDictionary(int revisionParam, PdfDictionary dictionaryParam, String nameParam) {
	this.revision = revisionParam;
	this.dictionary = dictionaryParam;
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
     * {@inheritDoc}
     * @see java.lang.Comparable#compareTo(java.lang.Object)
     */
    @Override
    public final int compareTo(PDFSignatureDictionary o) {
	return revision.compareTo(o.getRevision());
    }
}
