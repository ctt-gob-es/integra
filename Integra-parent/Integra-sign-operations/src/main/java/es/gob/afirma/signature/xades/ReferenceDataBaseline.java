// Copyright (C) 2020 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.signature.xades.ReferenceDataBaseline.java.</p>
 * <b>Description:</b>Class that represents a <code>ds:Reference</code> element and its dataObjectFormat information.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>16/04/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 16/04/2020.
 */
package es.gob.afirma.signature.xades;

import java.util.List;

import es.gob.afirma.integraFacade.pojo.TransformData;

/**
 * <p>Class that represents a <code>ds:Reference</code> element and its dataObjectFormat information.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 16/04/2020.
 */
public class ReferenceDataBaseline {

    /**
     * Attribute that represents the <code>Id</code> attribute.
     */
    private String id;

    /**
     * Attribute that represents the <code>URI</code> attribute.
     */
    private String uri;

    /**
     * Attribute that represents the <code>Type</code> attribute.
     */
    private String type;

    /**
     * Attribute that represents the list of <code>ds:Transforms</code> elements.
     */
    private List<TransformData> transforms;

    /**
     * Attribute that represents the <code>ds:DigestMethod</code> element.
     */
    private String digestMethodAlg;

    /**
     * Attribute that represents the <code>ds:DigestValue</code> element.
     */
    private String digestValue;

    /**
     * Attribute that represents the <code>Xades:Description</code> element of the dataObjectFormat.
     */
    private String dataFormatDescription;
    
    /**
     * Attribute that represents the <code>Xades:Encoding</code> element of the dataObjectFormat.
     */
    private String dataFormatEncoding;
    
    /**
     * Attribute that represents the <code>Xades:MimeType</code> element of the dataObjectFormat.
     */
    private String dataFormatMimeType;

    /**
     * Constructor method for the class ReferenceDataBaseline.java.
     * @param digestMethodAlgParam Parameter that represents the <code>ds:DigestMethod</code> element.
     * @param digestValueParam Parameter that represents the <code>ds:DigestValue</code> element.
     */
    public ReferenceDataBaseline(String digestMethodAlgParam, String digestValueParam) {
	digestMethodAlg = digestMethodAlgParam;
	digestValue = digestValueParam;
    }

    /**
     * Gets the value of the attribute {@link #transforms}.
     * @return the value of the attribute {@link #transforms}.
     */
    public final List<TransformData> getTransforms() {
	return transforms;
    }

    /**
     * Gets the value of the attribute {@link #digestMethodAlg}.
     * @return the value of the attribute {@link #digestMethodAlg}.
     */
    public final String getDigestMethodAlg() {
	return digestMethodAlg;
    }

    /**
     * Gets the value of the attribute {@link #digestValue}.
     * @return the value of the attribute {@link #digestValue}.
     */
    public final String getDigestValue() {
	return digestValue;
    }

    /**
     * Gets the value of the attribute {@link #id}.
     * @return the value of the attribute {@link #id}.
     */
    public final String getId() {
	return id;
    }

    /**
     * Sets the value of the attribute {@link #id}.
     * @param idParam The value for the attribute {@link #id}.
     */
    public final void setId(String idParam) {
	this.id = idParam;
    }

    /**
     * Gets the value of the attribute {@link #uri}.
     * @return the value of the attribute {@link #uri}.
     */
    public final String getUri() {
	return uri;
    }

    /**
     * Sets the value of the attribute {@link #uri}.
     * @param uriParam The value for the attribute {@link #uri}.
     */
    public final void setUri(String uriParam) {
	this.uri = uriParam;
    }

    /**
     * Gets the value of the attribute {@link #type}.
     * @return the value of the attribute {@link #type}.
     */
    public final String getType() {
	return type;
    }

    /**
     * Sets the value of the attribute {@link #type}.
     * @param typeParam The value for the attribute {@link #type}.
     */
    public final void setType(String typeParam) {
	this.type = typeParam;
    }

    /**
     * Sets the value of the attribute {@link #transforms}.
     * @param transformsParams The value for the attribute {@link #transforms}.
     */
    public final void setTransforms(List<TransformData> transformsParams) {
	this.transforms = transformsParams;
    }

    /**
     * Gets the value of the attribute {@link #dataFormatDescription}.
     * @return the value of the attribute {@link #dataFormatDescription}.
     */
    public String getDataFormatDescription() {
        return dataFormatDescription;
    }
    
    /**
     * Sets the value of the attribute {@link #dataFormatDescription}.
     * @param dataFormatDescriptionParam The value for the attribute {@link #dataFormatDescription}.
     */
    public void setDataFormatDescription(String dataFormatDescriptionParam) {
        this.dataFormatDescription = dataFormatDescriptionParam;
    }
    
    /**
     * Gets the value of the attribute {@link #dataFormatEncoding}.
     * @return the value of the attribute {@link #dataFormatEncoding}.
     */
    public String getDataFormatEncoding() {
        return dataFormatEncoding;
    }

    /**
     * Sets the value of the attribute {@link #dataFormatEncoding}.
     * @param dataFormatEncodingParam The value for the attribute {@link #dataFormatEncoding}.
     */
    public void setDataFormatEncoding(String dataFormatEncodingParam) {
        this.dataFormatEncoding = dataFormatEncodingParam;
    }

    /**
     * Gets the value of the attribute {@link #dataFormatMimeType}.
     * @return the value of the attribute {@link #dataFormatMimeType}.
     */
    public String getDataFormatMimeType() {
        return dataFormatMimeType;
    }

    /**
     * Sets the value of the attribute {@link #dataFormatMimeType}.
     * @param dataFormatMimeTypeParam The value for the attribute {@link #dataFormatMimeType}.
     */
    public void setDataFormatMimeType(String dataFormatMimeTypeParam) {
        this.dataFormatMimeType = dataFormatMimeTypeParam;
    }

}
