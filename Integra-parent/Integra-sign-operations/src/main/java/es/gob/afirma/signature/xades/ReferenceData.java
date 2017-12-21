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
 * <b>File:</b><p>es.gob.afirma.signature.xades.ReferenceData.java.</p>
 * <b>Description:</b>Class that represents a <code>ds:Reference</code> element as defined on XML Signature Syntax and Processing (Second Edition).</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>04/08/2011.</p>
 * @author Gobierno de España.
 * @version 1.0, 04/08/2011.
 */
package es.gob.afirma.signature.xades;

import java.util.List;

import es.gob.afirma.integraFacade.pojo.TransformData;

/**
 * <p>Class that represents a <code>ds:Reference</code> element as defined on XML Signature Syntax and Processing (Second Edition).</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 04/08/2011.
 */
public class ReferenceData {

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
     * Constructor method for the class ReferenceData.java.
     * @param digestMethodAlgParam Parameter that represents the <code>ds:DigestMethod</code> element.
     * @param digestValueParam Parameter that represents the <code>ds:DigestValue</code> element.
     */
    public ReferenceData(String digestMethodAlgParam, String digestValueParam) {
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
    //
    // JPM - Se extrae la clase a TransformData del modulo Integra-commons

    // /**
    // * <p>Class that represents a <code>ds:Transform</code> element as defined
    // on XML Signature Syntax and Processing (Second Edition).</p>
    // * <b>Project:</b><p>Library for the integration with the services of
    // @Firma, eVisor and TS@.</p>
    // * @version 1.0, 04/08/2011.
    // */
    // public class TransformData {
    //
    // /**
    // * Attribute that represents the <code>Algorithm</code> attribute.
    // */
    // private String alg;
    //
    // /**
    // * Attribute that represents the list of <code>XPath</code> elements.
    // */
    // private List<String> xPath;
    //
    // /**
    // * Constructor method for the class TransformData.
    // * @param algorithm Parameter that represents the algorithm.
    // */
    // public TransformData(String algorithm) {
    // this.alg = algorithm;
    // }
    //
    // /**
    // * Constructor method for the class TransformData.
    // * @param algorithm Parameter that represents the <code>Algorithm</code>
    // attribute.
    // * @param xpathList Parameter that represents the list of
    // <code>XPath</code> elements.
    // */
    // public TransformData(String algorithm, List<String> xpathList) {
    // this.alg = algorithm;
    // this.xPath = xpathList;
    // }
    //
    // /**
    // * Gets the value of the attribute {@link #alg}.
    // * @return the value of the attribute {@link #alg}.
    // */
    // public final String getAlgorithm() {
    // return alg;
    // }
    //
    // /**
    // * Gets the value of the attribute {@link #xPath}.
    // * @return the value of the attribute {@link #xPath}.
    // */
    // public final List<String> getXPath() {
    // return xPath;
    // }
    //
    // }

}
