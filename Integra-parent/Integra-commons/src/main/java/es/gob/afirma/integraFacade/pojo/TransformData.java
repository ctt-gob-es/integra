package es.gob.afirma.integraFacade.pojo;

import java.util.List;

/**
 * <p>Class that represents a <code>ds:Transform</code> element as defined on XML Signature Syntax and Processing (Second Edition).</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 04/08/2011.
 */
public class TransformData {

    /**
     * Attribute that represents the <code>Algorithm</code> attribute.
     */
    private String alg;

    /**
     * Attribute that represents the list of <code>XPath</code> elements.
     */
    private List<String> xPath;

    /**
     * Constructor method for the class TransformData.
     * @param algorithm Parameter that represents the algorithm.
     */
    public TransformData(String algorithm) {
	this.alg = algorithm;
    }

    /**
     * Constructor method for the class TransformData.
     * @param algorithm Parameter that represents the <code>Algorithm</code> attribute.
     * @param xpathList Parameter that represents the list of <code>XPath</code> elements.
     */
    public TransformData(String algorithm, List<String> xpathList) {
	this.alg = algorithm;
	this.xPath = xpathList;
    }

    /**
     * Gets the value of the attribute {@link #alg}.
     * @return the value of the attribute {@link #alg}.
     */
    public final String getAlgorithm() {
	return alg;
    }

    /**
     * Gets the value of the attribute {@link #xPath}.
     * @return the value of the attribute {@link #xPath}.
     */
    public final List<String> getXPath() {
	return xPath;
    }

}