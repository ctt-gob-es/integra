package es.gob.afirma.integraFacade.pojo;

import es.gob.afirma.signature.xades.IXMLConstants;

/**
 * <p>Class that represents the different document type for a web service request.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 04/12/2014.
 */
public enum DocumentTypeEnum {

    /**
     * Attribute that represents identifiers of document types.
     */
    BASE64_DATA(IXMLConstants.ELEMENT_BASE64_DATA), BASE64_XML(IXMLConstants.ELEMENT_BASE64_XML), INLINE_XML(IXMLConstants.ELEMENT_INLINE_XML), ESCAPED_XML(IXMLConstants.ELEMENT_ESCAPED_XML), DOCUMENT_HASH(IXMLConstants.ELEMENT_DOCUMENT_HASH), TRANSFORMED_DATA(IXMLConstants.ELEMENT_TRANSFORMED_DATA), DOCUMENT_HASH_TRANSFORMED_DATA(IXMLConstants.ELEMENT_DOCUMENT_HASH_TRANSFORMED_DATA);
    
    /**
     * Attribute that represents the type of the document.
     */
    private final String type;

    /**
     * Constructor method for the class DocumentTypeEnum.java.
     * @param typeParam Parameter that represents the type of the document.
     */
    private DocumentTypeEnum(String typeParam) {
	this.type = typeParam;
    }

    /**
     * Gets the value of the attribute {@link #type}.
     * @return the value of the attribute {@link #type}.
     */
    public String getType() {
	return type;
    }
}
