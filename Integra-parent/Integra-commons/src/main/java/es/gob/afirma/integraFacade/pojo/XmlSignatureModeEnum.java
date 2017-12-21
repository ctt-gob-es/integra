package es.gob.afirma.integraFacade.pojo;

import es.gob.afirma.utils.DSSConstants;

/**
 * <p>Class that represents the different xml signature type for a web service request.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 04/12/2014.
 */
public enum XmlSignatureModeEnum {

    /**
     * Attribute that represents identifiers of document types.
     */
    ENVELOPING(DSSConstants.XmlSignatureMode.ENVELOPING), ENVELOPED(DSSConstants.XmlSignatureMode.ENVELOPED), DETACHED(DSSConstants.XmlSignatureMode.DETACHED);
    
    /**
     * Attribute that represents the mode of the xml signature.
     */
    private final String mode;

    /**
     * Constructor method for the class XmlSignatureModeEnum.java.
     * @param modeParam Parameter that represents the mode of the xml signature.
     */
    private XmlSignatureModeEnum(String modeParam) {
	this.mode = modeParam;
    }

    /**
     * Gets the value of the attribute {@link #type}.
     * @return the value of the attribute {@link #type}.
     */
    public String getMode() {
	return mode;
    }
}
