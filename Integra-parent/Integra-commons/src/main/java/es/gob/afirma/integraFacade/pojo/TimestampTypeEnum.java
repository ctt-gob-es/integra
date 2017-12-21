package es.gob.afirma.integraFacade.pojo;

import es.gob.afirma.utils.DSSConstants;

/**
 * <p>Class that represents the different timestamp type for a web service request.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 04/12/2014.
 */
public enum TimestampTypeEnum {

    /**
     * Attribute that represents identifiers of timestamp types.
     */
    XML(DSSConstants.TimestampForm.XML), RFC_3161(DSSConstants.TimestampForm.RFC_3161);
    
    /**
     * Attribute that represents the type of the timestamp.
     */
    private final String type;

    /**
     * Constructor method for the class TimestampTypeEnum.java.
     * @param typeParam Parameter that represents the type of the timestamp.
     */
    private TimestampTypeEnum(String typeParam) {
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
