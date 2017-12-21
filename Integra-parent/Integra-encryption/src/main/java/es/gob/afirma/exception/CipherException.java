package es.gob.afirma.exception;

/**
 * 
 * <p>Class .</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 22/02/2016.
 */
public class CipherException extends Exception {

    /**
    * Attribute that represents class serial version. 
    */
    private static final long serialVersionUID = 3960773877603295614L;

    /**
     * Constructor method for the class CipherException.java.
     */
    public CipherException() {
	super();
    }

    /**
     * Constructor method for the class CipherException.java.
     * @param message Error message.
     */
    public CipherException(String message) {
	super(message);
    }

    /**
     * Constructor method for the class CipherException.java.
     * @param cause Error cause.
     */
    public CipherException(Throwable cause) {
	super(cause);

    }

    /**
     * Constructor method for the class CipherException.java.
     * @param message Error message.
     * @param cause Error cause.
     */
    public CipherException(String message, Throwable cause) {
	super(message, cause);
    }
}
