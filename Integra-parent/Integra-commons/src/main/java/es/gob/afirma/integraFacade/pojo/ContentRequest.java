/* 
* Este fichero forma parte de la plataforma de @firma. 
* La plataforma de @firma es de libre distribución cuyo código fuente puede ser consultado
* y descargado desde http://forja-ctt.administracionelectronica.gob.es
*
* Copyright 2013-,2014 Gobierno de España
* Este fichero se distribuye bajo las licencias EUPL versión 1.1  y GPL versión 3, o superiores, según las
* condiciones que figuran en el fichero 'LICENSE.txt' que se acompaña.  Si se   distribuyera este 
* fichero individualmente, deben incluirse aquí las condiciones expresadas allí.
*/

/** 
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.ContentRequest.java.</p>
 * <b>Description:</b><p>Class that represents the request for the services related to the content of a document.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;

/** 
 * <p>Class that represents the request for the services related to the content of a document.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2014.
 */
public class ContentRequest implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 7454971938011739127L;

    /**
     * Attribute that represents the application identifier.
     */
    private String applicationId;

    /**
     * Attribute that represents the transaction identifier or document identifier.
     */
    private String transactionId;

    /**
     * Gets the value of the attribute {@link #applicationId}.
     * @return the value of the attribute {@link #applicationId}.
     */
    public final String getApplicationId() {
	return applicationId;
    }

    /**
     * Sets the value of the attribute {@link #applicationId}.
     * @param applicationIdParam The value for the attribute {@link #applicationId}.
     */
    public final void setApplicationId(String applicationIdParam) {
	this.applicationId = applicationIdParam;
    }

    /**
     * Gets the value of the attribute {@link #transactionId}.
     * @return the value of the attribute {@link #transactionId}.
     */
    public final String getTransactionId() {
	return transactionId;
    }

    /**
     * Sets the value of the attribute {@link #idTransaction}.
     * @param idTransactionParam The value for the attribute {@link #idTransaction}.
     */
    public final void setTransactionId(String idTransactionParam) {
	this.transactionId = idTransactionParam;
    }

}
