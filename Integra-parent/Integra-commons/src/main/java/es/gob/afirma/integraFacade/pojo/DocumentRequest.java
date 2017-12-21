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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.DocumentRequest.java.</p>
 * <b>Description:</b><p>Class that represents the request for the services related to retrieve a document.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>06/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 06/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;

/**
 * <p>Class that represents the request for the services related to retrieve a document.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 06/11/2014.
 */
public class DocumentRequest implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 1801464266006228348L;

    /**
     * Attribute that represents application identifier.
     */
    private String applicationId;

    /**
     * Attribute that represents the document to be stored.
     */
    private byte[ ] document;

    /**
     * Attribute that represents the name of the document.
     */
    private String name;

    /**
     * Attribute that represents the type of the document.
     */
    private String type;

    /**
     * Gets the value of the attribute {@link #idApplication}.
     * @return the value of the attribute {@link #idApplication}.
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
     * Gets the value of the attribute {@link #document}.
     * @return the value of the attribute {@link #document}.
     */
    public final byte[ ] getDocument() {
	return document;
    }

    /**
     * Sets the value of the attribute {@link #document}.
     * @param documentParam The value for the attribute {@link #document}.
     */
    public final void setDocument(byte[ ] documentParam) {
	if (documentParam != null) {
	    this.document = documentParam.clone();
	}
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

}
