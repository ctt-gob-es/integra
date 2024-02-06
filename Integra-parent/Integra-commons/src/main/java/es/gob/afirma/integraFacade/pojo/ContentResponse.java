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
// https://eupl.eu/1.1/es/

/**
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.ContentResponse.java.</p>
 * <b>Description:</b><p>Class that represents the response from the services related to the content of a document.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;

/**
 * <p>Class that represents the response from the services related to the content of a document.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2014.
 */
public class ContentResponse implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = -6784433381280262155L;

    /**
     * Attribute that indicates whether the operation has been satisfied.
     */
    private boolean state;

    /**
     * Attribute that represents description of the error or exception happened.
     */
    private String description;

    /**
     * Attribute that represents the contents of the document associated with the given transaction identifier.
     */
    private byte[ ] content;

    /**
     * Attribute that represents the information about the error response returned.
     */
    private ErrorResponse error;

    /**
     * Constructor method for the class ContentResponse.java.
     */
    public ContentResponse() {
    }

    /**
     * Gets the value of the attribute {@link #state}.
     * @return the value of the attribute {@link #state}.
     */
    public final boolean isState() {
	return state;
    }

    /**
     * Sets the value of the attribute {@link #state}.
     * @param stateParam The value for the attribute {@link #state}.
     */
    public final void setState(boolean stateParam) {
	this.state = stateParam;
    }

    /**
     * Gets the value of the attribute {@link #description}.
     * @return the value of the attribute {@link #description}.
     */
    public final String getDescription() {
	return description;
    }

    /**
     * Sets the value of the attribute {@link #description}.
     * @param descriptionParam The value for the attribute {@link #description}.
     */
    public final void setDescription(String descriptionParam) {
	this.description = descriptionParam;
    }

    /**
     * Gets the value of the attribute {@link #content}.
     * @return the value of the attribute {@link #content}.
     */
    public final byte[ ] getContent() {
	return content;
    }

    /**
     * Sets the value of the attribute {@link #content}.
     * @param contentParam The value for the attribute {@link #content}.
     */
    public final void setContent(byte[ ] contentParam) {
	if (contentParam != null) {
	    this.content = contentParam.clone();
	}
    }

    /**
     * Gets the value of the attribute {@link #error}.
     * @return the value of the attribute {@link #error}.
     */
    public final ErrorResponse getError() {
	return error;
    }

    /**
     * Sets the value of the attribute {@link #error}.
     * @param errorParam The value for the attribute {@link #error}.
     */
    public final void setError(ErrorResponse errorParam) {
	this.error = errorParam;
    }

}
