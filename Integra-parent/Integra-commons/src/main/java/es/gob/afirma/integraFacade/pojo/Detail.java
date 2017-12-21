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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.Detail.java.</p>
 * <b>Description:</b><p>Class that contains the detailed information of a web service response.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>05/12/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 05/12/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;

/**
 * <p>Class that contains the detailed information of a web service response.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 05/12/2014.
 */
public final class Detail implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 1622271624799416617L;

    /**
     * Attribute that represents the URI which identifies the validation task executed.
     */
    private String type;

    /**
     * Attribute that represents the URI specifying the above result.
     */
    private String code;

    /**
     * Attribute that represents the descriptive message of the process output.
     */
    private String message;

    /**
     * Constructor method for the class Detail.java.
     */
    public Detail() {
    }

    /**
     * Gets the value of the attribute {@link #type}.
     * @return the value of the attribute {@link #type}.
     */
    public String getType() {
	return type;
    }

    /**
     * Sets the value of the attribute {@link #type}.
     * @param typeParam The value for the attribute {@link #type}.
     */
    public void setType(String typeParam) {
	this.type = typeParam;
    }

    /**
     * Gets the value of the attribute {@link #code}.
     * @return the value of the attribute {@link #code}.
     */
    public String getCode() {
	return code;
    }

    /**
     * Sets the value of the attribute {@link #code}.
     * @param codeParam The value for the attribute {@link #code}.
     */
    public void setCode(String codeParam) {
	this.code = codeParam;
    }

    /**
     * Gets the value of the attribute {@link #message}.
     * @return the value of the attribute {@link #message}.
     */
    public String getMessage() {
	return message;
    }

    /**
     * Sets the value of the attribute {@link #message}.
     * @param messageParam The value for the attribute {@link #message}.
     */
    public void setMessage(String messageParam) {
	this.message = messageParam;
    }

}
