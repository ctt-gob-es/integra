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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.ErrorResponse.java.</p>
 * <b>Description:</b><p>Class that contains information about an error occurred while invoking a native service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>06/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 06/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;

/**
 * <p>Class that contains information about an error occurred while invoking a native service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 06/11/2014.
 */
public class ErrorResponse implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = -1054176606784611925L;

    /**
     * Attribute that represents the error code.
     */
    private String codeError;

    /**
     * Attribute that represents the error description.
     */
    private String description;

    /**
     * Gets the value of the attribute {@link #codeError}.
     * @return the value of the attribute {@link #codeError}.
     */
    public final String getCodeError() {
	return codeError;
    }

    /**
     * Sets the value of the attribute {@link #codeError}.
     * @param codeErrorParam The value for the attribute {@link #codeError}.
     */
    public final void setCodeError(String codeErrorParam) {
	this.codeError = codeErrorParam;
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

}
