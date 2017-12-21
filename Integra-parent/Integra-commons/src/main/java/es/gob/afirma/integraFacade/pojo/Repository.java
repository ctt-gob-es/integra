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
 * <b>File:</b><p>es.gob.afirma.integraWSFacade.Repository.java.</p>
 * <b>Description:</b><p>Class that contains the information needed to locate a documents repository or documents manager.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>13/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 13/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;

/**
 * <p>Class that contains the information needed to locate a documents repository or documents manager.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 13/11/2014.
 */
public class Repository implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 728378426834510214L;

    /**
     * Attribute that represents the identifier of Document Management System or the identifier of the repository where the document is stored.
     */
    private String id;

    /**
     * Attribute that represents Unique Identifier (UUID) element of the document in the repository.
     */
    private String object;

    /**
     * Gets the value of the attribute {@link #id}.
     * @return the value of the attribute {@link #id}.
     */
    public final String getId() {
	return id;
    }

    /**
     * Sets the value of the attribute {@link #id}.
     * @param idParam The value for the attribute {@link #id}.
     */
    public final void setId(String idParam) {
	this.id = idParam;
    }

    /**
     * Gets the value of the attribute {@link #object}.
     * @return the value of the attribute {@link #object}.
     */
    public final String getObject() {
	return object;
    }

    /**
     * Sets the value of the attribute {@link #object}.
     * @param objectParam The value for the attribute {@link #object}.
     */
    public final void setObject(String objectParam) {
	this.object = objectParam;
    }

}