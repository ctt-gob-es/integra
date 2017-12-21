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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.CertificateValidity.java.</p>
 * <b>Description:</b><p>Class that represents the information about a validated certificate.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>23/12/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 23/12/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>Class that represents the information about a validated certificate.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 23/12/2014.
 */
public final class CertificateValidity implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 291153373273920483L;

    /**
     * Attribute that represents a map containing information of a validated certificate.
     */
    private Map<String, String> infoMap;

    /**
     * Constructor method for the class CertificateValidity.java.
     */
    public CertificateValidity() {
	infoMap = new HashMap<String, String>();
    }

    /**
     * Gets the value of the attribute {@link #infoMap}.
     * @return the value of the attribute {@link #infoMap}.
     */
    public Map<String, String> getInfoMap() {
	return infoMap;
    }

    /**
     * Sets the value of the attribute {@link #infoMap}.
     * @param infoMapParam The value for the attribute {@link #infoMap}.
     */
    public void setInfoMap(Map<String, String> infoMapParam) {
	this.infoMap = infoMapParam;
    }
}
