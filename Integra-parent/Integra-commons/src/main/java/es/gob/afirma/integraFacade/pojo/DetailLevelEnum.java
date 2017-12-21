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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.DetailLevelEnum.java.</p>
 * <b>Description:</b><p>Class that represents the different detail levels for a web service response.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>04/12/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 04/12/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import es.gob.afirma.utils.DSSConstants.ReportDetailLevel;

/**
 * <p>Class that represents the different detail levels for a web service response.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 04/12/2014.
 */
public enum DetailLevelEnum {
    /**
     * Attribute that represents the identifiers of the different details levels.
     */
    NO_DETAILS(ReportDetailLevel.NO_DETAILS), NO_PATH_DETAILS(ReportDetailLevel.NO_PATH_DETAILS), ALL_DETAILS(ReportDetailLevel.ALL_DETAILS);

    /**
     * Attribute that represents the URI corresponding to each detail level.
     */
    private final String uri;

    /**
     * Constructor method for the class DetailLevelEnum.java.
     * @param uriParam Parameter that represents the URI corresponding to each type of algorithm.
     */
    private DetailLevelEnum(String uriParam) {
	this.uri = uriParam;
    }

    /**
     * Gets the value of the attribute {@link #uri}.
     * @return the value of the attribute {@link #uri}.
     */
    public String getUri() {
	return uri;
    }
}
