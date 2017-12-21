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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.ProcessingDetail.java.</p>
 * <b>Description:</b><p>Class that contains the result of the different steps involved in the process of verifying signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>05/12/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 05/12/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;
import java.util.List;

/**
 * <p>Class that contains the result of the different steps involved in the process of verifying signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 05/12/2014.
 */
public final class ProcessingDetail implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 6650080299051044474L;

    /**
     * Attribute that represents list of details where each contains a validation task that has produced a satisfactory result.
     */
    private List<Detail> listValidDetail;

    /**
     * Attribute that represents list of details where each contains a validation task that has produced an unsatisfactory result.
     */
    private List<Detail> listInvalidDetail;

    /**
     * Attribute that represents list of details where each contains a validation task that has produced an indeterminate result.
     */
    private List<Detail> listIndeterminateDetail;

    /**
     * Constructor method for the class ProcessingDetail.java.
     */
    public ProcessingDetail() {
    }

    /**
     * Gets the value of the attribute {@link #listValidDetail}.
     * @return the value of the attribute {@link #listValidDetail}.
     */
    public List<Detail> getListValidDetail() {
	return listValidDetail;
    }

    /**
     * Sets the value of the attribute {@link #listValidDetail}.
     * @param listValidDetailParam The value for the attribute {@link #listValidDetail}.
     */
    public void setListValidDetail(List<Detail> listValidDetailParam) {
	this.listValidDetail = listValidDetailParam;
    }

    /**
     * Gets the value of the attribute {@link #listInvalidDetail}.
     * @return the value of the attribute {@link #listInvalidDetail}.
     */
    public List<Detail> getListInvalidDetail() {
	return listInvalidDetail;
    }

    /**
     * Sets the value of the attribute {@link #listInvalidDetail}.
     * @param listInvalidDetailParam The value for the attribute {@link #listInvalidDetail}.
     */
    public void setListInvalidDetail(List<Detail> listInvalidDetailParam) {
	this.listInvalidDetail = listInvalidDetailParam;
    }

    /**
     * Gets the value of the attribute {@link #listIndeterminateDetail}.
     * @return the value of the attribute {@link #listIndeterminateDetail}.
     */
    public List<Detail> getListIndeterminateDetail() {
	return listIndeterminateDetail;
    }

    /**
     * Sets the value of the attribute {@link #listIndeterminateDetail}.
     * @param listIndeterminateDetailParam The value for the attribute {@link #listIndeterminateDetail}.
     */
    public void setListIndeterminateDetail(List<Detail> listIndeterminateDetailParam) {
	this.listIndeterminateDetail = listIndeterminateDetailParam;
    }

}
