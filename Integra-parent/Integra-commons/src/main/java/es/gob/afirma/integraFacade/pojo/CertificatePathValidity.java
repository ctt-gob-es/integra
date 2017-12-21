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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.CertificatePathValidity.java.</p>
 * <b>Description:</b><p>Class that contains information about the verification of a certificate chain.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>24/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 24/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;
import java.util.List;

/**
 * <p>Class that contains information about the verification of a certificate chain.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 24/11/2014.
 */
public class CertificatePathValidity implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 4939059021053304746L;

    /**
     * Attribute that specifies the overall result of verifying the signer certificate.
     */
    private Detail summary;

    /**
     * Attribute that specifies the identifier of a certificate that is part of the signature.
     */
    private String identifier;

    /**
     * Attribute that contains additional information about certificate validation.
     */
    private List<CertificateValidity> detail;

    /**
     * Constructor method for the class CertificatePathValidity.java.
     */
    public CertificatePathValidity() {
    }

    /**
     * Gets the value of the attribute {@link #summary}.
     * @return the value of the attribute {@link #summary}.
     */
    public final Detail getSummary() {
	return summary;
    }

    /**
     * Sets the value of the attribute {@link #summary}.
     * @param summaryParam The value for the attribute {@link #summary}.
     */
    public final void setSummary(Detail summaryParam) {
	this.summary = summaryParam;
    }

    /**
     * Gets the value of the attribute {@link #identifier}.
     * @return the value of the attribute {@link #identifier}.
     */
    public final String getIdentifier() {
	return identifier;
    }

    /**
     * Sets the value of the attribute {@link #identifier}.
     * @param identifierParam The value for the attribute {@link #identifier}.
     */
    public final void setIdentifier(String identifierParam) {
	this.identifier = identifierParam;
    }

    /**
     * Gets the value of the attribute {@link #detail}.
     * @return the value of the attribute {@link #detail}.
     */
    public final List<CertificateValidity> getDetail() {
	return detail;
    }

    /**
     * Sets the value of the attribute {@link #detail}.
     * @param detailParam The value for the attribute {@link #detail}.
     */
    public final void setDetail(List<CertificateValidity> detailParam) {
	this.detail = detailParam;
    }

}
