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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.DataInfo.java.</p>
 * <b>Description:</b><p>Class that contains the information of the data signed by an individual signature contained inside of the response of verified signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>24/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 24/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;
import java.util.List;

/**
 * <p>Class that contains the information of the data signed by an individual signature contained inside of the response of verified signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 24/11/2014.
 */
public class DataInfo implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 1261234624210927532L;

    /**
     * Attribute that contains the information of the data signed by an individual signature contained inside of the response of verified signature.
     */
    private byte[ ] contentData;

    /**
     * Attribute that contains information about references signed by a particular signature signer XML.
     */
    private List<String> signedDataRefs;

    /**
     * Attribute that contains the summary of the original signed data.
     */
    private DocumentHash documentHash;

    /**
     * Constructor method for the class DataInfo.java.
     */
    public DataInfo() {
    }

    /**
     * Gets the value of the attribute {@link #contentData}.
     * @return the value of the attribute {@link #contentData}.
     */
    public final byte[ ] getContentData() {
	return contentData;
    }

    /**
     * Sets the value of the attribute {@link #contentData}.
     * @param contentDataParam The value for the attribute {@link #contentData}.
     */
    public final void setContentData(byte[ ] contentDataParam) {
	if (contentDataParam != null) {
	    this.contentData = contentDataParam.clone();
	}
    }

    /**
     * Gets the value of the attribute {@link #signedDataRefs}.
     * @return the value of the attribute {@link #signedDataRefs}.
     */
    public final List<String> getSignedDataRefs() {
	return signedDataRefs;
    }

    /**
     * Sets the value of the attribute {@link #signedDataRefs}.
     * @param signedDataRefsParam The value for the attribute {@link #signedDataRefs}.
     */
    public final void setSignedDataRefs(List<String> signedDataRefsParam) {
	this.signedDataRefs = signedDataRefsParam;
    }

    /**
     * Gets the value of the attribute {@link #documentHash}.
     * @return the value of the attribute {@link #documentHash}.
     */
    public final DocumentHash getDocumentHash() {
	return documentHash;
    }

    /**
     * Sets the value of the attribute {@link #documentHash}.
     * @param documentHashParam The value for the attribute {@link #documentHash}.
     */
    public final void setDocumentHash(DocumentHash documentHashParam) {
	this.documentHash = documentHashParam;
    }

}
