// Copyright (C) 2012-15 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.tsl.elements.CTslImpl.java.</p>
 * <b>Description:</b><p>Class that maps the <i>C_TSL_IMPL</i> database table as a Plain Old Java Object.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 11/11/2020.
 */
package es.gob.afirma.tsl.elements;

import java.io.Serializable;


/** 
 * <p>Class that maps the <i>C_TSL_IMPL</i> database table as a Plain Old Java Object.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 11/11/2020.
 */
public class CTslImpl implements Serializable {

    /**
     * Attribute that represents the serial version UID. 
     */
    private static final long serialVersionUID = -2111769136943080838L;

    /**
	 * Attribute that represents the object ID.
	 */
	private Long idTSLImpl;

	/**
	 * Attribute that represents the ETSI TS number specification for TSL.
	 */
	private String specification;

	/**
	 * Attribute that represents the ETSI TS specification version.
	 */
	private String version;

	/**
	 * Attribute that represents the namespace used in this specification and version for the TSL.
	 */
	private String namespace;

	
	/**
	 * Gets the value of the attribute {@link #idTSLImpl}.
	 * @return the value of the attribute {@link #idTSLImpl}.
	 */
	public Long getIdTSLImpl() {
	    return idTSLImpl;
	}

	
	/**
	 * Sets the value of the attribute {@link #idTSLImpl}.
	 * @param idTSLImpl The value for the attribute {@link #idTSLImpl}.
	 */
	public void setIdTSLImpl(Long idTSLImpl) {
	    this.idTSLImpl = idTSLImpl;
	}

	
	/**
	 * Gets the value of the attribute {@link #specification}.
	 * @return the value of the attribute {@link #specification}.
	 */
	public String getSpecification() {
	    return specification;
	}

	
	/**
	 * Sets the value of the attribute {@link #specification}.
	 * @param specification The value for the attribute {@link #specification}.
	 */
	public void setSpecification(String specification) {
	    this.specification = specification;
	}

	
	/**
	 * Gets the value of the attribute {@link #version}.
	 * @return the value of the attribute {@link #version}.
	 */
	public String getVersion() {
	    return version;
	}

	
	/**
	 * Sets the value of the attribute {@link #version}.
	 * @param version The value for the attribute {@link #version}.
	 */
	public void setVersion(String version) {
	    this.version = version;
	}

	
	/**
	 * Gets the value of the attribute {@link #namespace}.
	 * @return the value of the attribute {@link #namespace}.
	 */
	public String getNamespace() {
	    return namespace;
	}

	
	/**
	 * Sets the value of the attribute {@link #namespace}.
	 * @param namespace The value for the attribute {@link #namespace}.
	 */
	public void setNamespace(String namespace) {
	    this.namespace = namespace;
	}


}
