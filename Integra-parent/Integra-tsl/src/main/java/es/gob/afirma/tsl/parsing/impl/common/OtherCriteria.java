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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.OtherCriteria.java.</p>
 * <b>Description:</b><p>Abstract class that represents a TSL Other Criteria with could contains
 * differents elements regardless it implementation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 11/11/2020.
 */
package es.gob.afirma.tsl.parsing.impl.common;

import es.gob.afirma.tsl.exceptions.TSLMalformedException;
import es.gob.afirma.tsl.parsing.ifaces.IAnyTypeOtherCriteria;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;


/** 
 * <p>Abstract class that represents a TSL Other Criteria with could contains
 * differents elements regardless it implementation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 11/11/2020.
 */
public abstract class OtherCriteria implements IAnyTypeOtherCriteria {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = 2156106059211827850L;

    /**
	 * Constructor method for the class OtherCriteria.java.
	 */
	public OtherCriteria() {
		super();
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.ifaces.IAnyTypeOtherCriteria#checkOtherCriteriaValue(es.gob.afirma.tsl.parsing.ifaces.ITSLObject)
	 */
	@Override
	public void checkOtherCriteriaValue(ITSLObject tsl) throws TSLMalformedException {
	    checkOtherCriteriaValueSpec119612Vers020101();
	}

	/**
	 * Checks if the Other Criteria has an appropiate value in the TSL for the specification ETSI 119612
	 * and version 2.1.1.
	 * @throws TSLMalformedException In case of the Other Criteria has not a correct value.
	 */
	protected abstract void checkOtherCriteriaValueSpec119612Vers020101() throws TSLMalformedException;

	/**
	 * Abstract method that returns the element name for this Other Criteria Type.
	 * @return element name for this Other Criteria Type.
	 */
	protected abstract String getOtherCriteriaType();

}
