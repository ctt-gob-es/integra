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
// https://eupl.eu/1.1/es/

/** 
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.TSLValidatorFactory.java.</p>
 * <b>Description:</b><p>Class that represents a TSL Validator Factory for all differents
 * specification and versions of TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 16/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 16/11/2020.
 */
package es.gob.afirma.tsl.certValidation.impl;

import es.gob.afirma.tsl.certValidation.ifaces.ITSLValidator;
import es.gob.afirma.tsl.certValidation.impl.ts119612.v020101.TSLValidator;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;

/** 
 * <p>Class that represents a TSL Validator Factory for all differents
 * specification and versions of TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 16/11/2020.
 */
public final class TSLValidatorFactory {

    /**
     * Constructor method for the class TSLValidatorFactory.java.
     */
    private TSLValidatorFactory() {
	super();
    }

    /**
     * Factory method that creates a new instance of a TSL Validator for a concrete
     * TSL Object based on its specification and version.
     * @param tslObject TSL object representation from which cretate the TSL Validator.
     * @return a TSL Validator object representation. If the input parameter is <code>null</code>, then the return
     * also is <code>null</code>.
     */
    public static ITSLValidator createTSLValidator(ITSLObject tslObject) {

	ITSLValidator result = null;

	if (tslObject != null) {
	    result = new TSLValidator(tslObject);

	}

	return result;

    }

}
