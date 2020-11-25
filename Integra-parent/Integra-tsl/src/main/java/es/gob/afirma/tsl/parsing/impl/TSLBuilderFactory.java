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
 * <b>File:</b><p>TSLBuilderFactory.TSLBuilderFactory.java.</p>
 * <b>Description:</b><p>Class that represents a TSL Builder Factory for all differents
 * specification and versions of TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/11/2020.
 */
package es.gob.afirma.tsl.parsing.impl;

import es.gob.afirma.tsl.parsing.ifaces.ITSLBuilder;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.ifaces.ITSLSpecificationsVersions;
import es.gob.afirma.tsl.parsing.impl.tsl119612.v020101.TSLBuilder;

/** 
 * <p>Class that represents a TSL Builder Factory for all differents
 * specification and versions of TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2020.
 */
public final class TSLBuilderFactory {

    /**
     * Constructor method for the class TSLBuilderFactory.java.
     */
    private TSLBuilderFactory() {
	super();
    }

    /**
     * Factory method that creates a new instance of a TSL Builder for a concrete
     * TSL Object based on its specification and version.
     * @param tslObject TSL object representation from which create the TSL Builder.
     * @return a TSL Builder object representation. If the input parameter is <code>null</code>, then the return
     * also is <code>null</code>.
     */
    public static ITSLBuilder createTSLBuilder(ITSLObject tslObject) {

	ITSLBuilder result = null;

	if (tslObject != null) {
	    result = new TSLBuilder(tslObject);
	}

	return result;
    }

}
