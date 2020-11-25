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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.ifaces.ITSLChecker.java.</p>
 * <b>Description:</b><p>Interface that represents a TSL data checker regardless it implementation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/11/2020.
 */
package es.gob.afirma.tsl.parsing.ifaces;

import es.gob.afirma.tsl.exceptions.TSLMalformedException;

/** 
 * <p>Interface that represents a TSL data checker regardless it implementation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2020.
 */
public interface ITSLChecker {

	/**
	 * Checks all the actual values assigned to this TSL as the concrecte specification and version
	 * requires.
	 * @param checkSignature Flag that indicates if the TSL signature must be checked (<code>true</code>)
	 * or not (<code>false</code>).
	 * @param fullTSLxml Byte array that represents the full TSL xml to check the signature.
	 * @throws TSLMalformedException In case of some data does not exist or has not a correct value.
	 */
	void checkTSLValues(boolean checkSignature, byte[ ] fullTSLxml) throws TSLMalformedException;
}
