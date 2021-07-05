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
 * <b>File:</b><p>es.gob.afirma.tsl.ITslValidation.java.</p>
 * <b>Description:</b><p>Interface that publishes the necessary methods to perform certificate validation through a TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 19/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 15/06/2021.
 */
package es.gob.afirma.tsl;


import java.util.Map;


import es.gob.afirma.tsl.exceptions.TSLManagingException;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.impl.common.TSLObject;

/** 
 * <p>Interface that publishes the necessary methods to perform certificate validation through a TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 15/06/2021.
 */
public interface ITslValidation {


	/**
	 * Constant attribute that represents the token parameter 'certificate'.
	 */
	String PARAM_CERTIFICATE = "certificate";
	
	/**
	 * Constant attribute that represents the token parameter 'tslObject'.
	 */
	String PARAM_TSLOBJECT = "tslObject";
	
	/**
	 *  Method to obtain the TSL mapped from a file.
	 *  
	 * @param pathTsl Path where the file with the TSL is located.
	 * @return  a TSL Data Object representation.
	 * @throws TSLManagingException In case of some error getting the information from the file.
	 */
	ITSLObject getTSLObjectFromPath(String pathTsl) throws TSLManagingException;
	
	/**
	 * MEthod that downloads a TSL from a specified URI
	 * 
	 * @param uriTSL RL from where the TSL will be downloaded.
	 * @return a TSL Data Object representation.
	 * @throws TSLManagingException  In case of some error getting the information from the file.
	 */
	ITSLObject downloadTLSbyHTTP(String uriTSL, int connectionTimeout, int readTimeout) throws TSLManagingException ;
	
	
	/**
	 * Method to obtain the logical fields from the date of issuance of the certificate.
	 * 
	 * @param certByteArrayB64 Certificate to detect (byte[] in Base64 encoded).
	 * @param tslObject TSL object representation to use.

	 * @throws TSLManagingException If some error is produced in the execution of the service.
	 */
	public Map<String, String> getLogicalFieldsTSL(byte[] certByteArrayB64, TSLObject tslObject) throws TSLManagingException;
}
