/*
/*******************************************************************************
 * Copyright (C) 2018 MINHAFP, Gobierno de España
 * This program is licensed and may be used, modified and redistributed under the  terms
 * of the European Public License (EUPL), either version 1.1 or (at your option)
 * any later version as soon as they are approved by the European Commission.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and
 * more details.
 * You should have received a copy of the EUPL1.1 license
 * along with this program; if not, you may find it at
 * https://eupl.eu/1.1/es/
 ******************************************************************************/

/**
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.ifaces.ITSLBuilder.java.</p>
 * <b>Description:</b><p>Interface that represents a TSL builder regardless it implementation.</p>
 * <b>Project:</b><p>Platform for detection and validation of certificates recognized in European TSL.</p>
 * <b>Date:</b><p>10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/11/2020.
 */
package es.gob.afirma.tsl.parsing.ifaces;

import java.io.InputStream;

import es.gob.afirma.tsl.exceptions.TSLArgumentException;
import es.gob.afirma.tsl.exceptions.TSLEncodingException;
import es.gob.afirma.tsl.exceptions.TSLParsingException;



/**
 * <p>Interface that represents a TSL builder regardless it implementation.</p>
 * <b>Project:</b><p>Platform for detection and validation of certificates recognized in European TSL.</p>
 * @version 1.0, 10/11/2020.
 */
public interface ITSLBuilder {

	/**
	 * Method that builds the TSL data from a input XML. This process overwrites
	 * the actual information of the TSL object.
	 * @param is InputStream Input Stream of the XML (TSL representation).
	 * @return byte array with the full TSL loaded.
	 * @throws TSLArgumentException In case of the input parameter is <code>null</code>.
	 * @throws TSLParsingException In case of some error parsing the XML input stream.
	 */
	byte[ ] buildTSLFromXML(InputStream is) throws TSLArgumentException, TSLParsingException;

	/**
	 * Method that builds the XML representation (concrete specification and version) of the TSL.
	 * @return byte array that represents the XML of the TSL.
	 * @throws TSLEncodingException In case of some error encoding the XML
	 */
	byte[ ] buildXMLfromTSL() throws TSLEncodingException;

}
