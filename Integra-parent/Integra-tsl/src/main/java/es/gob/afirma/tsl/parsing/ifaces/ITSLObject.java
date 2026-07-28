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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.ITSLObject.java.</p>
 * <b>Description:</b><p>Interface that represents a TSL object regardless it implementation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/11/2020.
 */
package es.gob.afirma.tsl.parsing.ifaces;

import java.io.InputStream;
import java.io.Serializable;
import java.net.URI;
import java.util.List;

import org.w3.x2000.x09.xmldsig.SignatureType;

import es.gob.afirma.tsl.exceptions.TSLArgumentException;
import es.gob.afirma.tsl.exceptions.TSLEncodingException;
import es.gob.afirma.tsl.exceptions.TSLMalformedException;
import es.gob.afirma.tsl.exceptions.TSLParsingException;
import es.gob.afirma.tsl.parsing.impl.common.SchemeInformation;
import es.gob.afirma.tsl.parsing.impl.common.TrustServiceProvider;


/** 
 * <p>Interface that represents a TSL object regardless it implementation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2020.
 */
public interface ITSLObject extends Serializable {

	/**
	 * Gets the URI that represents the tag attribute for the TrustServiceStatus element.
	 * @return URI that represents the tag attribute for the TrustServiceStatus element.
	 */
	URI getTSLTag();

	/**
	 * Sets the URI that represents the tag attribute for the TrustServiceStatus element.
	 * @param tslTag URI to set.
	 * @throws TSLArgumentException In case of the input parameter is <code>null</code> or not well formed.
	 */
	void setTSLTag(URI tslTag) throws TSLArgumentException;

	/**
	 * Gets the ID attribute from the TrustServiceStatus element.
	 * @return String with the ID of the TrustServiceStatus element. <code>null</code> if not
	 * is defined.
	 */
	String getID();

	/**
	 * Sets the ID attribute for the TSL.
	 * @param tslID String that represents the ID to set. It can be <code>null</code>.
	 */
	void setID(String tslID);

	/**
	 * Gets the scheme information of the TSL.
	 * @return representation object not dependent of the TSL implementation and version
	 * that represents the scheme information of this TSL.
	 */
	SchemeInformation getSchemeInformation();

	/**
	 * Sets the scheme information associated to this TSL.
	 * @param si Scheme information to be associated to this TSL.
	 * @throws TSLArgumentException In case of the input parameter is <code>null</code> or not well formed.
	 */
	void setSchemeInformation(SchemeInformation si) throws TSLArgumentException;

	/**
	 * Gets the list with all the Trust Services Providers associated to this TSL.
	 * @return list with all the Trust Services Providers associated to this TSL, if there is not,
	 * then <code>null</code>.
	 */
	List<TrustServiceProvider> getTrustServiceProviderList();

	/**
	 * Adds a new trust service provider to the list associated to this TSL.
	 * @param tsp Trust Service Provider to add. It can not be <code>null</code>.
	 * @throws TSLArgumentException In case of the input parameter is <code>null</code> or not well formed.
	 */
	void addNewTrustServiceProvider(TrustServiceProvider tsp) throws TSLArgumentException;

	/**
	 * Checks if exists at least one Trust Service Provider associated to this TSL.
	 * @return <code>true</code> if exists at least one, otherwise <code>false</code>.
	 */
	boolean isThereSomeTrustServiceProvider();

	/**
	 * Gets the TSL signature.
	 * @return TSL signature.
	 */
	SignatureType getSignature();

	/**
	 * Sets the XML Signature for the TSL.
	 * @param signature XML Signature to set for this TSL.
	 */
	void setSignature(SignatureType signature);

	/**
	 * Checks all the actual values assigned to this TSL as the concrecte specification and version
	 * requires.
	 * @throws TSLMalformedException In case of some data does not exist or has not a correct value.
	 */
	void checkTSLValues() throws TSLMalformedException;

	/**
	 * Method that builds the TSL data from a input XML. This process overwrites
	 * the actual information of the object, but if there is some error parsing the XML,
	 * no data will be changed. When the data is parsed, then is checked if it has
	 * the correct values as the specification and version requires.
	 * @param is InputStream Input Stream of the XML (TSL representation).
	 * @throws TSLArgumentException In case of the input parameter is <code>null</code>.
	 * @throws TSLParsingException In case of some error parsing the XML input stream.
	 * @throws TSLMalformedException In case of some data does not exist or has not a correct value.
	 */
	void buildTSLFromXMLcheckValues(InputStream is) throws TSLArgumentException, TSLParsingException, TSLMalformedException;

	/**
	 * Method that builds the TSL data from a input XML. This process overwrites
	 * the actual information of the object, but if there is some error parsing the XML,
	 * no data will be changed. When the data is parsed, then is checked if it has
	 * the correct values as the specification and version requires.
	 * @param is InputStream Input Stream of the XML (TSL representation).
	 * @param checkSignature Flag that indicates if the TSL signature must be checked (<code>true</code>).
	 * @throws TSLArgumentException In case of the input parameter is <code>null</code>.
	 * @throws TSLParsingException In case of some error parsing the XML input stream.
	 * @throws TSLMalformedException In case of some data does not exist or has not a correct value.
	 */
	void buildTSLFromXMLcheckValues(InputStream is, boolean checkSignature) throws TSLArgumentException, TSLParsingException, TSLMalformedException;

	/**
	 * Method that check that the data of the TSL is correct as the specification and version requires.
	 * After this, builds the XML representation (concrete specification and version) of the TSL.
	 * @return byte array that represents the XML of the TSL.
	 * @throws TSLMalformedException In case of some data does not exist or has not a correct value.
	 * @throws TSLEncodingException In case of some error encoding the TSL.
	 */
	byte[ ] checkValuesBuildXMLfromTSL() throws TSLMalformedException, TSLEncodingException;


}
