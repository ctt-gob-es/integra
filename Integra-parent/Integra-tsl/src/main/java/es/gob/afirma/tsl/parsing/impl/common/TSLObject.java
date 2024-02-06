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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.TSLObject.java.</p>
 * <b>Description:</b><p>Class that represents a TSL object with the principal functions
 * (access information) regardless it implementation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 15/06/2021.
 */
package es.gob.afirma.tsl.parsing.impl.common;

import java.io.InputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import org.w3.x2000.x09.xmldsig.SignatureType;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.exceptions.TSLArgumentException;
import es.gob.afirma.tsl.exceptions.TSLEncodingException;
import es.gob.afirma.tsl.exceptions.TSLMalformedException;
import es.gob.afirma.tsl.exceptions.TSLParsingException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.parsing.ifaces.ITSLBuilder;
import es.gob.afirma.tsl.parsing.ifaces.ITSLChecker;
import es.gob.afirma.tsl.parsing.ifaces.ITSLElementsAndAttributes;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.impl.TSLBuilderFactory;
import es.gob.afirma.tsl.parsing.impl.TSLCheckerFactory;

/** 
 * <p>Class that represents a TSL object with the principal functions
 * (access information) regardless it implementation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 15/06/2021.
 */
public class TSLObject implements ITSLObject {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = -3597740204632576733L;


    /**
     * Constant attribute that represents the token '119612'.
     */
    private static final String SPECIFICATION = "119612";
    /**
     * Constant attribute that represents the token '2.1.1.'.
     */
    private static final String VERSION = "2.1.1.";
    
    /**
     * Attribute that represents the specification of this TSL object.
     */
    private String tslSpecification = null;

    /**
     * Attribute that represents the specification version of this TSL object.
     */
    private String tslSpecificationVersion = null;

    /**
     * Attribute that represents the tag attribute for the TrustServiceStatus element.
     */
    private URI tslTag = null;

    /**
     * Attribute that represents an optional identifier for the TSL.
     */
    private String tslID = null;

    /**
     * Attribute that represents the TSL Scheme Information with all its information.
     */
    private SchemeInformation schemeInformation = null;

    /**
     * Attribute that represents a list with all the Trust Services Providers associated to this TSL.
     */
    private List<TrustServiceProvider> trustServiceProviderList = null;

    /**
     * Attribute that represents the signature of the TSL.
     */
    private SignatureType signature = null;

    /**
     * Attribute that represents the full TSL.
     */
    private transient byte[ ] fullTSLxml = null;

    /**
     * Constructor method for the class TSLObject.java.
     */
    public TSLObject() {
	super();
	tslSpecification = SPECIFICATION;
	tslSpecificationVersion= VERSION;
	schemeInformation = new SchemeInformation();
	trustServiceProviderList = new ArrayList<TrustServiceProvider>();
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.ifaces.ITSLObject#getTSLTag()
     */
    @Override
    public final URI getTSLTag() {
	return tslTag;
    }

    /**
     * Gets the value of the attribute {@link #tslSpecification}.
     * @return the value of the attribute {@link #tslSpecification}.
     */
    public String getTslSpecification() {
	return tslSpecification;
    }

    /**
     * Sets the value of the attribute {@link #tslSpecification}.
     * @param tslSpecification The value for the attribute {@link #tslSpecification}.
     */
    public void setTslSpecification(String tslSpecification) {
	this.tslSpecification = tslSpecification;
    }

    /**
     * Gets the value of the attribute {@link #tslSpecificationVersion}.
     * @return the value of the attribute {@link #tslSpecificationVersion}.
     */
    public String getTslSpecificationVersion() {
	return tslSpecificationVersion;
    }

    /**
     * Sets the value of the attribute {@link #tslSpecificationVersion}.
     * @param tslSpecificationVersion The value for the attribute {@link #tslSpecificationVersion}.
     */
    public void setTslSpecificationVersion(String tslSpecificationVersion) {
	this.tslSpecificationVersion = tslSpecificationVersion;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.ifaces.ITSLObject#setTSLTag(java.net.URI)
     */
    @Override
    public final void setTSLTag(URI tag) throws TSLArgumentException {

	// Si la entrada es nula, lanzamos excepción.
	if (tag == null) {
	    throw new TSLArgumentException(Language.getFormatResIntegraTsl(ILogTslConstant.TO_LOG001, new Object[ ] { ITSLElementsAndAttributes.ATTRIBUTE_TSL_TAG }));
	} else {
	    tslTag = tag;
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.ifaces.ITSLObject#getID()
     */
    @Override
    public final String getID() {
	return tslID;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.ifaces.ITSLObject#setID(java.lang.String)
     */
    @Override
    public final void setID(String id) {
	tslID = id;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.ifaces.ITSLObject#getSchemeInformation()
     */
    @Override
    public final SchemeInformation getSchemeInformation() {
	return schemeInformation;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.ifaces.ITSLObject#setSchemeInformation(es.gob.afirma.tsl.parsing.impl.common.SchemeInformation)
     */
    @Override
    public final void setSchemeInformation(SchemeInformation si) throws TSLArgumentException {

	// Si la entrada es nula, lanzamos excepción.
	if (si == null) {
	    throw new TSLArgumentException(Language.getFormatResIntegraTsl(ILogTslConstant.TO_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_SCHEME_INFORMATION }));
	} else {
	    schemeInformation = si;
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.ifaces.ITSLObject#getTrustServiceProviderList()
     */
    @Override
    public final List<TrustServiceProvider> getTrustServiceProviderList() {

	if (trustServiceProviderList.isEmpty()) {
	    return null;
	} else {
	    return trustServiceProviderList;
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.ifaces.ITSLObject#addNewTrustServiceProvider(es.gob.afirma.tsl.parsing.impl.common.TrustServiceProvider)
     */
    @Override
    public final void addNewTrustServiceProvider(TrustServiceProvider tsp) throws TSLArgumentException {

	// Si la entrada es nula, lanzamos excepción.
	if (tsp == null) {
	    throw new TSLArgumentException(Language.getFormatResIntegraTsl(ILogTslConstant.TO_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_TRUST_SERVICE_PROVIDER }));
	} else {
	    trustServiceProviderList.add(tsp);
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.ifaces.ITSLObject#isThereSomeTrustServiceProvider()
     */
    @Override
    public final boolean isThereSomeTrustServiceProvider() {
	return !trustServiceProviderList.isEmpty();
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.ifaces.ITSLObject#getSignature()
     */
    @Override
    public final SignatureType getSignature() {
	return signature;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.ifaces.ITSLObject#setSignature(org.w3.x2000.x09.xmldsig.SignatureType)
     */
    @Override
    public final void setSignature(SignatureType dsSignature) {
	signature = dsSignature;
    }

    /**
     * Gets the TSL Builder associated to this specification and version of TSL.
     * @return TSL Builder associated to this specification and version of TSL.
     */
    private ITSLBuilder getTSLBuilder() {
	return TSLBuilderFactory.createTSLBuilder(this);
    }

    /**
     * Gets the TSL Data Checker associated to this specification and version of TSL.
     * @return TSL Data Checker associated to this specification and version of TSL.
     */
    private ITSLChecker getTSLChecker() {
	return TSLCheckerFactory.createTSLChecker(this);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.ifaces.ITSLObject#checkTSLValues()
     */
    @Override
    public final void checkTSLValues() throws TSLMalformedException {
	getTSLChecker().checkTSLValues(false, fullTSLxml);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.ifaces.ITSLObject#buildTSLFromXMLcheckValues(java.io.InputStream)
     */
    @Override
    public final void buildTSLFromXMLcheckValues(InputStream isParam) throws TSLArgumentException, TSLParsingException, TSLMalformedException {
	buildTSLFromXMLcheckValues(isParam, true);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.ifaces.ITSLObject#buildTSLFromXMLcheckValues(java.io.InputStream, boolean)
     */
    @Override
    public final void buildTSLFromXMLcheckValues(InputStream is, boolean checkSignature) throws TSLArgumentException, TSLParsingException, TSLMalformedException {

	// Almacenamos una "copia de seguridad" de los actuales datos,
	// para que en caso de error, los podamos restaurar.
	URI backupTslTag = tslTag;
	String backupTslID = tslID;
	SchemeInformation backupSchemeInformation = schemeInformation;
	List<TrustServiceProvider> backupTrustServiceProviderList = trustServiceProviderList;
	SignatureType backupSignature = signature;
	boolean restoreBackup = false;

	try {

	    // Construimos la TSL a partir del XML.
	    fullTSLxml = getTSLBuilder().buildTSLFromXML(is);
	    // Comprobamos que los valores establecidos son los correctos.
	    getTSLChecker().checkTSLValues(checkSignature, fullTSLxml);

	} catch (TSLParsingException | TSLMalformedException e) {
	    restoreBackup = true;
	    throw e;
	} finally {
	    // Si hubiera que restaurar los datos originales debido a un fallo
	    // en el parseo
	    // o en la comprobación de los valores...
	    if (restoreBackup) {
		tslTag = backupTslTag;
		tslID = backupTslID;
		schemeInformation = backupSchemeInformation;
		trustServiceProviderList = backupTrustServiceProviderList;
		signature = backupSignature;
	    }
	}

    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.parsing.ifaces.ITSLObject#checkValuesBuildXMLfromTSL()
     */
    @Override
    public final byte[ ] checkValuesBuildXMLfromTSL() throws TSLMalformedException, TSLEncodingException {

	byte[ ] result = null;

	// Comprobamos que los valores establecidos son los correctos.
	getTSLChecker().checkTSLValues(false, null);
	// Una vez comprobados, construimos el XML.
	result = getTSLBuilder().buildXMLfromTSL();

	return result;

    }
}
