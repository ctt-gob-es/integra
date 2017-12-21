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
 * <b>File:</b><p>es.gob.afirma.testrfc3161services.RFC3161ServicesTest.java.</p>
 * <b>Description:</b><p>Class that allows to tests the TS@ RFC 3161 services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>23/01/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 23/01/2014.
 */
package es.gob.afirma.testrfc3161services;

import junit.framework.TestCase;

import org.bouncycastle.tsp.TimeStampResponse;

import es.gob.afirma.rfc3161TSAServiceInvoker.RFC3161TSAServiceInvoker;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerConstants;
import es.gob.afirma.utils.UtilsFileSystemCommons;

/**
 * <p>Class that allows to tests the TS@ RFC 3161 services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 23/01/2014.
 */
public class RFC3161ServicesTest extends TestCase {

    /**
     * Constant attribute that identifies the application name for tests.
     */
    private static final String APPLICATION = "pruebasTSARFC3161SHA1";

    /**
     * Attribute that represents the file for tests.
     */
    private byte[ ] file = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);

    /**
     * Test for generating an ASN-1 timestamp from TS@ via RFC 3161 - TCP service.
     */
    public void testRFC3161Service() {
	try {
	    RFC3161TSAServiceInvoker invoker = new RFC3161TSAServiceInvoker();
	    byte[ ] response = invoker.generateTimeStampToken(TSAServiceInvokerConstants.RFC3161Protocol.TCP, APPLICATION, file);
	    TimeStampResponse tsp = new TimeStampResponse(response);
	    assertNull(tsp.getFailInfo());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for generating an ASN-1 timestamp from TS@ via RFC 3161 - HTTPS service.
     */
    public void testRFC3161HTTPSService() {
	try {
	    RFC3161TSAServiceInvoker invoker = new RFC3161TSAServiceInvoker();
	    byte[ ] response = invoker.generateTimeStampToken(TSAServiceInvokerConstants.RFC3161Protocol.HTTPS, APPLICATION, file);
	    TimeStampResponse tsp = new TimeStampResponse(response);
	    assertNull(tsp.getFailInfo());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    /**
     * Test for generating an ASN-1 timestamp from TS@ via RFC 3161 - SSL service.
     */
    public void testRFC3161SSLService() {
	try {
	    RFC3161TSAServiceInvoker invoker = new RFC3161TSAServiceInvoker();
	    byte[ ] response = invoker.generateTimeStampToken(TSAServiceInvokerConstants.RFC3161Protocol.SSL, APPLICATION, file);
	    TimeStampResponse tsp = new TimeStampResponse(response);
	    assertNull(tsp.getFailInfo());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    // /**
    // * Test for generating an ASN-1 timestamp from TS@ via RFC 3161 - HTTPS
    // service.
    // */
    // public void testRFC3161HTTPSServiceNoApp() {
    // try {
    // System.setProperty("https.proxyHost", "V2GATE.risenet.eu");
    // System.setProperty("https.proxyPort", "8080");
    // RFC3161TSAServiceInvoker invoker = new RFC3161TSAServiceInvoker();
    // byte[ ] response =
    // invoker.generateTimeStampToken(TSAServiceInvokerConstants.RFC3161Protocol.HTTPS,
    // "noapp", file);
    // TimeStampResponse tsp = new TimeStampResponse(response);
    // assertNull(tsp.getFailInfo());
    // } catch (Exception e) {e.printStackTrace();
    // assertTrue(false);
    // }
    // }

}
