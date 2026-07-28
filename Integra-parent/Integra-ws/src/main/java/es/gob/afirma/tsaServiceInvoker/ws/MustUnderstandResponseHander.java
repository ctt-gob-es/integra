// Copyright (C) 2020 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.tsaServiceInvoker.ws.MustUnderstandResponseHander.java.</p>
 * <b>Description:</b><p>Class that represents the handler used to manage the mustUnderstand attribute in responses.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>04/03/2020.</p>
 * @author Gobierno de España.
 * @version 1.2, 18/04/2022.
 */
package es.gob.afirma.tsaServiceInvoker.ws;

import java.util.Iterator;

import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPHeader;
import org.apache.axiom.soap.SOAPHeaderBlock;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.Logger;

/**
 * <p>Class that represents the handler used to manage the mustUnderstand attribute in responses.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 18/04/2022.
 */
public class MustUnderstandResponseHander extends AbstractTSAHandler {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = Logger.getLogger(MustUnderstandResponseHander.class);
    
    /**
     * Constant attribute that represents the handler name. 
     */
    private static final String HANDLER_NAME = "mustUnderstandResponseHanderIntegra";

    /**
     * Constructor method for the class CopyOfClientHandler.java.
     */
    public MustUnderstandResponseHander() {
	this.handlerDesc.setName(HANDLER_NAME);
	this.handlerDesc.getRules().setPhaseLast(true);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public InvocationResponse invoke(MessageContext msgContext) throws AxisFault {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.MURH_LOG001));
	try {
	    // Obtenemos la cabecera SOAP.
	    SOAPEnvelope envelope = msgContext.getEnvelope();
	    SOAPHeader header = envelope.getHeader();

	    // Deshabilitamos el mustUnderstand de la cabecera SOAP.
	    if (header != null) {
		Iterator<?> elems = header.getChildElements();
		while (elems.hasNext()) {
		    SOAPHeaderBlock headerBlock = (SOAPHeaderBlock) elems.next();
		    if (headerBlock.getMustUnderstand()) {
			headerBlock.setMustUnderstand(false);
		    }
		}
	    }
	} catch (Exception e) {
	    LOGGER.error(Language.getResIntegra(ILogConstantKeys.MURH_LOG002));
	    throw AxisFault.makeFault(e);
	}
	return InvocationResponse.CONTINUE;
    }

}
