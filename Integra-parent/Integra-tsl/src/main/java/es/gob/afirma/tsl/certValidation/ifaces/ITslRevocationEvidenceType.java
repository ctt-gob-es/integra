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
 * <b>File:</b><p>es.gob.afirma.tsl.certValidation.ifaces.ITslRestServiceRevocationEvidenceType.java.</p>
 * <b>Description:</b><p>Interface that defines the constants for the differents revocation evidence types.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 19/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 19/11/2020.
 */
package es.gob.afirma.tsl.certValidation.ifaces;


/** 
 * <p>Interface that defines the constants for the differents revocation evidence types.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 19/11/2020.
 */
public interface ITslRevocationEvidenceType {
    /**
	 * Constant attribute that represents an evidence type: OCSP.
	 */
	int REVOCATION_EVIDENCE_TYPE_OCSP = 1;

	/**
	 * Constant attribute that represents an evidence type: CRL.
	 */
	int REVOCATION_EVIDENCE_TYPE_CRL = 2;
}
