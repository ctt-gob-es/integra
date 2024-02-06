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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.ifaces.ITSLSpecificationsVersions.java.</p>
 * <b>Description:</b><p>Interface that contains the tokens of the differents specifications and versions
 * of the TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/11/2020.
 */
package es.gob.afirma.tsl.parsing.ifaces;


/** 
 * <p>Interface that contains the tokens of the differents specifications and versions
 * of the TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2020.
 */
public interface ITSLSpecificationsVersions {
	/**
	 * Constant attribute that represents the ID for the constant value that represents
	 * the ETSI TS 119612 1.1.1 specification.
	 */
	Long C_ETSI_TS_119612_020101_ID = 3L;

	/**
	 * Constant attribute that represents the ETSI TS Specification 119612.
	 */
	String SPECIFICATION_119612 = "119612";

	/**
	 * Constant attribute that represents the version identifier 2.1.1.
	 */
	String VERSION_020101 = "2.1.1";

	/**
	 * Constant attribute that represents the specfication ETSI TS 119612 2.1.1.
	 */
	String SPECVERS_119612_020101 = "119612 2.1.1";
}
