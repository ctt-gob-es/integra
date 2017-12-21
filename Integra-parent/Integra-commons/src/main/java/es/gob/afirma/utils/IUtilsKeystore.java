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
 * <b>File:</b><p>es.gob.afirma.utils.IUtilsKeystore.java.</p>
 * <b>Description:</b><p>Interface that defines constants related to keystores.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>14/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 03/02/2016.
 */
package es.gob.afirma.utils;

/** 
 * <p>Interface that defines constants related to keystores.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 03/02/2016.
 */
public interface IUtilsKeystore {

    /**
     * Constant attribute that represents the PKCS#12 keystore type.
     */
    String PKCS12 = "PKCS12";

    /**
     * Constant attribute that represents the JCEKS keystore type.
     */
    String JCEKS = "JCEKS";

    /**
     * Constant attribute that represents the Java Key Store keystore type.
     */
    String JKS = "JKS";
}
