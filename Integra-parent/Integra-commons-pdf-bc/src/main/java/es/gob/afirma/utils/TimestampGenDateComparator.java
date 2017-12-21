// Copyright (C) 2016 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.utils.TimestampGenDateComparator.java.</p>
 * <b>Description:</b><p>Class used to sort a map of {@link TimeStampToken} objects by generation time.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>04/08/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 04/08/2016.
 */
package es.gob.afirma.utils;

import java.util.Comparator;

import org.bouncycastle.tsp.TimeStampToken;

/** 
 * <p>Class used to sort a map of {@link TimeStampToken} objects by generation time.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 04/08/2016.
 */
public class TimestampGenDateComparator implements Comparator<TimeStampToken> {

	/**
	 * {@inheritDoc}
	 * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
	 */
	@Override
	public final int compare(TimeStampToken o1, TimeStampToken o2) {
		return o1.getTimeStampInfo().getGenTime().compareTo(o2.getTimeStampInfo().getGenTime());
	}

}
