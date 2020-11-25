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
 * <b>File:</b><p>es.gob.afirma.tsl.elements.json.DateString.java.</p>
 * <b>Description:</b><p>Class that represents an element transformation between a Date
 * and a string in a specific format: {@value UtilsDate#FORMAT_DATE_TIME_JSON}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/10/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/10/2020.
 */
package es.gob.afirma.tsl.elements.json;

import java.io.Serializable;
import java.text.ParseException;
import java.util.Date;

import es.gob.afirma.tsl.utils.UtilsDate;

/** 
 * <p>Class that represents an element transformation between a Date
 * and a string in a specific format: {@value UtilsDate#FORMAT_DATE_TIME_JSON}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/10/2020.
 */
public class DateString implements Serializable {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = 8961652832724946108L;
    /**
	 * Attribute that represents the date.
	 */
	private Date date = null;

	/**
	 * Attribute that represents the date in string format.
	 */
	private String dateString = null;

	/**
	 * Constructor method for the class DateString.java.
	 */
	private DateString() {
		super();
	}

	/**
	 * Constructor method for the class DateString.java.
	 * @param dateParam Date to set.
	 */
	public DateString(Date dateParam) {
		this();
		this.date = dateParam;
	}

	/**
	 * Constructor method for the class DateString.java.
	 * @param dateStringParam Date to set in string format.
	 */
	public DateString(String dateStringParam) {
		this();
		this.dateString = dateStringParam;
	}

	/**
	 * Gets the value of the attribute {@link #date}.
	 * @return the value of the attribute {@link #date}.
	 * @throws ParseException In case of some error parsing the input date string.
	 */
	public final Date getDate() throws ParseException {
		if (date == null && dateString != null) {
			date = UtilsDate.transformDate(dateString, UtilsDate.FORMAT_DATE_TIME_JSON);
		}
		return date;
	}

	/**
	 * Gets the value of the attribute {@link #dateString}.
	 * @return the value of the attribute {@link #dateString}.
	 */
	public final String getDateString() {
		if (dateString == null && date != null) {
			dateString = UtilsDate.toString(UtilsDate.FORMAT_DATE_TIME_JSON, date);
		}
		return dateString;
	}

	/**
	 * {@inheritDoc}
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return getDateString();
	}

}
