// Copyright (C) 2018, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.mreport.utils.UtilsTime.java.</p>
 * <b>Description:</b><p> Class that provides methods for managing dates.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>25/08/2020.</p>
 * @author Spanish Government.
 * @version 1.0, 25/08/2020.
 */
package es.gob.afirma.mreport.utils;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/** 
 * <p>Class that provides methods for managing dates.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 25/08/2020.
 */
public class UtilsTime {

	/**
	 * Constant attribute that represents the number 3.
	 */
	private static final int NUM3 = 3;

	/**
	 * Constant attribute that represents the number 10.
	 */
	private static final int NUM10 = 10;

	/**
	 * Constant attribute that represents the number 7.
	 */
	private static final int NUM7 = 7;

	/**
	 * Constant attribute that represents the number 5.
	 */
	private static final int NUM5 = 5;

	/**
	 * Constant attribute that represents the number 6.
	 */
	private static final int NUM6 = 6;

	/**
	 * Constant attribute that represents the number 4.
	 */
	private static final int NUM4 = 4;

	/**
	 * Constant attribute that represents the number 8.
	 */
	private static final int NUM8 = 8;

	/**
	 * Constant attribute that represents the number 9.
	 */
	private static final int NUM9 = 9;

	/**
	 * Constant attribute that represents the date format <code>yyyy-MM-dd EEE HH:mm:ss ZZZZ</code>.
	 */
	public static final String FORMATO_COMPLETO = "yyyy-MM-dd EEE HH:mm:ss ZZZZ";

	/**
	 * Constant attribute that represents the date format <code>yyyy-MM-dd</code>.
	 */
	public static final String FORMATO_FECHA = "yyyy-MM-dd";

	/**
	 * Constant attribute that represents the date format <code>HH:mm:ss</code>.
	 */
	public static final String FORMATO_HORA = "HH:mm:ss";

	/**
	 * Constant attribute that represents the date format <code>yyyy-MM-dd HH:mm:ss</code>.
	 */
	public static final String FORMATO_FECHA_HORA = "yyyy-MM-dd HH:mm:ss";

	/**
	 * Constant attribute that represents the date format <code>dd/MM/yyyy</code>.
	 */
	public static final String FORMATO_FECHA_CORTO = "dd/MM/yyyy";

	/**
	 * Constant attribute that represents the date format <code>yyyyMMddHHmmss</code>.
	 */
	public static final String FORMATO_FECHA_JUNTA = "yyyyMMddHHmmss";
	
	/**
	 * Constant attribute that represents the date format <code>yyyyMMdd</code>.
	 */
	public static final String FORMATO_FECHA_JUNTA_CORTA = "yyyyMMdd";

	/**
	 * Constant attribute that represents the date format <code>dd_MM_yyyy</code>.
	 */
	public static final String FORMATO_FECHA_BAJA = "dd_MM_yyyy";

	/**
	 * Constant attribute that represents the date format <code>"dd/MM/yyyy HH:mm:ss"</code>.
	 */
	public static final String FORMATO_FECHA_ESTANDAR = "dd/MM/yyyy HH:mm:ss";

	/**
	 * Constant attribute that represents the date format <code>"dd/MM/yyyy/HH/mm/ss"</code>.
	 */
	public static final String FORMATO_FECHA_BARRAS = "dd/MM/yyyy/HH/mm/ss";

	/**
	 * Constant attribute that represents the date format <code>"yyyyMMddHHmmss.SZ"</code>.
	 */
	public static final String FORMATO_FECHA_JUNTA_ADICIONAL = "yyyyMMddHHmmss.SZ";

	/**
	 * Constant attribute that represents the date format <code>"yyyy-MM-dd'T'HHmmssZ"</code>.
	 */
	public static final String FORMATO_FECHA_HORA_ADICIONAL = "yyyy-MM-dd'T'HHmmssZ";

	/**
	 * Constant attribute that represents the date format <code>"yyyy-MM-dd HH:mm:ss,SSS"</code>.
	 */
	public static final String FORMATO_FECHA_HORA_COMPLETA = "yyyy-MM-dd HH:mm:ss,SSS";

	/**
	 * Constant attribute that represents the date format <code>"dd-MM-yyyy"</code>.
	 */
	public static final String FORMATO_FECHA_INVERTIDO = "dd-MM-yyyy";

	/**
	 * Constant attribute that represents the date format <code>"dd/MM/yyyy HH:mm:ss.SSS"</code>.
	 */
	public static final String FORMATO_FECHA_ESTANDAR_ADICIONAL = "dd/MM/yyyy HH:mm:ss.SSS";

	/**
	 * Constant attribute that represents the date format <code>"dd-MMM-yyyy HH:mm"</code>.
	 */
	public static final String FORMATO_FECHA_HORA_MINUTOS = "dd-MMM-yyyy HH:mm";

	/**
	 * Constant attribute that represents the date format <code>"yyyy-MM-dd HH:mm:ss ZZZZ"</code>.
	 */
	public static final String FORMATO_SEMICOMPLETO = "yyyy-MM-dd HH:mm:ss ZZZZ";

	/**
	 * Constant attribute that represents the date format <code>"yyyy-MM-dd'T'HH:mm:ss.SSS"</code>.
	 */
	public static final String FORMATO_FECHA_UTC = "yyyy-MM-dd'T'HH:mm:ss.SSS";

	/**
	 * Constant attribute that represents the date format <code>"yyyy/MM/dd EEE hh:mm:ss zzzz"</code>.
	 */
	public static final String FORMATO_COMPLETO_ADICIONAL = "yyyy/MM/dd EEE hh:mm:ss zzzz";

	/**
	 * Constant attribute that represents the date format <code>"dd-MM-yy_HH-mm-ss"</code>.
	 */
	public static final String FORMATO_FECHA_HORA_SEGUNDOS = "dd-MM-yy_HH-mm-ss";

	/**
	 * Attribute that represents the value of the date.
	 */
	private java.util.Date fecha;

	/**
	 * Attribute that represents the time zone offset.
	 */
	private TimeZone zona = null;

	/**
	 * Constructor method for the class UtilsTime.java.
	 */
	public UtilsTime() {
		fecha = new Date();
		zona = null;
	}

	/**
	 * Constructor method for the class UtilsTime.java.
	 * @param pFecha Parameter that represents the value of the date.
	 */
	public UtilsTime(Date pFecha) {
		fecha = pFecha;
		zona = null;
	}

	/**
	 * Constructor method for the class UtilsTime.java.
	 * @param c Parameter that represents the object to set the value of the date and the time zone offset.
	 */
	public UtilsTime(Calendar c) {
		fecha = c.getTime();
		zona = c.getTimeZone();
	}

	/**
	 * Constructor method for the class UtilsTime.java.
	 * @param t Parameter that represents the time zone offset.
	 */
	public UtilsTime(TimeZone t) {
		fecha = new Date();
		zona = t;
	}

	/**
	 * Constructor method for the class UtilsTime.java.
	 * @param timezone Parameter that represents the identifier for the time zone offset.
	 */
	public UtilsTime(String timezone) {
		fecha = new Date();
		zona = TimeZone.getTimeZone(timezone);
	}

	/**
	 * Constructor method for the class UtilsTime.java.
	 * @param fechaStr Parameter that represents the value of the date.
	 * @param formato Parameter that represents the format used for the date.
	 * @throws ParseException If the method fails.
	 */
	public UtilsTime(String fechaStr, String formato) throws ParseException {
		Locale l = new Locale("ES", "es");

		SimpleDateFormat formador = new SimpleDateFormat(formato, l);
		if (zona != null) {
			formador.setTimeZone(zona);
		}
		fecha = formador.parse(fechaStr);

	}

	/**
	 * Method that obtains a string with the value of the date for certain format.
	 * @param formato Parameter that represents the format to apply for the date.
	 * @return a string with the value of the date for certain format.
	 */
	public String toString(String formato) {
		Locale l = new Locale("ES", "es");
		SimpleDateFormat formador = new SimpleDateFormat(formato, l);
		if (zona != null) {
			formador.setTimeZone(zona);
		}
		return formador.format(fecha);
	}

	/**
	 * Method that obtains a string with the value of the date for certain format.
	 * @param formador Parameter that represents the concrete object for formatting and parsing the date in a locale-sensitive manner.
	 * @return a string with the value of the date for certain format.
	 */
	public String toString(SimpleDateFormat formador) {
		return formador.format(fecha);
	}

	/**
	 * Method that obtains a string which represents the date on <code>UTC</code> format.
	 * @return the string on <code>UTC</code> format.
	 */
	public String toUTCString() {
		SimpleDateFormat sdf = new SimpleDateFormat(FORMATO_FECHA_UTC);
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		return sdf.format(fecha) + "Z";
	}

	/**
	 * Method that obtains a date from a string with <code>UTC</code> format.
	 * @param utcDate Parameter that represents the string with <code>UTC</code> format.
	 * @return the date.
	 * @throws ParseException If the method fails.
	 */
	public static Date getUTCDate(String utcDate) throws ParseException {
		String[ ] t = utcDate.split("T");
		String pattern = "yyyy";
		String dateStr = null;
		dateStr = t[0].substring(0, NUM4);
		if (t[0].length() > NUM6) {
			dateStr = dateStr + t[0].substring(NUM5, NUM7);
			pattern = pattern + "MM";
			if (t[0].length() > NUM9) {
				dateStr = dateStr + t[0].substring(NUM8, NUM10);
				pattern = pattern + "dd";
			}
		}
		if (t.length == 2) {
			String offSet = null;
			if (t[1].indexOf('Z') > -1) {
				t[1] = t[1].substring(0, t[1].indexOf('Z'));
				offSet = "+0000";
			} else if (t[1].indexOf('-') > -1) {
				offSet = t[1].substring(t[1].indexOf('-')).replaceAll(":", "");
				t[1] = t[1].substring(0, t[1].indexOf('-'));
			} else if (t[1].indexOf('+') > -1) {
				offSet = t[1].substring(t[1].indexOf('+')).replaceAll(":", "");
				t[1] = t[1].substring(0, t[1].indexOf('+'));
			}
			if (t[1].length() > 1) {
				dateStr = dateStr + t[1].substring(0, 2);
				pattern = pattern + "HH";
				if (t[1].length() > NUM4) {
					dateStr = dateStr + t[1].substring(NUM3, NUM5);
					pattern = pattern + "mm";
					if (t[1].length() > NUM7) {
						dateStr = dateStr + t[1].substring(NUM6, NUM8);
						pattern = pattern + "ss";
						if (t[1].length() > NUM9) {
							pattern = pattern + ".SSS";
							t[1] = t[1].substring(NUM8);
							for (int i = t[1].length(); i < NUM4; i++) {
								t[1] = t[1] + "0";
							}
							dateStr = dateStr + t[1].substring(0, NUM4);
						}
					}
				}
				if (offSet != null) {
					pattern = pattern + "Z";
					dateStr = dateStr + offSet;
				}
			}
		}
		SimpleDateFormat sdf = new SimpleDateFormat(pattern);
		return sdf.parse(dateStr);
	}

	/**
	 * Method that obtains the current date and hour of the system.
	 * @param formato Parameter that represents the format used to obtain the date.
	 * @return the current date and hour of the system.
	 */
	public static String getFechaSistema(String formato) {
		String fechaSistema = "";
		try {
			UtilsTime serClsFecha = new UtilsTime();
			fechaSistema = serClsFecha.toString(formato);
		} catch (Exception e) {
			fechaSistema = "FECHA KO";
		}
		return fechaSistema;
	}

	/**
	 * {@inheritDoc}
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		return toString(FORMATO_FECHA_HORA);
	}

	/**
	 * Gets the value of the attribute {@link #fecha}.
	 * @return the value of the attribute {@link #fecha}.
	 */
	public Date getFecha() {
		return fecha;
	}

	/**
	 * Sets the value of the attribute {@link #fecha}.
	 * @param pFecha The value for the attribute {@link #fecha}.
	 */
	public void setFecha(Date pFecha) {
		fecha = pFecha;
	}

	/**
	 * Method that adds a number of days to the date.
	 * @param numDias Parameter that represents the number of days to add.
	 */
	public void sumar(int numDias) {
		Calendar fechaCalendar = Calendar.getInstance();
		fechaCalendar.setTime(fecha);
		fechaCalendar.add(Calendar.DATE, numDias);

		fecha = fechaCalendar.getTime();
	}

	/**
	 * Method that modifies the format of a date.
	 * @param fecha Parameter that represents the date.
	 * @param formatoOriginal Parameter that represents the original format.
	 * @param nuevoFormato Parameter that represents the new format.
	 * @return a string that represents the date with the new format.
	 * @throws ParseException If the method fails.
	 */
	public static String modificarFormato(String fecha, String formatoOriginal, String nuevoFormato) throws ParseException {
		UtilsTime fechaAux = new UtilsTime(fecha, formatoOriginal);
		return fechaAux.toString(nuevoFormato);
	}

	/**
	 * Method that adds a number of days to the system date.
	 * @param numDias Parameter that represents the number of days to add.
	 * @return a string that represents the date returned on format <code>yyyy-mm-dd</code>.
	 * @throws ParseException If the method fails.
	 */
	public String sumarDias(int numDias) throws ParseException {

		Calendar fechaCalendar = Calendar.getInstance();

		fechaCalendar.add(Calendar.DATE, numDias);

		fecha = fechaCalendar.getTime();

		return modificarFormato(toString(), FORMATO_COMPLETO_ADICIONAL, FORMATO_FECHA);
	}

	/**
	 * Method that adds a number of days to certain date.
	 * @param fechaEnt Parameter that represents the date to add the days. It's a string with <code>YYYYMMDD</code> format.
	 * @param diasAdd Parameter that represents the number of days to add.
	 * @return a string that represents the date returned on format <code>yyyyMMDD</code>.
	 * @throws ParseException If the method fails.
	 */
	public static String getFechaMasNDias(String fechaEnt, int diasAdd) throws ParseException {
		/*Calendar	diaCaducidad 	= null;
		String		separadorFech	= "/";
		diaCaducidad = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
		separadorFech = fechaEnt.substring(4,5);
		diaCaducidad.set(Integer.parseInt(fechaEnt.substring(0,4)), (Integer.parseInt(fechaEnt.substring(5,7))) - 1, Integer.parseInt(fechaEnt.substring(8,10)));
		diaCaducidad.add(Calendar.DATE,diasAdd);

		return  String.valueOf(diaCaducidad.get(Calendar.YEAR)) + separadorFech + String.valueOf(diaCaducidad.get(Calendar.MONTH) + 1) + separadorFech + String.valueOf(diaCaducidad.get(Calendar.DAY_OF_MONTH));
		 */
		UtilsTime fecha = new UtilsTime(fechaEnt, FORMATO_FECHA);
		return fecha.sumarDias(diasAdd);

	}

	/**
	 * Method that obtains a date from a string using a determined pattern.
	 * @param fecha Parameter that represents the string to transform in date.
	 * @param patron Parameter that represents the pattern used to generate the date.
	 * @return a date from a string using a determined pattern.
	 * @throws ParseException If the method fails.
	 */
	public static Date convierteFecha(String fecha, String patron) throws ParseException {
		SimpleDateFormat format = new SimpleDateFormat(patron);
		Date fechaParseada = null;
		fechaParseada = format.parse(fecha);
		return fechaParseada;
	}

}
