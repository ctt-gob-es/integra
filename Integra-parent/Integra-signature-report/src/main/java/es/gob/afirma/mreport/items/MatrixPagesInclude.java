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
// https://eupl.eu/1.1/es/

/** 
 * <b>File:</b><p>es.gob.signaturereport.mreport.items.MatrixPagesInclude.java.</p>
 * <b>Description:</b><p> Class that contains information about the pages of a signed document will 
be included in a signature report.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>19/08/2020.</p>
 * @author Spanish Government.
 * @version 1.0, 19/08/2020.
 */
package es.gob.afirma.mreport.items;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Set;

/** 
 * <p>Class that contains information about the pages of a signed document will 
be included in a signature report.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 19/08/2020.
 */
public class MatrixPagesInclude {

    /**
     * Map that contains information about the pages to include in a signature report. The content is: <br>
     * 
     * Key: Page number of signature report. Value: Map with the pages of the original document to include in the page specified in the key. The content is:<br/>
     * 
     * Key: Page number of signed document. Value: Array of {@link PageIncludeFormat} that contains the location where the page is included.
     */
    private LinkedHashMap<Integer, LinkedHashMap<Integer, PageIncludeFormat[ ]>> matrix = null;

    /**
     * Constructor method for the class MatrixPagesInclude.java. 
     */
    public MatrixPagesInclude() {
	matrix = new LinkedHashMap<Integer, LinkedHashMap<Integer, PageIncludeFormat[ ]>>();
    }

    /**
     * Add page to the matrix.
     * @param targetNumPage	Page number of signature report.
     * @param originNumPage	Page number of signed document.
     * @param format		{@link PageIncludeFormat} that contains the location where the page is included.
     */
    public void addPage(int targetNumPage, int originNumPage, PageIncludeFormat format) {
	Integer targetKey = Integer.valueOf(targetNumPage);
	if (!matrix.containsKey(targetKey)) {
	    matrix.put(targetKey, new LinkedHashMap<Integer, PageIncludeFormat[ ]>());
	}
	Integer origenKey = Integer.valueOf(originNumPage);
	if (!matrix.get(targetKey).containsKey(origenKey)) {
	    matrix.get(targetKey).put(origenKey, new PageIncludeFormat[ ] { format });
	} else {
	    PageIncludeFormat[ ] formats = matrix.get(targetKey).remove(origenKey);
	    PageIncludeFormat[ ] newFormats = new PageIncludeFormat[formats.length + 1];
	    System.arraycopy(formats, 0, newFormats, 0, formats.length-1);
	    newFormats[formats.length] = format;
	    matrix.get(targetKey).put(origenKey, newFormats);
	}
    }

    /**
     * Gets the number of pages of the signed document will be included into the page of the report provided.
     * @param targetNumPage	Page number of signature report.
     * @return			Array of signed document pages.
     */
    public int[ ] getPageToInclude(int targetNumPage) {
	int[ ] pages = null;
	Integer targetKey = Integer.valueOf(targetNumPage);
	if (matrix.containsKey(targetKey)) {
	    Set<Integer> keys = matrix.get(targetKey).keySet();
	    pages = new int[keys.size()];
	    int i = 0;
	    Iterator<Integer> it = keys.iterator();
	    while (it.hasNext()) {
		pages[i] = it.next().intValue();
		i++;
	    }
	}
	return pages;
    }

    /**
     * Gets a array of {@link PageIncludeFormat} that contains the location where the page is included.
     * @param targetNumPage	Page number of signature report.
     * @param originNumPage	Page number of signed document.
     * @return	Array of {@link PageIncludeFormat} that contains the location where the page is included.
     */
    public PageIncludeFormat[ ] getPagesFormat(int targetNumPage, int originNumPage) {
	Integer targetKey = Integer.valueOf(targetNumPage);
	Integer origenKey = Integer.valueOf(originNumPage);
	if (matrix.containsKey(targetKey) && matrix.get(targetKey).containsKey(origenKey)) {
	    return matrix.get(targetKey).get(origenKey);
	}
	return null;
    }

    /**
     * Reports if the table is empty.
     * @return	True if the table is empty, false otherwise.
     */
    public boolean isEmpty() {
	return matrix.isEmpty();
    }
}
