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
 * <b>File:</b><p>es.gob.signaturereport.mreport.items.PageDocumentImage.java.</p>
 * <b>Description:</b><p> Class that represents the image of a signed document.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>19/08/2020.</p>
 * @author Spanish Government.
 * @version 1.0, 19/08/2020.
 */
package es.gob.afirma.mreport.items;


/** 
 * <p>Class that represents the image of a signed document.</p>
 * <b>Project:</b><p>Horizontal platform to generation signature reports in legible format.</p>
 * @version 1.0, 19/02/2020.
 */
public class PageDocumentImage extends AImage{
    
    /**
     * Attribute that represents the page number. 
     */
    private int numPage = 0;
    
    /**
     * Constructor method for the class PageDocumentImage.java.
     * @param num page number.
     */
    public PageDocumentImage(int num) {
	super();
	this.numPage = num;
    }

	
	/**
	 * Gets the value of the page number.
	 * @return the value of the page number.
	 */
	public int getNumPage() {
		return numPage;
	}

	
	/**
	 * Sets the value of the page number.
	 * @param num The value for the page number.
	 */
	public void setNumPage(int num) {
		this.numPage = num;
	}

    
   


}
