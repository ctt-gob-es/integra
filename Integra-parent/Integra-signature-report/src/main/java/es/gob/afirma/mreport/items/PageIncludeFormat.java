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
 * <b>File:</b><p>es.gob.signaturereport.mreport.items.PageIncludeFormat.java.</p>
 * <b>Description:</b><p> Class that contains the format of a pdf page.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>19/08/2020.</p>
 * @author Spanish Government.
 * @version 1.0, 19/08/2020.
 */
package es.gob.afirma.mreport.items;


/** 
 * <p>Class that contains the format of a PDF page.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 19/08/2020.
 */
public class PageIncludeFormat {
    
	/**
	 * Attribute that represents the constant used to indicate the layout is front. 
	 */
	public static final String FRONT_LAYOUT = "front";
	/**
	 * Attribute that represents the constant used to indicate the layout is back. 
	 */
	public static final String BACK_LAYOUT = "back";
	
	/**
	 * Attribute that represents the Y position in millimeters. 
	 */
	private double ypos = 0;
    
	/**
	 * Attribute that represents the X position in millimeters. 
	 */
    private double xpos = 0;
    
    /**
	 * Attribute that represents the page width in millimeters. 
	 */
    private double width = 0;
    
    /**
	 * Attribute that represents the page height in millimeters. 
	 */
    private double height = 0;

    /**
     * Attribute that represents the page layout. 
     */
    private String layout = FRONT_LAYOUT;
    
    /**
     * Gets the Y position.
     * @return	Position in millimeters.
     */
    public double getYpos() {
        return ypos;
    }

    
    
	/**
	 * Gets the value of the page layout.
	 * @return the value of the page layout.
	 */
	public String getLayout() {
		return layout;
	}


	
	/**
	 * Sets the value of the page layout.
	 * @param layer The value for the page layout.
	 */
	public void setLayout(String layer) {
		this.layout = layer;
	}


	/**
	 * Sets the Y position in millimeters.
	 * @param pos	Y position in millimeters.
	 */
	public void setYpos(double pos) {
        this.ypos = pos;
    }

    
    /**
     * Gets the X position.
     * @return	Position in millimeters.
     */
    public double getXpos() {
        return xpos;
    }

    
    /**
     * Sets the X position.
     * @param pos	Position in millimeters.
     */
    public void setXpos(double pos) {
        this.xpos = pos;
    }

    
    /**
     * Gets the page width. 
     * @return	Width in millimeters.
     */
    public double getWidth() {
        return width;
    }

    
    /**
     * Sets the page width.
     * @param pageWidth	Width in millimeters.
     */
    public void setWidth(double pageWidth) {
        this.width = pageWidth;
    }

    
    /**
     * Gets the page height.
     * @return	Height in millimeters.
     */
    public double getHeight() {
        return height;
    }

    
    /**
     * Sets the page height.
     * @param pageHeight	Height in millimeters.
     */
    public void setHeight(double pageHeight) {
        this.height = pageHeight;
    }

}
