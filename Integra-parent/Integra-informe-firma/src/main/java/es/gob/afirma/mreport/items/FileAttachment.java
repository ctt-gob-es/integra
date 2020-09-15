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
 * <b>File:</b><p>es.gob.signaturereport.mreport.items.FileAttachment.java.</p>
 * <b>Description:</b><p> Class that contains an attachment for including into PDF file.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>19/08/2020.</p>
 * @author Spanish Government.
 * @version 1.0, 19/08/2020.
 */
package es.gob.afirma.mreport.items;

import java.util.Arrays;


/** 
 * <p>Class that contains an attachment for including into PDF file.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 19/08/2020.
 */
public class FileAttachment {
    
    /**
     * Attribute that represents the attachment name. 
     */
    private String name = null;
    
    /**
     * Attribute that represents the attachment description. 
     */
    private String description = null;
    
    /**
     * Attribute that represents the attachment content. 
     */
    private byte[] content = null;

    /**
     * Constructor method for the class FileAttachment.java.
     * @param attName			Attachment name.
     * @param attDescription 	Attachment description.
     */
    public FileAttachment(String attName, String attDescription) {
	super();
	this.name = attName;
	this.description = attDescription;
    }

	
	/**
	 * Gets the value of the attachment name.
	 * @return the value of the attachment name.
	 */
	public String getName() {
		return name;
	}

	
	/**
	 * Sets the value of the attachment name.
	 * @param attName The value for the attachment name.
	 */
	public void setName(String attName) {
		this.name = attName;
	}

	
	/**
	 * Gets the value of the attachment description.
	 * @return the value of the attachment description.
	 */
	public String getDescription() {
		return description;
	}

	
	/**
	 * Sets the value of the attachment description.
	 * @param attDescription The value for the attachment description.
	 */
	public void setDescription(String attDescription) {
		this.description = attDescription;
	}

	
	/**
	 * Gets the value of the attachment content.
	 * @return the value of the attachment content.
	 */
	public byte[ ] getContent() {
		return content;
	}

	
	/**
	 * Sets the value of the attachment content.
	 * @param attContent The value for the attachment content.
	 */
	public void setContent(byte[ ] attContent) {
      if(attContent!=null){
    	this.content = Arrays.copyOf(attContent,attContent.length);
      }
	}
}
