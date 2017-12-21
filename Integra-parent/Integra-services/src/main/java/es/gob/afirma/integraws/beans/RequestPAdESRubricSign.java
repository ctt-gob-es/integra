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
 * <b>File:</b><p>es.gob.afirma.integraws.beans.RequestSign.java.</p>
 * <b>Description:</b><p> Class that represents the request object for SIGN PADES RUBRIC service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.beans;

/** 
 * <p>Class that represents the request object for SIGN PADES RUBRIC service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public class RequestPAdESRubricSign {
    /**
     * Attribute that represents data to sign. 
     */
    private byte[ ] dataToSign; 
    
    /**
     * Attribute that represents alias of signer certificate. 
     */
    private String alias;
    
    /**
     * Attribute that indicates if signature policy will be include. 
     */
    private boolean includeSignaturePolicy;
    
    /**
     * Attribute that indicates if timestamp will be include. 
     */
    private boolean includeTimestamp;
    
    /**
     * Attribute that represents id of WS client. 
     */
    private String idClient;
    
    /**
     * the image to be inserted as a rubric in the PDF. 
     */
    private byte[ ] image; 
    
    /**
     * Attribute that represents the page where the image will be inserted.. 
     */
    private String imagePage;
    
    /**
     * Attribute that represents the coordinate horizontal lower left of the image position.. 
     */
    private int lowerLeftX;
    
    /**
     * Attribute that represents the coordinate vertically lower left of the image position.. 
     */
    private int lowerLeftY; 
    
    /**
     * Attribute that represents the coordinate horizontal upper right of the image position.. 
     */
    private int upperRightX;
    
    /**
     * Attribute that represents the coordinate vertically upper right of the image position.. 
     */
    private int upperRightY;

    /**
     * Gets the value of the attribute {@link #dataToSign}.
     * @return the value of the attribute {@link #dataToSign}.
     */
    public final byte[ ] getDataToSign() {
        return dataToSign;
    }

    /**
     * Sets the value of the attribute {@link #dataToSign}.
     * @param dataToSignParam The value for the attribute {@link #dataToSign}.
     */
    public final void setDataToSign(byte[ ] dataToSignParam) {
        this.dataToSign = dataToSignParam;
    }


    /**
     * Gets the value of the attribute {@link #alias}.
     * @return the value of the attribute {@link #alias}.
     */
    public final String getAlias() {
        return alias;
    }

    /**
     * Sets the value of the attribute {@link #alias}.
     * @param aliasParam The value for the attribute {@link #alias}.
     */
    public final void setAlias(String aliasParam) {
        this.alias = aliasParam;
    }

    /**
     * Gets the value of the attribute {@link #includeSignaturePolicy}.
     * @return the value of the attribute {@link #includeSignaturePolicy}.
     */
    public final boolean isIncludeSignaturePolicy() {
        return includeSignaturePolicy;
    }

    /**
     * Sets the value of the attribute {@link #includeSignaturePolicy}.
     * @param includeSignaturePolicyParam The value for the attribute {@link #includeSignaturePolicy}.
     */
    public final void setIncludeSignaturePolicy(boolean includeSignaturePolicyParam) {
        this.includeSignaturePolicy = includeSignaturePolicyParam;
    }

    /**
     * Gets the value of the attribute {@link #includeTimestamp}.
     * @return the value of the attribute {@link #includeTimestamp}.
     */
    public final boolean isIncludeTimestamp() {
        return includeTimestamp;
    }

    /**
     * Sets the value of the attribute {@link #includeTimestamp}.
     * @param includeTimestampParam The value for the attribute {@link #includeTimestamp}.
     */
    public final void setIncludeTimestamp(boolean includeTimestampParam) {
        this.includeTimestamp = includeTimestampParam;
    }

    /**
     * Gets the value of the attribute {@link #idClient}.
     * @return the value of the attribute {@link #idClient}.
     */
    public final String getIdClient() {
        return idClient;
    }

    /**
     * Sets the value of the attribute {@link #idClient}.
     * @param idClientParam The value for the attribute {@link #idClient}.
     */
    public final void setIdClient(String idClientParam) {
        this.idClient = idClientParam;
    }

    /**
     * Gets the value of the attribute {@link #image}.
     * @return the value of the attribute {@link #image}.
     */
    public final byte[ ] getImage() {
        return image;
    }

    /**
     * Sets the value of the attribute {@link #image}.
     * @param imageParam The value for the attribute {@link #image}.
     */
    public final void setImage(byte[ ] imageParam) {
        this.image = imageParam;
    }

    /**
     * Gets the value of the attribute {@link #imagePage}.
     * @return the value of the attribute {@link #imagePage}.
     */
    public final String getImagePage() {
        return imagePage;
    }

    /**
     * Sets the value of the attribute {@link #imagePage}.
     * @param imagePageParam The value for the attribute {@link #imagePage}.
     */
    public final void setImagePage(String imagePageParam) {
        this.imagePage = imagePageParam;
    }

    /**
     * Gets the value of the attribute {@link #lowerLeftX}.
     * @return the value of the attribute {@link #lowerLeftX}.
     */
    public final int getLowerLeftX() {
        return lowerLeftX;
    }

    /**
     * Sets the value of the attribute {@link #lowerLeftX}.
     * @param lowerLeftXParam The value for the attribute {@link #lowerLeftX}.
     */
    public final void setLowerLeftX(int lowerLeftXParam) {
        this.lowerLeftX = lowerLeftXParam;
    }

    /**
     * Gets the value of the attribute {@link #lowerLeftY}.
     * @return the value of the attribute {@link #lowerLeftY}.
     */
    public final int getLowerLeftY() {
        return lowerLeftY;
    }

    /**
     * Sets the value of the attribute {@link #lowerLeftY}.
     * @param lowerLeftYParam The value for the attribute {@link #lowerLeftY}.
     */
    public final void setLowerLeftY(int lowerLeftYParam) {
        this.lowerLeftY = lowerLeftYParam;
    }

    /**
     * Gets the value of the attribute {@link #upperRightX}.
     * @return the value of the attribute {@link #upperRightX}.
     */
    public final int getUpperRightX() {
        return upperRightX;
    }

    /**
     * Sets the value of the attribute {@link #upperRightX}.
     * @param upperRightXParam The value for the attribute {@link #upperRightX}.
     */
    public final void setUpperRightX(int upperRightXParam) {
        this.upperRightX = upperRightXParam;
    }

    /**
     * Gets the value of the attribute {@link #upperRightY}.
     * @return the value of the attribute {@link #upperRightY}.
     */
    public final int getUpperRightY() {
        return upperRightY;
    }

    /**
     * Sets the value of the attribute {@link #upperRightY}.
     * @param upperRightYParam The value for the attribute {@link #upperRightY}.
     */
    public final void setUpperRightY(int upperRightYParam) {
        this.upperRightY = upperRightYParam;
    }
    
    
}
