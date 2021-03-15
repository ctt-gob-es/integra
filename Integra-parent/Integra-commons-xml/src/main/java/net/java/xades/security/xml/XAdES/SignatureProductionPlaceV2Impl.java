package net.java.xades.security.xml.XAdES;

public class SignatureProductionPlaceV2Impl extends SignatureProductionPlaceImpl
implements SignatureProductionPlaceV2
{
	private String streetAddress;

	public SignatureProductionPlaceV2Impl() 
	{
		super();
	}

	public SignatureProductionPlaceV2Impl(String city, String streetAddress, String stateOrProvince, String postalCode, String countryName) 
	{
		super(city, stateOrProvince, postalCode, countryName);
		this.streetAddress = streetAddress;
	}
	
	public String getStreetAddress()
	{
		return this.streetAddress;
	}

	public void setStreetAddress(String streetAddress)
	{
		this.streetAddress = streetAddress;
	}
}