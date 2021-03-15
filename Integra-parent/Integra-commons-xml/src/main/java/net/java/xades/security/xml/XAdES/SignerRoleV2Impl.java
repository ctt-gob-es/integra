package net.java.xades.security.xml.XAdES;

import java.util.ArrayList;

public class SignerRoleV2Impl implements SignerRoleV2
{
	private ArrayList<String> claimedRoles;
	private ArrayList<String> certifiedRolesV2;
	private ArrayList<String> signedAssertions;

	public SignerRoleV2Impl()
	{
		this.claimedRoles = new ArrayList<String>();
		this.certifiedRolesV2 = new ArrayList<String>();
		this.signedAssertions = new ArrayList<String>();
	}

	public ArrayList<String> getClaimedRoles()
	{
		return this.claimedRoles;
	}

	public void setClaimedRoles(ArrayList<String> claimedRole)
	{
		this.claimedRoles = claimedRole;
	}

	public void addClaimedRole(String role)
	{
		this.claimedRoles.add(role);
	}
	
	public ArrayList<String> getCertifiedRolesV2()
	{
		return this.certifiedRolesV2;
	}

	public void setCertifiedRolesV2(ArrayList<String> certifiedRole)
	{
		this.certifiedRolesV2 = certifiedRole;
	}

	public void addCertifiedRoleV2(String role)
	{
		this.certifiedRolesV2.add(role);
	}
	
	public ArrayList<String> getSignedAssertions()
	{
		return this.signedAssertions;
	}

	public void setSignedAssertions(ArrayList<String> signedAssertions)
	{
		this.signedAssertions = signedAssertions;
	}
}