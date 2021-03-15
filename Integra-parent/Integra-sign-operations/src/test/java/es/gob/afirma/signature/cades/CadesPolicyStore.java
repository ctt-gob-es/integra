package es.gob.afirma.signature.cades;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collection;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

public class CadesPolicyStore {

    private static final ASN1ObjectIdentifier ID_SIGNATURE_POLICY_STORE = new ASN1ObjectIdentifier("0.4.0.19122.1.3");

    public static void main(String[ ] args) throws Exception {

	// Cargamos el fichero con la firma
	File signatureFile = new File("C:\\Users\\carlos.gamuci\\Documents\\Afirma\\Repositorios_GitHub\\integra\\Integra-parent\\Integra-sign-operations\\src\\test\\resources\\signatures\\CAdES_BLevel_con_roles_y_politica_3413782179613781543.csig");
	byte[] sigBlock = new byte[(int) signatureFile.length()];
	try (InputStream is = new FileInputStream(signatureFile)) {
	    is.read(sigBlock);
	}

	// Cargamos la firma
	CMSSignedData signedData = new CMSSignedData(sigBlock);
	Collection<SignerInformation> signerInfos = signedData.getSignerInfos().getSigners();
	SignerInformation signerInformation = (SignerInformation) signerInfos.iterator().next();

	// Cargamos le fichero con la política de firma
	File policyFile = new File("C:\\Users\\carlos.gamuci\\Desktop\\baseline EN\\signature-policy.der");
	byte[] policyEncoded = new byte[(int) policyFile.length()];
	try (InputStream is = new FileInputStream(policyFile)) {
	    is.read(policyEncoded);
	}

	// Cargamos la política de firma
	SPDocSpecification docSpecification = new SPDocSpecification(new ASN1ObjectIdentifier("2.16.724.1.3.1.1.2.1.10"));
	SignaturePolicyDocument policyDocument = SignaturePolicyDocument.getInstance(policyEncoded);
	SignaturePolicyStore policyStore = new SignaturePolicyStore(docSpecification, policyDocument); 

	// Agregamos a la firma el almacen de la politica
	AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
	if (unsignedAttributes == null) {
	    unsignedAttributes = new AttributeTable(new Hashtable<ASN1ObjectIdentifier, DERSequence>());
	}
	unsignedAttributes = unsignedAttributes.add(ID_SIGNATURE_POLICY_STORE, policyStore);

	// Actualizamos el almacen de politica de la firma
	SignerInformation newSignerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
	signerInfos.clear();
	signerInfos.add(newSignerInformation);
	SignerInformationStore newSignerStore = new SignerInformationStore(signerInfos);

	// Componemos la nueva firma
	CMSSignedData newSignedData = CMSSignedData.replaceSigners(signedData, newSignerStore);

	byte[] signature = newSignedData.getContentInfo().getDEREncoded();


	// Guardamos la firma
	File outSignatureFile = new File("C:\\Users\\carlos.gamuci\\Desktop\\baseline EN\\CAdES_BBLevel_PolicyStore_OK.csig");
	try (	OutputStream os = new FileOutputStream(outSignatureFile);
		) {
	    os.write(signature);
	}

	System.out.println("OK");
    }
}
