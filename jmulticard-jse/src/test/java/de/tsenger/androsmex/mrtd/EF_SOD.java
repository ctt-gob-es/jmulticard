/*
 * EFSODDataContainer.java
 *
 * Created on 22. November 2007
 *
 *  This file is part of JSmex.
 *
 *  JSmex is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  JSmex is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Foobar; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

package de.tsenger.androsmex.mrtd;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
//import opencard.core.util.HexString;
//import org.bouncycastle.asn1.ASN1InputStream;
//import org.bouncycastle.asn1.ASN1Object;
//import org.bouncycastle.asn1.ASN1Sequence;
//import org.bouncycastle.asn1.ASN1Set;
//import org.bouncycastle.asn1.DERApplicationSpecific;
//import org.bouncycastle.asn1.DERObject;
//import org.bouncycastle.asn1.DERObjectIdentifier;
//import org.bouncycastle.asn1.DEROctetString;
//import org.bouncycastle.asn1.DEROutputStream;
//import org.bouncycastle.asn1.DERSequence;
//import org.bouncycastle.asn1.DERTaggedObject;
//import org.bouncycastle.asn1.cms.ContentInfo;
//import org.bouncycastle.asn1.cms.SignedData;
//import org.bouncycastle.asn1.cms.SignerInfo;
//import org.bouncycastle.asn1.x509.X509CertificateStructure;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.jce.provider.JDKDSASigner;
//import org.bouncycastle.jce.provider.X509CertificateObject;
//import org.bouncycastle.math.ec.ECCurve;

/**
 *
 * @author Tobias Senger (jsmex@t-senger.de)
 */
public class EF_SOD {
//    
//    private byte[] data = null;
//    private SignedData signedData = null;
//    private X509CertificateObject x509Cert = null;
//    
//    /** Creates a new instance of EFSODDataContainer */
//    public EF_SOD(byte[] rawData) {
//        this.data = rawData;
//        
//        this.signedData = new SignedData(getsignedDataBytes(data));
//    }
//    
//    private ASN1Sequence getsignedDataBytes(byte[] b) {
//        
//        ASN1InputStream asn1in = new ASN1InputStream(new ByteArrayInputStream(b));
//        DERApplicationSpecific appspec = null;
//        DERSequence seq = null;
//        try {
//            appspec = (DERApplicationSpecific) asn1in.readObject();
//            seq = (DERSequence)appspec.getObject();
//        } catch (IOException ex) {
//            ex.printStackTrace();
//        }
//        
//        DERObjectIdentifier objectIdentifier = (DERObjectIdentifier)seq.getObjectAt(0);
//        if (!objectIdentifier.getId().equals("1.2.840.113549.1.7.2")) System.out.println("Didn't found SignedData!");
//        DERSequence s2 = (DERSequence)((DERTaggedObject)seq.getObjectAt(1)).getObject();
//        return s2;
//    }
//    
//    /**
//     * Gets the document signing certificate.
//     * Use this certificate to verify that
//     * <i>eSignature</i> is a valid signature for
//     * <i>eContent</i>. This certificate itself is
//     * signed using the country signing certificate.
//     *
//     * @see #getEContent()
//     * @see #getSignature()
//     *
//     * @return the document signing certificate
//     */
//    public Certificate getDocSigningCertificate() throws IOException, Exception {
//        byte[] certSpec = null;
//        X509CertificateStructure e = null;
//        ASN1Set certs = signedData.getCertificates();
//        if (certs.size() != 1) {
//            System.out.println("DEBUG: WARNING: found "
//                    + certs.size() + " certificates");
//        }
//        for (int i = 0; i < certs.size(); i++) {
//            e = new X509CertificateStructure((DERSequence)certs.getObjectAt(i));
//        }
//        return new X509CertificateObject(e);
//    }
//    
//    /**
//     * Reads the security object (containing the hashes
//     * of the data groups) found in the SOd on the passport.
//     *
//     * @return the security object
//     *
//     * @throws IOException
//     */
//    private byte[] getSecurityObject() throws IOException, Exception {
//        ContentInfo contentInfo = signedData.getEncapContentInfo();
//        byte[] content = ((DEROctetString)contentInfo.getContent()).getOctets();
//        ASN1InputStream in =
//                new ASN1InputStream(new ByteArrayInputStream(content));
//        byte[] sod = in.readObject().getEncoded();
//        Object nextObject = in.readObject();
//        if (nextObject != null) {
//            System.out.println("DEBUG: WARNING: extra object found after LDSSecurityObject...");
//        }
//        return sod;
//    }
//    
//    private SignerInfo getSignerInfo()  {
//        ASN1Set signerInfos = signedData.getSignerInfos();
//        if (signerInfos.size() > 1) {
//            System.out.println("DEBUG: WARNING: found " + signerInfos.size() + " signerInfos");
//        }
//        for (int i = 0; i < signerInfos.size(); i++) {
//            SignerInfo info = new SignerInfo((DERSequence)signerInfos.getObjectAt(i));
//            return info;
//        }
//        return null;
//    }
//    
//    /**
//     * Gets the contents of the security object over which the
//     * signature is to be computed.
//     *
//     * See RFC 3369, Cryptographic Message Syntax, August 2002,
//     * Section 5.4 for details.
//     *
//     * @see #getDocSigningCertificate()
//     * @see #getSignature()
//     *
//     * @return the contents of the security object over which the
//     *         signature is to be computed
//     */
//    public byte[] getSignedAttributes() {
//        SignerInfo signerInfo = getSignerInfo();
//        ASN1Set signedAttributes = signerInfo.getAuthenticatedAttributes();
//        return signedAttributes.getDEREncoded();
//    }
//    
//    public byte[] getSignature(){
//        byte[] signatureBytes = null;      
//        
//        System.out.println(getSignerInfo().getDigestEncryptionAlgorithm().getObjectId().toString());
//        
//        DEROctetString octetString = (DEROctetString)getSignerInfo().getEncryptedDigest().getDERObject();
//        signatureBytes = octetString.getOctets();
//      
//        System.out.println("Encrypted Digest: \n"+HexString.hexify(signatureBytes));
//        return signatureBytes;
//    }
//    
//    public byte[] getBytes() {
//        return data;
//    }
//    
//    // -------------FOR TESTING--------------
//    public static void main(String args[]) {
//        
//        Security.addProvider(new BouncyCastleProvider());
//        
//        EF_SOD e = new EF_SOD(readFile("/home/tobias/Desktop/MUSTERMANN_EF_SOD.bin"));
////        EFSODDataContainer e = new EFSODDataContainer(readFile("D:/dev/projects/MUSTERMANN_EF_SOD.bin"));
//        
//        // get Certificate
//        try {
//            e.x509Cert = (X509CertificateObject) e.getDocSigningCertificate();
//            saveToFile("Certificate.cert",e.x509Cert.getEncoded());
//        } catch (IOException ex) {
//            ex.printStackTrace();
//        } catch (Exception ex) {
//            ex.printStackTrace();
//        }
//        
//        // Certificate validate?
//        try {
//            e.x509Cert.checkValidity();
//        } catch (CertificateNotYetValidException ex) {
//            ex.printStackTrace();
//        } catch (CertificateExpiredException ex) {
//            ex.printStackTrace();
//        }
//        
//        // Get Hashes
//        byte[] hashes = null;
//        try {
//            hashes = e.getSecurityObject();
//            System.out.println("Hashes: \n"+HexString.hexify(hashes));
//        } catch (IOException ex) {
//            ex.printStackTrace();
//        } catch (Exception ex) {
//            ex.printStackTrace();
//        }
//        
//        // Get SignedAtrributes
//        System.out.println("SignedAttributes: \n"+HexString.hexify(e.getSignedAttributes()));
//       
//        // Get SignedData Signature      
//        byte[] mySignature = e.getSignature();
//        
//        
//        System.out.println(HexString.hexify(e.x509Cert.getSignature()));
//            
//        //verify hash over hashes    
//        byte[] sha1OfHashes = calculateSHA1(hashes);
//        Signature sig = null;
//        try {
//            sig = Signature.getInstance("SHA1withECDSA", "BC");
//            sig.initVerify(e.x509Cert.getPublicKey());
//            sig.update(e.getSignedAttributes());
//            System.out.println(sig.getAlgorithm()); 
//            boolean isValid = sig.verify(mySignature);
//            System.out.println("Signature verifies: "+isValid);
//        } catch (NoSuchProviderException ex) {
//            ex.printStackTrace();
//        } catch (NoSuchAlgorithmException ex) {
//            ex.printStackTrace();
//        } catch (InvalidKeyException ex) {
//            ex.printStackTrace();
//        } catch (SignatureException ex) {
//            ex.printStackTrace();
//        }
//       
//        
//        
//    }
//    
//    private static byte[] calculateSHA1(byte[] input) {
//        MessageDigest md = null;
//        try {
//            md = MessageDigest.getInstance("SHA");
//        } catch (NoSuchAlgorithmException ex) {
//            System.out.println("method calculateKSeed("+HexString.hexify(input)+") throws SuchAlgorithmException");
//        }
//        md.update( input );
//        return md.digest();
//    }
//    
//    private static byte[] readFile(String efName) {
//        byte[] data = null;
//        try {
//            File file = new File(efName);
//            
//            if (file != null) {
//                FileInputStream fis = new FileInputStream( file );
//                data = new byte[(int)file.length()];
//                fis.read(data);
//                fis.close();
//                
//            }
//        } catch ( Exception e ) { e.printStackTrace(); }
//        return data;
//    }
//    
//    /**Saves data with the name given in parameter efName into a local file.
//     *
//     * @param efName The Name of the EF.
//     * @param data
//     * @return Returns 'true' if the record were saved to a local file on hd.
//     */
//    private static boolean saveToFile(String efName, byte[] data) {
//        
//        boolean success = false;
//                
//        try {
//            File file = new File(efName);
//            
//            if (file != null) {
//                FileOutputStream fos = new FileOutputStream( file );
//                fos.write(data);
//                fos.close();
//                success = true;
//            } else success = false;
//        } catch ( Exception e ) { e.printStackTrace(); }
//        return success;
//    }       
}
