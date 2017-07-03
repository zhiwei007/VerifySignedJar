package com.verify.jarfile;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class EncryptUtils {
	public static String SHA256(byte[] strSrc) {
        MessageDigest md = null;
        String strDes = null;
        String encName="SHA-256";
        byte[] bt = strSrc;
        try {
            md = MessageDigest.getInstance(encName);
            md.update(bt);
            strDes = bytes2Hex(md.digest()); // to HexString
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
        return strDes;
    }
	
	public static String SHA1(byte[] strSrc) {
        MessageDigest md = null;
        String strDes = null;
        String encName="SHA-1";
        byte[] bt = strSrc;
        try {
            md = MessageDigest.getInstance(encName);
            md.update(bt);
            strDes = bytes2Hex(md.digest()); // to HexString
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
        return strDes;
    }
/*   public static byte[] sha256(byte[] strSrc) {
    	MessageDigest md = null;
    	String encName="SHA-256";
    	byte[] bt = strSrc;
    	try {
    		md = MessageDigest.getInstance(encName);
    		md.update(bt);
    		return (md.digest()); // to HexString
    	} catch (NoSuchAlgorithmException e) {
    		return null;
    	}
    }*/
   
   public static final int SHA1 = 1;
   public static final int SHA256 = 2;
   public static byte[] sha(byte[] strSrc,int shaType) {
	   MessageDigest md = null;
//	   String encName="SHA-1";
	   String encName= (shaType == 1?"SHA-1":"SHA-256");
	   byte[] bt = strSrc;
	   try {
		   md = MessageDigest.getInstance(encName);
		   md.update(bt);
		   return (md.digest()); // to HexString
	   } catch (NoSuchAlgorithmException e) {
		   return null;
	   }
   }

    public static String bytes2Hex(byte[] bts) {
        String des = "";
        String tmp = null;
        for (int i = 0; i < bts.length; i++) {
            tmp = (Integer.toHexString(bts[i] & 0xFF));
            if (tmp.length() == 1) {
                des += "0";
            }
            des += tmp;
        }
        return des;
    }
}
