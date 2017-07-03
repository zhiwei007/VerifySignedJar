package com.verify.jarfile;

import java.util.Arrays;

public class SignatureBean {
   private byte[] rsaFileBytes;
   private byte[] sfFileBytes;
public byte[] getRsaFileBytes() {
	return rsaFileBytes;
}
public void setRsaFileBytes(byte[] rsaFileBytes) {
	this.rsaFileBytes = rsaFileBytes;
}
public byte[] getSfFileBytes() {
	return sfFileBytes;
}
public void setSfFileBytes(byte[] sfFileBytes) {
	this.sfFileBytes = sfFileBytes;
}
@Override
public String toString() {
	return "SignatureBean [rsaFileBytes=" + Arrays.toString(rsaFileBytes) + ", sfFileBytes="
			+ Arrays.toString(sfFileBytes) + "]";
}
   
   
}
