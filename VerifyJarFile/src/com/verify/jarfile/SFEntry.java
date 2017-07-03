package com.verify.jarfile;

public class SFEntry {
	private String fileName;
    private String fileSHAValue;
 
	public String getFileName() {
		return fileName;
	}
	public void setFileName(String fileName) {
		this.fileName = fileName;
	}
	public String getFileSHAValue() {
		return fileSHAValue;
	}
	public void setFileSHAValue(String fileSHAValue) {
		this.fileSHAValue = fileSHAValue;
	}
	@Override
	public String toString() {
		return "SFEntry [fileName=" + fileName + ", fileSHAValue=" + fileSHAValue + "]";
	}
}
