package com.verify.jarfile;


public class MFEntry {
    private String fileName;
    private String digestValue;
    
    /*items内容:
     * Name: com/ftsafe/res/toggle_btn_left.png
       SHA-256-Digest: IRFl4dQYKeA7RUK27wB9KKOdvaGGo8fQxw2AyaoOATc=
     * 末尾加上\r\n
     * */
    private String items;//
    
    private String itemShaBase64;//对itemsSHA并Base64
    
	public String getFileName() {
		return fileName;
	}
	public void setFileName(String fileName) {
		this.fileName = fileName;
	}
	public String getDigestValue() {
		return digestValue;
	}
	public void setDigestValue(String digestValue) {
		this.digestValue = digestValue;
	}
	public String getItems() {
		return items;
	}
	public void setItems(String items) {
		this.items = items;
	}
	public String getItemShaBase64() {
		return itemShaBase64;
	}
	public void setItemShaBase64(String itemShaBase64) {
		this.itemShaBase64 = itemShaBase64;
	}

	@Override
	public String toString() {
		return "MFEntry [fileName=" + fileName + ", digestValue=" + digestValue + ", items=" + items
				+ ", itemShaBase64=" + itemShaBase64 + "]";
	}

	 
	 
	
	
}
