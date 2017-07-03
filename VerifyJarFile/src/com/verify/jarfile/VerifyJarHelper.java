package com.verify.jarfile;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.jar.JarFile;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
public class VerifyJarHelper {
	private static Set<String> collectJarFileName;
	private static Set<String> collectMFItemsFileName;
	private String parseMFFileShaBySF;// 从SF属性中解析获取MF摘要值
	private String mfFileSHAValue;// 计算MF整个文件内容的摘要值
	private int shaTypeByMFFile;//解析MF文件获取摘要类型
	
	
	
	
	
	private int getShaTypeByMFFile() {
		return shaTypeByMFFile;
	}

	private void setShaTypeByMFFile(int shaTypeByMFFile) {
		this.shaTypeByMFFile = shaTypeByMFFile;
	}

	private String getParseMFFileShaBySF() {
		return parseMFFileShaBySF;
	}

	public void setParseMFFileShaBySF(String parseMFFileShaBySF) {
		this.parseMFFileShaBySF = parseMFFileShaBySF;
	}

	private String getMfFileSHAValue() {
		return mfFileSHAValue;
	}

	private void setMfFileSHAValue(String mfFileSHAValue) {
		this.mfFileSHAValue = mfFileSHAValue;
	}

	private VerifyJarHelper() {
		collectJarFileName = new HashSet<>();
		collectMFItemsFileName = new HashSet<>();
		collectJarFileName.clear();
		collectMFItemsFileName.clear();
	}
	
	private static VerifyJarHelper  verifyHelper = null;
    public static VerifyJarHelper getInstance(){
    	  if(verifyHelper == null){
    		  verifyHelper = new VerifyJarHelper();
    		  return verifyHelper;
    	  }else
		return verifyHelper;
    }
	

	private Set<MFEntry> parseMFManifest(JarFile jar) throws Exception {
		Set<MFEntry> set = new HashSet<MFEntry>();
		Enumeration<java.util.jar.JarEntry> entries = jar.entries();
		while (entries.hasMoreElements()) {
			java.util.jar.JarEntry entry = entries.nextElement();
			if (entry.getName().endsWith(".MF")) {
				InputStream ios = jar.getInputStream(entry);
				byte[] b = new byte[ios.available()];
				int len = ios.read(b);
				// Streams.readReally(b)???
				String mfContents = new String(b, 0, len);
				if (mfContents.contains("SHA1-Digest")) {
					setShaTypeByMFFile(EncryptUtils.SHA1);// 获取摘要类型
					setMfFileSHAValue(Base64.encode(EncryptUtils.sha(b, EncryptUtils.SHA1)));
				} else if (mfContents.contains("SHA-256-Digest")) {
					setShaTypeByMFFile(EncryptUtils.SHA256);
					setMfFileSHAValue(Base64.encode(EncryptUtils.sha(b, EncryptUtils.SHA256)));
				}

				String items[] = mfContents.split("\r\n\r\n");
				if (items != null && items.length >= 1) {
					for (int i = 0; i < items.length; i++) {
						if (items[i].contains("Name:") && items[i].contains("-Digest:")) {
							MFEntry mfEntry = new MFEntry();
							String item = items[i] + "\r\n\r\n";
							mfEntry.setItems(item);
							int shaType = getShaTypeByMFFile();
							mfEntry.setItemShaBase64(Base64.encode(EncryptUtils.sha(item.getBytes(), shaType)));
							String[] oneItem = items[i].split("\r\n");
							String[] tag = oneItem[0].split(":");
							String fileName = tag[1];
							mfEntry.setFileName(fileName);

							collectMFItemsFileName.add(fileName.replace(" ", ""));// 从MF
																					// item中读取的文件名前面有空格
							String digest[] = oneItem[1].split(":");
							String digestValue = digest[1];
							mfEntry.setDigestValue(digestValue);
							set.add(mfEntry);
						}
					}
				}
			}
		}
		return set;
	}

	private Set<SFEntry> parseSFManifest(JarFile jar) throws Exception {
		Set<SFEntry> set = new HashSet<SFEntry>();
		Enumeration<java.util.jar.JarEntry> entries = jar.entries();
		while (entries.hasMoreElements()) {
			java.util.jar.JarEntry entry = entries.nextElement();
			if (entry.getName().endsWith(".SF")) {
				InputStream ios = jar.getInputStream(entry);
				byte[] b = new byte[ios.available()];
				int len = ios.read(b);
				String mfContents = new String(b, 0, len);
				String items[] = mfContents.split("\r\n\r\n");

				if (items != null && items.length >= 1) {
					for (int i = 0; i < items.length; i++) {
						if (items[i].contains("-Digest-Manifest:")) {
							String item[] = items[i].split("\r\n");
							for (int j = 0; j < item.length; j++) {
								// System.out.println("items:\n"+item[j]);
								// jsingner 创建的签名包 有五行 有-MAIN-Attributes:
								/*
								 * if(item[j].contains("Oracle Corporation")){
								 * 
								 * }else if(item[j].contains("Android")){
								 * 
								 * }
								 */
								if (item[j].contains("-Digest-Manifest")) {
									String mainfestItem[] = item[j].split(":");
									setParseMFFileShaBySF(mainfestItem[1]);
								}
							}

						} else if (items[i].contains("Digest-Manifest-Main-Attributes:")) {
							// String item[] =
							// items[i].split("\r\n");//暂时未用到该属性,apk中无此属性
						} else if (items[i].contains("Name:") && items[i].contains("-Digest:")) {
							SFEntry sfEntry = new SFEntry();
							// String item = items[i]+"\r\n\r\n";
							String[] oneItem = items[i].split("\r\n");
							String[] tag = oneItem[0].split(":");
							String fileName = tag[1];
							sfEntry.setFileName(fileName);
							// collectMFItemsFileName.add(fileName.replace(" ",
							// ""));//从MF item中读取的文件名前面有空格
							String digest[] = oneItem[1].split(":");
							String digestValue = digest[1];
							sfEntry.setFileSHAValue(digestValue);
							set.add(sfEntry);
						}
					}
				}
			}
		}
		return set;
	}

	//获取jar或apk中所有文件的摘要值
	private Set<MFEntry> getAllFilesHash(JarFile jar) throws Exception {
		Set<MFEntry> fileSet = new HashSet<MFEntry>();
		Enumeration<java.util.jar.JarEntry> entries = jar.entries();
		while (entries.hasMoreElements()) {
			java.util.jar.JarEntry entry = entries.nextElement();
			String entryName = entry.getName();

			MFEntry mf = new MFEntry();
			if (!entry.isDirectory() && !entryName.endsWith(".MF") && !entryName.endsWith(".SF")
					&& !entryName.endsWith(".RSA") && !entryName.endsWith(".DSA") && !entryName.endsWith(".EC")) {
				InputStream ios = jar.getInputStream(entry);
				byte[] b = new byte[ios.available()];
				Streams.readFully(ios, b);
				mf.setFileName(entry.getName());
				mf.setDigestValue(
						java.util.Base64.getEncoder().encodeToString(EncryptUtils.sha(b, getShaTypeByMFFile())));
				collectJarFileName.add(entry.getName());
				fileSet.add(mf);
				ios.close();
			}
		}
		return fileSet;
	}

	private Set<MFEntry> setJarfiles;
	private Set<MFEntry> setMFFile;

	// 检查jar中所有的文件是否记录在MF中
	// 检查MF记录的所有条目中是否包含jar所有的文件
	public boolean isAllFileInMFFile(JarFile jar) {
		try {
			// note: parseMFManifest ,getAllFilesHash the two funtions can be by
			// order
			setMFFile = parseMFManifest(jar);
			setJarfiles = getAllFilesHash(jar);
			if (!collectJarFileName.containsAll(collectMFItemsFileName)) {
				return false;
			} else if (!collectMFItemsFileName.containsAll(collectJarFileName)) {
				return false;
			}
		} catch (Exception e) {
			return false;
		}
		return true;
	}

	private boolean compareMFFileSha() {
		Set<String> setJarFileSha = new HashSet<>();
		Iterator<MFEntry> it = setJarfiles.iterator();
		while (it.hasNext()) {
			MFEntry mf = it.next();
			setJarFileSha.add(mf.getDigestValue());
		}
		Set<String> setMFItemSha = new HashSet<>();
		Iterator<MFEntry> ii = setMFFile.iterator();
		while (ii.hasNext()) {
			MFEntry mf = ii.next();
			setMFItemSha.add(mf.getDigestValue().replace(" ", ""));// MF中部分条目中的记录的文件SHA值前面有空格，需要去掉
		}

		if (!setJarFileSha.containsAll(setMFItemSha)) {
			return false;
		}
		return true;
	}

	private boolean compareMFFileContentSha(JarFile jar) {
		try {

			//检测jar中是否曾加或删除了文件
			boolean isFilesExist = isAllFileInMFFile(jar);
			if (!isFilesExist) {
				return false;
			}
			//将jar中所有文件哈希值与MF条目中比对
			boolean isMfHashTrue = compareMFFileSha();
			if (!isMfHashTrue) {
				return false;
			}

			Set<SFEntry> ss = parseSFManifest(jar);
			//获取SF中每个条目的BASE64哈希值
			String getMfContentShaFromSfMeta = getParseMFFileShaBySF().replace(" ", "");
		    //对MF中每个条目进行哈希再BASE64
			String getMFShaValue = getMfFileSHAValue();

			// System.out.println("getMfContentShaFromSfMeta:"+getMfContentShaFromSfMeta);
			// System.out.println("getMFShaValue:"+getMFShaValue);
			// 将MF整个文件内容的摘要值与SF文件属性中记录的摘要值比对
			if (getMfContentShaFromSfMeta != null && !getMfContentShaFromSfMeta.equalsIgnoreCase(getMFShaValue)) {
				return false;
			}
			// 将MF每个条目的摘要值与SF条目中的摘要值比对(MF中每个条目再次SHA并Base64)

			Iterator<SFEntry> it = ss.iterator();

			Set<String> sfSha = new HashSet<String>();
			while (it.hasNext()) {
				 SFEntry sf = it.next();
//				 System.out.println("getSFItemBase:"+sf.getFileSHAValue().replace(" ", ""));
				sfSha.add(sf.getFileSHAValue().replace(" ", ""));
			}
//		 System.out.println("=====================================");

			Iterator<MFEntry> im = setMFFile.iterator();
			Set<String> mfSha = new HashSet<String>();
			while (im.hasNext()) {
				MFEntry mf = im.next();
//				System.out.println("getMFItemBase:" + mf.getItemShaBase64());
				mfSha.add(mf.getItemShaBase64());
			}

			if (!sfSha.containsAll(mfSha)) {
				return false;
			}

			if (!mfSha.containsAll(sfSha)) {
				return false;
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
//			System.out.println("compareMFFileContentSha:" + e.toString());
			return false;
		}
		return true;
	}

	private SignatureBean getSpecifyFileBytes(JarFile jar) {
		Enumeration<java.util.jar.JarEntry> entries = jar.entries();
		SignatureBean sbg = new SignatureBean();
		while (entries.hasMoreElements()) {
			java.util.jar.JarEntry entry = entries.nextElement();
			String entryName = entry.getName();
			try {
				if (!entry.isDirectory()) {
					if (entryName.endsWith(".SF")) {
						InputStream ios = jar.getInputStream(entry);
						byte[] b = new byte[ios.available()];
						Streams.readFully(ios, b);
						ios.close();
						sbg.setSfFileBytes(b);
					} else if (entryName.endsWith(".RSA") || entryName.endsWith(".DSA")) {
						InputStream ios = jar.getInputStream(entry);
						byte[] b = new byte[ios.available()];
						Streams.readFully(ios, b);
						ios.close();
						sbg.setRsaFileBytes(b);
					}
				}
			} catch (Exception e) {
				return null;
			}
		}
		return sbg;
	}

	// sign CERT.RSA中的数据
	// data:CERT.SF中的数据
	private boolean verifyJarSignature(JarFile jar) throws IOException, NoSuchAlgorithmException, SignatureException,
			InvalidKeyException, CertificateException, NoSuchProviderException {
		SignatureBean sgb = getSpecifyFileBytes(jar);
		if (sgb == null) {
			return false;
		}
		PKCS7 p7 = new PKCS7(sgb.getRsaFileBytes());
		SignerInfo[] sis = p7.verify(sgb.getSfFileBytes());
		 
		if (sis == null)
			return false;
		else
			return true;
	}
	
	public boolean verifyJar( String jarFilePath){
		try {
			JarFile myJar  = new JarFile(jarFilePath,true);
			 //1.先验证RSA的数字签名是否正确
			 boolean isSignatureTrue =  verifyJarSignature(myJar);
			 if(!isSignatureTrue){
				 return false;
			 }
			 //2.检查jar中的所有文件是否存在于MF条目中
			boolean compareFileHash  = compareMFFileContentSha(myJar);
			if(!compareFileHash){
				return false;
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			return false;
		}
		return true;
	       
	}
	
}
