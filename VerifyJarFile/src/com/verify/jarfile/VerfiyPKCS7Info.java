package com.verify.jarfile;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;

public class VerfiyPKCS7Info {
	/**
	 * 主函数
	 * 
	 * @param args
	 */
	
	public static byte[] hexString2Bytes(String hex) {
		return String2Bytes(hex, 16);
	}

	public static byte[] String2Bytes(String str) {
		return String2Bytes(str, 10);
	}

	private static byte[] String2Bytes(String str, int digit) {
		// Adding one byte to get the right conversion
		// values starting with "0" can be converted
		byte[] bArray = new BigInteger("10" + str, digit).toByteArray();

		// Copy all the REAL bytes, not the "first"
		byte[] ret = new byte[bArray.length - 1];
		for (int i = 0; i < ret.length; i++) {
			ret[i] = bArray[i + 1];
		}

		return ret;
	}
	public static void main(String[] args) {
		String PKCS7info = "3082052c06092a864886f70d010702a082051d30820519020101310f300d06096086480165030402010500300b06092a864886f70d010701a082035f3082035b30820243a0030201020204489a7780300d06092a864886f70d01010b0500305e310b3009060355040613023836310b3009060355040813026864310b300906035504071302626a310f300d060355040a1306667473616665310f300d060355040b1306667473616665311330110603550403130a77616e677a6869776569301e170d3137303632303130333433395a170d3237303631383130333433395a305e310b3009060355040613023836310b3009060355040813026864310b300906035504071302626a310f300d060355040a1306667473616665310f300d060355040b1306667473616665311330110603550403130a77616e677a686977656930820122300d06092a864886f70d01010105000382010f003082010a0282010100dc1122cdac977fb8773f1a7d998004a48d7de7799f484d70cbda66fa69377ba11896b5184e96f1af7413e6ef28c6b3bca3787635a2f0737769725150e652828106ca88b1bcd741a35803a01b4a5451c06dc7fa7f2fc92cd9d6fd09905cc3fac7dd9b6655bd7a1aa92ebd8813df1223e95fb5827f49e2aff03a50edb0aa4826ffd068064278068dc88b030f47aa270a7b414b71b82a681ce6227a989f2558c73f2c2cfe1640b99a106e32de483fc018e438d8d1baad8085a5b9198b432669d21b73a30feb3ef56fa6b120e10b42651ab6d664f78e76ca69db462dfce55e658b9b3da3486616538bf7868c46af053355dcac47a60ad0766331cba9d32a9b936bff0203010001a321301f301d0603551d0e0416041445ef08e42949254b072238721ff8c3130c1964a2300d06092a864886f70d01010b05000382010100ac68b89eb399b37faef758bf57b64f20ada27ff253c7b813978933f64fa0d6c9aa0345c20b96567cb43ee696802e11253fcef3c456966e1ddd76e1441907d95f038ca7f2934f69fe578b2485227a7c28f07d2f3ae41e107c553966029759a85c0917c8be69aa7f2ac1722426a3d8efb95bb2f07fb1db89e365bb6113698028768121663f090f9543575a394f368358bcb7171957d7abda2f6c93294a9d4e2fa8a017a70e25acbcaec0689c162d322f46400f1d9289a0bca21b45568a20a759617dd6bc99671af75d11b660e3bc087c6715af1017e3a1a736b4e1e5016f4549ee1b68e05c4edd491c8ae780fb01bfb192696ad5996ceb796af1ed2bf0996a04c2318201913082018d0201013066305e310b3009060355040613023836310b3009060355040813026864310b300906035504071302626a310f300d060355040a1306667473616665310f300d060355040b1306667473616665311330110603550403130a77616e677a68697765690204489a7780300d06096086480165030402010500300d06092a864886f70d0101010500048201009a904f7ef0d62ecc1c28ac5bae735f65d933b2da5bd4dff3a0f5d7a444e1ffc7c27dabc234fc647a4e96a9bdc0d1f59dfc3d8c32f67bb5922d3841f898e64c3b69859cb40df42e7b5516639b7da3061bf4db7f3dd140c89fbc9e1b906ff9aad6fe055237a39e7442233fdf4fdbb2951f4c13254869d585307f3ff4a0c44a15a688e4c87d15c645a21acf264797ddfd5d755c36d49e0e3eae13883b263d76696ebe485990ffcebdb641d96207539e281363b679bc744f698a8f55ed58610a05ffd01f696e81f4a1bfb1de84908fe0cb0cfb1a7afb2fb37f0aad309a43a6eb684fab448f0428d643270ffc215f0ea723ff81834c303728f29f61d17c58efa66d45";
//		byte[] rsa = HexUtil.hexStringToBytes(rsaContent);
		String dn = "CN=wangzhiwei, OU=ftsafe, O=ftsafe, L=bj, ST=hd, C=86";
		try {
			File f =  new File("F:\\ftABCBank_signed\\META-INF\\CHUANGXI.SF");
			InputStream is = new FileInputStream(f);
			byte[] b = new byte[is.available()];
			is.read(b);
			
			 
			verify(hexString2Bytes(PKCS7info), b);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("verify success!");
	}
	

	public static void verify(byte[] sign, byte[] data)
			throws IOException, NoSuchAlgorithmException, SignatureException,
			InvalidKeyException, CertificateException, NoSuchProviderException {

		PKCS7 p7 = new PKCS7(sign);
		SignerInfo[] sis = p7.verify(data);

		// check the results of the verification
		if (sis == null)
			throw new SignatureException("Signature failed verification, data has been tampered");
 /*		for (int i = 0; i < sis.length; i++) {
			SignerInfo si = sis[i];
			X509Certificate cert = si.getCertificate(p7);
			// 证书是否过期验证，如果不用系统日期可用cert.checkValidity(date);
			cert.checkValidity();
			// if (!cert.equals(rootCertificate)) {
			// //验证证书签名
			// cert.verify(rootCertificate.getPublicKey());
			// }
			// 验证dn
			if (i == 0 && dn != null) {
				X500Principal name = cert.getSubjectX500Principal();
				if (!dn.equals(name.getName(X500Principal.RFC1779))
						&& !new X500Principal(dn).equals(name))
					throw new SignatureException("Signer dn '"
							+ name.getName(X500Principal.RFC1779)
							+ "' does not matchs '" + dn + "'");
			}
		} */
	}
	
	 
	/**
	 * 从hex string生成公钥
	 * 
	 * @param stringN
	 * @param stringE
	 * @return 构造好的公钥
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PublicKey createPublicKey(String stringN, String stringE)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		try {
			BigInteger N = new BigInteger(stringN, 16); // hex base
			BigInteger E = new BigInteger(stringE, 16); // hex base

			RSAPublicKeySpec spec = new RSAPublicKeySpec(N, E);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(spec);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * 从hex string 生成私钥
	 * 
	 * @param stringN
	 * @param stringD
	 * @return 构造好的私钥
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PrivateKey createPrivateKey(String stringN, String stringD)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		try {
			BigInteger N = new BigInteger(stringN, 16); // hex base
			BigInteger D = new BigInteger(stringD, 16); // hex base

			RSAPrivateKeySpec spec = new RSAPrivateKeySpec(N, D);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(spec);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * 用公钥加密信息
	 * 
	 * @param message
	 * @param key
	 * @return 加密后的密文
	 */
	public static byte[] encrypt(String message, PublicKey key) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] data = cipher.doFinal(message.getBytes());
			return data;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return new byte[1];
	}

	/**
	 * 用公钥解密信息
	 * 
	 * @param cipherText
	 * @param key
	 * @return 解密后的明文
	 */
	public static byte[] decrypt(byte[] cipherText, PublicKey key) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, key);
			return cipher.doFinal(cipherText);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return cipherText;
	}
}