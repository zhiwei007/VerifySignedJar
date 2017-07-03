package com.verify.jarfile;
import java.io.IOException;
import java.io.InputStream;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;


public class VerifyJarDemo  extends JarInputStream{

	public VerifyJarDemo(InputStream in) throws IOException {
		super(in);
	}
   
	
	
	
	public static void main(String[] args)   {
			
		    try
		    {
//		     String jarPath = "c:\\ICBCBT4.0Sample.apk";
		      String jarPath = "f:\\ftABCBnk_signed.jar";
		       boolean isTampered =  VerifyJarHelper.getInstance().verifyJar(jarPath);
		       System.out.println(""+(isTampered?"No tampered!":"May be tampered!"));
		    } catch (Exception ioe){
		        System.out.println("JarFile is not exist!");
		    }
	}
	
	

 
}
