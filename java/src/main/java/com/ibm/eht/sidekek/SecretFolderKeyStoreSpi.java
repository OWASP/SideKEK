/*
  Copyright 2019 IBM Corp. All Rights Reserved.

  SPDX-License-Identifier: Apache-2.0
*/

package com.ibm.eht.sidekek;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.KeyStore.ProtectionParameter;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;

import javax.crypto.SecretKey;

/*
 * Secret folder keystore implementation.
 * 
 * @author Dmitriy Beryoza
 * @author Ron Craig
 */
public class SecretFolderKeyStoreSpi extends KeyStoreSpi {

	/**
	 * Map that holds known keys.
	 */
	private HashMap<String,Key> keyMap = new HashMap<String,Key>();
	
	@Override
	public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
		return keyMap.get(alias);
	}

	@Override
	public Certificate[] engineGetCertificateChain(String alias) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Certificate engineGetCertificate(String alias) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Date engineGetCreationDate(String alias) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
			throws KeyStoreException {
		keyMap.put(alias, key);
	}

	@Override
	public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void engineDeleteEntry(String alias) throws KeyStoreException {
		keyMap.remove(alias);
	}

	@Override
	public Enumeration<String> engineAliases() {		
		return Collections.enumeration(keyMap.keySet());
	}

	@Override
	public boolean engineContainsAlias(String alias) {
		return keyMap.containsKey(alias);
	}

	@Override
	public int engineSize() {
		return keyMap.size();
	}

	@Override
	public boolean engineIsKeyEntry(String alias) {
		return keyMap.containsKey(alias);
	}

	@Override
	public boolean engineIsCertificateEntry(String alias) {
		return false;
	}

	@Override
	public String engineGetCertificateAlias(Certificate cert) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void engineStore(OutputStream stream, char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		throw new UnsupportedOperationException();
	}

	@Override 
    public void engineStore(KeyStore.LoadStoreParameter param)
            throws IOException, NoSuchAlgorithmException,
            CertificateException {
		
		// Verify parameter type
		if (!(param instanceof SecretFolderKeyStoreParameter)) {
			throw new InvalidParameterException("Expecting an instance of " + SecretFolderKeyStoreParameter.class.getName());
		}
		
		SecretFolderKeyStoreParameter kParam = (SecretFolderKeyStoreParameter)param;
		
		// Make sure we have a writable base folder defined
		File baseFolder = kParam.getBaseFolder();
		
		if (!baseFolder.exists() || !baseFolder.isDirectory() || !baseFolder.canWrite()) {
			throw new InvalidParameterException("Writable base folder " + kParam.getBaseFolder().getCanonicalPath() + " does not exist");
		}
		
		// Look for a single folder with specific prefix 
		File[] matchingFiles = baseFolder.listFiles(new FilenameFilter() {
		    public boolean accept(File dir, String name) {
		        return name.startsWith(kParam.getFolderNamePrefix());
		    }
		});
		
		if (matchingFiles.length > 1) {
			throw new IllegalStateException("More than one entity with prefix '" + kParam.getFolderNamePrefix() + "' found");
		}
		
		File keyFolder;
		
		if (matchingFiles.length == 0) {
			
			// Create a folder is one is not found
			keyFolder = new File(kParam.getBaseFolder(), kParam.getFolderNamePrefix() + SideKEK.getRandomAlphanumericString(kParam.getRandomNameLength()));
			
			boolean created = keyFolder.mkdir();
			
			if (!created) {
				throw new IllegalStateException("Unable to create keystore folder");
			}
			
		} else {
			
			if (!matchingFiles[0].isDirectory()) {
				throw new IllegalStateException("Expecting the entity with prefix '" + kParam.getFolderNamePrefix() + "' to be a folder");
			}
			
			keyFolder = matchingFiles[0];
			
			// Find all stored key files
			File[] keys = keyFolder.listFiles(new FilenameFilter() {
			    public boolean accept(File dir, String name) {
			        return name.endsWith(SecretFolderKeyStoreParameter.DEFAULT_KEY_FILE_EXTENSION);
			    }
			});

			// Delete all key files, we will store keys from memory
			for (int i = 0; i < keys.length; i++) {
				try {
					keys[i].delete(); 
				} catch (Exception ex) {
					throw new IllegalStateException("Error deleting key file " + keys[i].getName(), ex);
				}
			}
		}
		
		for (String alias : keyMap.keySet()) {
			// Store each key serialized in a file "<alias>.key" where <alias> is the name of the key
			File aliasFile = new File(keyFolder, alias + SecretFolderKeyStoreParameter.DEFAULT_KEY_FILE_EXTENSION);
			try {
				FileOutputStream file = new FileOutputStream(aliasFile); 
	            ObjectOutputStream out = new ObjectOutputStream(file); 
	              
	            out.writeObject(keyMap.get(alias)); 
	            
	            out.close(); 
	            file.close();
			} catch (Exception ex) {
				throw new IllegalStateException("Error writing key for alias " + alias, ex);
			}
		}
	}
	
	@Override
	public void engineLoad(InputStream stream, char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		throw new UnsupportedOperationException();
	}
	
	@Override 
    public void engineLoad(KeyStore.LoadStoreParameter param)
            throws IOException, NoSuchAlgorithmException,
            CertificateException {
		
		keyMap.clear();
		
		// Verify parameter type
		if (!(param instanceof SecretFolderKeyStoreParameter)) {
			throw new InvalidParameterException("Expecting an instance of " + SecretFolderKeyStoreParameter.class.getName());
		}
		
		SecretFolderKeyStoreParameter kParam = (SecretFolderKeyStoreParameter)param;
		
		// Make sure a writable base folder is specified
		File baseFolder = kParam.getBaseFolder();
		
		if (!baseFolder.exists() || !baseFolder.isDirectory() || !baseFolder.canWrite()) {
			throw new InvalidParameterException("Writable base folder " + kParam.getBaseFolder().getCanonicalPath() + " does not exist");
		}
		
		File[] matchingFiles = baseFolder.listFiles(new FilenameFilter() {
		    public boolean accept(File dir, String name) {
		        return name.startsWith(kParam.getFolderNamePrefix());
		    }
		});
		
		if (matchingFiles.length > 1) {
			throw new IllegalStateException("More than one entity with prefix '" + kParam.getFolderNamePrefix() + "' found");
		}		
		
		if (matchingFiles.length == 1) {
			
			if (!matchingFiles[0].isDirectory()) {
				throw new IllegalStateException("Expecting the entity with prefix '" + kParam.getFolderNamePrefix() + "' to be a folder");
			}
			
			// Find all key files
			File[] keys = matchingFiles[0].listFiles(new FilenameFilter() {
			    public boolean accept(File dir, String name) {
			        return name.endsWith(SecretFolderKeyStoreParameter.DEFAULT_KEY_FILE_EXTENSION);
			    }
			});
			
			// Deserialize each key from a file
			for (int i = 0; i < keys.length; i++) {
				try {
					FileInputStream keyFile = new FileInputStream(keys[i]); 
		            ObjectInputStream in = new ObjectInputStream(keyFile); 
		              
		            SecretKey key = (SecretKey)in.readObject(); 
		            
		            String keyAlias = keys[i].getName().substring(0, keys[i].getName().length() - SecretFolderKeyStoreParameter.DEFAULT_KEY_FILE_EXTENSION.length()); 
		            
		            keyMap.put(keyAlias, key);
		            
		            in.close(); 
		            keyFile.close();
				} catch (Exception ex) {
					keyMap.clear();
					throw new IllegalStateException("Error reading key file " + keys[i].getName(), ex);
				}
			}
		}
	}

	
	/**
	 * Keystore creation parameters. 
	 *
	 */
	public static class SecretFolderKeyStoreParameter implements KeyStore.LoadStoreParameter {

		/**
		 * Default folder name prefix.
		 */
		public static final String DEFAULT_FOLDER_NAME_PREFIX = "kek";
		
		/**
		 * Default unique folder name portion length.
		 */
		public static final int DEFAULT_RANDOM_NAME_LENGTH = 32;
		
		/**
		 * Default key file extension.
		 */
		public static final String DEFAULT_KEY_FILE_EXTENSION = ".key";
		
		private File baseFolder;
		private String folderNamePrefix;
		private int randomNameLength;
		
		/**
		 * Constructor.
		 * 
		 * @param folder Base folder.
		 * @param namePrefix Folder name prefix.
		 * @param nameLength Unique file name portion length.
		 */
		public SecretFolderKeyStoreParameter(File folder, String namePrefix, int nameLength) {
			baseFolder = folder;
			folderNamePrefix = namePrefix;
			randomNameLength = nameLength;
		}
		
		/**
		 * Constructor.
		 * 
		 * @param folder Base folder.
		 */
		public SecretFolderKeyStoreParameter(File folder) {
			this(folder, DEFAULT_FOLDER_NAME_PREFIX, DEFAULT_RANDOM_NAME_LENGTH);
		}
		
		/**
		 * Returns base folder to create files in.
		 * 
		 * @return Base folder
		 */
		public File getBaseFolder() {
			return baseFolder;
		}
		
		/**
		 * Returns prefix string to use in the folder name.
		 * 
		 * @return Name prefix.
		 */
		public String getFolderNamePrefix() {
			return folderNamePrefix;
		}
		
		/**
		 * Returns length of the random portion of the folder name.
		 * 
		 * @return Length of the random portion of the folder name.
		 */
		public int getRandomNameLength() {
			return randomNameLength;
		}
		
		@Override
		public ProtectionParameter getProtectionParameter() {
			return null;
		}		
	}
}
