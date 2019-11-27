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
import java.io.OutputStream;
import java.nio.ByteBuffer;
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
import java.util.Properties;

import javax.crypto.spec.SecretKeySpec;

/**
 * Timestamp-based keystore implementation. 
 * 
 * @author Dmitriy Beryoza
 * @author Ron Craig
 */
public class TimestampKeyStoreSpi extends KeyStoreSpi {

	/*
	 * Names of parameters in proerty file.
	 */
	private static final String PROP_KEY_SIZE = "KeySize";
	private static final String PROP_KEY_SEGMENT_POSITION = "KeySegmentPosition";
	private static final String PROP_KEY_SEGMENT_SIZE = "KeySegmentSize";
	private static final String PROP_KEY_ALGORITHM = "Algorithm";
	
	/**
	 * Current key map.
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
		
		// Check the parameter type
		if (!(param instanceof TimestampKeyStoreParameter)) {
			throw new InvalidParameterException("Expecting an instance of " + TimestampKeyStoreParameter.class.getName());
		}
		
		TimestampKeyStoreParameter kParam = (TimestampKeyStoreParameter)param;
		
		// Make sure we are dealing with a writeable folder
		File baseFolder = kParam.getBaseFolder();
		
		if (!baseFolder.exists() || !baseFolder.isDirectory() || !baseFolder.canWrite()) {
			throw new InvalidParameterException("Writable base folder " + kParam.getBaseFolder().getCanonicalPath() + " does not exist");
		}
		
		// Find existing keys in the folder
		File[] keys = baseFolder.listFiles(new FilenameFilter() {
		    public boolean accept(File dir, String name) {
		        return name.endsWith(TimestampKeyStoreParameter.DEFAULT_KEY_FILE_EXTENSION);
		    }
		});

		//...and delete them all
		for (int i = 0; i < keys.length; i++) {
			try {
				keys[i].delete(); 
			} catch (Exception ex) {
				throw new IllegalStateException("Error deleting key file " + keys[i].getName(), ex);
			}
		}
		
		for (String alias : keyMap.keySet()) {
			
			Key key = keyMap.get(alias);
			
			// Prepare properties for the key
			Properties props = new Properties();
			props.setProperty(PROP_KEY_SIZE, Integer.toString(key.getEncoded().length));
			props.setProperty(PROP_KEY_SEGMENT_POSITION, Integer.toString(kParam.getKeySegmentPosition()));
			props.setProperty(PROP_KEY_SEGMENT_SIZE, Integer.toString(kParam.getKeySegmentSize()));
			props.setProperty(PROP_KEY_ALGORITHM, key.getAlgorithm());
			
			// Figure out the number of files necessary to store the key
			int numFiles = key.getEncoded().length / kParam.getKeySegmentSize();
			if (key.getEncoded().length % kParam.getKeySegmentSize() != 0) {
				numFiles++;
			}
			
			// Store the key over required set of files
			for (int i = 0; i < numFiles; i++) {
				
				// Prepare name in the form <alias>-<fileNumber>-<uniqueName>.key
				File aliasFile = new File(baseFolder, String.format("%s-%d-%s%s", alias, i, 
						SideKEK.getRandomAlphanumericString(kParam.getRandomNameLength()), 
						TimestampKeyStoreParameter.DEFAULT_KEY_FILE_EXTENSION));
				
				try {
					// Store properties in the first file
					if (i == 0) {
						FileOutputStream file = new FileOutputStream(aliasFile); 
						
						props.store(file, null);
			            
			            file.close();
					} else {
						// Just create empty files for the rest
						aliasFile.createNewFile();
					}					
					
					// Inject key bytes into the timestamp
					aliasFile.setLastModified(embedKeySegment(key.getEncoded(), i, kParam.getKeySegmentPosition(), kParam.getKeySegmentSize()));
				} catch (Exception ex) {
					throw new IllegalStateException("Error writing key for alias " + alias, ex);
				}
			}
			
		}
	}
	
	/**
	 * Inject key bytes into the timestamp.
	 * 
	 * @param key Key byte array.
	 * @param fileNo Number of the file we are dealing with.
	 * @param segPos Position of the byte in the timestamp (lowest significant byte is 0).
	 * @param segSize Number of bytes to store in the timestamp.
	 * @return
	 */
	private long embedKeySegment(byte[] key, int fileNo, int segPos, int segSize) {

		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		// Get the current timestamp, we will give files timestamps that are in reasonable vicinity of the current time 
		long timestamp = System.currentTimeMillis();
		
		// Put timestamp into a buffer for easier handling
	    buffer.putLong(timestamp);

		for (int i = 0; i < segSize; i++) {
			
			int keyBytePos = fileNo * segSize + i;
			// Check if we ran out of key bytes
			if (keyBytePos >= key.length) {
				break;
			}
			
			// Set the key byte into the right position in the timestamp
			buffer.put(7 - (segPos + i), key[keyBytePos]);
		}
		
		buffer.flip(); 
		
		// Return updated timestamp
	    return buffer.getLong();
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

		// Make sure we are supplied the right parameter type
		if (!(param instanceof TimestampKeyStoreParameter)) {
			throw new InvalidParameterException("Expecting an instance of " + TimestampKeyStoreParameter.class.getName());
		}
		
		TimestampKeyStoreParameter kParam = (TimestampKeyStoreParameter)param;
		
		// Check if we are given a writeable base folder
		File baseFolder = kParam.getBaseFolder();
		
		if (!baseFolder.exists() || !baseFolder.isDirectory() || !baseFolder.canWrite()) {
			throw new InvalidParameterException("Writable base folder " + kParam.getBaseFolder().getCanonicalPath() + " does not exist");
		}
		
		// FInd all key files
		File[] matchingFiles = baseFolder.listFiles(new FilenameFilter() {
		    public boolean accept(File dir, String name) {
		        return name.endsWith(TimestampKeyStoreParameter.DEFAULT_KEY_FILE_EXTENSION);
		    }
		});

		HashMap<String,HashMap<String, File>> keyFilesMap = new HashMap<String,HashMap<String, File>>(); 
		
		for (File f : matchingFiles) {
			
			// Split each file name into sections
			String[] nameParts = f.getName().split("-");
			
			// Build a map of alias -> fileIDs -> files
			HashMap<String, File> aliasFiles = keyFilesMap.get(nameParts[0]);
			
			if (aliasFiles == null) {
				aliasFiles = new HashMap<String, File>();
				keyFilesMap.put(nameParts[0], aliasFiles);
			}
			
			aliasFiles.put(nameParts[1], f);
		}
		
		for (String alias : keyFilesMap.keySet()) {

			// Process each alias separately
			HashMap<String, File> aliasFiles = keyFilesMap.get(alias);
			
			try {
				// Load and process properties
				FileInputStream propFile = new FileInputStream(aliasFiles.get("0")); 
				
				Properties props = new Properties();
				props.load(propFile);
	            
	            propFile.close();	            
	            
				int keySize = Integer.parseInt(props.getProperty(PROP_KEY_SIZE));
				int keySegPos = Integer.parseInt(props.getProperty(PROP_KEY_SEGMENT_POSITION));
				int keySegSize = Integer.parseInt(props.getProperty(PROP_KEY_SEGMENT_SIZE));

				// What is the total expected number of files?
				int numFiles = keySize / keySegSize;
				if (keySize % keySegSize != 0) {
					numFiles++;
				}
				byte[] keyBytes = new byte[keySize];
				
				for (int i = 0; i < numFiles; i++) {
					
					// Get the timestamp for each file
					long timestamp = aliasFiles.get(Integer.toString(i)).lastModified();
					
					// Extract key bytes and store them into an array
					for (int j = 0; j < keySegSize; j++) {
						int keyBytePos = i * keySegSize + j;
						if (keyBytePos >= keySize) {
							break;
						}
						
						keyBytes[keyBytePos] = (byte)((timestamp >> ((keySegPos + j) * 8)) & 0xFF);
					}
				}
				
				// Build and store the key
				keyMap.put(alias, new SecretKeySpec(keyBytes, props.getProperty(PROP_KEY_ALGORITHM)));

			} catch (Exception ex) {
				throw new IllegalStateException("Error reading key file for alias " + alias, ex);
			}			
		}
	}

	/**
	 * Keystore creation parameters.
	 * 
	 */
	public static class TimestampKeyStoreParameter implements KeyStore.LoadStoreParameter {

		/**
		 * Default position of the key bytes in the timestamp. On some platforms (e.g. macOS) the 
		 * millisecond portion of the timestamp is not reliable (see {@link java.io.File#setLastModified(long)})
		 * so we will use the second portion of the timestamp.
		 */
		public static final int DEFAULT_KEY_SEGMENT_POSITION = 2;
		
		/**
		 * Default number of bytes to use from timestamp. We do not want to use too broad a range in order not to have an 
		 * unreasonable timestamp (too far in the past or the future).
		 */
		public static final int DEFAULT_KEY_SEGMENT_SIZE = 2;
		
		/**
		 * Default length of the random protion of the file name.
		 */
		public static final int DEFAULT_RANDOM_NAME_LENGTH = 16;
		
		/**
		 * Default file extension.
		 */
		public static final String DEFAULT_KEY_FILE_EXTENSION = ".key";
		
		private File baseFolder;
		private int keySegPos;
		private int keySegSize;
		private int randomNameLength;
		
		/**
		 * Constructor.
		 * 
		 * @param folder Base folder.
		 * @param segPos Position of the key bytes in timestamp.
		 * @param segSize Number of the key bytes in timestamp.
		 * @param nameLength Length of the random portion of the name.
		 */
		public TimestampKeyStoreParameter(File folder, int segPos, int segSize, int nameLength) {
			baseFolder = folder;
			keySegPos = segPos;
			keySegSize = segSize;
			randomNameLength = nameLength;
		}
		
		/**
		 * Constructor.
		 * 
		 * @param folder Base folder.
		 */
		public TimestampKeyStoreParameter(File folder) {
			this(folder, DEFAULT_KEY_SEGMENT_POSITION, DEFAULT_KEY_SEGMENT_SIZE, DEFAULT_RANDOM_NAME_LENGTH);
		}

		/**
		 * Returns base folder.
		 * 
		 * @return Base folder.
		 */
		public File getBaseFolder() {
			return baseFolder;
		}
		
		/**
		 * Returns position of the key bytes in timestamp.
		 * 
		 * @return Position of the key bytes in timestamp.
		 */
		public int getKeySegmentPosition() {
			return keySegPos;
		}
		
		/**
		 * Returns number of the key bytes in timestamp.
		 * @return Number of the key bytes in timestamp.
		 */
		public int getKeySegmentSize() {
			return keySegSize;
		}
		
		/**
		 * Returns length of the random portion of the name.
		 * 
		 * @return Length of the random portion of the name.
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
