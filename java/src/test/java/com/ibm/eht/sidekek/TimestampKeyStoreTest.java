/*
  Copyright 2019 IBM Corp. All Rights Reserved.

  SPDX-License-Identifier: Apache-2.0
*/

package com.ibm.eht.sidekek;

import java.io.File;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.security.KeyStore.LoadStoreParameter;
import java.util.Arrays;

import javax.crypto.spec.SecretKeySpec;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * Timestamp-based keystore unit tests.
 * 
 * @author Dmitriy Beryoza
 * @author Ron Craig
 */
public class TimestampKeyStoreTest {

	@Rule
    public TemporaryFolder baseFolder = new TemporaryFolder();


	@Test
	public void testFullCycle() throws Exception {
		Security.addProvider(new SideKEK());
		
		KeyStore ks = KeyStore.getInstance(SideKEK.TIMESTAMP_KEYSTORE);
		
		File folder = new File(baseFolder.getRoot(), "secretFolderTest");
		folder.mkdir();
		
		LoadStoreParameter param = new TimestampKeyStoreSpi.TimestampKeyStoreParameter(folder); 
		
		ks.load(param);
		
		Key key1 = new SecretKeySpec("testkey1".getBytes(), "AES");
		Key key2 = new SecretKeySpec("testkey2testkey2testkey2testkey2t".getBytes(), "AES");
		
		ks.setKeyEntry("key1", key1, null, null);
		ks.setKeyEntry("key2", key2, null, null);
		
		ks.store(param);

		ks.load(param);

		assert(ks.size() == 2);
		assert(Arrays.equals(ks.getKey("key1", null).getEncoded(), key1.getEncoded()));
		assert(Arrays.equals(ks.getKey("key2", null).getEncoded(), key2.getEncoded()));
	}
}
