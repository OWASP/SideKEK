/*
  Copyright 2019 IBM Corp. All Rights Reserved.

  SPDX-License-Identifier: Apache-2.0
*/

package com.ibm.eht.sidekek;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * SideKEK security provider unit tests.
 * 
 * @author Dmitriy Beryoza
 * @author Ron Craig
 */
public class SideKEKTest {

	@Test
	public void testRandomNames() {
		
		for (int i = 0; i < 100; i++) {
			for (int j = 0; j < 10; j++) {
				String str = SideKEK.getRandomAlphanumericString(i);
				for (int x = 0; x < str.length(); x++) {
					
					assertEquals("Size is not the expected value", i, str.length());
					char c = str.charAt(x);
					if (((c >= 'a') && (c <= 'z')) ||
					    ((c >= 'A') && (c <= 'Z')) ||
						((c >= '0') && (c <= '9')) ||
						(c == '-') || (c == '_')) {
						continue;
					}
					fail("String is not fully alphanumeric: " + str);
				}
			}
		}
	}

}
