package org.mitre.pickledcanary;

import java.io.IOException;
import java.net.URL;

import org.xml.sax.SAXException;

import generic.jar.ResourceFile;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;

public class SleighTestUtils {
	
	/* Retrieves a Sleigh resource from a filename */
	public static ResourceFile getSleighResource(String name) {
		URL url = SleighTestUtils.class.getClassLoader().getResource("sleigh/" + name);

		if (url == null) {
			return null;
		}
		
		return new ResourceFile(url.getPath());
	}
	
	/* Quickly create a SleighLanguage instance from .ldefs */
	public static SleighLanguage lazyLanguage(ResourceFile lDefsFile) 
			throws SAXException, IOException {
		
		/* Constructor is normally only visible in its package, had to edit Ghidra source */
		SleighLanguageProvider provider = new SleighLanguageProvider(lDefsFile);
		
		/* Get the SleighLanguage we just added to SleighLanguageProvider 
		 * using LanguageID from its LanguageDescription */
		return (SleighLanguage) provider.getLanguage(provider.getLanguageDescriptions()[0].getLanguageID());
	}
}
