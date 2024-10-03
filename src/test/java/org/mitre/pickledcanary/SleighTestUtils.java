package org.mitre.pickledcanary;

import java.io.IOException;
import java.net.URL;

import org.xml.sax.SAXException;

import generic.jar.ResourceFile;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

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
			throws SAXException, IOException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {

		/* This constructor is private so we need to make it accessible before calling it */
		Constructor<SleighLanguageProvider> constructor = SleighLanguageProvider.class.getDeclaredConstructor(ResourceFile.class);
		constructor.setAccessible(true);
	    SleighLanguageProvider provider = constructor.newInstance(lDefsFile);
	    
		/* Get the SleighLanguage we just added to SleighLanguageProvider 
		 * using LanguageID from its LanguageDescription */
		return (SleighLanguage) provider.getLanguage(provider.getLanguageDescriptions()[0].getLanguageID());
	}
}
