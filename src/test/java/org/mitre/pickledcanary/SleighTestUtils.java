package org.mitre.pickledcanary;

import java.io.IOException;
import java.net.URL;
import java.util.*;

import org.antlr.runtime.RecognitionException;
import org.xml.sax.SAXException;

import generic.jar.ResourceFile;
import ghidra.app.plugin.processors.sleigh.SleighCompilerSpecDescription;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcodeCPort.slgh_compile.SleighCompileLauncher;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.DecoderException;


public class SleighTestUtils {
	
	/* Retrieves a Sleigh resource from a filename */
	public static ResourceFile getSleighResource(String name) {
		URL url = SleighTestUtils.class.getClassLoader().getResource("sleigh/" + name);

		if (url == null) {
			return null;
		}
		
		return new ResourceFile(url.getPath());
	}
	
	/* Compile the .slaspec and return .sla resource
	 * Returns null if .slaspec can't be located */
	public static ResourceFile compileSlaSpec(ResourceFile slaSpecFile) 
			throws DecoderException, UnknownInstructionException, SAXException, IOException {
		
		if (slaSpecFile == null) {
			return null;
		}
		
		try {
			SleighCompileLauncher.runMain(new String[] { slaSpecFile.getAbsolutePath() });
		}
		catch (IOException | RecognitionException e) {
			throw new AssertionError(e);
			
		}
		String slaSpecFileName = slaSpecFile.getName();
		String slaFileName = slaSpecFileName.substring(0, slaSpecFileName.lastIndexOf('.')) + ".sla";
		ResourceFile slaFile = getSleighResource(slaFileName);
		
		return slaFile;
	}
	
	/* Quickly create a SleighLanguage instance from minimal arguments */
	public static SleighLanguage lazyLanguage(String langName, Endian endian, int size) 
			throws DecoderException, UnknownInstructionException, SAXException, IOException {

		/* TODO: check if these actually exist */
		ResourceFile cSpecFile = getSleighResource(langName + ".cspec");
		ResourceFile lDefsFile = getSleighResource(langName + ".ldefs");
		ResourceFile pSpecFile = getSleighResource(langName + ".pspec");
		ResourceFile slaSpecFile = getSleighResource(langName + ".slaspec");
		
		CompilerSpecDescription cSpecDesc =
			new SleighCompilerSpecDescription(new CompilerSpecID("default"), "default", cSpecFile);
		
		ResourceFile slaFile = compileSlaSpec(slaSpecFile);
		
		SleighLanguageDescription langDesc = new SleighLanguageDescription(
			new LanguageID(langName + ":"+ endian.toShortString() +":" + size + ":default"), langName,
			Processor.findOrPossiblyCreateProcessor(langName), endian, // endian
			endian, // instructionEndian
			size, "default", // variant
			0, // major version
			0, // minor version
			false, // deprecated
			new HashMap<>(), // truncatedSpaceMap
			new ArrayList<>(List.of(cSpecDesc)), new HashMap<>() // externalNames
		);
		
		langDesc.setDefsFile(lDefsFile);
		langDesc.setSpecFile(pSpecFile);
		langDesc.setSlaFile(slaFile);
		
		/* constructor is normally package scope, had to edit Ghidra source */
		return new SleighLanguage(langDesc);
	}
}
