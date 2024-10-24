// Copyright (C) 2024 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.utils;

import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.app.plugin.processors.sleigh.ContextCache;
import ghidra.asm.wild.WildOperandInfo;
import ghidra.asm.wild.sem.WildAssemblyResolvedPatterns;
import ghidra.program.model.lang.DisassemblerContextAdapter;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;

import org.mitre.pickledcanary.PickledCanary;
import org.mitre.pickledcanary.patterngenerator.output.steps.*;
import org.mitre.pickledcanary.util.PCAssemblerUtils;
import org.mitre.pickledcanary.util.PCBytes;

import java.util.List;
import java.util.Set;

/**
 * Utility class for building up {@link LookupStep} objects from resolved assembly patterns.
 */
public class LookupStepBuilder {
	private final AllLookupTables tables;
	private final LookupStep lookupStep;

	/**
	 * Create a new instance of this builder.
	 * @param tables reference to the lookup tables so they can be updated as patterns are parsed.
	 */
	public LookupStepBuilder(LookupStep lookupStep, AllLookupTables tables) {
		this.tables = tables;
		this.lookupStep = lookupStep;
	}

	/**
	 * Add a resolved assembly pattern to the LookupStep.
	 * @param pats the resolved assembly pattern
	 * @return this builder.
	 */
	public LookupStepBuilder addAssemblyPattern(WildAssemblyResolvedPatterns pats, RegisterValue context) {
		AssemblyPatternBlock assemblyPatternBlock = pats.getInstruction();
		Set<WildOperandInfo> operandInfos = pats.getOperandInfo();

		if (PickledCanary.DEBUG) {
			System.err.println("assemblyPatternBlock = " + assemblyPatternBlock);
		}
		AssemblyPatternBlock noWildcardMask =
				PCAssemblerUtils.getNoWildcardMask(operandInfos, assemblyPatternBlock);
		if (PickledCanary.DEBUG) {
			System.err.println("noWildcardMask = " + noWildcardMask);
		}
		if (noWildcardMask == null)
			return this;

		List<Integer> noWildcardMaskList = PCBytes.integerList(noWildcardMask.getMaskAll());

		// build data instruction for json
		// lookup step mask exists
		if (lookupStep.hasMask(noWildcardMaskList)) {
			Data data = lookupStep.getData(noWildcardMaskList);
			if (data instanceof LookupData lookupData) {
				// if InstructionEncoding does not exist, make one
				if (!lookupData.hasChoice(noWildcardMask.getValsAll())) {
					InstructionEncoding ie = new InstructionEncoding(noWildcardMask.getValsAll());
					lookupData.putChoice(noWildcardMask.getValsAll(), ie);
				}
				lookupStep.putData(noWildcardMaskList, lookupData);
			}
		}
		else {
			// no LookupData or InstructionEncoding -- make both
			InstructionEncoding ie = new InstructionEncoding(noWildcardMask.getValsAll());
			LookupData lookupData = new LookupData(noWildcardMask.getMaskAll());
			lookupData.putChoice(noWildcardMask.getValsAll(), ie);
			lookupStep.putData(noWildcardMaskList, lookupData);
		}

		for (WildOperandInfo assemblyOperandData : operandInfos) {
			if (assemblyOperandData.wildcard().compareTo(PCAssemblerUtils.WILDCARD) == 0) {
				continue;
			}

			List<Integer> wildcardMask =
					PCBytes.integerList(assemblyOperandData.location().getMaskAll());

			while (wildcardMask.size() < assemblyPatternBlock.length()) {
				wildcardMask.add(0);
			}

			// get key of table
			String tableKey = noWildcardMask + "_" + assemblyOperandData.wildcard();

			// It's not a scalar operand
			if (assemblyOperandData.choice() != null) {
				tables.addOperand(assemblyOperandData, assemblyPatternBlock, tableKey);
			}

			// add operand to json
			OperandMeta ot;
			if (assemblyOperandData.choice() == null) {
				ot = new ScalarOperandMeta(wildcardMask, assemblyOperandData.wildcard(),
						assemblyOperandData.expression());
				
				// Only add the input context when required
				if (lookupStep.getContext() == null && ((ScalarOperandMeta) ot).hasContext()) {
					System.err.println("Adding the context!!!");
					lookupStep.putContext(convertContext(context));
				}
			}
			else {
				ot = new FieldOperandMeta(wildcardMask, tableKey,
						assemblyOperandData.wildcard());
			}
			Data data = lookupStep.getData(noWildcardMaskList);
			if (data instanceof LookupData lookupData) {
				InstructionEncoding ie = lookupData.getChoice(noWildcardMask.getValsAll());
				if (!ie.matches(ot)) {
					ie.addOperand(ot);
				}
			}
		}

		return this;
	}
	
	// Class to help convert context into form expected by the solver
	// Beats having to reimplement a ton of functions
	static class SearchContext implements DisassemblerContextAdapter {
		private final RegisterValue context;

		public SearchContext(RegisterValue context) {
			this.context = context;
		}

		@Override
		public RegisterValue getRegisterValue(Register register) {
			return context.getRegisterValue(register);
		}
	};
	
	// Convert the context from the pattern into form expected by the solver
	public int[] convertContext(RegisterValue context) {
		// TODO: Slight hack
		// Just using ContextCache for conversion from RegisterValue -> int[]
		ContextCache temp = new ContextCache();
		temp.registerVariable(context.getRegister());
		
		int[] convert = new int[temp.getContextSize()];
		temp.getContext(new SearchContext(context), convert);
		
		return convert;
	}

	/**
	 * @return the {@link LookupStep} generated by this builder.
	 */
	public LookupStep buildLookupStep() {
		return lookupStep;
	}
}
