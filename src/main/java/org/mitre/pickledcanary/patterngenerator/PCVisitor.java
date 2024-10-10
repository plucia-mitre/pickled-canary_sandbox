
// Copyright (C) 2024 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Stack;
import java.util.TreeMap;

import org.antlr.v4.runtime.BaseErrorListener;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.RecognitionException;
import org.antlr.v4.runtime.Recognizer;
import org.json.JSONArray;
import org.json.JSONObject;
import org.mitre.pickledcanary.PickledCanary;
import org.mitre.pickledcanary.patterngenerator.generated.pc_grammar;
import org.mitre.pickledcanary.patterngenerator.generated.pc_grammarBaseVisitor;
import org.mitre.pickledcanary.patterngenerator.generated.pc_lexer;
import org.mitre.pickledcanary.patterngenerator.output.steps.AnyByteSequence;
import org.mitre.pickledcanary.patterngenerator.output.steps.Byte;
import org.mitre.pickledcanary.patterngenerator.output.steps.Jmp;
import org.mitre.pickledcanary.patterngenerator.output.steps.Label;
import org.mitre.pickledcanary.patterngenerator.output.steps.LookupStep;
import org.mitre.pickledcanary.patterngenerator.output.steps.MaskedByte;
import org.mitre.pickledcanary.patterngenerator.output.steps.Match;
import org.mitre.pickledcanary.patterngenerator.output.steps.NegativeLookahead;
import org.mitre.pickledcanary.patterngenerator.output.steps.OrMultiState;
import org.mitre.pickledcanary.patterngenerator.output.steps.Split;
import org.mitre.pickledcanary.patterngenerator.output.steps.SplitMulti;
import org.mitre.pickledcanary.patterngenerator.output.steps.Step;
import org.mitre.pickledcanary.patterngenerator.output.utils.AllLookupTables;
import org.mitre.pickledcanary.patterngenerator.output.utils.LookupStepBuilder;
import org.mitre.pickledcanary.search.Pattern;

import ghidra.app.plugin.assembler.AssemblySelector;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults;
import ghidra.app.plugin.assembler.sleigh.sem.DefaultAssemblyResolvedPatterns;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.asm.wild.WildSleighAssembler;
import ghidra.asm.wild.WildSleighAssemblerBuilder;
import ghidra.asm.wild.sem.DefaultWildAssemblyResolvedPatterns;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.DisassemblerContextAdapter;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.util.task.TaskMonitor;

public class PCVisitor extends pc_grammarBaseVisitor<Void> {

	private final Program currentProgram;
	private Address currentAddress;
	private final WildSleighAssembler assembler;
	private TaskMonitor monitor;
	private SleighLanguage language;
	private RegisterValue setCtx;
	
	private final List<OrMultiState> orStates;

	private final Deque<Integer> byteStack;
	private final Deque<PatternContext> contextStack;
	private final Deque<RegisterValue> ctxStack;
	private PatternContext currentContext;
	private JSONObject metadata;
	private final MyErrorListener errorListener;
	
	private HashMap<AssemblyParseResult, HashMap<DefaultWildAssemblyResolvedPatterns, HashMap<Address, RegisterValue>>> variantCtx;
	
//	private final HashMap<Address, HashSet<RegisterValue>> futureContexts;
	private  HashSet<RegisterValue> nextContexts;
	private final Stack<ContextStackItem> asmContextStack;
	private final Stack<Integer> asmContextOrStack;
	private RegisterValue asmCurrentContext;
	private PatternContext outputContext;
	
	/* Needed to reimplement this class, luckily it's small */
	static class ContextChanges implements DisassemblerContextAdapter {
		private final RegisterValue contextIn;
		private final Map<Address, RegisterValue> contextsOut = new TreeMap<>();

		public ContextChanges(RegisterValue contextIn) {
			this.contextIn = contextIn;
		}

		@Override
		public RegisterValue getRegisterValue(Register register) {
			if (register.getBaseRegister() == contextIn.getRegister()) {
				return contextIn.getRegisterValue(register);
			}
			return null;
		}

		@Override
		public void setFutureRegisterValue(Address address, RegisterValue value) {
			RegisterValue current = contextsOut.get(address);
			RegisterValue combined = current == null ? value : current.combineValues(value);
			contextsOut.put(address, combined);
		}

		public void addFlow(ProgramContext progCtx, Address after) {
			contextsOut.put(after, progCtx.getFlowValue(contextIn));
		}
	}

	public HashMap<Address, RegisterValue> getContextChanges(DefaultAssemblyResolvedPatterns pats, RegisterValue inputCtx) {
		ContextChanges contextChanges = new ContextChanges(inputCtx);
		ByteMemBufferImpl buffer = new ByteMemBufferImpl(currentAddress, pats.getInstruction().getVals(), this.language.isBigEndian());
		
		/* Use the language to parse the context changes for each encoding
		 * We might be disassembling the instruction we just assembled */
		try {
			language.parse(buffer, contextChanges, false);
		} catch (InsufficientBytesException | UnknownInstructionException e) {
			e.printStackTrace();
		}
		
		/* A single encoding may change the context at multiple addresses */
		HashMap<Address, RegisterValue> addressCtx = new HashMap<Address, RegisterValue>();
		
		for (Entry<Address, RegisterValue> ent : contextChanges.contextsOut.entrySet()) {
			addressCtx.put(ent.getKey(), inputCtx.combineValues(ent.getValue()));
		}
		return addressCtx;
	}

	private void printContextChanges(HashMap<AssemblyParseResult, HashMap<DefaultWildAssemblyResolvedPatterns, HashMap<Address, RegisterValue>>> variantCtx) {
		System.err.print(System.lineSeparator());
		
		for (AssemblyParseResult parseResult : variantCtx.keySet()) {
			System.err.println("Instruction variant: " + parseResult);
			
			HashMap<DefaultWildAssemblyResolvedPatterns, HashMap<Address, RegisterValue>> encodingCtx = variantCtx.get(parseResult);
			
			for (DefaultWildAssemblyResolvedPatterns resolvedPats: encodingCtx.keySet()) {
				System.err.println("Instruction encoding: " + resolvedPats.getInstruction());
				
				HashMap<Address, RegisterValue> addressCtx = encodingCtx.get(resolvedPats);
				
				for (Address address: addressCtx.keySet() ) {
					System.err.println("Context: " + addressCtx.get(address) +  " set at address: " + address);
					
					/* For testing purposes, set the new global context to 
					 * the last possible context change in the HashMap
					 * We can't fork yet */
					this.setCtx = addressCtx.get(address);
				}
				System.err.print(System.lineSeparator());
			}
		}	
	}

	/**
	 * Construct visitor to build Step output.
	 * 
	 * You likely want to call {@link #lexParseAndVisit(String, TaskMonitor)} once you've created an
	 * instance of this class. After that, {@link #getJSONObject(boolean)} or {@link #getPattern()}
	 * can be used to get the pattern output for export or searching respectively
	 * 
	 * This visitor can be reused for multiple patterns IF the reset method is called between calls
	 * to {@link #lexParseAndVisit(String, TaskMonitor)}.
	 *
	 * @param currentProgram
	 * @param currentAddress
	 * @param monitor
	 */
	public PCVisitor(final Program currentProgram, final Address currentAddress,
			final TaskMonitor monitor) {
		this.currentProgram = currentProgram;
		this.currentAddress = currentAddress;
		this.monitor = monitor;
		this.language = (SleighLanguage) currentProgram.getLanguage();
		WildSleighAssemblerBuilder builder = new WildSleighAssemblerBuilder(language);
		this.assembler = builder.getAssembler(new AssemblySelector(), currentProgram);

		this.orStates = new ArrayList<>();
		this.byteStack = new ArrayDeque<>();

		this.currentContext = new PatternContext();
		this.contextStack = new ArrayDeque<>();
		this.ctxStack = new ArrayDeque<>();

		this.metadata = new JSONObject();
		errorListener = new MyErrorListener();
		
		/* Derive initial context register value from current address */ 
		this.setCtx = this.currentProgram.getProgramContext().getDisassemblyContext(this.currentAddress);
		
//		this.futureContexts = new HashMap<>();
		this.nextContexts = new HashSet<>();
		this.asmContextStack = new Stack<>();
		this.asmContextOrStack = new Stack<>();
		this.outputContext = new PatternContext();
	}

	/**
	 * Reset back to state where this visitor can visit a new pattern.
	 */
	public void reset() {
		this.orStates.clear();
		this.byteStack.clear();
		this.currentContext = new PatternContext();
		this.contextStack.clear();
		this.ctxStack.clear();
		this.metadata = new JSONObject();
		this.setCtx = this.currentProgram.getProgramContext().getDisassemblyContext(this.currentAddress);
		
//		this.futureContexts.clear();;
		this.asmContextStack.clear();;
		this.asmContextOrStack.clear();
		this.outputContext = new PatternContext();
	}

	private static void raiseInvalidInstructionException(LookupStep lookupStep) {
		String instructionText = lookupStep.getInstructionText();

		if (instructionText.chars().filter(ch -> ch == '`').count() % 2 != 0) {
			throw new QueryParseException(
				"This line doesn't have a balanced number of '`' characters and didn't assemble to any instruction",
				lookupStep);
		}
		throw new QueryParseException(
			"An assembly instruction in your pattern (" + instructionText +
				") did not return any output. Make sure your assembly instructions" +
				" are valid or that you are using a binary with the same architecture.",
			lookupStep);
	}

	@Override
	public Void visitAny_bytes(pc_grammar.Any_bytesContext ctx) {

		Integer min = Integer.decode(ctx.getChild(1).getText());
		Integer max = Integer.decode(ctx.getChild(3).getText());
		Integer step = 1;

		if (ctx.children.size() > 6) {
			step = Integer.decode(ctx.getChild(5).getText());
		}

		var note = String.format(
			"AnyBytesNode Start: %d End: %d Interval: %d From: Token from line #%d: Token type: PICKLED_CANARY_COMMAND data: `%s`",
			min, max, step, ctx.start.getLine(), ctx.getText());

		this.currentContext.steps().add(new AnyByteSequence(min, max, step, note));

		return null;
	}

	@Override
	public Void visitByte_match(pc_grammar.Byte_matchContext ctx) {
		visitChildren(ctx);
		this.currentContext.steps().add(new Byte(this.byteStack.pop()));
		return null;
	}

	@Override
	public Void visitByte_string(pc_grammar.Byte_stringContext ctx) {

		var stringData = ctx.getText().strip();
		// Remove starting and ending '"' and translate escapes
		stringData = stringData.substring(1, stringData.length() - 1).translateEscapes();

		// Add a "Byte" for each character
		for (int x : stringData.toCharArray()) {
			this.currentContext.steps().add(new Byte(x));
		}

		return null;
	}

	@Override
	public Void visitMasked_byte(pc_grammar.Masked_byteContext ctx) {
		visitChildren(ctx);
		var value = this.byteStack.pop();
		var mask = this.byteStack.pop();
		this.currentContext.steps().add(new MaskedByte(mask, value));
		return null;
	}

	@Override
	public Void visitByte(pc_grammar.ByteContext ctx) {
		this.byteStack.push(Integer.decode(ctx.getText()));
		return null;
	}

	@Override
	public Void visitLabel(pc_grammar.LabelContext ctx) {
		var label = ctx.getText().strip();
		label = label.substring(0, label.length() - 1);
		this.currentContext.steps().add(new Label(label));
		return null;
	}

	@Override
	public Void visitMeta(pc_grammar.MetaContext ctx) {
		String meta = ctx.getText();
		// Remove `META` at the start
		meta = meta.replaceFirst("^ *`META`[\r\n]+", "");
		// Remove "`META_END`" at the end
		meta = meta.substring(0, meta.length() - 10);
		// Remove any comments
		meta = meta.replaceAll("[\n\r]+ *;[^\n\r]*", "");

		// Check if our existing metadata is equal to an empty JSONObject
		if (this.metadata.toString().equals(new JSONObject().toString())) {
			this.metadata = new JSONObject(meta);
		}
		else {
			throw new QueryParseException("Can not have more than one META section!", ctx);
		}
		return null;
	}

	@Override
	public Void visitStart_or(pc_grammar.Start_orContext ctx) {
		// Add a new "split" step for this OR block.
		this.currentContext.steps().add(new SplitMulti(this.currentContext.steps().size() + 1));

		// Add a new OrState and reference the index of the split node for this Or block
		this.orStates.add(new OrMultiState(this.currentContext.steps().size() - 1));
		return null;
	}

	@Override
	public Void visitMiddle_or(pc_grammar.Middle_orContext ctx) {
		// Add a new "jmp" step to (eventually) go to after the second "or" option.
		this.currentContext.steps().add(new Jmp(this.currentContext.steps().size() + 1));

		OrMultiState currentOrState = this.orStates.get(this.orStates.size() - 1);
		currentOrState.addMiddleStep(this.currentContext.steps().size() - 1);

		// Update the split to have its next dest point to here after the jmp ending
		// the first option
		SplitMulti s = (SplitMulti) this.currentContext.steps().get(currentOrState.getStartStep());
		s.addDest(this.currentContext.steps().size());
		return null;
	}

	@Override
	public Void visitEnd_or(pc_grammar.End_orContext ctx) {
		// Pop the current orState off the end (we're done with it)
		OrMultiState currentOrState = this.orStates.remove(this.orStates.size() - 1);

		// Update the jmp after each "or" option to jump to here (after the final
		// "or")
		List<Integer> middleSteps = currentOrState.getMiddleSteps();
		for (Integer jmp_idx : middleSteps) {
			Jmp j = (Jmp) this.currentContext.steps().get(jmp_idx);
			j.setDest(this.currentContext.steps().size());
		}

		// If we have exactly two OR options, change from a SplitMulti to a Split
		if (middleSteps.size() == 1) {
			List<Integer> origDests =
				((SplitMulti) this.currentContext.steps()
						.get(currentOrState.getStartStep())).getDests();

			Split newSplit = new Split(origDests.get(0));
			newSplit.setDest2(origDests.get(1));
			this.currentContext.steps().set(currentOrState.getStartStep(), newSplit);
		}
		return null;
	}

	@Override
	public Void visitStart_negative_lookahead(pc_grammar.Start_negative_lookaheadContext ctx) {
		// When we get into a "not" block, we'll essentially start to create a new
		// pattern (for the contents of the "not" block). We do this here by saving off
		// our current "steps" and "tables" and creating new ones that our next nodes
		// (until the end of the not block) will populate. When we get to the end of the
		// "not" block, we'll package up the then-current steps and tables into a
		// pattern (the new ones we're creating here), restore the steps and tables
		// saved here, and add the "NegativeLookahead" step containing the
		// just-generated pattern.
		this.contextStack.push(this.currentContext);
		this.currentContext = new PatternContext();
		return null;
	}

	@Override
	public Void visitEnd_negative_lookahead(pc_grammar.End_negative_lookaheadContext ctx) {
		// The final step of the not block should be a Match, so add it here.
		this.currentContext.steps.add(new Match());

		// Generate the JSON for the inner-pattern (that will go within the
		// NegativeLookahead)
		this.currentContext.canonicalize();
		JSONObject notPattern = this.currentContext.getJson(this.metadata);

		// Restore our "outer"/"main" steps and tables (which were saved at the
		// NotStartNode)
		this.currentContext = this.contextStack.pop();

		// Add the NegativeLookahead step (including its inner-pattern) to our main set
		// of steps
		this.currentContext.steps().add(new NegativeLookahead(notPattern));
		return null;
	}

	@Override
	public Void visitInstruction(pc_grammar.InstructionContext ctx) {
		if (PickledCanary.DEBUG) {
			System.out.println("CURRENTLY PROCESSING: " + ctx.getText());
		}

//		Collection<AssemblyParseResult> parses = assembler.parseLine(ctx.getText())
//				.stream()
//				.filter(p -> {
//					if (PickledCanary.DEBUG && p.isError()) {
//						System.err.println("Error in AssemblyParseResult: " + p);
//					}
//					return !p.isError();
//				})
//				.toList();
//		if (parses.isEmpty()) {
//			raiseInvalidInstructionException(ctx);
//		}
//
//		LookupStep lookupStep = this.makeLookupStepFromParseResults(parses);
//		if (lookupStep == null)
//			return null;
//		if (lookupStep.isEmpty()) {
//			raiseInvalidInstructionException(ctx);
//		}
		
		LookupStep lookupStep = new LookupStep(ctx.getText(), ctx.start.getLine(), ctx.start.getCharPositionInLine());

		this.currentContext.steps().add(lookupStep);

		return null;
	}

	@Override
	public Void visitCtx_set(pc_grammar.Ctx_setContext ctx) {
		visitChildren(ctx);
		RegisterValue toSet = ctxStack.pop();
		/* setCtx always contains the full context register 
		 * We set the specified value for the specified context variable 
		 * in that context register */
		this.setCtx = setCtx.assign(toSet.getRegister(), toSet);
		System.err.println(setCtx);
		return null;
	}
	
	@Override
	public Void visitCtx(pc_grammar.CtxContext ctx) {
		/* Right now, the entire context register is our "context variable".
		 * It should be trivial to adjust this so that it uses a real context variable instead */
		Register ctxReg = language.getContextBaseRegister();
		ctxStack.push(new RegisterValue(ctxReg, AssemblyPatternBlock.fromString(ctx.getText()).toBigInteger(ctxReg.getNumBytes())));
		return null;
	}


	
	
	
	
	public void doVisitorPart2() {
		System.out.println("VISITOR PART 2!!!");
		// set first context
		asmCurrentContext = this.currentProgram.getProgramContext().getDisassemblyContext(currentAddress);
		asmContextStack.add(new ContextStackItem(asmCurrentContext, 0));
		while (asmContextStack.size() != 0) {
			ContextStackItem csi = asmContextStack.removeLast();
			asmCurrentContext = csi.context;
			for (int i = csi.startIdx; i < this.currentContext.steps.size(); i++) {
				Step step = this.currentContext.steps.get(i);
				System.out.println("STEP TYPE: " + step.getStepType().toString());
				switch (step.getStepType()) {
				case Step.StepType.SPLITMULTI:
					int nextInst = visit((SplitMulti) step);
					i = nextInst - 1;
					break;
				case Step.StepType.SPLIT:
					nextInst = visit((Split) step);
					i = nextInst - 1;
					break;
				case Step.StepType.JMP:
					nextInst = visit((Jmp) step);
					i = nextInst - 1;
					break;
				case Step.StepType.LOOKUP:
					visit(i, (LookupStep) step);
					break;
				default:
					visit(step);
				}
			}
			if (asmContextStack.size() != 0) {
				int correspondingSplitIndex = asmContextOrStack.removeLast();
				this.outputContext.steps().add(new Jmp(0));
				System.out.println(this.outputContext.steps.get(correspondingSplitIndex).getStepType().toString());
				if (this.outputContext.steps().get(correspondingSplitIndex).getStepType() == Step.StepType.SPLIT) {
					Split split = (Split) this.outputContext.steps().get(correspondingSplitIndex);
					split.setDest2(this.outputContext.steps().size());
				} else {
					SplitMulti sm = (SplitMulti) this.outputContext.steps().get(correspondingSplitIndex);
					if (sm.getDests().size() == 1) {
						Split newSplit = new Split(sm.getDests().get(0));
						newSplit.setDest2(this.outputContext.steps().size());
						this.outputContext.steps().set(correspondingSplitIndex, newSplit);
					} else {
						sm.addDest(this.outputContext.steps().size());
					}
				}
			}
		}
		for (int i = 0; i < this.outputContext.steps().size(); i++) {
			if (this.outputContext.steps().get(i).getStepType() == Step.StepType.JMP) {
				((Jmp) outputContext.steps().get(i)).setDest(this.outputContext.steps().size());
			}
		}
	}
	
	private int visit(SplitMulti splitMultiStep) {
		for (int i = 1; i < splitMultiStep.getDests().size(); i++) {
			asmContextOrStack.add(this.outputContext.steps().size());
			asmContextStack.add(new ContextStackItem(asmCurrentContext, splitMultiStep.getDests().get(i)));
		}
		this.outputContext.steps().add(new SplitMulti(splitMultiStep.getDests().get(0)));
		return splitMultiStep.getDests().get(0);
	}
	
	private int visit(Split splitStep) {
		asmContextOrStack.add(this.outputContext.steps().size());
		asmContextStack.add(new ContextStackItem(asmCurrentContext, splitStep.getDest2()));
		this.outputContext.steps().add(new Split(splitStep.getDest1()));
		return splitStep.getDest1();
	}
	
	private int visit(Jmp jmpStep) {
		return jmpStep.getDest();
	}
	
	private void visit(int tokenIdx, LookupStep lookupStep) {
		System.out.println("Current address " + currentAddress.toString());
		Collection<AssemblyParseResult> parses = assembler.parseLine(lookupStep.getInstructionText())
				.stream()
				.filter(p -> {
					if (PickledCanary.DEBUG && p.isError()) {
						System.err.println("Error in AssemblyParseResult: " + p);
					}
					return !p.isError();
				})
				.toList();
		if (parses.isEmpty()) {
			raiseInvalidInstructionException(lookupStep);
		}

		lookupStep = this.makeLookupStepFromParseResults(lookupStep, parses);
		if (lookupStep == null)
			return;
		if (lookupStep.isEmpty()) {
			raiseInvalidInstructionException(lookupStep);
		}

		System.out.println("ADDING LOOKUP STEP:");
		System.out.println(lookupStep);
		this.outputContext.steps().add(lookupStep);
		
		/////
		if (nextContexts.size() == 0 || tokenIdx == this.currentContext.steps().size() - 1) {
			return;
		}
//		if (!futureContexts.containsKey(currentAddress)) {
//			return;
//		}
//		Object[] nextContexts = futureContexts.get(currentAddress).toArray(); //TODO: get next contexts
		Object[] nextContexts = this.nextContexts.toArray();
		asmCurrentContext = (RegisterValue) nextContexts[0];
		System.out.println("Context is now " + asmCurrentContext.toString());
		for (int i = 1; i < nextContexts.length; i++) {
			asmContextOrStack.add(this.outputContext.steps().size());
			asmContextStack.add(new ContextStackItem((RegisterValue) nextContexts[i], tokenIdx + 1));
		}
		if (nextContexts.length > 1) {
			this.outputContext.steps().add(new SplitMulti(this.outputContext.steps().size() + 1));
		}
	}
	
	private void visit(Step step) {
		this.outputContext.steps().add(step);
	}
	
	private LookupStep makeLookupStepFromParseResults(LookupStep lookupStep, Collection<AssemblyParseResult> parses) {

		LookupStepBuilder builder = new LookupStepBuilder(lookupStep, outputContext.tables);
		AssemblyPatternBlock assemblerCtx = AssemblyPatternBlock.fromRegisterValue(asmCurrentContext);
		
		this.variantCtx = new HashMap<AssemblyParseResult, HashMap<DefaultWildAssemblyResolvedPatterns, HashMap<Address, RegisterValue>>>();
		this.nextContexts = new HashSet<>();

		for (AssemblyParseResult p : parses) {
			if (PickledCanary.DEBUG) {
				/* Print each instruction variant */
				System.err.println("parse = " + p);
			}

			AssemblyResolutionResults results;

			/* Resolve each instruction variant to get the encodings
			 * All variants should use the same input context (global context) for resolution
			 * Encodings for variants which are not valid in the provided context are filtered out
			 * by the assembler */
			results = assembler.resolveTree(p, currentAddress, assemblerCtx);
			
			if (monitor.isCancelled()) {
				// Yield if user wants to cancel operation
				return null;
			}
			
			HashMap<DefaultWildAssemblyResolvedPatterns, HashMap<Address, RegisterValue>> encodingCtx = 
					new HashMap<DefaultWildAssemblyResolvedPatterns, HashMap<Address, RegisterValue>>();

			for (AssemblyResolution res : results) {
				if (res instanceof DefaultWildAssemblyResolvedPatterns pats) {
					/* We must compute the context changes (if any) for every pats,
					 * as the instruction encodings may affect the global context */
					encodingCtx.put(pats, getContextChanges(pats, setCtx));
					builder.addAssemblyPattern(pats);
					
					HashMap<Address, RegisterValue> encodingContextChanges = getContextChanges(pats, asmCurrentContext);
					System.out.println("produced " + encodingContextChanges.size() + " contexts");
					for (Address a : encodingContextChanges.keySet()) {
						nextContexts.add(encodingContextChanges.get(a));
//						if (!futureContexts.containsKey(a)) {
//							futureContexts.put(a, new HashSet<>());
//						}
						System.out.println("putting in address " + a.toString());
//						futureContexts.get(a).add(encodingContextChanges.get(a));
					}
				}
			}
			variantCtx.put(p, encodingCtx);
		}
		printContextChanges(this.variantCtx);
		return builder.buildLookupStep();
	}
	
	
	
	

	/**
	 * Return the results of having processed the pattern as a {@link JSONObject} which can be used
	 * to output this compiled pattern.
	 * 
	 * @param withDebugInfo
	 *            Include an extra "compile_info" tag with debug information (or not)
	 * @return A {@link JSONObject} containing the processed equivalent of the last pattern visited.
	 */
	public JSONObject getJSONObject(boolean withDebugInfo) {
		this.outputContext.canonicalize();
		JSONObject output = this.outputContext.getJson(this.metadata);

		if (withDebugInfo) {
			output.append("compile_info", this.getDebugJson());
		}
		else {
			output.put("compile_info", new JSONArray());
		}

		return output;
	}

	/**
	 * Return the results of having processed the pattern as a {@link Pattern} which can be used to
	 * perform a search.
	 * 
	 * @return A {@link Pattern} object containing the processed equivalent of the last pattern
	 *         visited.
	 */
	public Pattern getPattern() {
		this.outputContext.canonicalize();
		return this.outputContext.getPattern();
	}

	private JSONObject getDebugJson() {
		JSONObject compileInfo = new JSONObject();
		JSONObject sourceBinaryInfo = new JSONObject();
		sourceBinaryInfo.append("path", this.currentProgram.getExecutablePath());
		sourceBinaryInfo.append("md5", this.currentProgram.getExecutableMD5());
		sourceBinaryInfo.append("compiled_at_address", this.currentAddress);
		compileInfo.append("compiled_using_binary", sourceBinaryInfo);
		compileInfo.append("language_id", this.currentProgram.getLanguageID().getIdAsString());
		return compileInfo;
	}

	private record PatternContext(List<Step> steps, AllLookupTables tables) {
		PatternContext() {
			this(new ArrayList<>(), new AllLookupTables());
		}

		/**
		 * Replace temporary refs in the data structure with canonical id's.
		 */
		void canonicalize() {
			for (Step step : this.steps) {
				if (step instanceof LookupStep lookupStep) {
					lookupStep.resolveTableIds(this.tables);
				}
			}
		}

		Pattern getPattern() {
			return new Pattern(this.steps, this.tables.getPatternTables());
		}

		/**
		 * Get raw JSON (without) any debug or compile info
		 * 
		 * @return the JSON for this context
		 */
		JSONObject getJson(JSONObject metadata) {
			JSONObject out = new JSONObject();

			JSONArray arr = new JSONArray();
			for (Step step : steps) {
				arr.put(step.getJson());
			}
			out.put("steps", arr);
			out.put("tables", tables.getJson());
			out.put("pattern_metadata", metadata);
			return out;
		}
	}

	/**
	 * Update the address used by this visitor to assemble given instructions.
	 * 
	 * @param address
	 *            The address that we want to compile at
	 */
	public void setCurrentAddress(Address address) {
		currentAddress = address;
	}

	public void setMonitor(TaskMonitor m) {
		monitor = m;
	}

	private static class MyErrorListener extends BaseErrorListener {
		@Override
		public void syntaxError(Recognizer<?, ?> recognizer, Object offendingSymbol, int line,
				int charPositionInLine,
				String msg, RecognitionException e) {
			throw new QueryParseException(msg, line, charPositionInLine);
		}
	}

	/**
	 * Process the given pattern, making results available in {@link #getPattern()} or
	 * {@link #getJSONObject(boolean)} methods.
	 * 
	 * Call {@link #reset()} in between calls to this method if reusing this instance. If
	 * currentAddress has changed since this instance was created, call
	 * {@link #setCurrentAddress(Address)} before calling this method
	 * 
	 * @param pattern
	 *            The pattern string to parse into steps
	 * @param newMonitor
	 *            A monitor to display progress
	 */
	public void lexParseAndVisit(String pattern, TaskMonitor newMonitor) {
		monitor = newMonitor;
		monitor.setIndeterminate(true);

		var chars = CharStreams.fromString(pattern);
		var lexer = new pc_lexer(chars);
		lexer.addErrorListener(errorListener);
		var commonTokenStream = new CommonTokenStream(lexer);
		var parser = new pc_grammar(commonTokenStream);
		parser.addErrorListener(errorListener);

		var progContext = parser.prog();

		this.visit(progContext);
		
		this.doVisitorPart2();

		monitor.setIndeterminate(false);
	}
	
	static class ContextStackItem {
		RegisterValue context;
		int startIdx;
		
		public ContextStackItem(RegisterValue context, int startIdx) {
			this.context = context;
			this.startIdx = startIdx;
		}
	}
}
