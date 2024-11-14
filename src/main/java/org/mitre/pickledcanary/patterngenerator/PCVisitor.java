// Copyright (C) 2024 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
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
import org.mitre.pickledcanary.patterngenerator.output.steps.Context;
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
import ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype;
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
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;

/**
 * This class creates the generated pattern. There are two major steps to do this: 1. Process the
 * user pattern. This involves taking the token generated by the parser/lexer and creating the steps
 * for the pike VM to search. However, instruction tokens are ignored and handled in step 2. 2.
 * Assembly instructions and make the pattern context-aware. An instruction can generate different
 * encodings, each of which can change the context to a different value. New branches in the pattern
 * are created for each context.
 *
 * Each step is handled by its own visitor.
 */
public class PCVisitor extends pc_grammarBaseVisitor<Void> {

	private final Program currentProgram;
	private Address currentAddress;
	private final WildSleighAssembler assembler;
	private TaskMonitor monitor;
	private SleighLanguage language;

	private final List<OrMultiState> orStates;

	private final Deque<Integer> byteStack;
	private final Deque<PatternContext> contextStack;
	private final Deque<RegisterValue> ctxStack;
	private PatternContext currentContext; // contains output of first visitor
	private JSONObject metadata;
	private final MyErrorListener errorListener;

	private ResultMap variantCtx;
	
	private ContextVisitor contextVisitor;
	
//	// TODO: An instruction can set any address to change context. We current assume that an
//	// instruction can change the context of only the next instruction.
////	private final HashMap<Address, HashSet<RegisterValue>> futureContexts;
//	// contexts to apply for the next instruction -- this is a temp variable while above is being
//	// fixed
//	private HashSet<RegisterValue> nextContexts;
//
//	private final Stack<ContextStackItem> asmContextStack; // tracks new context branches that will
//															// be handled later
//	private final Stack<Integer> asmContextOrStack; // tracks where the start of the split steps
//	private RegisterValue asmCurrentContext; // current context used for assembling instructions
//	private PatternContext outputContext; // contains the generated pattern steps
	
	/**
	 * Individual key-value pairs within a single "CONTEXT" block
	 */
	private final HashMap<String, RegisterValue> contextEntries;
	
	/**
	 * Local cache so we're not constantly querying to get this list
	 */
	private List<Register> validContextRegisters = null;
	
	// Needed to reimplement this class, luckily it's small
	static class ContextAdapter implements DisassemblerContextAdapter {
		private final RegisterValue contextIn;
		private final Map<Address, RegisterValue> contextsOut = new TreeMap<>();

		public ContextAdapter(RegisterValue contextIn) {
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
	
	private record ContextChanges(RegisterValue localCtx, AddressMap globalCtx) {};

	private record ResultMap(HashMap<AssemblyParseResult, PatternMap> map) {
		ResultMap() {
			this(new HashMap<AssemblyParseResult, PatternMap>());
		}
	};

	private record PatternMap(HashMap<DefaultWildAssemblyResolvedPatterns, AddressMap> map) {
		PatternMap() {
			this(new HashMap<DefaultWildAssemblyResolvedPatterns, AddressMap>());
		}
	};

	private record AddressMap(HashMap<Address, RegisterValue> map) {
		AddressMap() {
			this(new HashMap<Address, RegisterValue>());
		}
	};

	private class ContextVisitor {
		protected HashSet<RegisterValue> nextContexts;
		protected Stack<ContextStackItem> contextStack;
		protected Stack<Integer> contextOrStack;
		protected PatternContext outputContext;
		protected RegisterValue asmCurrentContext;

		ContextVisitor() {
			this.nextContexts = new HashSet<RegisterValue>();
			this.contextStack = new Stack<ContextStackItem>();
			this.contextOrStack = new Stack<Integer>();
			this.outputContext = new PatternContext();
		}
		
		/**
		 * After the user pattern is passed through the first visitor above, run the output through this
		 * second visitor to make the generated pattern context-aware.
		 */
		public void makeContextAware() {
			// set first context
			asmCurrentContext = currentProgram.getProgramContext()
					.getDisassemblyContext(currentAddress);
			this.contextStack.add(new ContextStackItem(asmCurrentContext, 0));
			while (!this.contextStack.isEmpty()) {
				// process each context branch
				ContextStackItem csi = this.contextStack.removeLast();
				asmCurrentContext = csi.context;
				for (int i = csi.startIdx; i < currentContext.steps.size(); i++) {
					// process each instruction within the context branch
					Step step = currentContext.steps.get(i);
					switch (step.getStepType()) {
						case Step.StepType.SPLITMULTI:
							int nextInst = visit((SplitMulti) step);
							i = nextInst - 1;
							break;
						case Step.StepType.JMP:
							nextInst = visit((Jmp) step);
							i = nextInst - 1;
							break;
						case Step.StepType.LOOKUP:
							visit(i, ((LookupStep) step).copy());
							break;
						case Step.StepType.CONTEXT:
							visit((Context) step);
							break;
						default:
							visit(step);
					}
				}
				if (!this.contextStack.isEmpty()) {
					// there are more context branches to handle
					// add a jump, which will later be filled in with dest of end of pattern
					this.outputContext.steps().add(new Jmp(0));
					// add the next destination for a Split or SplitMulti block
					int correspondingSplitIndex = this.contextOrStack.removeLast();
					SplitMulti sm = (SplitMulti) this.outputContext.steps().get(correspondingSplitIndex);
					sm.addDest(this.outputContext.steps().size());
				}
			}

			for (int i = 0; i < this.outputContext.steps().size(); i++) {
				// turn all SplitMulti blocks with only 2 destinations into a Split block
				Step nextStep = this.outputContext.steps().get(i);
				if (nextStep.getStepType() == Step.StepType.SPLITMULTI) {
					SplitMulti sm = (SplitMulti) nextStep;
					if (sm.getDests().size() == 2) {
						Split newSplit = new Split(sm.getDests().get(0));
						newSplit.setDest2(sm.getDests().get(1));
						this.outputContext.steps().set(i, newSplit);
					}
				} else if (nextStep.getStepType() == Step.StepType.JMP) {
					// all jumps should go to the end of the pattern
					((Jmp) nextStep).setDest(this.outputContext.steps().size());
				}
			}

			for (int i = 0; i < this.outputContext.steps.size(); i++) {
				System.out.println(i + " " + this.outputContext.steps.get(i).toString());
			}
		}

		// #region Visit methods
		// Returns the index of the step in the output of the first visitor from where the next branch
		// should begin
		private int visit(SplitMulti splitMultiStep) {
			// when there is a split, we will process the first branch and put the other branches in a
			// stack to process them after the first branch
			for (int i = splitMultiStep.getDests().size() - 1; i > 0; i--) {
				this.contextOrStack.add(this.outputContext.steps().size());
				this.contextStack
						.add(new ContextStackItem(this.asmCurrentContext, splitMultiStep.getDests().get(i)));
			}
			this.outputContext.steps().add(new SplitMulti(this.outputContext.steps().size() + 1));
			return splitMultiStep.getDests().get(0);
		}

		// returns which step in the output of the first visitor to jump to in order to continue
		// processing the current branch
		private int visit(Jmp jmpStep) {
			return jmpStep.getDest();
		}

		private void visit(int tokenIdx, LookupStep lookupStep) {
			lookupStep = assembleInstruction(lookupStep);
			if (lookupStep == null) {
				return;
			}
			this.outputContext.steps().add(lookupStep);

			if (nextContexts.size() == 0 || tokenIdx == currentContext.steps().size() - 1) {
				return;
			}
//			if (!futureContexts.containsKey(currentAddress)) {
//				return;
//			}
//			Object[] nextContexts = futureContexts.get(currentAddress).toArray();
			// set the next context, and if there are additional contexts, place them on the stack, so
			// that new branches can be created for those contexts
			Object[] nextContexts = this.nextContexts.toArray();
			this.asmCurrentContext = (RegisterValue) nextContexts[0];
			for (int i = 1; i < nextContexts.length; i++) {
				this.contextOrStack.add(this.outputContext.steps().size());
				this.contextStack
						.add(new ContextStackItem((RegisterValue) nextContexts[i], tokenIdx + 1));
			}
			if (nextContexts.length > 1) {
				this.outputContext.steps().add(new SplitMulti(this.outputContext.steps().size() + 1));
			}
		}

		// Override the current context
		private void visit(Context contextStep) {
			for (RegisterValue contextVar: contextStep.getContextVars()) {
				// asmCurrentContext always contains the full context register
				// We set the specified value for the specified context variable in that context register
				contextVisitor.asmCurrentContext = contextVisitor.asmCurrentContext.assign(contextVar.getRegister(), contextVar);
			}
		}

		private void visit(Step step) {
			this.outputContext.steps().add(step);
		}
		// #endregion
	};

	public ContextChanges getContextChanges(DefaultAssemblyResolvedPatterns pats,
			RegisterValue inputCtx) {
		ContextAdapter contextAdapter = new ContextAdapter(inputCtx);
		ByteMemBufferImpl buffer = new ByteMemBufferImpl(currentAddress,
				pats.getInstruction().getVals(), this.language.isBigEndian());

		RegisterValue localCtx = null;
		// Use the language to parse the context changes for each encoding
		// We might be disassembling the instruction we just assembled
		try {
			SleighInstructionPrototype proto = (SleighInstructionPrototype) language.parse(buffer, contextAdapter, false);
			// Get the local context changes from the prototype
			// While we retrieve this for every encoding, we don't always need it
			localCtx = proto.getParserContext(buffer, contextAdapter).getContextRegisterValue();
		} catch (InsufficientBytesException | UnknownInstructionException | MemoryAccessException e) {
			e.printStackTrace();
		}

		// A single encoding may change the global context at multiple addresses
		AddressMap globalCtx = new AddressMap();

		for (Entry<Address, RegisterValue> ent : contextAdapter.contextsOut.entrySet()) {
			globalCtx.map.put(ent.getKey(), inputCtx.combineValues(ent.getValue()));
		}
		return new ContextChanges(localCtx, globalCtx);
	}

	private void printContextChanges(ResultMap variantCtx) {
		System.err.print(System.lineSeparator());

		for (AssemblyParseResult parseResult : variantCtx.map.keySet()) {
			System.err.println("Instruction variant: " + parseResult);

			PatternMap encodingCtx = variantCtx.map.get(parseResult);

			for (DefaultWildAssemblyResolvedPatterns resolvedPats : encodingCtx.map.keySet()) {
				System.err.println("Instruction encoding: " + resolvedPats.getInstruction());

				AddressMap addressCtx = encodingCtx.map.get(resolvedPats);

				for (Address address : addressCtx.map.keySet()) {
					System.err.println("Context: " + addressCtx.map.get(address) + " set at address: " + address);
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

//		this.futureContexts = new HashMap<>();
		
		this.contextVisitor = new ContextVisitor();

		this.contextEntries = new HashMap<>();
		
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

//		this.futureContexts.clear();
		
		this.contextVisitor = new ContextVisitor();
		this.contextEntries.clear();
	}

	private static void raiseInvalidInstructionException(LookupStep lookupStep) {
		String instructionText = lookupStep.getInstructionText();

		if (instructionText.chars().filter(ch -> ch == '`').count() % 2 != 0) {
			throw new QueryParseException(
					"This line doesn't have a balanced number of '`' characters and didn't assemble to any instruction",
					lookupStep);
		}
		throw new QueryParseException(
				"An assembly instruction in your pattern (" + instructionText
						+ ") did not return any output. Make sure your assembly instructions"
						+ " are valid or that you are using a binary with the same architecture.",
				lookupStep);
	}

	// region Visit methods
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
		} else {
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

		LookupStep lookupStep = new LookupStep(ctx.getText(), ctx.start.getLine(),
				ctx.start.getCharPositionInLine());

		this.currentContext.steps().add(lookupStep);

		return null;
	}
	
	@Override
	public Void visitContext_entry(pc_grammar.Context_entryContext ctx) {

		String[] parts = ctx.getText().split("=");
		String name = parts[0].strip();
		String valueString = parts[1].strip();
		BigInteger value = null;

		try {
			if (valueString.length() > 2) {
				String valuePrefix = valueString.substring(0, 2);
				if (valuePrefix.equals("0x")) {
					value = new BigInteger(valueString.substring(2), 16);
				}
				else if (valuePrefix.equals("0b")) {
					value = new BigInteger(valueString.substring(2), 2);
				}
			}
			if (value == null) {
				value = new BigInteger(valueString);
			}
		}
		catch (NumberFormatException e) {
			throw new QueryParseException(
				"Unable to parse context value: '" + valueString +
					" '. Is it properly prefixed with '0x' for hex, '0b' for binary, or no prefix for base 10?",
				ctx);
		}

		if (this.contextEntries.containsKey(name) ){
			throw new QueryParseException(
				"Cannot specify context value more than once! '" + name + "' was duplicated.", ctx);
		}
		
		if (this.validContextRegisters == null) {
			this.validContextRegisters = currentProgram.getProgramContext().getContextRegisters();
		}
		Optional<Register> match = this.validContextRegisters.stream().filter(reg -> reg.getName().equals(name)).findFirst();

		if (match.isEmpty()) {
			throw new QueryParseException("Invalid context variable '" + name + "' for language!", ctx);
			
		}

		RegisterValue contextVar = new RegisterValue(match.get(), value);
		System.err.println("Going to set this context variable: " + contextVar);
		this.contextEntries.put(name, contextVar);

		return null;
	}

	@Override
	public Void visitContext(pc_grammar.ContextContext ctx) {
		visitChildren(ctx);
		// Transient context override step
		Context contextStep = new Context();
		
		for (RegisterValue contextVar: contextEntries.values()) {
			contextStep.addContextVar(contextVar);
		}
		
		// Reset entries so we're ready for the next context block
		contextEntries.clear();

		this.currentContext.steps().add(contextStep);
 
		return null;
	}
	// end region

	private LookupStep assembleInstruction(LookupStep lookupStep) {
		Collection<AssemblyParseResult> parses = assembler
				.parseLine(lookupStep.getInstructionText()).stream().filter(p -> {
					if (PickledCanary.DEBUG && p.isError()) {
						System.err.println("Error in AssemblyParseResult: " + p);
					}
					return !p.isError();
				}).toList();
		if (parses.isEmpty()) {
			raiseInvalidInstructionException(lookupStep);
		}

		lookupStep = this.makeLookupStepFromParseResults(lookupStep, parses);
		if (lookupStep == null) {
			return null;
		}
		if (lookupStep.isEmpty()) {
			raiseInvalidInstructionException(lookupStep);
		}

		return lookupStep;
	}

	private LookupStep makeLookupStepFromParseResults(LookupStep lookupStep,
			Collection<AssemblyParseResult> parses) {

		LookupStepBuilder builder = new LookupStepBuilder(lookupStep, contextVisitor.outputContext.tables);
		AssemblyPatternBlock assemblerCtx = AssemblyPatternBlock
				.fromRegisterValue(contextVisitor.asmCurrentContext);

		System.err.println("Context going into assembler: " + assemblerCtx);
		this.variantCtx = new ResultMap();
		this.contextVisitor.nextContexts = new HashSet<>();

		for (AssemblyParseResult p : parses) {
			if (PickledCanary.DEBUG) {
				// Print each instruction variant
				System.err.println("parse = " + p);
			}

			AssemblyResolutionResults results;

			// Resolve each instruction variant to get the encodings
			// All variants should use the same input context (global context) for resolution
			// Encodings for variants which are not valid in the provided context are filtered out by the assembler
			results = assembler.resolveTree(p, currentAddress, assemblerCtx);

			if (monitor.isCancelled()) {
				// Yield if user wants to cancel operation
				return null;
			}

			PatternMap encodingCtx = new PatternMap();
			
			for (AssemblyResolution res : results) {
				if (res instanceof DefaultWildAssemblyResolvedPatterns pats) {
					// We must compute the context changes (if any) for every pats
					// The instruction encodings may affect the global context
					ContextChanges contextChanges = getContextChanges(pats, contextVisitor.asmCurrentContext);
					System.err.println("Printing local context: " + contextChanges.localCtx());

					builder.addAssemblyPattern(pats, contextChanges.localCtx());

					AddressMap encodingContextChanges = contextChanges.globalCtx();

					encodingCtx.map.put(pats, encodingContextChanges);

					for (Address a : encodingContextChanges.map.keySet()) {
						contextVisitor.nextContexts.add(encodingContextChanges.map.get(a));
//						if (!futureContexts.containsKey(a)) {
//							futureContexts.put(a, new HashSet<>());
//						}
//						futureContexts.get(a).add(encodingContextChanges.get(a));
					}
				}
			}
			variantCtx.map.put(p, encodingCtx);
		}
		printContextChanges(this.variantCtx);
		return builder.buildLookupStep();
	}

	/**
	 * Return the results of having processed the pattern as a {@link JSONObject} which can be used
	 * to output this compiled pattern.
	 *
	 * @param withDebugInfo Include an extra "compile_info" tag with debug information (or not)
	 * @return A {@link JSONObject} containing the processed equivalent of the last pattern visited.
	 */
	public JSONObject getJSONObject(boolean withDebugInfo) {
		this.contextVisitor.outputContext.canonicalize();
		JSONObject output = this.contextVisitor.outputContext.getJson(this.metadata);

		if (withDebugInfo) {
			output.append("compile_info", this.getDebugJson());
		} else {
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
		this.contextVisitor.outputContext.canonicalize();
		return this.contextVisitor.outputContext.getPattern();
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
	 * @param address The address that we want to compile at
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
				int charPositionInLine, String msg, RecognitionException e) {
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
	 * @param pattern    The pattern string to parse into steps
	 * @param newMonitor A monitor to display progress
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

		this.contextVisitor.makeContextAware();

		monitor.setIndeterminate(false);
	}

	/**
	 * Represents the start of a branch in the generated pattern.
	 */
	static class ContextStackItem {
		RegisterValue context; // context at the start of the branch
		int startIdx; // index of the output of the first visitor where the first step of the branch
						// begins

		public ContextStackItem(RegisterValue context, int startIdx) {
			this.context = context;
			this.startIdx = startIdx;
		}
	}
}
