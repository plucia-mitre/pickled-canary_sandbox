package org.mitre.pickledcanary;

import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mitre.pickledcanary.search.SavedDataAddresses;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.database.ProgramBuilder;

public class ContextTest extends PickledCanaryTest {

	@Override
	protected String getCompileInfoRaw() {
		return ",\"compile_info\":[{\"compiled_using_binary\":[{\"path\":[\"unknown\"],\"compiled_at_address\":[\"00000000\"],\"md5\":[\"unknown\"]}],\"language_id\":[\"ctxtest:LE:16:default\"]}],\"pattern_metadata\":{}}";
	}

	private static final String ambiguousContextPattern = 
			"Add R1, `Q1`\r\n"
			+ "Shift R1, R1";

	private static final String tablesForAmbiguousContextPattern = "{\"R2\":[{\"value\":[1],\"mask\":[15]}],\"R3\":[{\"value\":[2],\"mask\":[15]}],\"R4\":[{\"value\":[3],\"mask\":[15]}],\"R1\":[{\"value\":[0],\"mask\":[15]}]}";

	private static final String stepsForAmbiguousContextPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[15,0]}],\"value\":[0,12]},{\"operands\":[{\"expression\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[15,0]}],\"value\":[0,13]}],\"mask\":[240,255]}],\"type\":\"LOOKUP\"},{\"dest2\":4,\"type\":\"SPLIT\",\"dest1\":2},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,18]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"type\":\"JMP\",\"dest\":5},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,17]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"}";

	private static final String contextBasedBranchPattern = 
			"BranchC `Q1`\r\n"
			+ "`ANY_BYTES{2,2}`\r\n"
			+ "Add R1, R1";

	private static final String tablesForContextBasedBranchPattern = "";

	private static final String stepsForContextBasedBranchPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"Add\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":0,\"bigendian\":false,\"bytestart\":0}}},\"right\":{\"op\":\"ContextField\",\"value\":{\"bitend\":31,\"shift\":0,\"signbit\":false,\"bitstart\":28,\"byteend\":3,\"bytestart\":3}}}},\"right\":{\"op\":\"EndInstructionValue\"}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[15,0]}],\"context\":[1],\"value\":[0,14]}],\"mask\":[0,255]}],\"type\":\"LOOKUP\"},{\"note\":\"AnyBytesNode Start: 2 End: 2 Interval: 1 From: Token from line #2: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{2,2}`\",\"min\":2,\"max\":2,\"interval\":1,\"type\":\"ANYBYTESEQUENCE\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,12]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"}";

	private static final String contextValidityPattern = 
			"Set\r\n"
			+ "Unset\r\n"
			+ "Set\r\n"
			+ "Unset";

	private static final String tablesForContextValidityPattern = "";

	private static final String stepsForContextValidityPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,15]}],\"mask\":[0,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,16]}],\"mask\":[0,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,15]}],\"mask\":[0,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,16]}],\"mask\":[0,255]}],\"type\":\"LOOKUP\"}";

	private static final String contextAnnotationPattern = 
			"Shift R1, R1\r\n"
			+ "`CONTEXT`\r\n"
			+ "{set:1}\r\n"
			+ "`END_CONTEXT`\r\n"
			+ "`ANY_BYTES{2,2}`\r\n"
			+ "Shift R1, R1";

	private static final String tablesForContextAnnotationPattern = "";

	private static final String stepsForContextAnnotationPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,17]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"},{\"note\":\"AnyBytesNode Start: 2 End: 2 Interval: 1 From: Token from line #5: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{2,2}`\",\"min\":2,\"max\":2,\"interval\":1,\"type\":\"ANYBYTESEQUENCE\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[0,18]}],\"mask\":[255,255]}],\"type\":\"LOOKUP\"}";

	@Before
	public void setUp() throws Exception {
		SleighLanguage dummy = SleighTestUtils.lazyLanguage(SleighTestUtils.getSleighResource("ctxtest.ldefs"));
		ProgramBuilder builder = new ProgramBuilder("context_test", dummy);

		builder.setBytes("0x00000000", "00 0C"); // Add R1, R1
		builder.setBytes("0x00000002", "00 11"); // Shift R1, R1
		builder.setBytes("0x00000004", "00 0D"); // Add R1, 0x0
		builder.setBytes("0x00000006", "00 12"); // Shift R1, R1

		builder.setBytes("0x00000008", "01 0E"); // BranchC 0xC
		builder.setBytes("0x0000000A", "00 12"); // Shift R1, R1
		builder.setBytes("0x0000000C", "00 0C"); // Add R1, R1

		builder.setBytes("0x0000000E", "00 0F"); // Set
		builder.setBytes("0x00000010", "00 10"); // Unset
		builder.setBytes("0x00000012", "00 0F"); // Set
		builder.setBytes("0x00000014", "00 10"); // Unset

		builder.setBytes("0x00000016", "00 11"); // Shift R1, R1
		builder.setBytes("0x00000018", "00 0F"); // Set
		builder.setBytes("0x0000001A", "00 12"); // Shift R1, R1

		program = builder.getProgram();
	}

	// Compile tests
	@Test
	public void testCompileAmbiguousContextPattern() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForAmbiguousContextPattern + "],\"steps\":["
				+ stepsForAmbiguousContextPattern + "]";
		generatePatternTestHelper(ambiguousContextPattern, testQueryPatternExpected + this.getCompileInfo());
	}

	@Test
	public void testCompileContextBasedBranchPattern() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForContextBasedBranchPattern + "],\"steps\":["
				+ stepsForContextBasedBranchPattern + "]";
		generatePatternTestHelper(contextBasedBranchPattern, testQueryPatternExpected + this.getCompileInfo(this.program.getMinAddress().add(8)), this.program.getMinAddress().add(8));
	}

	@Test
	public void testCompileContextValidityPattern() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForContextValidityPattern + "],\"steps\":["
				+ stepsForContextValidityPattern + "]";
		generatePatternTestHelper(contextValidityPattern, testQueryPatternExpected + this.getCompileInfo());
	}

	@Test
	public void testCompileContextAnnotationPattern() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForContextAnnotationPattern + "],\"steps\":["
				+ stepsForContextAnnotationPattern + "]";
		generatePatternTestHelper(contextAnnotationPattern, testQueryPatternExpected + this.getCompileInfo());
	}

	// Search tests
	@Test
	public void testSearchAmbiguousContextPattern() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program, this.program.getMinAddress(), ambiguousContextPattern);
		Assert.assertEquals(2, results.size());
		Assert.assertEquals(this.program.getMinAddress(), results.get(0).getStart());
		Assert.assertEquals(this.program.getMinAddress().add(4), results.get(1).getStart());
	}

	@Test
	public void testSearchContextBasedBranchPattern() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program, this.program.getMinAddress().add(8), contextBasedBranchPattern);
		Assert.assertEquals(1, results.size());
		Assert.assertEquals(this.program.getMinAddress().add(8), results.get(0).getStart());
	}

	@Test
	public void testSearchContextValidityPattern() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program, this.program.getMinAddress(), contextValidityPattern);
		Assert.assertEquals(1, results.size());
		Assert.assertEquals(this.program.getMinAddress().add(14), results.get(0).getStart());
	}

	@Test
	public void testSearchContextAnnotationPattern() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program, this.program.getMinAddress(), contextAnnotationPattern);
		Assert.assertEquals(2, results.size());
		Assert.assertEquals(this.program.getMinAddress().add(2), results.get(0).getStart());
		Assert.assertEquals(this.program.getMinAddress().add(22), results.get(1).getStart());
	}
}
