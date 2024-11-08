package org.mitre.pickledcanary;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;
import org.mitre.pickledcanary.gui.*;
import org.mitre.pickledcanary.headless.*;

@RunWith(Suite.class)

// All GUI tests must run before any non-GUI tests
@SuiteClasses( 
	{
		// GUI Tests
		GuiTest.class,
		
		// Non-GUI Tests
		Aarch64LE64AppleSiliconPickledCanaryTest.class,
		ArmLePickledCanaryTest.class,
		ArmThumbLePickledCanaryTest.class,
		BitArrayTest.class,
		MipsBePickledCanaryTest.class,
		MipsLePickledCanaryTest.class,
		MiscTest.class,
		SearchBenchmark.class,
		SearchTest.class,
		X86_64LePickledCanaryTest.class,
		X86LePickledCanaryTest.class
	}
)
public class AllTests {

}
