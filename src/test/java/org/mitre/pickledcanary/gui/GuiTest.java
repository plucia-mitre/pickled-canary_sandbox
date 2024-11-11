package org.mitre.pickledcanary.gui;

import org.junit.Before;
import org.junit.Test;
import org.mitre.pickledcanary.searchInterface.PickledCanarySearchTablePlugin;
import org.mitre.pickledcanary.searchInterface.PickledCanarySearchTableProvider;

import docking.action.DockingActionIf;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractProgramBasedTest;

import java.util.concurrent.TimeUnit;

import javax.swing.JTextArea;

import org.junit.Assert;

public class GuiTest extends AbstractProgramBasedTest {

	@Override
	protected String getProgramName() {
		return "TestBinary";
	}

	static final int dataBase = 0x1000;
	static final int beqOffset = 0x1000;
	
	@Override
	protected Program getProgram() throws Exception {
		
		ProgramBuilder builder = new ProgramBuilder("arm_le_test", "ARM:LE:32:v8");
		String movr10 = "00 10 a0 e3";
		String movr30 = "00 30 a0 e3";
		builder.setBytes(String.format("0x%08X", dataBase),
				"85 4f dc 77 85 4f dc 77 " + movr10 + " " + movr30 + " " + movr10 + "ff ");
		builder.setBytes(String.format("0x%08X", dataBase + beqOffset),
				"02 00 00 0a 00 00 a0 e1 00 00 a0 e1 00 00 a0 e1 00 00 a0 e1");

		 
		return builder.getProgram();
	}
	
	private PickledCanarySearchTablePlugin plugin;
	
	@Before
	public void setUp() throws Exception {
		initialize();
		env.getTool().addPlugin(PickledCanarySearchTablePlugin.class.getName());
		
		plugin = getPlugin(env.getTool(), PickledCanarySearchTablePlugin.class);
	}
	
	@Test
	public void testLaunch() throws InterruptedException {
		var expected = """
{
    "tables": [{
        "r2": [{
            "value": [2],
            "mask": [15]
        }],
        "r3": [{
            "value": [3],
            "mask": [15]
        }],
        "r4": [{
            "value": [4],
            "mask": [15]
        }],
        "r5": [{
            "value": [5],
            "mask": [15]
        }],
        "r6": [{
            "value": [6],
            "mask": [15]
        }],
        "r7": [{
            "value": [7],
            "mask": [15]
        }],
        "r8": [{
            "value": [8],
            "mask": [15]
        }],
        "lr": [{
            "value": [14],
            "mask": [15]
        }],
        "r9": [{
            "value": [9],
            "mask": [15]
        }],
        "r0": [{
            "value": [0],
            "mask": [15]
        }],
        "r1": [{
            "value": [1],
            "mask": [15]
        }]
    }],
    "steps": [{
        "data": [{
            "type": "MaskAndChoose",
            "choices": [{
                "operands": [{
                    "var_id": "Q1",
                    "type": "Field",
                    "table_id": 0,
                    "mask": [
                        0,
                        240,
                        0,
                        0
                    ]
                }],
                "value": [0,0,160,227]
            }],
            "mask": [
                255,
                15,
                255,
                255
            ]
        }],
        "type": "LOOKUP"
    }],
    "compile_info": [{
        "compiled_using_binary": [{
            "path": ["unknown"],
            "compiled_at_address": ["00001000"],
            "md5": ["unknown"]
        }],
        "language_id": ["ARM:LE:32:v8"]
    }],
    "pattern_metadata": {}
}""";
		
		DockingActionIf action = getAction(plugin, "Search Stuff");
		
		performAction(action);
		
		PickledCanarySearchTableProvider provider = (PickledCanarySearchTableProvider) getInstanceField("provider", plugin);
		JTextArea textArea = (JTextArea) getInstanceField("textArea", provider);
		JTextArea compiledTextArea = (JTextArea) getInstanceField("textAreaCompiled", provider);

		Assert.assertEquals("Compile pattern first!", compiledTextArea.getText());
		
		TimeUnit.SECONDS.sleep(1);

		textArea.setText("mov `Q1/[lr].`,#0x0");
		invokeInstanceMethod("doSearch", provider, new Class<?>[] {boolean.class}, new Object[] {false});
		
		// TODO: Check status here rather than generic sleep
		TimeUnit.SECONDS.sleep(10);
		Assert.assertEquals(expected, compiledTextArea.getText());
		TimeUnit.SECONDS.sleep(1);
	}
}