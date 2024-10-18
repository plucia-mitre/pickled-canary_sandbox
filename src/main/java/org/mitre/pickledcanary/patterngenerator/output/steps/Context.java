
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.lang.RegisterValue;

public class Context extends StepBranchless {

	private List<RegisterValue> contextVars;

	public Context() {
		super(StepType.CONTEXT, null);
		contextVars = new ArrayList<RegisterValue>();
	}

	public List<RegisterValue> getContextVars() {
		return contextVars;
	}
	
	public void addContextVar(RegisterValue contextVar) {
		contextVars.add(contextVar);
	}

	@Override
	public String toString() {
		return "CONTEXT: " + contextVars.toString();
	}
}
