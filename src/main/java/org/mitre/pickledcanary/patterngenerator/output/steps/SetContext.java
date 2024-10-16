
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import ghidra.program.model.lang.RegisterValue;

public class SetContext extends StepBranchless {

	private RegisterValue toSet;

	public SetContext(RegisterValue toSet) {
		super(StepType.SETCONTEXT, null);
		this.toSet = toSet;
	}
	
	public RegisterValue getContextVar() {
		return this.toSet;
	}
}
