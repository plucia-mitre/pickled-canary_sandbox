
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

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
	

	@Override
	public boolean equals(Object o) {
		// self check
		if (this == o) {
			return true;
		}
		// null check
		if (o == null) {
			return false;
		}
		// type check and cast
		if (getClass() != o.getClass()) {
			return false;
		}
		Context other = (Context) o;
		// field comparison
		if (!Objects.equals(this.stepType, other.stepType) || this.contextVars.size() != other.contextVars.size()) {
			return false;
		}
		
		// TODO: Is this sufficient? does order matter in this list?
		return this.contextVars.containsAll(other.contextVars);
	}
}
