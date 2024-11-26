
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;

import ghidra.program.model.lang.RegisterValue;

public class Context extends StepBranchless {

	private Collection<RegisterValue> contextVars;

	public Context() {
		super(StepType.CONTEXT, null);
		contextVars = new HashSet<>();
	}

	public Collection<RegisterValue> getContextVars() {
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
		
		return this.contextVars.containsAll(other.contextVars);
	}
	
	@Override
	public int hashCode() {
		return Objects.hash(stepType, contextVars);
	}
}
