
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Objects;

public class Match extends StepBranchless {

	public Match() {
		super(StepType.MATCH, null);
	}

	public Match(String note) {
		super(StepType.MATCH, note);
	}

	@Override
	public String toString() {
		return "MATCH";
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
		Match other = (Match) o;
		// field comparison
		return Objects.equals(this.stepType, other.stepType);
	}
	
	@Override
	public int hashCode() {
		return stepType.hashCode();
	}
}
