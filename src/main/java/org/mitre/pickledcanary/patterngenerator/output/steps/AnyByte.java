
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Objects;

public class AnyByte extends StepBranchless {

	public AnyByte() {
		super(StepType.ANYBYTE, null);
	}

	public AnyByte(String note) {
		super(StepType.ANYBYTE, note);
	}

	@Override
	public String toString() {
		return "AnyByte";
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
		AnyByte other = (AnyByte) o;
		// field comparison
		return Objects.equals(this.stepType, other.stepType);
	}
}
