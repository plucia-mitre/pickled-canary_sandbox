
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Objects;

public class SaveStart extends StepBranchless {

	public SaveStart() {
		super(StepType.SAVESTART, null);
	}

	public SaveStart(String note) {
		super(StepType.SAVESTART, note);
	}

	@Override
	public String toString() {
		return "SAVE START";
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
		SaveStart other = (SaveStart) o;
		// field comparison
		return Objects.equals(this.stepType, other.stepType);
	}
}
