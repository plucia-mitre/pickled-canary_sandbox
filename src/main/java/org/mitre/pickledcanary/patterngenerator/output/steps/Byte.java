
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Objects;

import org.json.JSONObject;

public class Byte extends StepBranchless {

	private int value;

	public Byte(int value) {
		super(StepType.BYTE, null);
		checkValue(value);
		this.value = value;
	}

	public Byte(int value, String note) {
		super(StepType.BYTE, note);
		checkValue(value);
		this.value = value;
	}

	public void setValue(int value) {
		checkValue(value);
		this.value = value;
	}

	private void checkValue(int valueIn) {
		if (valueIn > 255) {
			throw new IllegalArgumentException("Byte value must be <255!");
		}
	}

	public int getValue() {
		return this.value;
	}

	@Override
	public JSONObject getJson() {
		JSONObject out = super.getJson();
		out.put("value", this.value);
		return out;
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
		Byte other = (Byte) o;
		// field comparison
		return Objects.equals(this.stepType, other.stepType) && this.value == other.value;
	}
}
