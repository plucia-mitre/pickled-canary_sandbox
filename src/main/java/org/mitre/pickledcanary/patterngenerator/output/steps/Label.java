
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Objects;

import org.json.JSONObject;

public class Label extends StepBranchless {

	private String value;

	public Label(String value) {
		super(StepType.LABEL, null);
		this.value = value;
	}

	public Label(String value, String note) {
		super(StepType.BYTE, note);
		this.value = value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	public String getValue() {
		return this.value;
	}

	@Override
	public JSONObject getJson() {
		JSONObject out = super.getJson();
		out.put("value", this.value);
		return out;
	}

	@Override
	public String toString() {
		return "LABEL: " + value;
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
		Label other = (Label) o;
		// field comparison
		return Objects.equals(this.stepType, other.stepType) && this.value.equals(other.value);
	}
}
