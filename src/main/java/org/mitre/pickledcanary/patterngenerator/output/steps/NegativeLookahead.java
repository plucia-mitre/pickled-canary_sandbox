
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.Objects;

import org.json.JSONObject;

public class NegativeLookahead extends StepBranchless {

	private JSONObject pattern;

	public NegativeLookahead(JSONObject pattern) {
		super(StepType.NEGATIVELOOKAHEAD, null);
		this.pattern = pattern;
	}

	public NegativeLookahead(JSONObject pattern, String note) {
		super(StepType.NEGATIVELOOKAHEAD, note);
		this.pattern = pattern;
	}

	public void setPattern(JSONObject pattern) {
		this.pattern = pattern;
	}

	@Override
	public JSONObject getJson() {
		JSONObject out = super.getJson();
		out.put("pattern", this.pattern);
		return out;
	}

	@Override
	public String toString() {
		return "NEGATIVE LOOK AHEAD Pattern: " + pattern.toString();
	}

	@Override
	/**
	 * THIS ISN'T GREAT! It compares the inner patterns as JSONObjects, which will almost always say
	 * they are different even if the content is the same!
	 */
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
		NegativeLookahead other = (NegativeLookahead) o;
		// field comparison
		return Objects.equals(this.stepType, other.stepType) && this.pattern.equals(other.pattern);
	}
}
