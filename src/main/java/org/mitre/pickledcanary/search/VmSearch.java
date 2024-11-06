
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.search;

import java.util.LinkedList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.task.TaskMonitor;

/**
 * Wraps pikevm allowing for the entire binary to be searched (e.g. all
 * addressRanges are searched, not just one).
 * <p>
 * Additionally, provides a helper method which can search across
 *
 */
public class VmSearch {

	public final Pattern pattern;
	public final Memory memory;

	public VmSearch(Pattern pattern, Memory memory) {
		this.pattern = pattern;
		this.memory = memory;
	}

	/**
	 * Finds the first match in the given buf which starts at address start
	 */
	SavedDataAddresses runBuf(TaskMonitor monitor, MemBuffer buf, Address start) {
		Pikevm vm = new Pikevm(pattern, buf, monitor);
		SavedData result = vm.run();
		if (result != null) {
			return new SavedDataAddresses(result, start);
		}
		return null;
	}

	/**
	 * Finds the first match (and only the first match)
	 */
	public SavedDataAddresses run(TaskMonitor monitor) {

		for (AddressRange range : this.memory.getAddressRanges()) {

			if (monitor.isCancelled()) {
				return null;
			}

			MemBuffer buf = new MemoryBufferImpl(this.memory, range.getMinAddress());
			return runBuf(monitor, buf, range.getMinAddress());
		}
		return null;
	}

	/**
	 * Finds all matches
	 */
	public List<SavedDataAddresses> runAll(TaskMonitor monitor) {
		List<SavedDataAddresses> out = new LinkedList<>();
		for (AddressRange range : this.memory.getAddressRanges()) {

			if (monitor.isCancelled()) {
				return null;
			}

			Address start = range.getMinAddress();

			while (true) {

				MemBuffer buf = new MemoryBufferImpl(this.memory, start);
				SavedDataAddresses rangeOut = runBuf(monitor, buf, start);
				if (rangeOut == null) {
					break;
				}
				out.add(rangeOut);

				start = rangeOut.getStart().next();
				if (start == null) {
					break;
				}

			}
		}
		return out;
	}

	/**
	 * Finds all matches
	 */
	public void runAll(TaskMonitor monitor, Accumulator<SavedDataAddresses> accumulator) {

		int totalRanges = this.memory.getNumAddressRanges();
		int currentRangeNumber = 1;
		monitor.setIndeterminate(false);
		
		long totalSizeToSearch = 0;
		for (AddressRange range: this.memory.getAddressRanges()) {
			totalSizeToSearch += range.getLength();
		}

		monitor.setIndeterminate(false);
		monitor.setProgress(0);
		monitor.setMaximum(totalSizeToSearch);
		long totalSearched = 0;
		for (AddressRange range : this.memory.getAddressRanges()) {

			monitor.setMessage("Searching memory range " + currentRangeNumber + " of " + totalRanges);

			Address start = range.getMinAddress();

			while (true) {

				MemBuffer buf = new MemoryBufferImpl(this.memory, start);
				SavedDataAddresses rangeOut = runBuf(monitor, buf, start);
				if (rangeOut == null) {
					break;
				}
				accumulator.add(rangeOut);
				
				totalSearched += rangeOut.getStart().subtract(start);
				monitor.setProgress(totalSearched);

				start = rangeOut.getStart().next();
				if (start == null) {
					break;
				}
 
				monitor.setMessage("Searching memory range " + currentRangeNumber + " of " + totalRanges);
				if (monitor.isCancelled()) {
					return;
				}
			}

			currentRangeNumber += 1;
		}
	}
}
