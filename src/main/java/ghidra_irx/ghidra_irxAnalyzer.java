/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra_irx;

import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * TODO: Provide class-level documentation that describes what this analyzer
 * does.
 */
public class ghidra_irxAnalyzer extends AbstractAnalyzer {
	private static byte[] IOPMOD_IMPORT_MAGIC = { 0x00, 0x00, (byte) 0xe0, 0x41, 0x00, 0x00, 0x00, 0x00 }; // 0x41e00000;
	private static byte[] IOPMOD_EXPORT_MAGIC = { 0x00, 0x00, (byte) 0xc0, 0x41, 0x00, 0x00, 0x00, 0x00 }; // 0x41c00000;
	private static byte[] jr_ra = { 0x08, 0x00, (byte) 0xe0, 0x03 };

	public ghidra_irxAnalyzer() {
		super("IRX import analyzer", "Finds and names IRX imports", AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		var blocks = program.getMemory().getBlocks();
		for (MemoryBlock b : blocks) {
			if (b.getName().equals(".iopmod")) {
				return true;
			}
		}

		return false;
	}

	private static String getStubName(Program program, Address addr) {
		byte[] namebytes = new byte[8];

		try {
			program.getMemory().getBytes(addr.add(12), namebytes, 0, 8);
		} catch (MemoryAccessException e) {
			e.printStackTrace();
		}

		String nameString = new String(namebytes).split("\0")[0];

		return nameString;
	}

	private static boolean labelImports(Program program, ModuleDB db) {
		SymbolTable tbl = program.getSymbolTable();
		MemoryBlock b = program.getMemory().getBlock(".text");
		Address searchAddr = b.getStart();
		Address endAddr = b.getEnd();

		while (searchAddr.compareTo(endAddr) == -1) {
			Address addr = program.getMemory().findBytes(searchAddr, endAddr, IOPMOD_IMPORT_MAGIC, null, true,
					TaskMonitor.DUMMY);

			if (addr == null) {
				break;
			}

			String nameString = getStubName(program, addr);

			try {
				tbl.createLabel(addr, "imports_" + nameString, SourceType.ANALYSIS);
			} catch (InvalidInputException e) {
				return false;
			}

			searchAddr = addr.add(20);
			while (true) {
				addr = program.getMemory().findBytes(searchAddr, searchAddr.add(8), jr_ra, null, true,
						TaskMonitor.DUMMY);
				if (addr == null) {
					break;
				}

				int imm = 0;
				try {
					imm = program.getMemory().getShort(addr.add(4));
				} catch (MemoryAccessException e) {
					return false;
				}

				String function = db.getEntry(nameString, imm);

				try {
					if (function != "") {
						tbl.createLabel(addr, function, SourceType.ANALYSIS);
					} else {
						tbl.createLabel(addr, nameString.concat("_").concat(Integer.toString(imm)),
								SourceType.ANALYSIS);
					}
				} catch (InvalidInputException e) {
					return false;
				}

				searchAddr = addr.add(8);
			}
		}

		return true;
	}

	private static boolean labelExports(Program program, ModuleDB db) throws MemoryAccessException {
		SymbolTable tbl = program.getSymbolTable();
		Memory mem = program.getMemory();
		MemoryBlock b = program.getMemory().getBlock(".text");
		Address searchAddr = b.getStart();
		Address endAddr = b.getEnd();
		RelocationTable rel = program.getRelocationTable();

		while (searchAddr.compareTo(endAddr) == -1) {
			Address addr = program.getMemory().findBytes(searchAddr, endAddr, IOPMOD_EXPORT_MAGIC, null, true,
					TaskMonitor.DUMMY);

			if (addr == null) {
				break;
			}

			String nameString = getStubName(program, addr);

			try {
				tbl.createLabel(addr, "exports_" + nameString, SourceType.ANALYSIS);
			} catch (InvalidInputException e) {
				return false;
			}

			searchAddr = addr.add(20);
			addr = addr.add(20);
			int i = 0;
			while (true) {
				int ptr = mem.getInt(addr);
				if (ptr == 0 && !rel.hasRelocation(addr)) {
					break;
				}

				Address funAddr = b.getStart().add(ptr);

				String function = db.getEntry(nameString, i);

				try {
					if (function != "") {
						tbl.createLabel(funAddr, function, SourceType.ANALYSIS);
					}
				} catch (InvalidInputException e) {
					return false;
				}

				i++;
				addr = addr.add(4);
			}

		}

		return true;
	}

	// Code borrowed from ghidra_psx_loader
	private static DataTypeManager loadTypeArchive(Program program, String gdtName, AddressSetView set,
			TaskMonitor monitor, MessageLog log) {
		DataTypeManagerService srv = AutoAnalysisManager.getAnalysisManager(program).getDataTypeManagerService();

		if (gdtName.isEmpty()) {
			return null;
		}

		try {
			DataTypeManager[] mgrs = srv.getDataTypeManagers();

			for (DataTypeManager mgr : mgrs) {
				if (mgr.getName().equals(gdtName)) {
					applyDataTypes(program, set, mgr, monitor);
					return mgr;
				}
			}

			DataTypeManager mgr = srv.openDataTypeArchive(gdtName);

			if (mgr == null) {
				throw new IOException(String.format("Cannot find \"%s\" data type archive!", gdtName));
			}

			if (set != null) {
				applyDataTypes(program, set, mgr, monitor);
			}

			return mgr;
		} catch (IOException | DuplicateIdException e) {
			log.appendException(e);
		}

		return null;
	}

	private static void applyDataTypes(Program program, AddressSetView set, DataTypeManager mgr, TaskMonitor monitor) {
		int transId = program.startTransaction("Apply function data types");

		List<DataTypeManager> gdtList = new ArrayList<>();
		gdtList.add(mgr);
		ApplyFunctionDataTypesCmd cmd = new ApplyFunctionDataTypesCmd(gdtList, set, SourceType.ANALYSIS, true, false);
		cmd.applyTo(program, monitor);

		program.endTransaction(transId, true);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		try {
			File listFile = Application.getModuleDataFile("modules.list").getFile(false);
			ModuleDB db = new ModuleDB(listFile);

			labelImports(program, db);
			labelExports(program, db);

			loadTypeArchive(program, "iop_types", set, TaskMonitor.DUMMY, log);

		} catch (IOException | MemoryAccessException e) {
			return false;
		}

		return true;
	}
}
