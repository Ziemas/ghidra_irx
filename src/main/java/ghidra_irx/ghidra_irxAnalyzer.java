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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class ghidra_irxAnalyzer extends AbstractAnalyzer {
    private byte[] IOPMOD_IMPORT_MAGIC = {0x00, 0x00, (byte) 0xe0, 0x41, 0x00, 0x00, 0x00, 0x00}; // 0x41e00000;
    private byte[] jr_ra = {0x08, 0x00, (byte) 0xe0, 0x03};

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


    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        SymbolTable tbl = program.getSymbolTable();

        try {
            File listFile = Application.getModuleDataFile("modules.list").getFile(false);
            ModuleDB db = new ModuleDB(listFile);

            MemoryBlock b = program.getMemory().getBlock(".text");
            Address searchAddr = b.getStart();
            Address endAddr = b.getEnd();
            while (!monitor.isCancelled() && searchAddr.compareTo(endAddr) == -1) {
                Address addr = program.getMemory().findBytes(searchAddr, endAddr, IOPMOD_IMPORT_MAGIC, null, true, TaskMonitor.DUMMY);

                if (addr == null) {
                    break;
                }

                byte[] namebytes = new byte[8];

                try {
                    program.getMemory().getBytes(addr.add(12), namebytes, 0, 8);
                } catch (MemoryAccessException e) {
                    e.printStackTrace();
                }

                String nameString = new String(namebytes).split("\0")[0];

                try {
                    tbl.createLabel(addr, "imports_" + nameString, SourceType.ANALYSIS);
                } catch (InvalidInputException e) {
                    return false;
                }

                searchAddr = addr.add(20);
                while (!monitor.isCancelled()) {
                    addr = program.getMemory().findBytes(searchAddr, searchAddr.add(8), jr_ra, null, true, TaskMonitor.DUMMY);
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
                            tbl.createLabel(addr, nameString.concat("_").concat(Integer.toString(imm)), SourceType.ANALYSIS);
                        }
                    } catch (InvalidInputException e) {
                        return false;
                    }

                    searchAddr = addr.add(8);

                }
            }

        } catch (IOException e) {
            return false;
        }

        return true;
    }
}
