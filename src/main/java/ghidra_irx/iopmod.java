package ghidra_irx;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class iopmod implements StructConverter {
	
	
	private long id_addr = 0, entry_addr = 0;
	private long unk = 0, text_size = 0;
	private long data_size = 0, bss_size = 0;
	private long version = 0;
	
	private String name = "";
	
	private void Parse(BinaryReader reader) throws IOException {
		id_addr = reader.readNextUnsignedInt();
		entry_addr = reader.readNextUnsignedInt();
		unk = reader.readNextUnsignedInt();
		text_size = reader.readNextUnsignedInt();
		data_size = reader.readNextUnsignedInt();
		bss_size = reader.readNextUnsignedInt();
		version = reader.readNextShort();
		name = reader.readNextNullTerminatedAsciiString();
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("IOPMod", 0);
		s.add(POINTER, 4, "id_addr", null);
		s.add(POINTER, 4, "entry_addr", null);
		s.add(DWORD, 4, "unknown", null);
		s.add(DWORD, 4, "text_size", null);
		s.add(DWORD, 4, "data_size", null);
		s.add(DWORD, 4, "bss_size", null);
		s.add(WORD, 2, "version", null);
		s.add(STRING, 0, "name", null);
		
		
		return null;
	}

}
