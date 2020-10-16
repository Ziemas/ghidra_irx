package ghidra_irx;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class iopmod_import implements StructConverter {
	private static final int IOPMOD_MAX_LIBRARY_NAME = 8;
	
	private long magic = 0, zero = 0, version = 0;
	private String name = "";
	
	private void Parse(BinaryReader reader) throws IOException {
		magic = reader.readNextUnsignedInt();
		zero = reader.readNextUnsignedInt();
		version = reader.readNextUnsignedInt();
		name = reader.readNextAsciiString(IOPMOD_MAX_LIBRARY_NAME);	
	}


	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("iopmod_import", 0);
		s.add(DWORD, 4, "magic", null);
		s.add(DWORD, 4, "zero", null);
		s.add(DWORD, 4, "version", null);
		s.add(ASCII, IOPMOD_MAX_LIBRARY_NAME, "name", null);
		return null;
	}

}
