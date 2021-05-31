import ghidra.app.util.headless.HeadlessScript;

import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

import java.io.PrintWriter;
import java.io.PrintStream;
import java.io.FileOutputStream;

import java.util.Iterator;
import java.util.Stack;
import java.util.HashSet;
import java.util.Set;

public class ExportCFG extends HeadlessScript {

    public void run() throws Exception {

        // Get the output file from the command line argument
        String[] args = getScriptArgs();
        String path   = "/dev/shm/cfg.json";
        if (args.length == 0) {
            System.err.println("Using /dev/shm/cfg.json as default path");
        } else {
            path = args[0];
        }

        printf("[DEBUG] Output file: %s\n", path); // DEBUG
        FileOutputStream fout;
        try {
            fout = new FileOutputStream(path);
        } catch (Exception e) {
            printf("Failed opening output file: Exception %s\n", e.toString());
            return;
        }
        PrintStream pout = new PrintStream(fout);

        // The actual thing
        SimpleBlockModel model = new SimpleBlockModel(currentProgram);

        Listing listing = currentProgram.getListing();
        FunctionIterator iter_functions = listing.getFunctions(true);

        boolean first_iter_functions = true;
        pout.format("[\n");
        while (iter_functions.hasNext() && !monitor.isCancelled()) {
            Function f = iter_functions.next();
            // if (f.isExternal() || f.isThunk()) {
            //     continue;
            // }

            if (!first_iter_functions)
                pout.format(" },\n");
            else
                first_iter_functions = false;

            pout.format(" {\n");
            pout.format("  \"name\": \"%s\",\n", f.getName());
            pout.format("  \"addr\": \"%#x\",\n", f.getEntryPoint().getOffset());
            pout.format("  \"blocks\": [\n");
            CodeBlock entry_block  = model.getCodeBlockAt(f.getEntryPoint(), monitor);
            if (entry_block == null) {
                pout.format("  ]\n");
                continue;
            }

            Stack<CodeBlock> stack = new Stack<>();
            Set<CodeBlock> visited = new HashSet<>();
            stack.push(entry_block);

            while (!stack.empty()) {
                CodeBlock block = stack.pop();
                visited.add(block);

                pout.format("    {\n");
                pout.format("      \"addr\" : \"%#x\",\n", block.getFirstStartAddress().getOffset());
                pout.format("      \"instructions\" : [\n", block.getFirstStartAddress().getOffset());
                InstructionIterator iter = currentProgram.getListing().getInstructions(block, true);
                while (iter.hasNext()) {
                    Instruction inst = iter.next();
                    pout.format("        { \"addr\": \"%#x\", \"mnemonic\" : \"%s\" }", inst.getAddress().getOffset(), inst.toString());
                    if (iter.hasNext())
                        pout.format(",\n");
                    else
                        pout.format("\n");
                }
                pout.format("      ],\n");

                pout.format("      \"successors\" : [\n");
                boolean first_iter_insts = true;
                Set<Long> call_successors = new HashSet<>();
                CodeBlockReferenceIterator succ_iter = block.getDestinations​(monitor);
                while (succ_iter.hasNext()) {
                    CodeBlockReference succ_ref = succ_iter.next();
                    if (succ_ref.getFlowType().isCall()) {
                        call_successors.add(succ_ref.getDestinationAddress().getOffset());
                        continue;
                    }

                    if (!first_iter_insts)
                        pout.format(",\n");
                    else
                        first_iter_insts = false;

                    CodeBlock succ = succ_ref.getDestinationBlock();
                    if (!visited.contains(succ) && succ != null)
                        stack.push(succ);
                    pout.format("        \"%#x\"", succ.getFirstStartAddress().getOffset());
                }
                pout.format("\n");
                pout.format("      ],\n");

                pout.format("      \"calls\" : [\n");
                Iterator<Long> calls = call_successors.iterator();
                while(calls.hasNext()) {
                    Long call = calls.next();
                    pout.format("        \"%#x\"", call);
                    if (calls.hasNext())
                        pout.format(",\n");
                    else
                        pout.format("\n");
                }
                pout.format("      ]\n");

                if (stack.empty())
                    pout.format("    }\n");
                else
                    pout.format("    },\n");
            }
            pout.format("  ]\n");
        }
        if (!first_iter_functions)
            pout.format(" }\n");
        pout.format("]\n");

        fout.close();
        pout.close();
    }
}
