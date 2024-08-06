import pyhidra
import re

with pyhidra.open_program("C:\\Users\\samub\\Documents\\Uni\\"+
    "Tesi Magistrale\\COOP\\COOP_Vuln_program\\x64\\Debug\\COOP_Vuln_program.exe") as flat_api:
    program = flat_api.getCurrentProgram()
    listing = program.getListing()
    functionManager = program.getFunctionManager()

    from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
    from ghidra.program.model.symbol import *
    from ghidra.app.plugin.assembler import *
    decomp_api = FlatDecompilerAPI(flat_api)

    symbol_table = program.getSymbolTable()

    #callguard bypass

    def getAddress(offset):
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

    icall_addr = flat_api.toAddr("__guard_dispatch_icall_fptr")
    if icall_addr is not None:
        refMng = program.getReferenceManager()
        refs = []
        for ref in refMng.getReferencesTo(icall_addr):
            #if ref.getReferenceType() == RefType.INDIRECTION:
                refs.append(ref)

        asm = Assemblers.getAssembler(program)
        for ref in refs:
            ref_addr = ref.getFromAddress()
            callRax = bytearray(b'\xff\xd0\x90\x90\x90\x90') #override call guard with CALL RAX
            asm.patchProgram(callRax, ref_addr)
            for h in range(0,6):
                flat_api.disassemble(ref_addr.add(h))

    print("\n\tVirtual Functions\n")

    vfuncs = []

    for n in symbol_table.getClassNamespaces():
        for c in symbol_table.getChildren(n.getSymbol()):
            if(c.getName()=="`vftable'"):
                for j in range(int(c.object.bytes.length/8)):
                    buff = "0x"+"".join(format((c.object.bytes[j*8+k]+256)% 256,'02x') 
                                   for k in reversed(range(0,8)))
                    addr = getAddress(buff)
                    f = functionManager.getFunctionAt(addr)

                    if f.getName() == "_purecall": #remember to test for multiple constructors!!!
                        for fun in functionManager.getFunctions(True):
                            if n.getName() == fun.getName():
                                f = fun
                    if f.getName() == "`scalar_deleting_destructor'":
                        #flat_api.getGlobalFunctions("~"+f.parentNamespace.getName())
                        for fun in functionManager.getFunctions(True):
                            if "~"+f.parentNamespace.getName() == fun.getName():
                                f = fun

                    if not(any(ele[0].toString() == f.toString() for ele in vfuncs)):
                        d = decomp_api.decompile(f)
                        vfuncs.append([f,d]) 
                break
    
    vfuncs = sorted(vfuncs, key=lambda x: x[0].toString())
    for vf in vfuncs:
        print(vf[0])

    print("\n\tML-Gadgets\n")

    m_loop_g = []

    for vf in vfuncs:
        if re.search(r'for *?\(.*?\) *?\{\s+?\((\*)+\(code\s*?(\*)+\)(\*)?.*?\)\(this->[\s\S^,]*?\);[\s\S]*?\}',vf[1]):
            m_loop_g.append(vf)
            vfuncs.remove(vf)

    for ml in m_loop_g:
        print(ml[0])

    print("\n\tInvoke-Gadgets\n")

    inv_g = []

    for vf in vfuncs:
        if re.search(r'\(\s*?\*this->.*?\s*?\)\(\s*?(this->.*?)?\s*?\)',vf[1]):
            inv_g.append(vf)
            vfuncs.remove(vf)

    for inv in inv_g:
        print(inv[0])

    print("\n\tRead/Write-Gadgets\n")

    w_r_g = []

    for vf in vfuncs:
        if re.search(r'strncpy\((this->.*?|param_.*?),(this->.*?|param_.*?),.*?\)',vf[1]):
            w_r_g.append(vf)
            vfuncs.remove(vf)

    for w_r in w_r_g:
        print(w_r[0])

    decomp_api.dispose()