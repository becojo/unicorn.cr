require "../unicorn/all"

X86_CODE32             = "\x41\x4a\x66\x0f\xef\xc1"         # INC ecx; DEC edx; PXOR xmm0, xmm1
X86_CODE32_LOOP        = "\x41\x4a\xeb\xfe"                 # INC ecx; DEC edx; JMP self-loop
X86_CODE32_JUMP        = "\xeb\x02\x90\x90\x90\x90\x90\x90" # jmp 4; nop; nop; nop; nop; nop; nop
X86_CODE32_JMP_INVALID = "\xe9\xe9\xee\xee\xee\x41\x4a"     # JMP outside; INC ecx; DEC edx
X86_CODE32_MEM_READ    = "\x8B\x0D\xAA\xAA\xAA\xAA\x41\x4a" # mov ecx,[0xaaaaaaaa]; INC ecx; DEC edx
X86_CODE32_MEM_WRITE   = "\x89\x0D\xAA\xAA\xAA\xAA\x41\x4a" # mov [0xaaaaaaaa], ecx; INC ecx; DEC edx
X86_CODE64             = "\x41\xBC\x3B\xB0\x28\x2A\x49\x0F\xC9\x90\x4D\x0F\xAD\xCF\x49\x87\xFD\x90\x48\x81\xD2\x8A\xCE\x77\x35\x48\xF7\xD9\x4D\x29\xF4\x49\x81\xC9\xF6\x8A\xC6\x53\x4D\x87\xED\x48\x0F\xAD\xD2\x49\xF7\xD4\x48\xF7\xE1\x4D\x19\xC5\x4D\x89\xC5\x48\xF7\xD6\x41\xB8\x4F\x8D\x6B\x59\x4D\x87\xD0\x68\x6A\x1E\x09\x3C\x59"
X86_CODE32_INOUT       = "\x41\xE4\x3F\x4a\xE6\x46\x43" # INC ecx; IN AL, 0x3f; DEC edx; OUT 0x46, AL; INC ebx
X86_CODE64_SYSCALL     = "\x0f\x05"                     # SYSCALL
X86_CODE16             = "\x00\x00"                     # add  byte ptr [bx + si], al

# memory address where emulation starts
ADDRESS = 0x1000000_u64

def make_hook_code_proc(uc)
  Proc(UInt64, UInt64, Nil).new do |address, size|
    puts ">>> Tracing instruction at 0x%x, instruction size = 0x%x" % {address, size}
    eip = uc.reg_read(UC_X86_REG_EFLAGS)
    puts ">>> --- EFLAGS is 0x%x" % (eip)
  end
end

def make_hook_block_proc(uc)
  Proc(UInt64, UInt64, Nil).new do |address, size|
    puts ">>> Tracing basic block at 0x%x, block size = 0x%x" % {address, size}
  end
end

def test_i386_inout
  puts "Emulate i386 code with IN/OUT instructions"

  # Initialize emulator in X86-32bit mode
  mu = Uc.new(UC_ARCH_X86, UC_MODE_32)

  # map 2MB memory for this emulation
  mu.mem_map(ADDRESS, 2 * 1024 * 1024)

  # write machine code to be emulated to memory
  mu.mem_write(ADDRESS, X86_CODE32_INOUT)

  # initialize machine registers
  mu.reg_write(UC_X86_REG_EAX, 0x1234)
  mu.reg_write(UC_X86_REG_ECX, 0x6789)

  # tracing all basic blocks with customized callback
  mu.hook_block(&make_hook_block_proc(mu))

  # tracing all instructions with customized callback
  mu.hook_code(&make_hook_code_proc(mu))

  mu.hook_insn_in { |port, size|
    eip = mu.reg_read(UC_X86_REG_EIP)

    puts "--- reading from port 0x%x, size: %d, address: 0x%x" % {port, size, eip}

    0xf0_u64 | size
  }

  mu.hook_insn_out { |port, size, value|
    eip = mu.reg_read(UC_X86_REG_EIP)

    puts "--- writing to port 0x%x, size: %d, value: 0x%x, address: 0x%x" % {port, size, value, eip}

    v = if size == 1
          mu.reg_read(UC_X86_REG_AL)
        elsif size == 2
          mu.reg_read(UC_X86_REG_AX)
        elsif size == 4
          mu.reg_read(UC_X86_REG_EAX)
        else
          0
        end

    puts "--- register value = 0x%x" % v
  }

  mu.emu_start(ADDRESS, ADDRESS + X86_CODE32_INOUT.bytesize)

  puts ">>> Emulation done. Below is the CPU context"

  r_ecx = mu.reg_read(UC_X86_REG_ECX)
  r_eax = mu.reg_read(UC_X86_REG_EAX)

  puts ">>> EAX = 0x%x" % r_eax
  puts ">>> ECX = 0x%x" % r_ecx
end

def test_i386_jump
  puts "Emulate i386 code with jump"

  # Initialize emulator in X86-32bit mode
  mu = Uc.new(UC_ARCH_X86, UC_MODE_32)

  # map 2MB memory for this emulation
  mu.mem_map(ADDRESS, 2 * 1024 * 1024)

  # write machine code to be emulated to memory
  mu.mem_write(ADDRESS, X86_CODE32_JUMP)

  # tracing all basic blocks with customized callback
  mu.hook_block(ADDRESS, ADDRESS, &make_hook_block_proc(mu))

  # tracing all instructions with customized callback
  mu.hook_code(ADDRESS, ADDRESS, &make_hook_code_proc(mu))

  mu.emu_start(ADDRESS, ADDRESS + X86_CODE32_JUMP.bytesize)
end

def test_x86_64
  puts "Emulate x86_64 code"

  mu = Uc.new(UC_ARCH_X86, UC_MODE_64)

  # map 2MB memory for this emulation
  mu.mem_map(ADDRESS, 2 * 1024 * 1024)

  # write machine code to be emulated to memory
  mu.mem_write(ADDRESS, X86_CODE64.bytes)

  # initialize machine registers
  mu.reg_write(UC_X86_REG_RAX, 0x71f3029efd49d41d)
  mu.reg_write(UC_X86_REG_RBX, 0xd87b45277f133ddb)
  mu.reg_write(UC_X86_REG_RCX, 0xab40d1ffd8afc461)
  mu.reg_write(UC_X86_REG_RDX, 0x919317b4a733f01)
  mu.reg_write(UC_X86_REG_RSI, 0x4c24e753a17ea358)
  mu.reg_write(UC_X86_REG_RDI, 0xe509a57d2571ce96)
  mu.reg_write(UC_X86_REG_R8, 0xea5b108cc2b9ab1f)
  mu.reg_write(UC_X86_REG_R9, 0x19ec097c8eb618c1)
  mu.reg_write(UC_X86_REG_R10, 0xec45774f00c5f682)
  mu.reg_write(UC_X86_REG_R11, 0xe17e9dbec8c074aa)
  mu.reg_write(UC_X86_REG_R12, 0x80f86a8dc0f6d457)
  mu.reg_write(UC_X86_REG_R13, 0x48288ca5671c5492)
  mu.reg_write(UC_X86_REG_R14, 0x595f72f6e4017f6e)
  mu.reg_write(UC_X86_REG_R15, 0x1efd97aea331cccc)

  # setup stack
  mu.reg_write(UC_X86_REG_RSP, ADDRESS + 0x200000)

  # tracing all basic blocks with customized callback
  mu.hook_block(&make_hook_block_proc(mu))

  # tracing all instructions with customized callback
  mu.hook_code(ADDRESS, ADDRESS + 20) { |address, size|
    puts ">>> Tracing instruction at 0x%x, instruction size = 0x%x" % {address, size}
  }

  # tracing all memory READ & WRITE access
  mu.hook_mem(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE) { |access, address, size, value|
    if access == UC_MEM_WRITE
      puts ">>> Memory is being WRITE at 0x%x, data size = %d, data value = 0x%x" % {address, size, value}
    else
      puts ">>> Memory is being READ at 0x%x, data size = %d" % {address, size}
    end
  }

  mu.emu_start(ADDRESS, ADDRESS + X86_CODE64.bytesize)
end

def test_x86_64_syscall
  puts "Emulate x86_64 code with 'syscall' instruction"
  mu = Uc.new(UC_ARCH_X86, UC_MODE_64)

  # map 2MB memory for this emulation
  mu.mem_map(ADDRESS, 2 * 1024 * 1024)

  # write machine code to be emulated to memory
  mu.mem_write(ADDRESS, X86_CODE64_SYSCALL)

  # hook interrupts for syscall
  mu.hook_syscall {
    rax = mu.reg_read(UC_X86_REG_RAX)
    if rax == 0x100
      mu.reg_write(UC_X86_REG_RAX, 0x200)
    else
      puts "ERROR: was not expecting rax=%d in syscall" % rax
    end
  }

  mu.reg_write(UC_X86_REG_RAX, 0x100)

  # emulate machine code in infinite time
  mu.emu_start(ADDRESS, ADDRESS + X86_CODE64_SYSCALL.bytesize)

  # now print out some registers
  puts ">>> Emulation done. Below is the CPU context"

  rax = mu.reg_read(UC_X86_REG_RAX)
  puts ">>> RAX = 0x%x" % rax
end

test_i386_inout

puts "=" * 35
test_i386_jump

puts "=" * 35
test_x86_64

puts "=" * 35
test_x86_64_syscall
