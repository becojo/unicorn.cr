require "./spec_helper"

include Unicorn

describe Unicorn do
  it "can instanciate architectures" do
    Uc.new(UC_ARCH_X86, UC_MODE_16)
    Uc.new(UC_ARCH_X86, UC_MODE_32)
    Uc.new(UC_ARCH_X86, UC_MODE_64)

    Uc.new(UC_ARCH_ARM, UC_MODE_ARM)
    Uc.new(UC_ARCH_ARM, UC_MODE_THUMB)
    Uc.new(UC_ARCH_ARM64, UC_MODE_ARM)
    Uc.new(UC_ARCH_ARM64, UC_MODE_THUMB)

    Uc.new(UC_ARCH_MIPS, UC_MODE_MIPS32)
    Uc.new(UC_ARCH_MIPS, UC_MODE_MIPS64)
  end

  it "can catch unmapped memory" do
    mu = Uc.new(UC_ARCH_X86, UC_MODE_32)
    x86_code32_mem_write = "\x89\x0d\xaa\xaa\xaa\xaa\x41\x4a"
    address = 0x100000

    mu.mem_map(address, 2 * 1024 * 1024)
    mu.mem_write(address, x86_code32_mem_write)

    mu.reg_write(UC_X86_REG_ECX, 0x1234_u64)
    mu.reg_write(UC_X86_REG_EDX, 0x7890_u64)

    mu.hook_mem(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED) { |type, address, size, value|
      if type == UC_MEM_WRITE_UNMAPPED
        mu.mem_map(0xaaaa0000, 2 * 1024*1024, UC_PROT_ALL)
      else
        false
      end
    }

    mu.emu_start(address, address + x86_code32_mem_write.size)
  end

  it "can emulate x86-32 interupt" do
    mu = Uc.new(UC_ARCH_X86, UC_MODE_32)
    x86_code32_intr = [0xcd_u8, 0x80_u8]
    address = 0x100000
    invoked = false

    mu.mem_map(address, 2 * 1024 * 1024)
    mu.mem_write(address, x86_code32_intr)

    mu.hook_intr { |no|
      no.should eq(0x80)
      invoked = true
    }

    mu.emu_start(address, address + x86_code32_intr.size)

    invoked.should be_true
  end

  it "can emulate x86-64 syscall" do
    mu = Uc.new(UC_ARCH_X86, UC_MODE_64)
    x86_code64_syscall = "\x0f\x05"
    address = 0x100000
    invoked = false

    mu.mem_map(address, 2 * 1024 * 1024)
    mu.mem_write(address, x86_code64_syscall)

    mu.hook_syscall {
      invoked = true
    }

    mu.emu_start(address, address + x86_code64_syscall.size)

    invoked.should be_true
  end

  it "can emulate x86-32" do
    mu = Uc.new(UC_ARCH_X86, UC_MODE_32)
    x86_code32_inout = "\x41\xE4\x3F\x4a\xE6\x46\x43"
    address = 0x100000

    mu.mem_map(address, 2 * 1024 * 1024)
    mu.mem_write(address, x86_code32_inout)

    mu.reg_write(UC_X86_REG_ECX, 0x6789_u64)
    mu.reg_write(UC_X86_REG_EAX, 0x1234_u64)

    mu.hook_insn_in { |port, size|
      eip = mu.reg_read(UC_X86_REG_EIP)

      # puts "--- reading from port 0x#{port.to_s(16)}, size: #{size}, address: 0x#{eip.to_s(16)}"

      0xf0_u64 | size
    }

    mu.hook_insn_out { |port, size, value|
      eip = mu.reg_read(UC_X86_REG_EIP)

      # puts "--- writing to port 0x#{port.to_s(16)}, size: #{size}, value: 0x#{value.to_s(16)}, address: 0x#{eip.to_s(16)}"

      v = 0
      if size == 1
        v = mu.reg_read(UC_X86_REG_AL)
      elsif size == 2
        v = mu.reg_read(UC_X86_REG_AX)
      elsif size == 4
        v = mu.reg_read(UC_X86_REG_EAX)
      end
    }

    mu.emu_start(address, address + x86_code32_inout.size)

    mu.reg_read(UC_X86_REG_EAX).to_u32.should eq(0x12f1)
    mu.reg_read(UC_X86_REG_ECX).to_u32.should eq(0x678a)
  end

  it "can emulate x86 16-bit code" do
    mu = Uc.new(UC_ARCH_X86, UC_MODE_16)
    x86_code16 = "\x00\x00" # add   byte ptr [bx + si], al

    # map 8KB memory for this emulatino
    mu.mem_map(0, 8 * 1024)

    # set CPU registers
    mu.reg_write(UC_X86_REG_EAX, 7)
    mu.reg_write(UC_X86_REG_EBX, 5)
    mu.reg_write(UC_X86_REG_ESI, 6)

    # write machine code to be emulated to memory
    mu.mem_write(0, x86_code16)

    # emulate machine code in infinite time
    mu.emu_start(0, x86_code16.size)

    tmp = mu.mem_read(11, 1)

    tmp[0].should eq(7)
  end

  it "can manipulate memory regions" do
    mu = Uc.new(UC_ARCH_X86, UC_MODE_16)

    mu.mem_map(0, 1024 * 1024)
    mu.mem_map(0x100000, 1024 * 1024, 3)

    mu.mem_regions.should eq([{0, 1024 * 1024 - 1, 7}, {0x100000, 0x100000 + 1024 * 1024 - 1, 3}])
  end
end
