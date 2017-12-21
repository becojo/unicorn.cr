require "../unicorn/all"

# Create a new instance of unicorn engine to emulate X86-32
mu = Uc.new(UC_ARCH_X86, UC_MODE_32)

code = "\x83\xc0{" # add eax, 123

# Map 1 mb of memory at address 0
mu.mem_map(0, 1024 * 1024)

# Write the code
mu.mem_write(0, code)

# Set eax = 54
mu.reg_write(UC_X86_REG_EAX, 54)

# Tracing all instructions with customized callback
mu.hook_code do |address, size|
  puts ">>> Tracing instruction at 0x%x, instruction size = 0x%x" % {address, size}
end

# Tracing all memory READ & WRITE access
mu.hook_mem(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE) { |access, address, size, value|
  if access == UC_MEM_WRITE
    puts ">>> Memory is being WRITE at 0x%x, data size = %d, data value = 0x%x" % {address, size, value}
  else
    puts ">>> Memory is being READ at 0x%x, data size = %d" % {address, size}
  end
}

mu.hook_block do |address, size|
  puts ">>> Tracing basic block at 0x%x, block size = 0x%x" % {address, size}
end

# Run the code
mu.emu_start(0, code.size)

# Inspect resulting context
r_eax = mu.reg_read(UC_X86_REG_EAX)

puts "123 + 54 = #{r_eax}"
