require "./unicorn/const/*"
require "./unicorn/*"

module Unicorn
  # Unicorn engine class
  class Uc
    @uc_engine : UcLib::UcEngine

    # Create new instance of unicorn engine.
    # - *arch*: architecture type (UC_ARCH_*)
    # - *mode*: hardware mode. This is combined of UC_MODE_*
    def initialize(arch : Int32, mode : Int32)
      @arch = arch
      @mode = mode

      check_error UcLib.uc_open(arch, mode, out @uc_engine)
    end

    # Write to register.
    def reg_write(reg : Int, value : Int)
      x = value.to_u64
      call(uc_reg_write, reg, pointerof(x))
    end

    # Read register value.
    def reg_read(reg : Int) : Int
      call(uc_reg_read, reg, out value)
      value
    end

    # Add hook to trace interrupts.
    #
    # If *start* < *end*, the *callback* is called only if related address is in range.
    def hook_intr(begin_addr : Int = 1, end_addr = 0, &callback : UInt64 ->) : UcLib::UcHook
      call(uc_hook_add, out handle, UC_HOOK_INTR, ->(uc, number, box, p4, p5, p6) {
        cb = Box(typeof(callback)).unbox(Pointer(Void).new(box))
        cb.call(number)

        1_u64
      }, Box.box(callback), begin_addr, end_addr)

      handle
    end

    # Add hook to trace syscall.
    #
    # If *start* < *end*, the *callback* is called only if related address is in range.
    def hook_syscall(begin_addr : Int = 1, end_addr = 0, &callback : ->) : UcLib::UcHook
      call(uc_hook_add, out handle, UC_HOOK_INSN, ->(uc, p2, box, p4, p5, p6) {
        cb = Box(typeof(callback)).unbox(Pointer(Void).new(box))
        cb.call

        0_u64
      }, Box.box(callback), begin_addr, end_addr, UC_X86_INS_SYSCALL)

      handle
    end

    # Add hook to trace X86 `in` instruction
    #
    # If *start* < *end*, the *callback* is called only if related address is in range.
    #
    # The block is of the form `{ |port, size| value }`
    #
    # Returns `UcLib::UcHook` that can be used in `hook_del` to remove the hook.
    def hook_insn_in(begin_addr : Int = 1, end_addr = 0, &callback : UInt64, UInt64 -> UInt64) : UcLib::UcHook
      call(uc_hook_add, out handle, UC_HOOK_INSN, ->(uc, port, size, box, p5, p6) {
        cb = Box(typeof(callback)).unbox(Pointer(Void).new(box))
        cb.call(port, size)
      }, Box.box(callback), begin_addr, end_addr, UC_X86_INS_IN)

      handle
    end

    # Add hook to trace X86 `out` instruction
    #
    # If *start* < *end*, the *callback* is called only if related address is in range.
    #
    # The block is of the form `{ |port, size, value|  }`
    #
    # Returns `UcLib::UcHook` that can be used in `hook_del` to remove the hook.
    def hook_insn_out(begin_addr : Int = 1, end_addr = 0, &callback : UInt64, UInt64, UInt64 ->) : UcLib::UcHook
      call(uc_hook_add, out handle, UC_HOOK_INSN, ->(uc, port, size, value, box, p6) {
        cb = Box(typeof(callback)).unbox(Pointer(Void).new(box))
        cb.call(port, size, value)

        0_u64
      }, Box.box(callback), begin_addr, end_addr, UC_X86_INS_OUT)

      handle
    end

    # Add hook to trace instructions.
    #
    # If *start* < *end*, the *callback* is called only if related address is in range.
    #
    # The block is of the form `{ |address, size|  }`
    #
    # Returns `UcLib::UcHook` that can be used in `hook_del` to remove the hook.
    def hook_code(begin_addr : Int = 1, end_addr = 0, &callback : UInt64, UInt64 ->) : UcLib::UcHook
      call(uc_hook_add, out handle, UC_HOOK_CODE, ->(uc, address, size, box, p5, p6) {
        cb = Box(typeof(callback)).unbox(Pointer(Void).new(box))
        cb.call(address, size)

        0_u64
      }, Box.box(callback), begin_addr, end_addr)

      handle
    end

    # Add hook to trace basic blocks..
    #
    # If *start* < *end*, the *callback* is called only if related address is in range.
    #
    # The block is of the form `{ |address, size|  }`
    #
    # Returns `UcLib::UcHook` that can be used in `hook_del` to remove the hook.
    def hook_block(begin_addr : Int = 1, end_addr = 0, &callback : UInt64, UInt64 ->) : UcLib::UcHook
      call(uc_hook_add, out handle, UC_HOOK_BLOCK, ->(uc, address, size, box, p5, p6) {
        cb = Box(typeof(callback)).unbox(Pointer(Void).new(box))
        cb.call(address, size)

        0_u64
      }, Box.box(callback), begin_addr, end_addr)

      handle
    end

    # Add hook to trace memory read/write
    #
    # If *start* < *end*, the *callback* is called only if related address is in range.
    #
    # The block is of the form `{ |address, size|  }`
    #
    # Returns `UcLib::UcHook` that can be used in `hook_del` to remove the hook.
    def hook_mem(type : Int, begin_addr : Int = 1, end_addr = 0, &callback : UInt64, UInt64, UInt64, UInt64 -> Bool | Nil) : UcLib::UcHook
      call(uc_hook_add, out handle, type, ->(uc, access, address, size, value, box) {
        cb = Box(typeof(callback)).unbox(Pointer(Void).new(box))
        continue = cb.call(access, address, size, value)

        (continue.nil? || continue) ? 1_u64 : 0_u64
      }, Box.box(callback), begin_addr, end_addr)

      handle
    end

    # Unregister (remove) a hook callback.
    #
    # - *handle*: Value returned by one of the hook functions
    def hook_del(handle : UcLib::UcHook)
      call(uc_hook_del, handle)
    end

    # Map memory in for emulation.
    #
    # - *address*: Starting address of the new memory region to be mapped in.
    # - *size*: Size of the new memory region to be mapped in.
    # - *perms*: Permissions for the newly mapped region.
    #
    # Both *address* and *size* must be multiple of 4KB, or this will raise the exception `UcError(error: UC_ERR_ARG)`.
    def mem_map(address : Int, size : Int, perms : Int = UC_PROT_ALL)
      call(uc_mem_map, address, size, perms)
    end

    # Set memory permissions for emulation memory.
    #
    # - *address*: Starting address of the new memory region to be modified
    # - *size*: Size of the memory region to be modified.
    # - *perms*:  New permissions for the mapped region.
    #
    # Both *address* and *size* must be multiple of 4KB, or this will raise the exception `UcError(error: UC_ERR_ARG)`.
    def mem_protect(address : Int, size : Int, perms : Int)
      call(uc_mem_protect, address, size, perms)
    end

    # Unmap a region of emulation memory.
    #
    # - *address*: Starting address of the memory region to be unmapped.
    # - *size*: size of the memory region to be modified.
    #
    # Both *address* and *size* must be multiple of 4KB, or this will raise the exception `UcError(error: UC_ERR_ARG)`.
    def mem_unmap(address : Int, size : Int)
      call(uc_mem_unmap, address, size)
    end

    # Retrieve all memory regions mapped by `mem_map`.
    #
    # Each region is represented by a tuple of the form `{begin_addr, end_addr, permissions}`
    def mem_regions : Array(Tuple(UInt64, UInt64, UInt32))
      output = [] of Tuple(UInt64, UInt64, UInt32)

      call(uc_mem_regions, out regions, out count)

      count.times do |i|
        output << {regions[i].begin_addr, regions[i].end_addr, regions[i].perms}
      end

      UcLib.uc_free(regions)

      output
    end

    # Write to a range of bytes in memory.
    #
    # - *address*: starting memory address of bytes to set.
    # - *code*: data to be written to memory.
    def mem_write(address : Int, code : Array(UInt8))
      call(uc_mem_write, address, code.to_unsafe, code.size)
    end

    # Write to a range of bytes in memory from a String.
    #
    # - *address*: starting memory address of bytes to set.
    # - *code*: data to be written to memory.
    def mem_write(address : Int, code : String)
      mem_write(address, code.bytes)
    end

    # Read a range of bytes in memory.
    #
    # - *address*:  starting memory address of bytes to get.
    # - *size*: size of memory to read.
    def mem_read(address : Int, size : Int) : Array(UInt8)
      buffer = Array(UInt8).new(size, 0_u8)

      call(uc_mem_read, address, buffer.to_unsafe, size)

      buffer
    end

    # Emulate machine code in a specific duration of time.
    #
    # - *begin_addr*: address where emulation starts
    # - *end_addr*: address where emulation stops (i.e when this address is hit)
    # - *timeout*: duration to emulate the code (in microseconds). When this value is 0, we will emulate the code in infinite time, until the code is finished.
    # - *count*: the number of instructions to be emulated. When this value is 0, we will emulate all the code available, until the code is finished.
    def emu_start(begin_addr : Int, end_addr : Int, timeout : Int = 0, count : Int = 0)
      call(uc_emu_start, begin_addr, end_addr, timeout, count)
    end

    # Stop the emulation
    def emu_stop
      call(uc_emu_stop)
    end

    # Close a Unicorn engine instance.
    def close
      UcLib.uc_close(@uc_engine)
    end

    # Close a Unicorn engine instance.
    def finalize
      close
    end

    private macro call(name, *args)
      check_error(UcLib.{{ name }}(@uc_engine, {{*args}}))
    end

    private def check_error(status)
      raise UcError.new(status) if status != UcError::Error::OK
    end
  end
end
