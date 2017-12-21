require "./const/*"

module Unicorn
  class UcError < Exception
    getter :error

    def initialize(error : Error)
      @error = error
      @message = String.new(UcLib.uc_strerror(error))
    end

    enum Error
      OK              = UC_ERR_OK
      NOMEM           = UC_ERR_NOMEM
      ARCH            = UC_ERR_ARCH
      HANDLE          = UC_ERR_HANDLE
      MODE            = UC_ERR_MODE
      VERSION         = UC_ERR_VERSION
      READ_UNMAPPED   = UC_ERR_READ_UNMAPPED
      WRITE_UNMAPPED  = UC_ERR_WRITE_UNMAPPED
      FETCH_UNMAPPED  = UC_ERR_FETCH_UNMAPPED
      HOOK            = UC_ERR_HOOK
      INSN_INVALID    = UC_ERR_INSN_INVALID
      MAP             = UC_ERR_MAP
      WRITE_PROT      = UC_ERR_WRITE_PROT
      READ_PROT       = UC_ERR_READ_PROT
      FETCH_PROT      = UC_ERR_FETCH_PROT
      ARG             = UC_ERR_ARG
      READ_UNALIGNED  = UC_ERR_READ_UNALIGNED
      WRITE_UNALIGNED = UC_ERR_WRITE_UNALIGNED
      FETCH_UNALIGNED = UC_ERR_FETCH_UNALIGNED
      HOOK_EXIST      = UC_ERR_HOOK_EXIST
      RESOURCE        = UC_ERR_RESOURCE
      EXCEPTION       = UC_ERR_EXCEPTION
    end
  end

  @[Link("unicorn")]
  lib UcLib
    type UcEngine = Void*
    type UcHook = Void*

    struct UcMemRegion
      begin_addr, end_addr : UInt64
      perms : UInt32
    end

    fun uc_version(major : UInt32*, minor : UInt32*) : UInt32
    fun uc_strerror(error : UcError::Error) : UInt8*
    fun uc_open(arch : UInt32, mode : UInt32, uc_engine : UcEngine*) : UcError::Error
    fun uc_emu_stop(uc_engine : UcEngine) : UcError::Error
    fun uc_close(uc_engine : UcEngine) : UcError::Error
    fun uc_free(ptr : Void*) : UcError::Error
    fun uc_reg_write(uc_engine : UcEngine, reg : Int32, value : Void*) : UcError::Error
    fun uc_reg_read(uc_engine : UcEngine, reg : Int32, value : UInt64*) : UcError::Error
    fun uc_emu_start(uc_engine : UcEngine, begin_addr : UInt64, end_addr : UInt64, timeout : UInt64, count : UInt64) : UcError::Error
    fun uc_mem_map(uc_engine : UcEngine, address : UInt64, size : UInt64, perms : UInt32) : UcError::Error
    fun uc_mem_write(uc_engine : UcEngine, address : UInt64, code : UInt8*, size : UInt32) : UcError::Error
    fun uc_mem_read(uc_engine : UcEngine, address : UInt64, bytes : UInt8*, size : UInt64) : UcError::Error
    fun uc_mem_unmap(uc_engine : UcEngine, address : UInt64, size : UInt64) : UcError::Error
    fun uc_mem_protect(uc_engine : UcEngine, address : UInt64, size : UInt64, perms : UInt32) : UcError::Error
    fun uc_mem_regions(uc_engine : UcEngine, regions : UcMemRegion**, count : UInt32*) : UcError::Error
    fun uc_hook_add(uc_engine : UcEngine, handle : UcHook*, type : Int32, callback : UInt64, UInt64, UInt64, UInt64, UInt64, UInt64 -> UInt64, user_data : Void*, begin_addr : UInt64, end_addr : UInt64, ...) : UcError::Error
  end
end
